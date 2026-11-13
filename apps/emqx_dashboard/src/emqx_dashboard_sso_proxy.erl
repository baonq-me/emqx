%%--------------------------------------------------------------------
%% Copyright (c) 2026 baonq-me. Licensed under the Apache License, Version 2.0.
%%
%% Passwordless dashboard login behind an authenticating reverse proxy
%% (oauth2-proxy with `--pass-access-token`).
%%
%% Nothing about the request path is trusted. The proxy forwards the OIDC
%% access token in `X-Forwarded-Access-Token`; this module verifies it:
%%   * compact JWS, alg RS256 only (no `none`, no HMAC),
%%   * signature against the issuer's JWKS (signing keys only, cached,
%%     re-fetched on an unknown `kid` at most once per ?MIN_REFETCH_MS),
%%   * `iss` equals the configured issuer,
%%   * `azp` (or `aud`) contains the configured audience (client id),
%%   * `exp` in the future (?LEEWAY_S seconds leeway), `nbf` not in the future,
%%   * `realm_access.roles` (or `resource_access.<audience>.roles`) contains
%%     the configured role.
%% On success a dashboard user `<user_prefix><claim>` is created on first use
%% (password hash = ?SSO_PWD_MARKER, which can never verify) and a normal
%% dashboard token is signed for it.
%%--------------------------------------------------------------------
-module(emqx_dashboard_sso_proxy).

-include("emqx_dashboard.hrl").
-include_lib("emqx/include/logger.hrl").

-export([
    create_tables/0,
    set_password_login/1,
    config/0,
    enabled/0,
    password_login_allowed/0,
    is_sso_proxy_user/1,
    login/1,
    verify/1,
    username_from_claims/1,
    sso_pwd_marker/0,
    clear_jwks_cache/0
]).

-ifdef(TEST).
-export([sanitize/1, fetch_jwks/1]).
-endif.

-define(SSO_PWD_MARKER, <<"!sso_proxy">>).
%% Runtime settings changed from the dashboard (password_login). Kept in a replicated
%% table rather than cluster.hocon: emqx_conf:update/3 on the dashboard root would persist
%% the whole root, env-supplied default_password included, and a cluster.hocon with
%% dashboard.sso_proxy would stop an upstream EMQX from booting after a rollback.
-define(SETTING_TAB, emqx_dashboard_sso_proxy_setting).
-record(?SETTING_TAB, {key :: atom(), value :: term()}).
-define(JWKS_KEY, {?MODULE, jwks}).
-define(MIN_REFETCH_MS, 30000).
-define(LEEWAY_S, 30).
-define(ALGS, [<<"RS256">>]).

%%--------------------------------------------------------------------
%% Config
%%--------------------------------------------------------------------

-spec config() -> map().
config() ->
    emqx:get_config([dashboard, sso_proxy], #{}).

enabled() ->
    maps:get(enable, config(), false) =:= true.

create_tables() ->
    ok = mria:create_table(?SETTING_TAB, [
        {type, set},
        {rlog_shard, ?DASHBOARD_SHARD},
        {storage, disc_copies},
        {record_name, ?SETTING_TAB},
        {attributes, record_info(fields, ?SETTING_TAB)}
    ]),
    [?SETTING_TAB].

%% Password login is only ever restricted when the feature is enabled. The dashboard
%% setting (table) wins over the config value, which is only the default.
password_login_allowed() ->
    Conf = config(),
    Default = maps:get(password_login, Conf, true),
    Value =
        case ets:whereis(?SETTING_TAB) of
            undefined ->
                Default;
            _ ->
                case ets:lookup(?SETTING_TAB, password_login) of
                    [#?SETTING_TAB{value = V}] when is_boolean(V) -> V;
                    _ -> Default
                end
        end,
    not (maps:get(enable, Conf, false) =:= true andalso Value =:= false).

-spec set_password_login(boolean()) -> ok | {error, term()}.
set_password_login(Allow) when is_boolean(Allow) ->
    Rec = #?SETTING_TAB{key = password_login, value = Allow},
    case mria:transaction(?DASHBOARD_SHARD, fun() -> mnesia:write(Rec) end) of
        {atomic, ok} -> ok;
        {aborted, Reason} -> {error, Reason}
    end.

sso_pwd_marker() -> ?SSO_PWD_MARKER.

is_sso_proxy_user(Username) when is_binary(Username) ->
    case emqx_dashboard_admin:lookup_user(Username) of
        [#?ADMIN{pwdhash = ?SSO_PWD_MARKER}] -> true;
        _ -> false
    end;
is_sso_proxy_user(_) ->
    false.

%%--------------------------------------------------------------------
%% Login
%%--------------------------------------------------------------------

-spec login(binary() | undefined) ->
    {ok, #{username := binary(), role := binary(), token := binary()}}
    | {error,
        disabled
        | missing_token
        | {bad_token, term()}
        | role_required
        | user_conflict
        | term()}.
login(Token) ->
    case enabled() of
        false ->
            {error, disabled};
        true when Token =:= undefined; Token =:= <<>> ->
            {error, missing_token};
        true ->
            case verify(Token) of
                {ok, Claims} -> login_with_claims(Claims);
                {error, _} = Error -> Error
            end
    end.

login_with_claims(Claims) ->
    case username_from_claims(Claims) of
        {ok, Username} ->
            case ensure_user(Username, Claims) of
                {ok, User} ->
                    %% The dashboard token is an HMAC JWT keyed on (salt, username,
                    %% password); SSO users have no password, so use random bytes.
                    {ok, Role, DashToken} =
                        emqx_dashboard_token:sign(User, crypto:strong_rand_bytes(32)),
                    {ok, #{username => Username, role => Role, token => DashToken}};
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

username_from_claims(Claims) ->
    Conf = config(),
    Claim = maps:get(username_claim, Conf, <<"preferred_username">>),
    Prefix = maps:get(user_prefix, Conf, <<"sso_">>),
    case maps:get(bin(Claim), Claims, undefined) of
        Value when is_binary(Value), Value =/= <<>> ->
            Name = sanitize(Value),
            {ok,
                binary:part(
                    <<(bin(Prefix))/binary, Name/binary>>,
                    0,
                    min(100, byte_size(Prefix) + byte_size(Name))
                )};
        _ ->
            {error, {bad_token, {missing_claim, Claim}}}
    end.

%% Dashboard usernames are `^[_a-zA-Z0-9]*$`; map anything else to `_`.
sanitize(Value) ->
    Lower = string:lowercase(Value),
    iolist_to_binary(re:replace(Lower, "[^a-z0-9_]", "_", [global, unicode])).

ensure_user(Username, Claims) ->
    Desc = iolist_to_binary([
        <<"Keycloak SSO">>,
        case maps:get(<<"email">>, Claims, undefined) of
            Email when is_binary(Email) -> [<<": ">>, Email];
            _ -> <<>>
        end
    ]),
    Trans = fun() ->
        case mnesia:wread({?ADMIN, Username}) of
            [] ->
                User = #?ADMIN{
                    username = Username,
                    pwdhash = ?SSO_PWD_MARKER,
                    description = Desc,
                    role = ?ROLE_DEFAULT,
                    extra = #{sso_proxy => true}
                },
                ok = mnesia:write(User),
                {created, User};
            [#?ADMIN{pwdhash = ?SSO_PWD_MARKER} = User] ->
                {existing, User};
            [_LocalUser] ->
                mnesia:abort(user_conflict)
        end
    end,
    case mria:sync_transaction(?DASHBOARD_SHARD, Trans) of
        {atomic, {created, User}} ->
            ?SLOG(info, #{msg => "dashboard_sso_proxy_user_created", username => Username}),
            {ok, User};
        {atomic, {existing, User}} ->
            {ok, User};
        {aborted, user_conflict} ->
            {error, user_conflict};
        {aborted, Reason} ->
            {error, Reason}
    end.

%%--------------------------------------------------------------------
%% Token verification
%%--------------------------------------------------------------------

-spec verify(binary()) -> {ok, map()} | {error, term()}.
verify(Token) when is_binary(Token) ->
    try
        verify_(Token)
    catch
        throw:Reason ->
            {error, {bad_token, Reason}};
        Class:Error:Stacktrace ->
            ?SLOG(debug, #{
                msg => "dashboard_sso_proxy_verify_crash",
                class => Class,
                reason => Error,
                stacktrace => Stacktrace
            }),
            {error, {bad_token, {Class, Error}}}
    end;
verify(_) ->
    {error, missing_token}.

verify_(Token) ->
    Conf = config(),
    Header = peek_header(Token),
    Alg = maps:get(<<"alg">>, Header, undefined),
    Kid = maps:get(<<"kid">>, Header, undefined),
    case lists:member(Alg, ?ALGS) of
        false ->
            {error, {bad_token, {alg_not_allowed, Alg}}};
        true ->
            case get_key(Kid, Conf) of
                {ok, JWK} ->
                    case jose_jwt:verify_strict(JWK, ?ALGS, Token) of
                        {true, {jose_jwt, Claims}, _JWS} ->
                            check_claims(Claims, Conf);
                        {false, _, _} ->
                            {error, {bad_token, bad_signature}};
                        Other ->
                            {error, {bad_token, Other}}
                    end;
                {error, _} = Error ->
                    Error
            end
    end.

peek_header(Token) ->
    case binary:split(Token, <<".">>, [global]) of
        [_H, _P, _S] ->
            Map = emqx_utils_json:decode(jose_jws:peek_protected(Token), [return_maps]),
            is_map(Map) orelse throw(bad_header),
            Map;
        _ ->
            throw(not_a_compact_jws)
    end.

check_claims(Claims, Conf) ->
    Now = erlang:system_time(second),
    Issuer = bin(maps:get(issuer, Conf, <<>>)),
    Audience = bin(maps:get(audience, Conf, <<>>)),
    Role = bin(maps:get(required_role, Conf, <<>>)),
    Checks = [
        {issuer, Issuer =/= <<>> andalso maps:get(<<"iss">>, Claims, undefined) =:= Issuer},
        {expired,
            is_integer(maps:get(<<"exp">>, Claims, undefined)) andalso
                maps:get(<<"exp">>, Claims) + ?LEEWAY_S > Now},
        {not_yet_valid, maps:get(<<"nbf">>, Claims, 0) - ?LEEWAY_S =< Now},
        {token_type, lists:member(maps:get(<<"typ">>, Claims, <<"Bearer">>), [<<"Bearer">>])},
        {audience, Audience =/= <<>> andalso has_audience(Claims, Audience)}
    ],
    case [Name || {Name, false} <- Checks] of
        [] ->
            case Role =:= <<>> orelse has_role(Claims, Role, Audience) of
                true -> {ok, Claims};
                false -> {error, role_required}
            end;
        [First | _] ->
            {error, {bad_token, First}}
    end.

has_audience(Claims, Audience) ->
    maps:get(<<"azp">>, Claims, undefined) =:= Audience orelse
        case maps:get(<<"aud">>, Claims, undefined) of
            Audience -> true;
            List when is_list(List) -> lists:member(Audience, List);
            _ -> false
        end.

has_role(Claims, Role, Audience) ->
    RealmRoles = deep_get([<<"realm_access">>, <<"roles">>], Claims),
    ClientRoles = deep_get([<<"resource_access">>, Audience, <<"roles">>], Claims),
    lists:member(Role, RealmRoles) orelse lists:member(Role, ClientRoles).

deep_get([], V) when is_list(V) -> V;
deep_get([K | Rest], M) when is_map(M) -> deep_get(Rest, maps:get(K, M, undefined));
deep_get(_, _) -> [].

%%--------------------------------------------------------------------
%% JWKS cache
%%--------------------------------------------------------------------

clear_jwks_cache() ->
    _ = persistent_term:erase(?JWKS_KEY),
    ok.

get_key(Kid, Conf) ->
    Now = erlang:system_time(millisecond),
    RefreshMs = maps:get(jwks_refresh_interval, Conf, 900000),
    Cache = persistent_term:get(?JWKS_KEY, #{fetched_at => 0, keys => #{}}),
    #{fetched_at := FetchedAt, keys := Keys} = Cache,
    Stale = Now - FetchedAt > RefreshMs,
    case maps:find(Kid, Keys) of
        {ok, JWK} when not Stale ->
            {ok, JWK};
        Found when Now - FetchedAt > ?MIN_REFETCH_MS ->
            case fetch_jwks(Conf) of
                {ok, NewKeys} ->
                    persistent_term:put(?JWKS_KEY, #{fetched_at => Now, keys => NewKeys}),
                    case maps:find(Kid, NewKeys) of
                        {ok, JWK} -> {ok, JWK};
                        error -> {error, {bad_token, unknown_kid}}
                    end;
                {error, Reason} ->
                    ?SLOG(warning, #{
                        msg => "dashboard_sso_proxy_jwks_fetch_failed", reason => Reason
                    }),
                    %% keep using a cached key rather than locking everyone out
                    case Found of
                        {ok, JWK} -> {ok, JWK};
                        error -> {error, {jwks_unavailable, Reason}}
                    end
            end;
        {ok, JWK} ->
            {ok, JWK};
        error ->
            {error, {bad_token, unknown_kid}}
    end.

fetch_jwks(Conf) ->
    Endpoint = str(maps:get(jwks_endpoint, Conf, <<>>)),
    HTTPOpts = [{timeout, 5000}, {connect_timeout, 5000} | ssl_opts(Endpoint)],
    case httpc:request(get, {Endpoint, []}, HTTPOpts, [{body_format, binary}]) of
        {ok, {{_, 200, _}, _Headers, Body}} ->
            #{<<"keys">> := KeyList} = emqx_utils_json:decode(Body, [return_maps]),
            Keys = maps:from_list([
                {maps:get(<<"kid">>, K, undefined), jose_jwk:from_map(K)}
             || K <- KeyList,
                maps:get(<<"kty">>, K, undefined) =:= <<"RSA">>,
                maps:get(<<"use">>, K, <<"sig">>) =:= <<"sig">>
            ]),
            {ok, Keys};
        {ok, {{_, Code, _}, _, _}} ->
            {error, {http_status, Code}};
        {error, Reason} ->
            {error, Reason}
    end.

ssl_opts("https://" ++ Rest) ->
    Host = hd(string:split(hd(string:split(Rest, "/")), ":")),
    [
        {ssl, [
            {verify, verify_peer},
            {cacerts, public_key:cacerts_get()},
            {server_name_indication, Host},
            {depth, 5},
            {customize_hostname_check, [
                {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
            ]}
        ]}
    ];
ssl_opts(_) ->
    [].

bin(A) when is_atom(A) -> atom_to_binary(A, utf8);
bin(L) when is_list(L) -> unicode:characters_to_binary(L);
bin(B) when is_binary(B) -> B.

str(B) when is_binary(B) -> binary_to_list(B);
str(L) when is_list(L) -> L.
