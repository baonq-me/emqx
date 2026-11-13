%%--------------------------------------------------------------------
%% Copyright (c) 2026 baonq-me. Licensed under the Apache License, Version 2.0.
%%--------------------------------------------------------------------
-module(emqx_dashboard_sso_proxy_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include("emqx_dashboard.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("common_test/include/ct.hrl").

-define(ISS, <<"https://id.example.test/realms/coder">>).
-define(AUD, <<"emqx-admin">>).
-define(ROLE, <<"emqx-admin">>).
-define(KID, <<"kid-1">>).
-define(HOST, "http://127.0.0.1:18083").

all() ->
    emqx_common_test_helpers:all(?MODULE).

init_per_suite(Config) ->
    Apps = emqx_cth_suite:start(
        [
            emqx_conf,
            emqx_management,
            emqx_mgmt_api_test_util:emqx_dashboard()
        ],
        #{work_dir => emqx_cth_suite:work_dir(Config)}
    ),
    %% a JWKS document served by inets httpd from a temp dir
    DocRoot = filename:join(?config(priv_dir, Config), "jwks"),
    ok = filelib:ensure_path(DocRoot),
    _ = inets:start(),
    {ok, Httpd} = inets:start(httpd, [
        {port, 0},
        {server_name, "jwks"},
        {server_root, DocRoot},
        {document_root, DocRoot},
        {bind_address, {127, 0, 0, 1}},
        {mime_types, [{"json", "application/json"}]}
    ]),
    [{port, Port}] = httpd:info(Httpd, [port]),
    Key = jose_jwk:generate_key({rsa, 2048}),
    Other = jose_jwk:generate_key({rsa, 2048}),
    [
        {apps, Apps},
        {httpd, Httpd},
        {docroot, DocRoot},
        {jwks_url, iolist_to_binary(io_lib:format("http://127.0.0.1:~b/jwks.json", [Port]))},
        {key, Key},
        {other_key, Other}
        | Config
    ].

end_per_suite(Config) ->
    inets:stop(httpd, ?config(httpd, Config)),
    emqx_cth_suite:stop(?config(apps, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    write_jwks(Config, [{?KID, ?config(key, Config)}]),
    emqx_dashboard_sso_proxy:clear_jwks_cache(),
    set_conf(Config, #{}),
    Config.

end_per_testcase(_Case, _Config) ->
    All = emqx_dashboard_admin:all_users(),
    [emqx_dashboard_admin:remove_user(Name) || #{username := Name} <- All],
    ok.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

set_conf(Config, Overrides) ->
    Base = #{
        enable => true,
        password_login => true,
        jwks_endpoint => ?config(jwks_url, Config),
        issuer => ?ISS,
        audience => ?AUD,
        required_role => ?ROLE,
        username_claim => <<"preferred_username">>,
        user_prefix => <<"sso_">>,
        jwks_refresh_interval => <<"15m">>,
        logout_url => <<"https://id.example.test/logout">>
    },
    Raw = maps:from_list([
        {atom_to_binary(K), V}
     || {K, V} <- maps:to_list(maps:merge(Base, Overrides))
    ]),
    {ok, _} = emqx_conf:update([dashboard], #{<<"sso_proxy">> => Raw}, #{override_to => cluster}),
    ok.

write_jwks(Config, Keys) ->
    Doc = #{
        <<"keys">> =>
            [
                begin
                    {_, Pub} = jose_jwk:to_public_map(K),
                    Pub#{<<"kid">> => Kid, <<"use">> => <<"sig">>, <<"alg">> => <<"RS256">>}
                end
             || {Kid, K} <- Keys
            ] ++
            %% an encryption key must be ignored
            [
                begin
                    {_, Enc} = jose_jwk:to_public_map(jose_jwk:generate_key({rsa, 1024})),
                    Enc#{<<"kid">> => <<"enc-1">>, <<"use">> => <<"enc">>}
                end
            ]
    },
    ok = file:write_file(
        filename:join(?config(docroot, Config), "jwks.json"), emqx_utils_json:encode(Doc)
    ).

claims() ->
    Now = erlang:system_time(second),
    #{
        <<"iss">> => ?ISS,
        <<"azp">> => ?AUD,
        <<"aud">> => <<"account">>,
        <<"typ">> => <<"Bearer">>,
        <<"exp">> => Now + 300,
        <<"iat">> => Now,
        <<"preferred_username">> => <<"Bao.NQ-me">>,
        <<"email">> => <<"user@example.test">>,
        <<"realm_access">> => #{<<"roles">> => [<<"offline_access">>, ?ROLE]}
    }.

sign(Key, Claims) ->
    sign(Key, #{<<"alg">> => <<"RS256">>, <<"kid">> => ?KID}, Claims).

sign(Key, JWS, Claims) ->
    {_, Token} = jose_jws:compact(jose_jwt:sign(Key, JWS, Claims)),
    Token.

token(Config) ->
    sign(?config(key, Config), claims()).

token(Config, Changes) ->
    sign(?config(key, Config), maps:merge(claims(), Changes)).

req(Method, Path, Headers) ->
    req(Method, Path, Headers, undefined).

req(Method, Path, Headers, Body) ->
    Url = ?HOST ++ "/api/v5/" ++ Path,
    H = [{str(K), str(V)} || {K, V} <- Headers],
    Request =
        case Body of
            undefined when Method =:= get -> {Url, H};
            undefined -> {Url, H, "application/json", <<>>};
            _ -> {Url, H, "application/json", emqx_utils_json:encode(Body)}
        end,
    {ok, {{_, Code, _}, _, RespBody}} =
        httpc:request(Method, Request, [], [{body_format, binary}]),
    Decoded =
        case RespBody of
            <<>> -> #{};
            _ -> emqx_utils_json:decode(RespBody, [return_maps])
        end,
    {Code, Decoded}.

sso_login(Token) ->
    req(post, "sso_proxy/login", [{"x-forwarded-access-token", Token}]).

bearer(DashToken) ->
    [{"authorization", <<"Bearer ", DashToken/binary>>}].

str(B) when is_binary(B) -> binary_to_list(B);
str(L) -> L.

%%--------------------------------------------------------------------
%% Cases
%%--------------------------------------------------------------------

t_status_disabled(Config) ->
    set_conf(Config, #{enable => false}),
    ?assertMatch(
        {200, #{<<"enable">> := false, <<"password_login">> := true}},
        req(get, "sso_proxy/status", [])
    ),
    ?assertMatch({404, _}, sso_login(token(Config))),
    %% password_login=false has no effect while disabled
    set_conf(Config, #{enable => false, password_login => false}),
    ?assert(emqx_dashboard_sso_proxy:password_login_allowed()).

t_login_creates_user(Config) ->
    ?assertMatch({200, #{<<"enable">> := true}}, req(get, "sso_proxy/status", [])),
    {200, #{<<"token">> := DashToken, <<"username">> := Username}} = sso_login(token(Config)),
    ?assertEqual(<<"sso_bao_nq_me">>, Username),
    ?assert(emqx_dashboard_sso_proxy:is_sso_proxy_user(Username)),
    %% the dashboard token works for normal API calls
    ?assertMatch({200, _}, req(get, "users", bearer(DashToken))).

t_login_existing_user(Config) ->
    {200, #{<<"username">> := U}} = sso_login(token(Config)),
    {200, #{<<"username">> := U, <<"token">> := T2}} = sso_login(token(Config)),
    ?assertEqual(1, length([X || #{username := X} <- emqx_dashboard_admin:all_users(), X =:= U])),
    ?assertMatch({200, _}, req(get, "users", bearer(T2))).

t_bad_signature(Config) ->
    Forged = sign(?config(other_key, Config), claims()),
    ?assertMatch({401, #{<<"code">> := <<"BAD_ACCESS_TOKEN">>}}, sso_login(Forged)).

t_alg_none(Config) ->
    _ = Config,
    H = jose_base64url:encode(emqx_utils_json:encode(#{alg => none, kid => ?KID})),
    P = jose_base64url:encode(emqx_utils_json:encode(claims())),
    ?assertMatch({401, _}, sso_login(<<H/binary, ".", P/binary, ".">>)).

t_hs256_with_public_key(Config) ->
    %% classic key-confusion attack: HMAC keyed with the RSA public key
    {_, PubPem} = jose_jwk:to_pem(jose_jwk:to_public(?config(key, Config))),
    Hmac = jose_jwk:from_oct(PubPem),
    Forged = sign(Hmac, #{<<"alg">> => <<"HS256">>, <<"kid">> => ?KID}, claims()),
    ?assertMatch({401, _}, sso_login(Forged)).

t_unknown_kid_refetch(Config) ->
    {200, _} = sso_login(token(Config)),
    %% key rotation: new kid appears in JWKS; cached set lacks it
    New = jose_jwk:generate_key({rsa, 2048}),
    write_jwks(Config, [{?KID, ?config(key, Config)}, {<<"kid-2">>, New}]),
    Tok = sign(New, #{<<"alg">> => <<"RS256">>, <<"kid">> => <<"kid-2">>}, claims()),
    %% within the 30 s refetch guard the unknown kid is rejected ...
    ?assertMatch({401, _}, sso_login(Tok)),
    %% ... and accepted once the cache may be refreshed
    emqx_dashboard_sso_proxy:clear_jwks_cache(),
    ?assertMatch({200, _}, sso_login(Tok)).

t_wrong_issuer(Config) ->
    ?assertMatch({401, _}, sso_login(token(Config, #{<<"iss">> => <<"https://evil">>}))).

t_wrong_azp(Config) ->
    ?assertMatch({401, _}, sso_login(token(Config, #{<<"azp">> => <<"other-client">>}))).

t_aud_list_accepted(Config) ->
    T = token(Config, #{<<"azp">> => <<"other">>, <<"aud">> => [<<"x">>, ?AUD]}),
    ?assertMatch({200, _}, sso_login(T)).

t_expired(Config) ->
    Past = erlang:system_time(second) - 120,
    ?assertMatch({401, _}, sso_login(token(Config, #{<<"exp">> => Past}))).

t_missing_role(Config) ->
    T = token(Config, #{<<"realm_access">> => #{<<"roles">> => [<<"offline_access">>]}}),
    ?assertMatch({403, #{<<"code">> := <<"ROLE_REQUIRED">>}}, sso_login(T)).

t_client_role_accepted(Config) ->
    T = token(Config, #{
        <<"realm_access">> => #{<<"roles">> => []},
        <<"resource_access">> => #{?AUD => #{<<"roles">> => [?ROLE]}}
    }),
    ?assertMatch({200, _}, sso_login(T)).

t_missing_header(_Config) ->
    ?assertMatch({401, _}, req(post, "sso_proxy/login", [])),
    ?assertMatch({401, _}, sso_login(<<"garbage">>)).

t_username_sanitize(Config) ->
    ?assertEqual(<<"bao_nq_me">>, emqx_dashboard_sso_proxy:sanitize(<<"Bao.NQ-me">>)),
    T = token(Config, #{<<"preferred_username">> => <<"a@b.c">>}),
    ?assertMatch({200, #{<<"username">> := <<"sso_a_b_c">>}}, sso_login(T)),
    NoName = maps:remove(<<"preferred_username">>, claims()),
    ?assertMatch({401, _}, sso_login(sign(?config(key, Config), NoName))).

t_user_conflict(Config) ->
    {ok, _} = emqx_dashboard_admin:add_user(
        <<"sso_bao_nq_me">>, <<"local_pass1">>, ?ROLE_DEFAULT, <<"local">>
    ),
    ?assertMatch({409, #{<<"code">> := <<"USER_CONFLICT">>}}, sso_login(token(Config))).

t_password_login_disabled_403(Config) ->
    {ok, _} = emqx_dashboard_admin:add_user(<<"admin2">>, <<"public_2x">>, ?ROLE_DEFAULT, <<>>),
    Body = #{username => <<"admin2">>, password => <<"public_2x">>},
    ?assertMatch({200, _}, req(post, "login", [], Body)),
    set_conf(Config, #{password_login => false}),
    ?assertMatch(
        {403, #{<<"code">> := <<"PASSWORD_LOGIN_DISABLED">>}}, req(post, "login", [], Body)
    ),
    ?assertMatch({200, #{<<"password_login">> := false}}, req(get, "sso_proxy/status", [])).

t_sso_user_password_rejected(Config) ->
    {200, #{<<"username">> := U}} = sso_login(token(Config)),
    Marker = emqx_dashboard_sso_proxy:sso_pwd_marker(),
    ?assertEqual({error, <<"password_error">>}, emqx_dashboard_admin:check(U, Marker)),
    ?assertEqual({error, <<"password_error">>}, emqx_dashboard_admin:check(U, <<>>)),
    ?assertMatch({401, _}, req(post, "login", [], #{username => U, password => Marker})).

t_settings_lockout_guard(Config) ->
    %% a password session may not switch password login off ...
    {ok, _} = emqx_dashboard_admin:add_user(<<"admin3">>, <<"public_3x">>, ?ROLE_DEFAULT, <<>>),
    {200, #{<<"token">> := PwdTok}} =
        req(post, "login", [], #{username => <<"admin3">>, password => <<"public_3x">>}),
    ?assertMatch(
        {409, #{<<"code">> := <<"NOT_ALLOWED">>}},
        req(put, "sso_proxy/settings", bearer(PwdTok), #{password_login => false})
    ),
    %% ... nor an API key
    ?assertMatch(
        {409, _},
        req(
            put,
            "sso_proxy/settings",
            [emqx_common_test_http:default_auth_header()],
            #{password_login => false}
        )
    ),
    %% an API key may switch it back on (recovery path)
    ?assertMatch(
        {200, #{<<"password_login">> := true}},
        req(
            put,
            "sso_proxy/settings",
            [emqx_common_test_http:default_auth_header()],
            #{password_login => true}
        )
    ),
    %% unauthenticated: 401
    ?assertMatch({401, _}, req(put, "sso_proxy/settings", [], #{password_login => true})).

t_settings_persist_cluster(Config) ->
    {200, #{<<"token">> := SsoTok}} = sso_login(token(Config)),
    ?assertMatch(
        {200, #{<<"password_login">> := false}},
        req(put, "sso_proxy/settings", bearer(SsoTok), #{password_login => false})
    ),
    ?assertEqual(false, emqx:get_config([dashboard, sso_proxy, password_login])),
    ?assertEqual(
        false,
        emqx_utils_maps:deep_get(
            [<<"sso_proxy">>, <<"password_login">>],
            emqx_config:get_raw([dashboard])
        )
    ),
    ?assertMatch(
        {200, #{<<"password_login">> := true}},
        req(put, "sso_proxy/settings", bearer(SsoTok), #{password_login => true})
    ).

t_logout_url_in_status(_Config) ->
    ?assertMatch(
        {200, #{<<"logout_url">> := <<"https://id.example.test/logout">>}},
        req(get, "sso_proxy/status", [])
    ).
