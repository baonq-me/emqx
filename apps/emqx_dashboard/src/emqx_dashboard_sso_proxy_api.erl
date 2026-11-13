%%--------------------------------------------------------------------
%% Copyright (c) 2026 baonq-me. Licensed under the Apache License, Version 2.0.
%%
%% REST API for passwordless dashboard login behind oauth2-proxy.
%% See emqx_dashboard_sso_proxy for the trust model.
%%--------------------------------------------------------------------
-module(emqx_dashboard_sso_proxy_api).

-behaviour(minirest_api).

-include("emqx_dashboard.hrl").
-include_lib("hocon/include/hoconsc.hrl").
-include_lib("emqx/include/logger.hrl").
-include_lib("typerefl/include/types.hrl").

-import(hoconsc, [mk/2, enum/1]).

-export([api_spec/0, paths/0, schema/1, namespace/0, fields/1]).
-export([status/2, login/2, settings/2]).

-define(TOKEN_HEADER, <<"x-forwarded-access-token">>).

namespace() -> "dashboard_sso_proxy".

api_spec() ->
    emqx_dashboard_swagger:spec(?MODULE, #{check_schema => true, translate_body => true}).

paths() ->
    ["/sso_proxy/status", "/sso_proxy/login", "/sso_proxy/settings"].

schema("/sso_proxy/status") ->
    #{
        'operationId' => status,
        get => #{
            tags => [<<"dashboard">>],
            desc => ?DESC(status_api),
            responses => #{200 => fields(status)},
            security => []
        }
    };
schema("/sso_proxy/login") ->
    #{
        'operationId' => login,
        post => #{
            tags => [<<"dashboard">>],
            desc => ?DESC(login_api),
            responses => #{
                200 => fields(login),
                401 => emqx_dashboard_swagger:error_codes(['BAD_ACCESS_TOKEN'], ?DESC(login_401)),
                403 => emqx_dashboard_swagger:error_codes(['ROLE_REQUIRED'], ?DESC(login_403)),
                404 => emqx_dashboard_swagger:error_codes(['NOT_FOUND'], ?DESC(login_404)),
                409 => emqx_dashboard_swagger:error_codes(['USER_CONFLICT'], ?DESC(login_409)),
                503 => emqx_dashboard_swagger:error_codes(
                    ['SERVICE_UNAVAILABLE'], ?DESC(login_503)
                )
            },
            security => []
        }
    };
schema("/sso_proxy/settings") ->
    #{
        'operationId' => settings,
        get => #{
            tags => [<<"dashboard">>],
            desc => ?DESC(get_settings_api),
            responses => #{200 => fields(settings)}
        },
        put => #{
            tags => [<<"dashboard">>],
            desc => ?DESC(put_settings_api),
            'requestBody' => fields(settings),
            responses => #{
                200 => fields(settings),
                404 => emqx_dashboard_swagger:error_codes(['NOT_FOUND'], ?DESC(login_404)),
                409 => emqx_dashboard_swagger:error_codes(['NOT_ALLOWED'], ?DESC(settings_409))
            }
        }
    }.

fields(status) ->
    [
        {enable, mk(boolean(), #{desc => ?DESC(enable)})},
        {password_login, mk(boolean(), #{desc => ?DESC(password_login)})},
        {logout_url, mk(binary(), #{desc => ?DESC(logout_url)})},
        {user_prefix, mk(binary(), #{desc => ?DESC(user_prefix)})}
    ];
fields(login) ->
    [
        {token, mk(binary(), #{desc => ?DESC(token)})},
        {username, mk(binary(), #{desc => ?DESC(username)})},
        {version, mk(string(), #{desc => ?DESC(version)})},
        {license, [{edition, mk(enum([opensource, enterprise]), #{desc => ?DESC(license)})}]}
    ];
fields(settings) ->
    [{password_login, mk(boolean(), #{desc => ?DESC(password_login), required => true})}].

%%--------------------------------------------------------------------
%% Handlers
%%--------------------------------------------------------------------

status(get, _Req) ->
    Conf = emqx_dashboard_sso_proxy:config(),
    {200, #{
        enable => emqx_dashboard_sso_proxy:enabled(),
        password_login => emqx_dashboard_sso_proxy:password_login_allowed(),
        logout_url => maps:get(logout_url, Conf, <<>>),
        user_prefix => maps:get(user_prefix, Conf, <<"sso_">>)
    }}.

login(post, #{headers := Headers}) ->
    Token = maps:get(?TOKEN_HEADER, Headers, undefined),
    case emqx_dashboard_sso_proxy:login(Token) of
        {ok, #{username := Username, token := DashToken}} ->
            minirest_handler:update_log_meta(#{log_from => dashboard, log_source => Username}),
            ?SLOG(info, #{msg => "dashboard_sso_proxy_login_successful", username => Username}),
            Version = iolist_to_binary(proplists:get_value(version, emqx_sys:info())),
            {200, #{
                token => DashToken,
                username => Username,
                version => Version,
                license => #{edition => emqx_release:edition()}
            }};
        {error, disabled} ->
            {404, 'NOT_FOUND', <<"SSO proxy login is not enabled">>};
        {error, missing_token} ->
            log_failure(missing_token),
            {401, 'BAD_ACCESS_TOKEN', <<"Missing X-Forwarded-Access-Token">>};
        {error, role_required} ->
            log_failure(role_required),
            {403, 'ROLE_REQUIRED', <<"Token lacks the required role">>};
        {error, user_conflict} ->
            log_failure(user_conflict),
            {409, 'USER_CONFLICT', <<"A local dashboard user with this name exists">>};
        {error, {jwks_unavailable, _} = Reason} ->
            log_failure(Reason),
            {503, 'SERVICE_UNAVAILABLE', <<"Identity provider keys unavailable">>};
        {error, Reason} ->
            log_failure(Reason),
            {401, 'BAD_ACCESS_TOKEN', <<"Invalid access token">>}
    end.

settings(get, _Req) ->
    {200, #{password_login => emqx_dashboard_sso_proxy:password_login_allowed()}};
settings(put, #{body := #{<<"password_login">> := Allow}, headers := Headers}) ->
    case emqx_dashboard_sso_proxy:enabled() of
        false ->
            {404, 'NOT_FOUND', <<"SSO proxy login is not enabled">>};
        true when Allow =:= false ->
            %% Lockout guard: only someone who is signed in through SSO right now
            %% (which proves SSO works) may switch password login off.
            case caller(Headers) of
                {ok, Caller} ->
                    case emqx_dashboard_sso_proxy:is_sso_proxy_user(Caller) of
                        true -> update_password_login(false, Caller);
                        false -> not_allowed()
                    end;
                error ->
                    not_allowed()
            end;
        true ->
            update_password_login(true, caller_name(Headers))
    end.

not_allowed() ->
    {409, 'NOT_ALLOWED', <<"Password login can only be disabled from an SSO session">>}.

update_password_login(Allow, Caller) ->
    case emqx_dashboard_sso_proxy:set_password_login(Allow) of
        ok ->
            ?SLOG(warning, #{
                msg => "dashboard_sso_proxy_password_login_changed",
                password_login => Allow,
                by => Caller
            }),
            {200, #{password_login => emqx_dashboard_sso_proxy:password_login_allowed()}};
        {error, Reason} ->
            {400, 'BAD_REQUEST', iolist_to_binary(io_lib:format("~0p", [Reason]))}
    end.

caller(Headers) ->
    case maps:get(<<"authorization">>, Headers, undefined) of
        <<Bearer:7/binary, Token/binary>> when
            Bearer =:= <<"Bearer ">>; Bearer =:= <<"bearer ">>
        ->
            case emqx_dashboard_token:owner(Token) of
                {ok, Owner} when is_binary(Owner) -> {ok, Owner};
                _ -> error
            end;
        _ ->
            error
    end.

caller_name(Headers) ->
    case caller(Headers) of
        {ok, Name} -> Name;
        error -> <<"api_key">>
    end.

log_failure(Reason) ->
    ?SLOG(warning, #{msg => "dashboard_sso_proxy_login_failed", reason => Reason}).
