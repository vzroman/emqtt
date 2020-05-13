%%%-------------------------------------------------------------------
%% @doc sasl public API
%% @end
%%%-------------------------------------------------------------------

-module(emqtt_sasl).

-export([ check/4
        , supported/0]).

check(<<"SCRAM-SHA-1">>, _Data, Context, apply) ->
    Data = esasl_app:apply(<<"SCRAM-SHA-1">>, Context),
    {ok, Data, maps:merge(Context, #{client_first => Data})};
check(<<"SCRAM-SHA-1">>, Data, Context, check) ->
    esasl_app:check(<<"SCRAM-SHA-1">>, Data, Context);
check(_Method, _Data, _Context, _State) ->
    {error, authentication_failed}.

supported() ->
    [<<"SCRAM-SHA-1">>].
