%%%-------------------------------------------------------------------
%% @doc sasl public API
%% @end
%%%-------------------------------------------------------------------

-module(emqtt_sasl).

-export([ check/4
        , supported/0]).

check(<<"SCRAM-SHA-1">>, _Data, Context, apply) ->
    emqtt_sasl_scram:make_client_first(Context);
check(<<"SCRAM-SHA-1">>, Data, Context, check) ->
    try
        emqtt_sasl_scram:check(Data, Context)
    catch 
        _ ->  {error, authentication_failed}
    end;
check(_Method, _Data, _Context, _State) ->
    {error, authentication_failed}.

supported() ->
    [<<"SCRAM-SHA-1">>].
