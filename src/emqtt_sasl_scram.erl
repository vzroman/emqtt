%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqtt_sasl_scram).

-export([ check/2
        , make_client_first/1]).

-ifdef(TEST).
-compile(export_all).
-compile(nowarn_export_all).
-endif.

check(Data, Context) ->
    case maps:get(next_step, Context, undefined) of
        _ -> check_server_first(Data, Context);
        check_server_final -> check_server_final(Data, Context)
    end.

make_client_first(Context = #{username := Username}) ->
    Data = list_to_binary("n,," ++ binary_to_list(serialize([{username, Username}, {nonce, nonce()}]))),
    {ok, Data, maps:merge(Context, #{next_step => check_server_first, client_first => Data})}.

check_server_first(ServerFirst, #{password := Password,
                                  client_first := ClientFirst}) ->
    Attributes = parse(ServerFirst),
    Nonce = proplists:get_value(nonce, Attributes),
    ClientFirstWithoutHeader = without_header(ClientFirst),
    ClientFinalWithoutProof = serialize([{channel_binding, <<"biws">>}, {nonce, Nonce}]),
    Auth = list_to_binary(io_lib:format("~s,~s,~s", [ClientFirstWithoutHeader, ServerFirst, ClientFinalWithoutProof])),
    Salt = base64:decode(proplists:get_value(salt, Attributes)),
    IterationCount = binary_to_integer(proplists:get_value(iteration_count, Attributes)),
    SaltedPassword = pbkdf2_sha_1(Password, Salt, IterationCount),
    ClientKey = client_key(SaltedPassword),
    StoredKey = crypto:hash(sha, ClientKey),
    ClientSignature = hmac(StoredKey, Auth),
    ClientProof = base64:encode(crypto:exor(ClientKey, ClientSignature)),
    ClientFinal = serialize([{channel_binding, <<"biws">>},
                             {nonce, Nonce},
                             {proof, ClientProof}]),
    {continue, ClientFinal, #{next_step => check_server_final,
                              password => Password,
                              client_first => ClientFirst,
                              server_first => ServerFirst}}.

check_server_final(ServerFinal, #{password := Password,
                                  client_first := ClientFirst,
                                  server_first := ServerFirst}) ->
    NewAttributes = parse(ServerFinal),
    Attributes = parse(ServerFirst),
    Nonce = proplists:get_value(nonce, Attributes),
    ClientFirstWithoutHeader = without_header(ClientFirst),
    ClientFinalWithoutProof = serialize([{channel_binding, <<"biws">>}, {nonce, Nonce}]),
    Auth = list_to_binary(io_lib:format("~s,~s,~s", [ClientFirstWithoutHeader, ServerFirst, ClientFinalWithoutProof])),
    Salt = base64:decode(proplists:get_value(salt, Attributes)),
    IterationCount = binary_to_integer(proplists:get_value(iteration_count, Attributes)),
    SaltedPassword = pbkdf2_sha_1(Password, Salt, IterationCount),
    ServerKey = server_key(SaltedPassword),
    ServerSignature = hmac(ServerKey, Auth),
    case base64:encode(ServerSignature) =:= proplists:get_value(verifier, NewAttributes) of
        true ->
            {ok, <<>>, #{}};
        false -> 
            {stop, invalid_server_final}
    end.

nonce() ->
    base64:encode([$a + rand:uniform(26) || _ <- lists:seq(1, 10)]).

pbkdf2_sha_1(Password, Salt, IterationCount) ->
    case pbkdf2:pbkdf2(sha, Password, Salt, IterationCount) of
        {ok, Bin} ->
            pbkdf2:to_hex(Bin);
        {error, Reason} ->
            error(Reason)
    end.

hmac(Key, Data) ->
    HMAC = crypto:hmac_init(sha, Key),
    HMAC1 = crypto:hmac_update(HMAC, Data),
    crypto:hmac_final(HMAC1).

client_key(SaltedPassword) ->
    hmac(<<"Client Key">>, SaltedPassword).

server_key(SaltedPassword) ->
    hmac(<<"Server Key">>, SaltedPassword).

without_header(<<"n,,", ClientFirstWithoutHeader/binary>>) ->
    ClientFirstWithoutHeader;
without_header(<<GS2CbindFlag:1/binary, _/binary>>) ->
    error({unsupported_gs2_cbind_flag, binary_to_atom(GS2CbindFlag, utf8)}).

without_proof(ClientFinal) ->
    [ClientFinalWithoutProof | _] = binary:split(ClientFinal, <<",p=">>, [global, trim_all]),
    ClientFinalWithoutProof.

parse(Message) ->
    Attributes = binary:split(Message, <<$,>>, [global, trim_all]),
    lists:foldl(fun(<<Key:1/binary, "=", Value/binary>>, Acc) ->
                    [{to_long(Key), Value} | Acc]
                end, [], Attributes).

serialize(Attributes) ->
    iolist_to_binary(
        lists:foldl(fun({Key, Value}, []) ->
                        [to_short(Key), "=", to_list(Value)];
                       ({Key, Value}, Acc) ->
                        Acc ++ [",", to_short(Key), "=", to_list(Value)]
                     end, [], Attributes)).

to_long(<<"a">>) ->
    authzid;
to_long(<<"c">>) ->
    channel_binding;
to_long(<<"n">>) ->
    username;
to_long(<<"p">>) ->
    proof;
to_long(<<"r">>) ->
    nonce;
to_long(<<"s">>) ->
    salt;
to_long(<<"v">>) ->
    verifier;
to_long(<<"i">>) ->
    iteration_count;
to_long(_) ->
    error(test).

to_short(authzid) ->
    "a";
to_short(channel_binding) ->
    "c";
to_short(username) ->
    "n";
to_short(proof) ->
    "p";
to_short(nonce) ->
    "r";
to_short(salt) ->
    "s";
to_short(verifier) ->
    "v";
to_short(iteration_count) ->
    "i";
to_short(_) ->
    error(test).

to_list(V) when is_binary(V) ->
    binary_to_list(V);
to_list(V) when is_list(V) ->
    V;
to_list(V) when is_integer(V) ->
    integer_to_list(V);
to_list(_) ->
    error(bad_type).

