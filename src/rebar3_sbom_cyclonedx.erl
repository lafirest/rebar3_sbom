-module(rebar3_sbom_cyclonedx).

-export([bom/2, bom/3, uuid/0]).

-define(APP, "rebar3_sbom").

-include_lib("xmerl/include/xmerl.hrl").

bom(File, Components) ->
    bom(File, Components, uuid()).

bom(File, Components, Serial) ->
    Bom = {bom, [{version, [get_version(File)]}, {serialNumber, Serial}, {xmlns, "http://cyclonedx.org/schema/bom/1.1"}], [
        {metadata, metadata()},
        {components, [], [component(Component) || Component <- Components, Component /= undefined]}
    ]},
    xmerl:export_simple([Bom], xmerl_xml).

metadata() ->
    [{timestamp, [calendar:system_time_to_rfc3339(erlang:system_time(second))]},
     {tools, [{tool, [?APP]}]},
     {licenses, [{license, [], [{id, [], [["BSD-3-Clause"]]}]}]}
    ].

component(Component) ->
    {component, [{type, "library"}],
        [component_field(Field, Value) || {Field, Value} <- Component, Value /= undefined]}.

component_field(name, Name) -> {name, [], [[Name]]};
component_field(version, Version) -> {version, [], [[Version]]};
component_field(author, Author) -> {author, [], [[string:join(Author, ",")]]};
component_field(description, Description) -> {description, [], [[Description]]};
component_field(licenses, Licenses) -> {licenses, [], [license(License) || License <- Licenses]};
component_field(purl, Purl) -> {purl, [], [[Purl]]};
component_field(sha256, Sha256) ->
    {hashes, [], [
        {hash, [{alg, "SHA-256"}], [[Sha256]]}
    ]}.

license(Name) ->
    case rebar3_sbom_license:spdx_id(Name) of
        undefined ->
            {license, [], [{name, [], [[Name]]}]};
        SpdxId ->
            {license, [], [{id, [], [[SpdxId]]}]}
    end.

uuid() ->
    [A, B, C, D, E] = [crypto:strong_rand_bytes(Len) || Len <- [4, 2, 2, 2, 6]],
    lists:join("-", [hex(Part) || Part <- [A, B, <<4:4, C:12/binary-unit:1>>, <<2:2, D:14/binary-unit:1>>, E]]).

hex(Bin) ->
    string:lowercase(<< <<Hex>> || <<Nibble:4>> <= Bin, Hex <- integer_to_list(Nibble,16) >>).

get_version(File) ->
    try
        case xmerl_scan:file(File) of
            {#xmlElement{attributes = Attrs}, _} ->
                case lists:keyfind(version, #xmlAttribute.name, Attrs) of
                    false ->
                        "1";
                    #xmlAttribute{value = Value} ->
                        Version = erlang:list_to_integer(Value),
                        erlang:integer_to_list(Version + 1)
                end;
            {error, enoent} ->
                "1"
        end
    catch _:Reason ->
            logger:error("scan file:~ts failed, reason:~p, will use the default version number 1",
                         [File, Reason]),
            "1"
    end.
