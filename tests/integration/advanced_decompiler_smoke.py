"""Real-Ghidra smoke coverage; invoke only on a disposable analyzed fixture.

Best fixture: a non-inlined function with a conditional branch, a direct call,
an integer parameter, stack locals surviving optimization, and a referenced
writable scalar global. Missing fixture features are reported, never counted as
passing operations. The driver intentionally commits database mutations.
"""

from __future__ import annotations

from agenticghidra_mcp.advanced import control_flow as graph, decompiler as decomp


def _function_candidates(program):
    """Find real analyzed functions with branch and call evidence for the smoke."""
    candidates = []
    for index, item in enumerate(program.getFunctionManager().getFunctions(True)):
        if index >= 10000:
            break
        if item.isExternal() or item.isThunk():
            continue
        calls = []
        conditional = False
        for instruction in program.getListing().getInstructions(item.getBody(), True):
            flow = instruction.getFlowType()
            conditional = conditional or bool(flow.isConditional())
            if flow.isCall():
                calls.append(str(instruction.getAddress()))
        candidates.append((2 * int(conditional) + bool(calls), item, calls, conditional))
    return candidates


def _preferred_candidate(candidates, scratch):
    preferred = scratch.get("function_start") if isinstance(scratch, dict) else None
    selected = next(
        (row for row in candidates if str(row[1].getEntryPoint()) == str(preferred)), None
    )
    return selected or max(candidates, key=lambda row: row[0])


def _select_fixture(program, scratch, requirements):
    candidates = _function_candidates(program)
    if not candidates:
        raise AssertionError("Decompiler smoke requires an analyzed native function")
    _, item, calls, conditional = _preferred_candidate(candidates, scratch)
    caller = item
    if not calls:
        caller_candidate = next((row for row in candidates if row[2]), None)
        if caller_candidate is not None:
            _, caller, calls, _ = caller_candidate
    if not conditional:
        requirements.append("A conditional branch is required to prove multi-successor CFG edges")
    if not calls:
        requirements.append("A call instruction is required for call paths and callsite overrides")
    return item, caller, calls, conditional


def _smoke_graphs(invoke, entry, caller, conditional, requirements):
    from ghidra.util.task import TaskMonitor

    call_entry = str(caller.getEntryPoint())
    basic = invoke(graph.basic_blocks, function_start=entry)
    assert basic["blocks"], basic
    edges = invoke(graph.cfg_edges, function_start=entry)
    if conditional:
        assert any(edge["conditional"] for edge in edges["edges"]), edges
    raw = invoke(graph.pcode_function, function_start=entry, limit=1000)
    assert raw["ops"], raw
    invoke(graph.pcode_block, address=entry)
    at = invoke(graph.op_at, address=raw["ops"][0]["address"])
    assert at["ops"], at
    callees = sorted(
        caller.getCalledFunctions(TaskMonitor.DUMMY), key=lambda fn: str(fn.getEntryPoint())
    )
    if callees:
        target = str(callees[0].getEntryPoint())
        paths = invoke(
            graph.call_paths,
            source_function=call_entry,
            target_function=target,
            max_depth=4,
            limit=10,
        )
        assert any(path[0] == call_entry and path[-1] == target for path in paths["paths"]), paths
    else:
        paths = invoke(
            graph.call_paths, source_function=entry, target_function=entry, max_depth=0, limit=1
        )
        assert paths["paths"] == [[entry]], paths
        requirements.append(
            "A resolved direct call target is required to prove a nontrivial call path"
        )


def _smoke_ssa_selection(invoke, entry, requirements, observations):
    code = invoke(decomp.decompile_function, function_start=entry)
    assert code["code"], code
    tree = invoke(decomp.ast, function_start=entry)
    assert tree["nodes"] and all("parent" in node and "kind" in node for node in tree["nodes"]), (
        tree
    )
    assert len(tree["nodes"]) <= 1000
    token_result = invoke(decomp.tokens, function_start=entry)
    assert token_result["tokens"] and any(token.get("text") for token in token_result["tokens"]), (
        token_result
    )
    assert len(token_result["tokens"]) <= 1000
    summary = invoke(decomp.high_function_summary, function_start=entry)
    assert summary["pcode"]["ops"] and summary["blocks"]["blocks"], summary
    nodes = summary["varnodes"]["varnodes"]
    assert nodes and "id" in nodes[0], nodes
    selector = nodes[0]
    uses = invoke(
        graph.varnode_uses,
        function_start=entry,
        varnode=f"id:{selector['id']}",
        address=selector["address"],
        space=selector["space"],
        size=selector["size"],
    )
    assert len(uses["varnodes"]) == 1, uses
    assert uses["varnodes"][0]["varnode"]["id"] == selector["id"], uses

    symbols = summary["symbols"]["symbols"]
    _smoke_type_traces(invoke, entry, symbols, nodes, requirements, observations)
    return symbols


def _assert_type_trace(trace, selected):
    assert trace["nodes"] and all(
        "data_type" in node for node in trace["nodes"] if "name" in node
    ), trace
    ids = {node["id"] for node in trace["nodes"]}
    assert any(node.get("name") == selected["name"] for node in trace["nodes"]), trace
    assert ids, trace


def _smoke_type_traces(invoke, entry, symbols, nodes, requirements, observations):
    instance_names = {node.get("name") for node in nodes}
    selected = next(
        (symbol for symbol in symbols if not symbol["global"] and symbol["name"] in instance_names),
        None,
    )
    if selected is None:
        requirements.append(
            "A decompiled parameter or local with SSA instances is required for both type traces"
        )
    else:
        selection = {
            "function_start": entry,
            "name": selected["name"],
            "ordinal": selected["ordinal"],
            "storage": selected["storage"],
        }
        for handler in (decomp.trace_type_backward, decomp.trace_type_forward):
            trace = invoke(handler, **selection)
            _assert_type_trace(trace, selected)
            observations[handler.__operation__.name] = {
                "nodes": len(trace["nodes"]),
                "edges": len(trace["edges"]),
            }


def _smoke_writeback(invoke, entry, item, symbols, requirements):
    inferred_params = {symbol["ordinal"]: symbol for symbol in symbols if symbol["parameter"]}
    committed_params = invoke(
        decomp.writeback_params, function_start=entry, use_data_types=True, commit_return=True
    )
    assert len(committed_params["parameters"]) == len(inferred_params), committed_params
    for param in committed_params["parameters"]:
        expected = inferred_params[param["ordinal"]]
        assert param["name"] == expected["name"], (param, expected)
    if not inferred_params:
        requirements.append(
            "An inferred parameter is required to prove nonempty parameter writeback"
        )
    committed_locals = invoke(decomp.writeback_locals, function_start=entry)
    for variable in committed_locals["locals"]:
        assert any(str(db.getName()) == variable["name"] for db in item.getLocalVariables()), (
            variable
        )
    if not committed_locals["locals"]:
        requirements.append(
            "A surviving decompiler local is required to prove nonempty local writeback"
        )


def _smoke_overrides(invoke, caller, calls):
    call_entry = str(caller.getEntryPoint())
    if calls:
        callsite = calls[0]
        invoke(decomp.override_get, function_start=call_entry, callsite=callsite)
        override = invoke(
            decomp.override_set,
            function_start=call_entry,
            callsite=callsite,
            signature="int advanced_smoke_override(int value)",
        )
        assert override["found"], override
        stored = override["overrides"][0]
        assert stored["return_type"] == "int" and len(stored["arguments"]) == 1, stored
        assert stored["arguments"][0]["data_type"] == "int", stored
        persisted = invoke(decomp.override_get, function_start=call_entry, callsite=callsite)
        assert persisted["overrides"] == override["overrides"], persisted


def _scalar_global(program, symbols):
    for symbol in symbols:
        if not symbol["global"] or symbol["size"] not in (1, 2, 4, 8):
            continue
        db_symbol = program.getSymbolTable().getSymbol(symbol["id"])
        if db_symbol is not None and not db_symbol.getAddress().isMemoryAddress():
            continue
        # Avoid functions; global code symbols also occur in the global map.
        if (
            db_symbol is not None
            and program.getFunctionManager().getFunctionAt(db_symbol.getAddress()) is not None
        ):
            continue
        return symbol
    return None


def _smoke_globals(invoke, program, entry, requirements):
    # Parameter/local commits can change recovered symbols, so select globals afresh.
    summary = invoke(decomp.high_function_summary, function_start=entry)
    global_symbol = _scalar_global(program, summary["symbols"]["symbols"])
    if global_symbol is None:
        requirements.append(
            "A referenced writable scalar memory global is required for rename/retype proof"
        )
    else:
        old_name = global_symbol["name"]
        new_name = f"advanced_smoke_global_{global_symbol['id']:x}"
        renamed = invoke(
            decomp.global_rename,
            function_start=entry,
            name=old_name,
            new_name=new_name,
            storage=global_symbol["storage"],
        )
        assert renamed["name"] == new_name, renamed
        location = program.getAddressFactory().getAddress(renamed["address"])
        assert str(program.getSymbolTable().getPrimarySymbol(location).getName()) == new_name
        signed = {1: "char", 2: "short", 4: "int", 8: "long long"}[global_symbol["size"]]
        old_type = str(global_symbol["data_type"])
        target_type = (
            signed if "uint" in old_type or "unsigned" in old_type else f"unsigned {signed}"
        )
        retyped = invoke(
            decomp.global_retype,
            function_start=entry,
            name=new_name,
            data_type=target_type,
            storage=global_symbol["storage"],
        )
        db_data = program.getListing().getDataAt(location)
        assert db_data is not None and int(db_data.getLength()) == global_symbol["size"], retyped
        assert retyped["data_type"] != old_type, (old_type, retyped)
        invoke(
            decomp.global_rename,
            function_start=entry,
            name=new_name,
            new_name=old_name,
            storage=global_symbol["storage"],
        )


def smoke_decompiler(runtime, owner, session_id, scratch):
    """Prove graphs, SSA selection, writeback, overrides, and globals on one fixture."""
    session = runtime.registry.resolve(session_id, owner)
    program = session.info.program
    executed = []
    requirements = []
    observations = {}

    def invoke(handler, **kwargs):
        result = runtime.invoke(handler.__operation__, {"session_id": session_id, **kwargs}, owner)
        executed.append(handler.__operation__.name)
        return result

    item, caller, calls, conditional = _select_fixture(program, scratch, requirements)
    entry = str(item.getEntryPoint())
    observations["function"] = entry
    _smoke_graphs(invoke, entry, caller, conditional, requirements)
    symbols = _smoke_ssa_selection(invoke, entry, requirements, observations)
    _smoke_writeback(invoke, entry, item, symbols, requirements)
    _smoke_overrides(invoke, caller, calls)
    _smoke_globals(invoke, program, entry, requirements)
    return {
        "executed": sorted(set(executed)),
        "fixture_requirements": requirements,
        "observations": observations,
    }
