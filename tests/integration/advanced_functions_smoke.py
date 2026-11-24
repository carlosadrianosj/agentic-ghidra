"""Explicit real-Ghidra smoke for all 31 function/variable operations.

Uses two analyzed internal functions as disposable scratch inside a rolled-back
runtime transaction. Optional scratch keys: function_start,
secondary_function_start, register, local_stack_offset, parameter_stack_offset,
and local_storage_address. No fixture bytes are patched or invented.
"""

from __future__ import annotations

import uuid

from agenticghidra_mcp.advanced import functions as operations
from agenticghidra_mcp.advanced.core import Call, address, function, source_type


def _fixture_functions(program):
    candidates = []
    for target in program.getFunctionManager().getFunctions(True):
        if (
            not target.isExternal()
            and not target.isThunk()
            and program.getListing().getInstructionAt(target.getEntryPoint()) is not None
            and int(target.getBody().getNumAddressRanges()) == 1
        ):
            candidates.append(target)
            if len(candidates) == 2:
                break
    if len(candidates) < 2:
        raise ValueError(
            "Functions smoke requires two analyzed non-thunk internal functions "
            "with contiguous bodies"
        )
    return candidates


def _fixture_register(program, supplied):
    if supplied is not None:
        return supplied
    stack_pointer = program.getCompilerSpec().getStackPointer()
    if stack_pointer is None or int(stack_pointer.getMinimumByteSize()) < 4:
        raise ValueError("Functions smoke requires a register of at least four bytes")
    return str(stack_pointer.getName())


def _assert_ambiguous_storage(call, entry, storage):
    with call.runtime.program_lock(call.program):
        try:
            operations.select_variable(call, entry, None, storage=storage)
        except ValueError as exc:
            assert "Ambiguous" in str(exc)
            return
        raise AssertionError("Shared storage selection did not reject ambiguous scoped locals")


def smoke_functions(runtime, owner, session_id, scratch):
    session = runtime.registry.resolve(session_id, owner)
    program = session.info.program
    options = scratch if isinstance(scratch, dict) else {}
    call = Call(runtime, session.context, owner, session, runtime.monitor())
    handlers = {
        value.__operation__.name: value
        for value in vars(operations).values()
        if callable(value) and hasattr(value, "__operation__")
    }
    exercised = set()
    proofs = set()

    def invoke(operation_name, **arguments):
        result = runtime.invoke(
            handlers[operation_name].__operation__, {"session_id": session_id, **arguments}, owner
        )
        exercised.add(operation_name)
        return result

    def expect_error(operation_name, **arguments):
        try:
            invoke(operation_name, **arguments)
        except (ValueError, RuntimeError):
            return
        raise AssertionError(f"{operation_name} accepted invalid input")

    candidates = _fixture_functions(program)
    first = function(call, options.get("function_start", candidates[0].getEntryPoint()))
    second = function(call, options.get("secondary_function_start", candidates[1].getEntryPoint()))
    if first == second:
        raise ValueError("Functions smoke scratch functions must be distinct")
    entry, other = str(first.getEntryPoint()), str(second.getEntryPoint())
    before = operations.get_signature(call, entry)
    before_second = operations.get_signature(call, other)
    body_start, body_end = (
        str(first.getBody().getMinAddress()),
        str(first.getBody().getMaxAddress()),
    )
    instruction_size = int(program.getListing().getInstructionAt(first.getEntryPoint()).getLength())
    frame = first.getStackFrame()
    local_offset = options.get("local_stack_offset", -0x100 if frame.growsNegative() else 0x100)
    frame_offset = local_offset - 0x20 if frame.growsNegative() else local_offset + 0x20
    parameter_offset = options.get(
        "parameter_stack_offset", 0x100 if frame.growsNegative() else -0x100
    )
    second_parameter_offset = (
        parameter_offset + 0x20 if frame.growsNegative() else parameter_offset - 0x20
    )
    register = _fixture_register(program, options.get("register"))
    memory_location = options.get("local_storage_address", other)
    prefix = "advanced_functions_" + uuid.uuid4().hex

    with runtime.program_lock(program):
        runtime.begin(session, owner, "Advanced functions smoke rollback")
    try:
        invoke("function.delete", function_start=entry)
        invoke("function.delete", function_start=other)
        created = invoke("function.create", address=entry, name=prefix + "_a")
        assert created["address"] == entry and created["name"] == prefix + "_a"
        assert invoke("function.create", address=other, name=prefix + "_b")["address"] == other
        invoke("function.body.set", function_start=entry, start=entry, length=instruction_size)
        assert int(function(call, entry).getBody().getNumAddresses()) == instruction_size
        invoke("function.body.set", function_start=entry, start=body_start, end=body_end)
        proofs.add("body_range")
        renamed = invoke("function.rename", function_start=entry, name=prefix + "_renamed")
        assert renamed["name"] == prefix + "_renamed"
        assert invoke("function.at", address=entry)["name"] == renamed["name"]
        names = invoke("function.by_name", name=renamed["name"], exact=True)
        assert len(names["functions"]) == 1 and names["functions"][0]["address"] == entry
        filtered = invoke("function.list", query=prefix, limit=1)
        assert len(filtered["functions"]) == 1 and filtered["has_more"]
        following = invoke("function.list", query=prefix, offset=1, limit=1)
        assert following["functions"][0]["address"] != filtered["functions"][0]["address"]
        proofs.add("function_pagination")

        conventions = invoke("function.calling_conventions.list")["calling_conventions"]
        assert "default" in conventions
        assert (
            invoke("function.calling_convention.set", function_start=entry, name="default")[
                "calling_convention"
            ]
            == "default"
        )
        flags = invoke(
            "function.flags.set",
            function_start=entry,
            varargs=True,
            inline=True,
            noreturn=False,
            custom_storage=False,
        )
        assert (
            flags["varargs"]
            and flags["inline"]
            and not flags["noreturn"]
            and not flags["custom_storage"]
        )
        invoke("function.flags.set", function_start=entry, varargs=False, inline=False)
        signature = invoke(
            "function.signature.set",
            function_start=entry,
            signature=f"int {prefix}_signature(int alpha, int beta)",
        )
        assert signature["return_type"] == "int"
        assert [var["name"] for var in signature["parameters"]] == ["alpha", "beta"]
        assert signature["signature_source"] == "USER_DEFINED"
        assert (
            invoke("function.signature.get", function_start=entry)["signature"]
            == signature["signature"]
        )
        changed = invoke("function.return_type.set", function_start=entry, data_type="unsigned int")
        assert changed["return_type"] != signature["return_type"]
        proofs.add("signature_and_return_type")

        # A public memory call reference makes caller/callee assertions meaningful
        # even when the selected fixture functions did not originally call each other.
        from ghidra.program.model.symbol import RefType

        with runtime.program_lock(program):
            program.getReferenceManager().addMemoryReference(
                address(call, entry),
                address(call, other),
                RefType.UNCONDITIONAL_CALL,
                source_type(),
                -1,
            )
        callees = invoke("function.callees", function_start=entry)
        callers = invoke("function.callers", function_start=other)
        assert any(item["address"] == other for item in callees["functions"])
        assert any(item["address"] == entry for item in callers["functions"])
        report = invoke("function.report", function_start=entry)
        assert report["address"] == entry and len(report["parameters"]) == 2
        proofs.add("real_call_edges")
        for action in (
            "decomp.function",
            "disasm.function",
            "function.signature.get",
            "function.variables",
            "function.callers",
            "function.callees",
            "report.function_summary",
        ):
            batch = invoke(
                "function.batch.run", action=action, query=prefix, limit=1, timeout_secs=120
            )
            assert batch["action"] == action and len(batch["items"]) == 1 and batch["has_more"]
            assert batch["items"][0]["status"] == "ok" and batch["items"][0]["result"] is not None
        batch_page = invoke(
            "function.batch.run", action="function.variables", query=prefix, offset=1, limit=1
        )
        assert len(batch_page["items"]) == 1 and batch_page["offset"] == 1
        proofs.add("all_seven_batch_actions")

        invoke(
            "variable.comment.set",
            function_start=entry,
            name="alpha",
            ordinal=0,
            comment="parameter comment",
        )
        added = invoke(
            "parameter.add", function_start=entry, name="gamma", data_type="int", ordinal=1
        )
        assert [var["name"] for var in added["parameters"]] == ["alpha", "gamma", "beta"]
        beta_storage = added["parameters"][2]["storage"]
        moved = invoke("parameter.move", function_start=entry, ordinal=2, new_ordinal=0)
        assert [var["name"] for var in moved["parameters"]] == ["beta", "alpha", "gamma"]
        assert [var["ordinal"] for var in moved["parameters"]] == [0, 1, 2]
        assert moved["parameters"][1]["comment"] == "parameter comment"
        assert moved["parameters"][0]["storage"] != beta_storage
        replaced = invoke(
            "parameter.replace",
            function_start=entry,
            ordinal=1,
            name="alpha",
            new_name="alpha_new",
            data_type="short",
            stack_offset=parameter_offset,
        )
        assert replaced["custom_storage"]
        assert replaced["parameters"][1]["name"] == "alpha_new"
        assert replaced["parameters"][1]["stack_offset"] == parameter_offset
        assert replaced["parameters"][1]["size"] == 2
        assert replaced["parameters"][0]["storage"] == moved["parameters"][0]["storage"]
        explicit = invoke(
            "parameter.add",
            function_start=entry,
            name="delta",
            data_type="int",
            stack_offset=second_parameter_offset,
        )
        delta_storage = explicit["parameters"][3]["storage"]
        moved_custom = invoke("parameter.move", function_start=entry, ordinal=3, new_ordinal=0)
        assert moved_custom["parameters"][0]["name"] == "delta"
        assert moved_custom["parameters"][0]["storage"] == delta_storage
        invoke("parameter.remove", function_start=entry, ordinal=0, name="delta")
        ordinal_renamed = invoke(
            "variable.rename",
            function_start=entry,
            name="alpha_new",
            new_name="alpha_final",
            ordinal=1,
        )
        assert ordinal_renamed["name"] == "alpha_final" and ordinal_renamed["ordinal"] == 1
        ordinal_retyped = invoke(
            "variable.retype",
            function_start=entry,
            name="alpha_final",
            data_type="unsigned short",
            ordinal=1,
        )
        assert ordinal_retyped["size"] == 2 and ordinal_retyped["stack_offset"] == parameter_offset
        for name in ("alpha_final", "beta", "gamma"):
            invoke("parameter.remove", function_start=entry, name=name)
        assert invoke("function.variables", function_start=entry)["parameters"] == []
        register_parameter = invoke(
            "parameter.add",
            function_start=entry,
            name="register_parameter",
            data_type="int",
            register=register,
        )
        assert register_parameter["custom_storage"] and len(register_parameter["parameters"]) == 1
        register_storage = register_parameter["parameters"][0]["storage"]
        stack_parameter = invoke(
            "parameter.replace",
            function_start=entry,
            name="register_parameter",
            stack_offset=parameter_offset,
        )
        assert stack_parameter["parameters"][0]["stack_offset"] == parameter_offset
        assert stack_parameter["parameters"][0]["storage"] != register_storage
        invoke("parameter.remove", function_start=entry, name="register_parameter")
        proofs.add("dynamic_and_custom_parameter_storage_ordinals")

        local = invoke(
            "variable.local.create",
            function_start=entry,
            name="scratch_local",
            data_type="int",
            stack_offset=local_offset,
            comment="created comment",
        )
        assert local["stack_offset"] == local_offset and local["comment"] == "created comment"
        renamed_local = invoke(
            "variable.rename",
            function_start=entry,
            name="scratch_local",
            new_name="renamed_local",
            storage=local["storage"],
        )
        assert renamed_local["name"] == "renamed_local"
        retyped = invoke(
            "variable.retype",
            function_start=entry,
            name="renamed_local",
            data_type="short",
            storage=local["storage"],
        )
        assert retyped["size"] == 2 and retyped["stack_offset"] == local_offset
        commented = invoke(
            "variable.comment.set",
            function_start=entry,
            name="renamed_local",
            comment="updated comment",
            storage=retyped["storage"],
        )
        assert commented["comment"] == "updated comment"
        register_one = invoke(
            "variable.local.create",
            function_start=entry,
            name="register_one",
            data_type="int",
            register=register,
            first_use_offset=4,
        )
        register_two = invoke(
            "variable.local.create",
            function_start=entry,
            name="register_two",
            data_type="int",
            register=register,
            first_use_offset=8,
        )
        assert register_one["storage"] == register_two["storage"]
        assert register_one["first_use_offset"] == 4 and register_two["first_use_offset"] == 8
        # Ghidra prohibits duplicate DB variable names. Distinct first-use scopes
        # can nevertheless reuse identical register storage, which must not select
        # an arbitrary variable when the shared selector is used without a name.
        _assert_ambiguous_storage(call, entry, register_one["storage"])
        memory_local = invoke(
            "variable.local.create",
            function_start=entry,
            name="memory_local",
            data_type="int",
            storage_address=memory_location,
        )
        assert memory_local["size"] == 4
        variables = invoke("function.variables", function_start=entry)
        assert {var["name"] for var in variables["locals"]} >= {
            "renamed_local",
            "register_one",
            "register_two",
            "memory_local",
        }
        for name, storage in (
            ("renamed_local", retyped["storage"]),
            ("register_one", register_one["storage"]),
            ("register_two", register_two["storage"]),
            ("memory_local", memory_local["storage"]),
        ):
            assert invoke(
                "variable.local.remove", function_start=entry, name=name, storage=storage
            )["deleted"]
        proofs.add("stack_register_memory_locals_and_ambiguous_selection")

        stack = invoke(
            "stackframe.variable.create",
            function_start=entry,
            name="frame_local",
            stack_offset=frame_offset,
            data_type="int",
        )
        assert stack["stack_offset"] == frame_offset
        stackframe = invoke("stackframe.variables", function_start=entry)
        assert any(var["name"] == "frame_local" for var in stackframe["variables"])
        assert invoke("stackframe.variable.clear", function_start=entry, stack_offset=frame_offset)[
            "deleted"
        ]
        assert not any(
            var["name"] == "frame_local"
            for var in invoke("stackframe.variables", function_start=entry)["variables"]
        )
        proofs.add("stackframe_crud")
        thunk = invoke("function.thunk.set", function_start=entry, thunk_target=other)
        assert thunk["thunk"] and thunk["thunk_target"] == other
        assert invoke("function.delete", function_start=entry)["deleted"]
        assert program.getFunctionManager().getFunctionAt(address(call, entry)) is None
    finally:
        with runtime.program_lock(program):
            if runtime.transaction_status(session)["pending"]:
                runtime.finish(session, owner, False)

    assert operations.get_signature(call, entry)["signature"] == before["signature"]
    assert operations.get_signature(call, other)["signature"] == before_second["signature"]
    # Invalid writes use separate automatic transactions so an expected failure
    # cannot accidentally abort the outer rollback transaction and its evidence.
    expect_error(
        "variable.local.create",
        function_start=entry,
        name="invalid_storage",
        data_type="int",
        stack_offset=local_offset,
        register=register,
    )
    expect_error(
        "variable.local.create", function_start=entry, name="missing_storage", data_type="int"
    )
    expect_error(
        "parameter.add",
        function_start=entry,
        name="invalid_parameter",
        data_type="int",
        stack_offset=parameter_offset,
        register=register,
    )
    expect_error("parameter.remove", function_start=entry)
    expect_error("function.batch.run", action="eval", query=prefix)
    expect_error("function.list", limit=1001)
    proofs.add("selector_and_pagination_errors")
    assert exercised == set(handlers), f"Missing function operations: {set(handlers) - exercised}"
    return {
        "operations": sorted(exercised),
        "operation_count": len(exercised),
        "proofs": sorted(proofs),
        "rolled_back": True,
    }
