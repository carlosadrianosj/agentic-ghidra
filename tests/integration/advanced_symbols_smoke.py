"""Real-Ghidra symbol/reference smoke; invoked explicitly by the integration driver.

The driver needs a writable analyzed program with a function and at least four
non-function-entry memory addresses. All smoke mutations are rolled back using
the shared runtime. The shared address/function_start scratch keys select the
data buffer and stack-reference function. Optional from_address, to_address,
second_to_address, stack_from_address, and register keys override individual choices.
"""

from __future__ import annotations

import uuid

from agenticghidra_mcp.advanced import symbols_references as operations
from agenticghidra_mcp.advanced.core import Call, address


def _symbol_namespaces(invoke, expect_error, prefix, alpha, beta, target, root, other_root, child):
    invoke("namespace.create", name=root)
    invoke("namespace.create", name=child, parent=root)
    invoke("namespace.create", name=other_root)
    invoke("namespace.create", name=child, parent=other_root)
    expect_error("class.create", name=prefix + "_ambiguous", parent=child)
    created_class = invoke("class.create", name=prefix + "_class", parent=root + "::" + child)
    assert created_class["namespace"].endswith(child)
    first = invoke("symbol.create", address=target, name=alpha, make_primary=False)
    second = invoke("symbol.create", address=target, name=beta, make_primary=False)
    assert first["source"] == "USER_DEFINED" and first["id"] != second["id"]
    assert invoke("symbol.primary.set", address=target, name=beta)["primary"]
    moved = invoke(
        "symbol.namespace.move",
        address=target,
        name=alpha,
        namespace=root + "::" + child,
    )
    assert moved["namespace"].endswith(child)
    renamed = invoke("symbol.rename", address=target, old_name=beta, new_name=beta + "_renamed")
    assert renamed["name"] == beta + "_renamed" and renamed["source"] == "USER_DEFINED"
    exact = invoke(
        "symbol.by_name", name=alpha, exact=True, limit=1, include_dynamic=False
    )
    assert exact["count"] == 1 and exact["symbols"][0]["id"] == first["id"]
    filtered = invoke("symbol.list", query=prefix, offset=0, limit=1, include_dynamic=True)
    assert len(filtered["symbols"]) == 1 and filtered["has_more"], filtered
    next_page = invoke("symbol.list", query=prefix, offset=1, limit=1, include_dynamic=False)
    assert (
        next_page["count"] == filtered["count"]
        and next_page["symbols"][0]["id"] != filtered["symbols"][0]["id"]
    )
    partial = invoke("symbol.by_name", name=prefix, exact=False, limit=1, include_dynamic=True)
    assert partial["count"] == filtered["count"] and partial["has_more"]
    deleted = invoke("symbol.delete", address=target, name=beta + "_renamed")
    assert deleted["deleted"]
    assert invoke("symbol.by_name", name=beta + "_renamed", exact=True)["count"] == 0
    return first


def _external_locations(invoke, prefix, target, second_target, library):
    invoke("external.library.create", name=library)
    path = invoke(
        "external.library.set_path", name=library, path="/" + library, user_defined=True
    )
    assert path["path"] == "/" + library
    libraries = invoke("external.library.list")
    assert any(
        item["name"] == library and item["path"] == "/" + library
        for item in libraries["libraries"]
    )
    location = invoke(
        "external.location.create",
        library_name=library,
        label=prefix + "_data",
        external_address=target,
    )
    external_function = invoke(
        "external.function.create",
        library_name=library,
        name=prefix + "_function",
        external_address=second_target,
    )
    assert not location["is_function"] and external_function["is_function"]
    assert (
        invoke("external.location.get", address=location["address"])["symbol"]["id"]
        == location["symbol"]["id"]
    )
    assert invoke("external.location.get", name=library + "::" + prefix + "_function")[
        "is_function"
    ]
    assert invoke("external.imports.list", limit=1)["count"] >= 2
    added = invoke("external.entrypoint.add", address=target)
    assert added["entrypoint"]
    assert target in invoke("external.entrypoint.list")["entrypoints"]
    exports = invoke("external.exports.list", limit=1000)
    assert any(item["address"] == target for item in exports["exports"])
    assert not invoke("external.entrypoint.remove", address=target)["entrypoint"]
    assert target not in invoke("external.entrypoint.list")["entrypoints"]
    return location


def _memory_references(invoke, source, target, second_target, first_id, qualified):
    invoke("reference.clear_from", from_address=source)
    memory = invoke(
        "reference.create.memory",
        from_address=source,
        to_address=target,
        operand_index=0,
        reference_type="READ",
        source_type="ANALYSIS",
    )
    assert memory["source_type"] == "ANALYSIS" and memory["reference_type"] == "READ"
    invoke(
        "reference.create.memory",
        from_address=source,
        to_address=second_target,
        operand_index=0,
    )
    assert invoke("reference.primary.set", from_address=source, to_address=target)["primary"]
    associated = invoke(
        "reference.association.set",
        from_address=source,
        to_address=target,
        symbol_address=target,
        symbol_name=qualified,
    )
    assert associated["symbol_id"] == first_id
    assert invoke("reference.from", address=source)["count"] == 2
    queried = invoke("reference.to", address=target)
    assert any(item["symbol_id"] == first_id for item in queried["references"])
    removed = invoke("reference.association.remove", from_address=source, to_address=target)
    assert removed["symbol_id"] == -1
    ranged = invoke("reference.from", start=source, end=source, limit=1)
    assert ranged["count"] == 2 and ranged["has_more"]
    to_range = invoke("reference.to", start=target, end=target, limit=1000)
    assert any(item["from_address"] == source for item in to_range["references"])
    assert (
        invoke(
            "reference.delete", from_address=source, to_address=second_target, operand_index=0
        )["deleted_count"]
        == 1
    )
    assert invoke("reference.from", address=source)["count"] == 1
    invoke("reference.clear_to", to_address=target)
    assert invoke("reference.to", address=target)["count"] == 0


def _special_references(invoke, prefix, source, stack_source, register, library, target, location):
    stack = invoke(
        "reference.create.stack",
        from_address=stack_source,
        stack_offset=-16,
        operand_index=0,
        reference_type="READ",
        source_type="USER_DEFINED",
    )
    assert stack["stack"] and stack["operand_index"] == 0
    register_reference = invoke(
        "reference.create.register",
        from_address=source,
        register=register,
        reference_type="READ",
        operand_index=0,
        source_type="ANALYSIS",
    )
    assert register_reference["register"] and register_reference["source_type"] == "ANALYSIS"
    external_reference = invoke(
        "reference.create.external",
        from_address=source,
        library_name=library,
        label=prefix + "_data",
        external_address=target,
        operand_index=0,
    )
    assert (
        external_reference["external"]
        and external_reference["to_address"] == location["address"]
    )
    assert any(
        item["from_address"] == source
        for item in invoke("reference.to", address=location["address"])["references"]
    )
    invoke("reference.clear_to", to_address=location["address"])
    assert invoke("reference.to", address=location["address"])["count"] == 0


def _range_clear(invoke, call, source, second_source, target):
    invoke("reference.create.memory", from_address=source, to_address=target)
    invoke("reference.create.memory", from_address=second_source, to_address=target)
    first_address = address(call, source)
    last_address = address(call, second_source)
    if first_address.getAddressSpace() == last_address.getAddressSpace():
        start, end = (
            (source, second_source)
            if first_address.compareTo(last_address) <= 0
            else (second_source, source)
        )
        invoke("reference.clear_from", from_address=start, end_address=end)
    else:
        invoke("reference.clear_from", from_address=source)
        invoke("reference.clear_from", from_address=second_source)
    assert invoke("reference.from", address=source)["count"] == 0
    assert invoke("reference.from", address=second_source)["count"] == 0


def _scratch_addresses(program, call, options):
    if options.get("address") is not None:
        buffer_start = address(call, options["address"])
        return [str(buffer_start.add(offset)) for offset in (16, 32, 48, 64)]
    addresses = []
    for block in program.getMemory().getBlocks():
        if not block.isInitialized():
            continue
        for offset in range(min(int(block.getSize()), 256)):
            candidate = block.getStart().add(offset)
            if program.getFunctionManager().getFunctionAt(candidate) is None:
                addresses.append(str(candidate))
                if len(addresses) == 4:
                    break
        if len(addresses) == 4:
            break
    if len(addresses) < 4:
        raise ValueError("Symbols smoke requires four non-function-entry memory addresses")
    return addresses


def _fixture_inputs(program, options, addresses):
    functions = iter(program.getFunctionManager().getFunctions(True))
    first_function = next(functions, None)
    stack_source = options.get("stack_from_address", options.get("function_start"))
    if stack_source is None:
        if first_function is None:
            raise ValueError("Symbols smoke requires a function for a real stack reference")
        stack_source = str(first_function.getEntryPoint())
    register = options.get("register")
    if register is None:
        stack_pointer = program.getCompilerSpec().getStackPointer()
        if stack_pointer is None:
            raise ValueError("Symbols smoke requires a register or a compiler stack pointer")
        register = str(stack_pointer.getName())
    return stack_source, register


def smoke_symbols(runtime, owner, session_id, scratch):
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
        raise AssertionError(f"{operation_name} accepted invalid or ambiguous input")

    addresses = _scratch_addresses(program, call, options)
    source = str(options.get("from_address", addresses[0]))
    target = str(options.get("to_address", addresses[1]))
    second_target = str(options.get("second_to_address", addresses[2]))
    second_source = addresses[3]
    stack_source, register = _fixture_inputs(program, options, addresses)

    prefix = "advanced_symbols_" + uuid.uuid4().hex
    root = prefix + "_root"
    other_root = prefix + "_other"
    child = prefix + "_child"
    alpha = prefix + "_alpha"
    beta = prefix + "_beta"
    library = prefix + "_library"
    table = program.getSymbolTable()
    target_address = address(call, target)
    was_entrypoint = bool(table.isExternalEntryPoint(target_address))
    before_references = invoke("reference.from", address=source, limit=1000)
    if before_references["has_more"]:
        raise ValueError(
            "Symbols smoke source has more than 1000 references; choose a different scratch source"
        )
    with runtime.program_lock(program):
        runtime.begin(session, owner, "Advanced symbols/references smoke rollback")
    try:
        first = _symbol_namespaces(
            invoke, expect_error, prefix, alpha, beta, target, root, other_root, child
        )

        location = _external_locations(invoke, prefix, target, second_target, library)

        _memory_references(
            invoke,
            source,
            target,
            second_target,
            first["id"],
            root + "::" + child + "::" + alpha,
        )
        _special_references(
            invoke, prefix, source, stack_source, register, library, target, location
        )
        _range_clear(invoke, call, source, second_source, target)
        expect_error("reference.from", address=source, start=source)
        expect_error("symbol.list", limit=1001)
        expect_error("external.location.get")
    finally:
        with runtime.program_lock(program):
            runtime.finish(session, owner, False)
    assert invoke("symbol.by_name", name=prefix, exact=False)["count"] == 0
    assert not program.getExternalManager().contains(library)
    assert bool(table.isExternalEntryPoint(target_address)) == was_entrypoint
    assert (
        invoke("reference.from", address=source, limit=1000)["references"]
        == before_references["references"]
    )
    assert exercised == set(handlers), f"Unexercised operations: {set(handlers) - exercised}"
    return {"operations": sorted(exercised), "operation_count": len(exercised), "rolled_back": True}
