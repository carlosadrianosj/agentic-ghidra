"""Symbol, namespace, external linkage, and reference operations via public Ghidra APIs."""

from __future__ import annotations

from .core import (
    MAX_RESULTS,
    Call,
    address as resolve_address,
    address_range,
    operation,
    reference_type as resolve_reference_type,
    source_type as resolve_source_type,
    symbol_dict,
)


def _results(call, items, key, offset=0, limit=100, convert=lambda item: item):
    if offset < 0 or not 1 <= limit <= MAX_RESULTS:
        raise ValueError(
            f"offset must be nonnegative and limit must be between 1 and {MAX_RESULTS}"
        )
    rows = []
    count = 0
    for item in items:
        if call.monitor is not None:
            call.monitor.checkCancelled()
        if offset <= count < offset + limit:
            rows.append(convert(item))
        count += 1
    more = count > offset + len(rows)
    return {
        key: rows,
        "count": count,
        "returned_count": len(rows),
        "offset": offset,
        "limit": limit,
        "has_more": more,
        "next_offset": offset + limit if more else None,
    }


def _name_matches(symbol, name):
    return str(symbol.getName()) == name or str(symbol.getName(True)) == name.removeprefix("::")


def _symbol(call, location, name=None):
    table = call.program.getSymbolTable()
    target = resolve_address(call, location)
    if name is None:
        found = table.getPrimarySymbol(target)
        if found is None:
            raise ValueError(f"No primary symbol at {target}")
        return found
    matches = [item for item in table.getSymbols(target) if _name_matches(item, name)]
    if len(matches) != 1:
        raise ValueError(
            f"Symbol {name!r} at {target} is {'ambiguous' if matches else 'not found'}"
        )
    return matches[0]


def _namespace(call, path=None, base=None):
    table = call.program.getSymbolTable()
    root = call.program.getGlobalNamespace()
    if path is None or path in ("", "::", "Global", "Global::"):
        return root if base is None else base
    text = str(path)
    parts = text.removeprefix("::").split("::")
    if parts[0] == "Global":
        parts = parts[1:]
        base = root
    if any(not part for part in parts):
        raise ValueError(f"Invalid namespace path: {path}")
    if base is None and len(parts) == 1 and not text.startswith("::"):
        candidates = [
            item.getObject()
            for item in table.getSymbols(parts[0])
            if item.getSymbolType().isNamespace()
        ]
        if len(candidates) != 1:
            raise ValueError(
                f"Namespace {path!r} is "
                f"{'ambiguous; use its qualified path' if candidates else 'not found'}"
            )
        return candidates[0]
    current = root if base is None else base
    for part in parts:
        candidates = [
            item.getObject()
            for item in table.getSymbols(part, current)
            if item.getSymbolType().isNamespace()
        ]
        if len(candidates) != 1:
            raise ValueError(
                f"Namespace path {path!r} is "
                f"{'ambiguous' if candidates else 'not found'} at {part!r}"
            )
        current = candidates[0]
    return current


def _creation_parent(call, name, parent):
    if not name or name.endswith("::"):
        raise ValueError("A nonempty namespace name is required")
    if "::" not in name:
        return _namespace(call, parent), name
    prefix, leaf = name.rsplit("::", 1)
    base = _namespace(call, parent) if parent is not None else None
    if name.startswith("::"):
        base = call.program.getGlobalNamespace()
    return _namespace(call, prefix or "::", base), leaf


def _make_primary(item):
    item.setPrimary()
    if not item.isPrimary():
        raise ValueError(f"Symbol {item.getName(True)} cannot be made primary")


@operation("symbol.list", api="SymbolTable.getAllSymbols(boolean)")
def symbol_list(call: Call, offset=0, limit=100, include_dynamic=False, query=None):
    symbols = call.program.getSymbolTable().getAllSymbols(include_dynamic)
    if query is not None:
        symbols = (
            item for item in symbols if query.casefold() in str(item.getName(True)).casefold()
        )
    return _results(call, symbols, "symbols", offset, limit, symbol_dict)


@operation("symbol.by_name", api="SymbolTable.getAllSymbols(boolean); Symbol.getName(boolean)")
def symbol_by_name(call: Call, name, exact=False, limit=20, include_dynamic=True):
    symbols = call.program.getSymbolTable().getAllSymbols(include_dynamic)
    if exact:
        matches = (item for item in symbols if _name_matches(item, name))
    else:
        matches = (
            item for item in symbols if name.casefold() in str(item.getName(True)).casefold()
        )
    return _results(call, matches, "symbols", limit=limit, convert=symbol_dict)


@operation("symbol.create", kind="write", api="SymbolTable.createLabel; Symbol.setPrimary")
def symbol_create(call: Call, address, name, make_primary=True):
    parent, leaf = _creation_parent(call, name, None)
    item = call.program.getSymbolTable().createLabel(
        resolve_address(call, address), leaf, parent, resolve_source_type()
    )
    if make_primary:
        _make_primary(item)
    return symbol_dict(item)


@operation("symbol.rename", kind="write", api="Symbol.setName(String, SourceType)")
def symbol_rename(call: Call, address, new_name, old_name=None):
    item = _symbol(call, address, old_name)
    item.setName(new_name, resolve_source_type())
    return symbol_dict(item)


@operation("symbol.delete", kind="write", api="Symbol.delete")
def symbol_delete(call: Call, address, name=None):
    item = _symbol(call, address, name)
    result = symbol_dict(item)
    if not item.delete():
        raise ValueError("Ghidra refused to delete the symbol")
    return {"deleted": True, "symbol": result}


@operation("symbol.primary.set", kind="write", api="Symbol.setPrimary")
def symbol_primary_set(call: Call, address, name=None):
    item = _symbol(call, address, name)
    _make_primary(item)
    return symbol_dict(item)


@operation("symbol.namespace.move", kind="write", api="Symbol.setNamespace")
def symbol_namespace_move(call: Call, address, namespace, name=None):
    item = _symbol(call, address, name)
    item.setNamespace(_namespace(call, namespace))
    return symbol_dict(item)


@operation("namespace.create", kind="write", api="SymbolTable.createNameSpace")
def namespace_create(call: Call, name, parent=None):
    namespace, leaf = _creation_parent(call, name, parent)
    created = call.program.getSymbolTable().createNameSpace(namespace, leaf, resolve_source_type())
    return symbol_dict(created.getSymbol())


@operation("class.create", kind="write", api="SymbolTable.createClass")
def class_create(call: Call, name, parent=None):
    namespace, leaf = _creation_parent(call, name, parent)
    created = call.program.getSymbolTable().createClass(namespace, leaf, resolve_source_type())
    return symbol_dict(created.getSymbol())


def _remote_address(call, value):
    if value is None:
        return None
    result = resolve_address(call, value)
    if not result.isMemoryAddress():
        raise ValueError(
            "external_address must be a memory address in the external program, "
            "not its synthetic EXTERNAL-space location"
        )
    return result


def _location_dict(item):
    remote = item.getAddress()
    return {
        "library_name": str(item.getLibraryName()),
        "label": str(item.getLabel()),
        "address": str(item.getExternalSpaceAddress()),
        "external_address": str(remote) if remote is not None else None,
        "namespace": str(item.getParentNameSpace().getName(True)),
        "source": str(item.getSource()),
        "is_function": bool(item.isFunction()),
        "symbol": symbol_dict(item.getSymbol()),
    }


def _external_locations(call):
    manager = call.program.getExternalManager()
    for library in manager.getExternalLibraryNames():
        yield from manager.getExternalLocations(str(library))


@operation("external.library.create", kind="write", api="ExternalManager.addExternalLibraryName")
def external_library_create(call: Call, name):
    library = call.program.getExternalManager().addExternalLibraryName(name, resolve_source_type())
    return {"name": str(library.getName()), "symbol": symbol_dict(library.getSymbol())}


@operation(
    "external.library.list", api="ExternalManager.getExternalLibraryNames; getExternalLibraryPath"
)
def external_library_list(call: Call):
    manager = call.program.getExternalManager()
    return _results(
        call,
        manager.getExternalLibraryNames(),
        "libraries",
        limit=MAX_RESULTS,
        convert=lambda name: {
            "name": str(name),
            "path": _optional_text(manager.getExternalLibraryPath(name)),
        },
    )


def _optional_text(value):
    return None if value is None else str(value)


@operation("external.library.set_path", kind="write", api="ExternalManager.setExternalPath")
def external_library_set_path(call: Call, name, path, user_defined=True):
    manager = call.program.getExternalManager()
    if not manager.contains(name):
        raise ValueError(f"External library not found: {name}")
    manager.setExternalPath(name, path, user_defined)
    return {
        "name": name,
        "path": _optional_text(manager.getExternalLibraryPath(name)),
        "user_defined": user_defined,
    }


@operation("external.location.create", kind="write", api="ExternalManager.addExtLocation")
def external_location_create(call: Call, library_name, label=None, external_address=None):
    item = call.program.getExternalManager().addExtLocation(
        library_name, label, _remote_address(call, external_address), resolve_source_type()
    )
    return _location_dict(item)


@operation("external.function.create", kind="write", api="ExternalManager.addExtFunction")
def external_function_create(call: Call, library_name, name, external_address=None):
    item = call.program.getExternalManager().addExtFunction(
        library_name, name, _remote_address(call, external_address), resolve_source_type()
    )
    return _location_dict(item)


@operation(
    "external.location.get", api="ExternalManager.getExternalLocation; ExternalLocation.getAddress"
)
def external_location_get(call: Call, address=None, name=None):
    if address is None and name is None:
        raise ValueError("Specify address or name to identify an external location")
    target = resolve_address(call, address) if address is not None else None
    matches = []
    for item in _external_locations(call):
        if call.monitor is not None:
            call.monitor.checkCancelled()
        if (
            target is not None
            and target != item.getExternalSpaceAddress()
            and target != item.getAddress()
        ):
            continue
        if name is not None and not _name_matches(item.getSymbol(), name):
            continue
        matches.append(item)
        if len(matches) > 1:
            raise ValueError(
                "External location is ambiguous; "
                "specify its EXTERNAL-space address or qualified name"
            )
    if not matches:
        raise ValueError("External location not found")
    return _location_dict(matches[0])


@operation("external.imports.list", api="ExternalManager.getExternalLocations(String)")
def external_imports_list(call: Call, offset=0, limit=100):
    return _results(call, _external_locations(call), "imports", offset, limit, _location_dict)


@operation(
    "external.exports.list", api="SymbolTable.getExternalEntryPointIterator; getPrimarySymbol"
)
def external_exports_list(call: Call, offset=0, limit=100):
    table = call.program.getSymbolTable()

    def convert(location):
        item = table.getPrimarySymbol(location)
        return {"address": str(location), "symbol": symbol_dict(item) if item is not None else None}

    return _results(call, table.getExternalEntryPointIterator(), "exports", offset, limit, convert)


@operation("external.entrypoint.list", api="SymbolTable.getExternalEntryPointIterator")
def external_entrypoint_list(call: Call):
    return _results(
        call,
        call.program.getSymbolTable().getExternalEntryPointIterator(),
        "entrypoints",
        limit=MAX_RESULTS,
        convert=str,
    )


@operation("external.entrypoint.add", kind="write", api="SymbolTable.addExternalEntryPoint")
def external_entrypoint_add(call: Call, address):
    target = resolve_address(call, address)
    table = call.program.getSymbolTable()
    table.addExternalEntryPoint(target)
    return {"address": str(target), "entrypoint": bool(table.isExternalEntryPoint(target))}


@operation("external.entrypoint.remove", kind="write", api="SymbolTable.removeExternalEntryPoint")
def external_entrypoint_remove(call: Call, address):
    target = resolve_address(call, address)
    table = call.program.getSymbolTable()
    existed = bool(table.isExternalEntryPoint(target))
    table.removeExternalEntryPoint(target)
    return {
        "address": str(target),
        "removed": existed,
        "entrypoint": bool(table.isExternalEntryPoint(target)),
    }


def _operand(value):
    if value < -1:
        raise ValueError("operand_index must be -1 (mnemonic) or nonnegative")
    return value


def _reference_dict(item):
    return {
        "from_address": str(item.getFromAddress()),
        "to_address": str(item.getToAddress()),
        "operand_index": int(item.getOperandIndex()),
        "reference_type": str(item.getReferenceType()),
        "source_type": str(item.getSource()),
        "primary": bool(item.isPrimary()),
        "symbol_id": int(item.getSymbolID()),
        "external": bool(item.isExternalReference()),
        "stack": bool(item.isStackReference()),
        "register": bool(item.isRegisterReference()),
    }


def _reference(call, from_address, to_address, operand_index):
    item = call.program.getReferenceManager().getReference(
        resolve_address(call, from_address),
        resolve_address(call, to_address),
        _operand(operand_index),
    )
    if item is None:
        raise ValueError("Reference not found for the specified source, destination, and operand")
    return item


def _source_addresses(call, selection=None):
    if selection is None:
        selection = call.program.getAddressFactory().getAddressSet()
    return call.program.getReferenceManager().getReferenceSourceIterator(selection, True)


def _references(call, direction, address=None, start=None, end=None):
    manager = call.program.getReferenceManager()
    if address is not None:
        if start is not None or end is not None:
            raise ValueError("Specify address or start/end, not both")
        target = resolve_address(call, address)
        yield from (
            manager.getReferencesFrom(target)
            if direction == "from"
            else manager.getReferencesTo(target)
        )
        return
    if end is not None and start is None:
        raise ValueError("end requires start")
    selection = address_range(call, start, end) if start is not None else None
    for source in _source_addresses(call, selection if direction == "from" else None):
        if call.monitor is not None:
            call.monitor.checkCancelled()
        for item in manager.getReferencesFrom(source):
            if direction == "from" or selection is None or selection.contains(item.getToAddress()):
                yield item


@operation("reference.from", api="ReferenceManager.getReferencesFrom; getReferenceSourceIterator")
def reference_from(call: Call, address=None, start=None, end=None, limit=100):
    return _results(
        call,
        _references(call, "from", address, start, end),
        "references",
        limit=limit,
        convert=_reference_dict,
    )


@operation("reference.to", api="ReferenceManager.getReferencesTo; getReferenceSourceIterator")
def reference_to(call: Call, address=None, start=None, end=None, limit=100):
    return _results(
        call,
        _references(call, "to", address, start, end),
        "references",
        limit=limit,
        convert=_reference_dict,
    )


@operation("reference.create.memory", kind="write", api="ReferenceManager.addMemoryReference")
def reference_create_memory(
    call: Call,
    from_address,
    to_address,
    reference_type="DATA",
    operand_index=0,
    source_type="USER_DEFINED",
):
    item = call.program.getReferenceManager().addMemoryReference(
        resolve_address(call, from_address),
        resolve_address(call, to_address),
        resolve_reference_type(reference_type),
        resolve_source_type(source_type),
        _operand(operand_index),
    )
    return _reference_dict(item)


@operation("reference.create.stack", kind="write", api="ReferenceManager.addStackReference")
def reference_create_stack(
    call: Call,
    from_address,
    stack_offset,
    reference_type="DATA",
    operand_index=0,
    source_type="USER_DEFINED",
):
    item = call.program.getReferenceManager().addStackReference(
        resolve_address(call, from_address),
        _operand(operand_index),
        stack_offset,
        resolve_reference_type(reference_type),
        resolve_source_type(source_type),
    )
    return _reference_dict(item)


@operation("reference.create.register", kind="write", api="ReferenceManager.addRegisterReference")
def reference_create_register(
    call: Call,
    from_address,
    register,
    reference_type="DATA",
    operand_index=0,
    source_type="USER_DEFINED",
):
    target = call.program.getRegister(register)
    if target is None:
        raise ValueError(f"Register not found: {register}")
    item = call.program.getReferenceManager().addRegisterReference(
        resolve_address(call, from_address),
        _operand(operand_index),
        target,
        resolve_reference_type(reference_type),
        resolve_source_type(source_type),
    )
    return _reference_dict(item)


@operation("reference.create.external", kind="write", api="ReferenceManager.addExternalReference")
def reference_create_external(
    call: Call,
    from_address,
    library_name,
    label=None,
    external_address=None,
    reference_type="DATA",
    operand_index=0,
    source_type="USER_DEFINED",
):
    item = call.program.getReferenceManager().addExternalReference(
        resolve_address(call, from_address),
        library_name,
        label,
        _remote_address(call, external_address),
        resolve_source_type(source_type),
        _operand(operand_index),
        resolve_reference_type(reference_type),
    )
    return _reference_dict(item)


@operation("reference.primary.set", kind="write", api="ReferenceManager.setPrimary")
def reference_primary_set(call: Call, from_address, to_address, operand_index=0):
    item = _reference(call, from_address, to_address, operand_index)
    call.program.getReferenceManager().setPrimary(item, True)
    return _reference_dict(_reference(call, from_address, to_address, operand_index))


@operation(
    "reference.association.set",
    kind="write",
    api="ReferenceManager.setAssociation(Symbol, Reference)",
)
def reference_association_set(
    call: Call, from_address, to_address, symbol_address, operand_index=0, symbol_name=None
):
    item = _reference(call, from_address, to_address, operand_index)
    symbol = _symbol(call, symbol_address, symbol_name)
    call.program.getReferenceManager().setAssociation(symbol, item)
    return _reference_dict(_reference(call, from_address, to_address, operand_index))


@operation("reference.association.remove", kind="write", api="ReferenceManager.removeAssociation")
def reference_association_remove(call: Call, from_address, to_address, operand_index=0):
    item = _reference(call, from_address, to_address, operand_index)
    call.program.getReferenceManager().removeAssociation(item)
    return _reference_dict(_reference(call, from_address, to_address, operand_index))


@operation("reference.delete", kind="write", api="ReferenceManager.getReferencesFrom; delete")
def reference_delete(call: Call, from_address, to_address=None, operand_index=None):
    manager = call.program.getReferenceManager()
    target = resolve_address(call, to_address) if to_address is not None else None
    if operand_index is not None:
        _operand(operand_index)
    count = 0
    for item in manager.getReferencesFrom(resolve_address(call, from_address)):
        if target is not None and item.getToAddress() != target:
            continue
        if operand_index is not None and item.getOperandIndex() != operand_index:
            continue
        manager.delete(item)
        count += 1
    return {"deleted_count": count}


@operation(
    "reference.clear_from",
    kind="write",
    api="ReferenceManager.removeAllReferencesFrom(Address, Address)",
)
def reference_clear_from(call: Call, from_address, end_address=None):
    selection = address_range(call, from_address, end_address)
    manager = call.program.getReferenceManager()
    count = sum(1 for _ in _references(call, "from", start=from_address, end=end_address))
    manager.removeAllReferencesFrom(selection.getMinAddress(), selection.getMaxAddress())
    return {"deleted_count": count}


@operation("reference.clear_to", kind="write", api="ReferenceManager.removeAllReferencesTo")
def reference_clear_to(call: Call, to_address):
    target = resolve_address(call, to_address)
    manager = call.program.getReferenceManager()
    count = sum(1 for _ in manager.getReferencesTo(target))
    manager.removeAllReferencesTo(target)
    return {"deleted_count": count}
