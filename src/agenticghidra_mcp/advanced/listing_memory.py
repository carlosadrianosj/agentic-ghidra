"""Bounded listing, memory and instruction-level search operations."""

from __future__ import annotations

import base64
import codecs
from collections import deque

from .core import (
    Call,
    address as resolve_address,
    address_range,
    datatype,
    decode_bytes,
    function,
    operation,
    page,
    read_bytes,
)


def _check(call):
    if call.monitor is not None:
        call.monitor.checkCancelled()


def _scope(call, start=None, end=None, *, initialized=False, function_start=None):
    from ghidra.program.model.address import AddressSet

    memory = call.program.getMemory()
    result = AddressSet(memory.getAllInitializedAddressSet() if initialized else memory)
    if start is not None or end is not None:
        supplied = resolve_address(call, start if start is not None else end)
        space = supplied.getAddressSpace()
        first = resolve_address(call, start) if start is not None else space.getMinAddress()
        last = resolve_address(call, end) if end is not None else space.getMaxAddress()
        result = result.intersect(address_range(call, first, last))
    if function_start is not None:
        result = result.intersect(function(call, function_start).getBody())
    return result


def _unit(unit):
    if unit is None:
        return None
    from ghidra.program.model.listing import Data

    result = {
        "address": str(unit.getMinAddress()),
        "end": str(unit.getMaxAddress()),
        "length": int(unit.getLength()),
        "text": str(unit),
        "mnemonic": str(unit.getMnemonicString()),
    }
    if isinstance(unit, Data):
        result.update(
            kind="data",
            data_type=str(unit.getDataType()),
            defined=bool(unit.isDefined()),
            value=str(unit.getValue()) if unit.getValue() is not None else None,
            representation=str(unit.getDefaultValueRepresentation()),
        )
    else:
        result.update(
            kind="instruction",
            operands=[
                str(unit.getDefaultOperandRepresentation(i)) for i in range(unit.getNumOperands())
            ],
        )
    return result


def _units(call, scope, *, instructions=False, forward=True):
    listing = call.program.getListing()
    iterator = (
        listing.getInstructions(scope, forward)
        if instructions
        else listing.getCodeUnits(scope, forward)
    )
    for unit in iterator:
        _check(call)
        if scope.contains(unit.getMinAddress(), unit.getMaxAddress()):
            yield _unit(unit)


@operation("listing.code_unit.at", api="Listing.getCodeUnitAt", analysis=True)
def code_unit_at(call: Call, address):
    return {
        "code_unit": _unit(call.program.getListing().getCodeUnitAt(resolve_address(call, address)))
    }


@operation("listing.code_unit.before", api="Listing.getCodeUnitBefore", analysis=True)
def code_unit_before(call: Call, address):
    return {
        "code_unit": _unit(
            call.program.getListing().getCodeUnitBefore(resolve_address(call, address))
        )
    }


@operation("listing.code_unit.after", api="Listing.getCodeUnitAfter", analysis=True)
def code_unit_after(call: Call, address):
    return {
        "code_unit": _unit(
            call.program.getListing().getCodeUnitAfter(resolve_address(call, address))
        )
    }


@operation("listing.code_unit.containing", api="Listing.getCodeUnitContaining", analysis=True)
def code_unit_containing(call: Call, address):
    return {
        "code_unit": _unit(
            call.program.getListing().getCodeUnitContaining(resolve_address(call, address))
        )
    }


@operation(
    "listing.code_units.list", api="Listing.getCodeUnits(AddressSetView,boolean)", analysis=True
)
def code_units_list(call: Call, start=None, end=None, offset=0, limit=100, forward=True):
    return page(
        _units(call, _scope(call, start, end), forward=forward), offset, limit, key="code_units"
    )


@operation("listing.data.at", api="Listing.getDataAt")
def data_at(call: Call, address):
    return {"data": _unit(call.program.getListing().getDataAt(resolve_address(call, address)))}


@operation("listing.data.list", api="Listing.getDefinedData(boolean)")
def data_list(call: Call, offset=0, limit=100):
    return page(
        (_unit(data) for data in call.program.getListing().getDefinedData(True)),
        offset,
        limit,
        key="data",
    )


@operation("listing.data.create", kind="write", api="Listing.createData; Listing.clearCodeUnits")
def data_create(call: Call, address, data_type, length=None, clear_existing=True):
    location = resolve_address(call, address)
    type_ = datatype(call, data_type)
    size = int(type_.getLength()) if length is None else length
    if size <= 0:
        raise ValueError("A positive length is required for a variable-length data type")
    scope = address_range(call, location, length=size)
    if not call.program.getMemory().contains(scope):
        raise ValueError("Data range must be mapped memory")
    listing = call.program.getListing()
    if clear_existing:
        listing.clearCodeUnits(location, scope.getMaxAddress(), False, call.monitor)
    created = (
        listing.createData(location, type_)
        if length is None
        else listing.createData(location, type_, length)
    )
    return {"data": _unit(created)}


@operation("listing.data.clear", kind="write", api="Listing.clearCodeUnits")
def data_clear(call: Call, address, length=1):
    scope = address_range(call, address, length=length)
    call.program.getListing().clearCodeUnits(
        scope.getMinAddress(), scope.getMaxAddress(), False, call.monitor
    )
    return {"start": str(scope.getMinAddress()), "end": str(scope.getMaxAddress()), "cleared": True}


def _equates_to_preserve(call, affected, scope, clear_equates):
    table = call.program.getEquateTable()
    for location in table.getEquateAddresses(affected):
        _check(call)
        if clear_equates and scope.contains(location):
            continue
        seen = set()
        for equate in table.getEquates(location):
            name = str(equate.getName())
            if name in seen:
                continue
            seen.add(name)
            for reference in equate.getReferences(location):
                yield (
                    name,
                    int(equate.getValue()),
                    location,
                    int(reference.getOpIndex()),
                    int(reference.getDynamicHashValue()),
                )


def _restore_equates(call, preserved):
    table = call.program.getEquateTable()
    for name, value, location, operand, dynamic_hash in preserved:
        equate = table.getEquate(name)
        if equate is None:
            equate = table.createEquate(name, value)
        if dynamic_hash:
            equate.addReference(dynamic_hash, location)
        else:
            equate.addReference(location, operand)


@operation(
    "listing.clear",
    kind="write",
    api=(
        "Listing.clearCodeUnits; ClearCmd(AddressSetView,ClearOptions); "
        "ReferenceManager.addReference"
    ),
)
def listing_clear(
    call: Call,
    start,
    end=None,
    length=None,
    clear_context=False,
    clear_symbols=False,
    clear_comments=False,
    clear_properties=False,
    clear_functions=False,
    clear_registers=False,
    clear_equates=False,
    clear_user_references=False,
    clear_analysis_references=False,
    clear_import_references=False,
    clear_default_references=False,
    clear_bookmarks=False,
):
    from ghidra.app.plugin.core.clear import ClearCmd, ClearOptions

    scope = address_range(call, start, end, length)
    # Partial code units are removed in full, including references outside the request.
    # Preserve those references regardless of the flags for the requested addresses.
    from ghidra.program.model.address import AddressSet

    affected = AddressSet(scope)
    listing = call.program.getListing()
    for boundary in (scope.getMinAddress(), scope.getMaxAddress()):
        unit = listing.getCodeUnitContaining(boundary)
        if unit is not None:
            affected.addRange(unit.getMinAddress(), unit.getMaxAddress())
    manager = call.program.getReferenceManager()
    flags = {
        "USER_DEFINED": clear_user_references,
        "ANALYSIS": clear_analysis_references,
        "IMPORTED": clear_import_references,
        "DEFAULT": clear_default_references,
    }
    # Clearing code intrinsically removes references. Preserve unselected sources explicitly.
    preserved = []
    for location in manager.getReferenceSourceIterator(affected, True):
        _check(call)
        for reference in manager.getReferencesFrom(location):
            if not scope.contains(location) or not flags[str(reference.getSource())]:
                preserved.append((reference, bool(reference.isPrimary())))
    # Code-unit removal also drops equates even when ClearOptions leaves them selected off.
    preserved_equates = list(_equates_to_preserve(call, affected, scope, clear_equates))
    call.program.getListing().clearCodeUnits(
        scope.getMinAddress(), scope.getMaxAddress(), clear_context, call.monitor
    )
    options = ClearOptions(False)
    selected = {
        "SYMBOLS": clear_symbols,
        "COMMENTS": clear_comments,
        "PROPERTIES": clear_properties,
        "FUNCTIONS": clear_functions,
        "REGISTERS": clear_registers,
        "EQUATES": clear_equates,
        "USER_REFERENCES": clear_user_references,
        "ANALYSIS_REFERENCES": clear_analysis_references,
        "IMPORT_REFERENCES": clear_import_references,
        "DEFAULT_REFERENCES": clear_default_references,
        "BOOKMARKS": clear_bookmarks,
    }
    for name, enabled in selected.items():
        options.setShouldClear(getattr(ClearOptions.ClearType, name), enabled)
    command = ClearCmd(scope, options)
    if not command.applyTo(call.program, call.monitor):
        raise ValueError(str(command.getStatusMsg() or "Clear command failed"))
    for reference, primary in preserved:
        restored = manager.addReference(reference)
        if primary:
            manager.setPrimary(restored, True)
    _restore_equates(call, preserved_equates)
    return {
        "start": str(scope.getMinAddress()),
        "end": str(scope.getMaxAddress()),
        "cleared": True,
        "clear_context": clear_context,
        "options": selected,
        "preserved_references": len(preserved),
    }


@operation(
    "listing.disassemble.function",
    api="FunctionManager.getFunctionContaining; Listing.getInstructions",
    analysis=True,
)
def disassemble_function(call: Call, address, limit=500):
    target = function(call, address)
    result = page(
        _units(call, target.getBody().intersect(call.program.getMemory()), instructions=True),
        limit=limit,
        key="instructions",
    )
    result["function"] = str(target.getEntryPoint())
    return result


@operation(
    "listing.disassemble.range",
    api="Listing.getInstructions(AddressSetView,boolean)",
    analysis=True,
)
def disassemble_range(call: Call, start, length, limit=200):
    scope = address_range(call, start, length=length).intersect(call.program.getMemory())
    return page(_units(call, scope, instructions=True), limit=limit, key="instructions")


@operation(
    "listing.disassemble.seed",
    kind="write",
    api="DisassembleCommand.applyTo; DisassembleCommand.getDisassembledAddressSet",
    analysis=True,
)
def disassemble_seed(call: Call, address, limit=128, clear_existing=False):
    from ghidra.app.cmd.disassemble import DisassembleCommand

    # Validate output bounds before performing a mutation.
    page((), limit=limit)
    seed = resolve_address(call, address)
    memory = call.program.getMemory()
    if not memory.getAllInitializedAddressSet().contains(seed):
        raise ValueError("Disassembly seed must be initialized mapped memory")
    if clear_existing:
        unit = call.program.getListing().getCodeUnitContaining(seed)
        if unit is not None:
            call.program.getListing().clearCodeUnits(
                unit.getMinAddress(), unit.getMaxAddress(), False, call.monitor
            )
    command = DisassembleCommand(seed, memory.getAllInitializedAddressSet(), True)
    command.enableCodeAnalysis(False)
    if not command.applyTo(call.program, call.monitor):
        raise ValueError(str(command.getStatusMsg() or "Disassembly failed"))
    scope = command.getDisassembledAddressSet()
    result = page(_units(call, scope, instructions=True), limit=limit, key="instructions")
    result.update(
        seed=str(seed),
        disassembled_address_count=int(scope.getNumAddresses()),
        disassembled_ranges=page(
            (
                {"start": str(r.getMinAddress()), "end": str(r.getMaxAddress())}
                for r in scope.getAddressRanges()
            ),
            limit=1000,
            key="ranges",
        ),
    )
    return result


def _block(block):
    return {
        "name": str(block.getName()),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "length": int(block.getSize()),
        "initialized": bool(block.isInitialized()),
        "read": bool(block.isRead()),
        "write": bool(block.isWrite()),
        "execute": bool(block.isExecute()),
        "comment": str(block.getComment()) if block.getComment() is not None else None,
        "type": str(block.getType()),
        "mapped": bool(block.isMapped()),
        "overlay": bool(block.isOverlay()),
    }


@operation("memory.blocks.list", api="Memory.getBlocks")
def blocks_list(call: Call):
    return {"blocks": [_block(block) for block in call.program.getMemory().getBlocks()]}


@operation(
    "memory.block.create",
    kind="write",
    api=(
        "Memory.createInitializedBlock; Memory.createUninitializedBlock; "
        "MemoryBlock.setPermissions"
    ),
)
def block_create(
    call: Call,
    name,
    address,
    length,
    initialized=True,
    fill=0,
    read=True,
    write=False,
    execute=False,
    comment=None,
):
    import jpype

    if length <= 0:
        raise ValueError("length must be positive")
    if not 0 <= fill <= 255:
        raise ValueError("fill must be between 0 and 255")
    location = resolve_address(call, address)
    address_range(call, location, length=length)
    memory = call.program.getMemory()
    block = (
        memory.createInitializedBlock(
            name,
            location,
            length,
            jpype.JByte(fill if fill < 128 else fill - 256),
            call.monitor,
            False,
        )
        if initialized
        else memory.createUninitializedBlock(name, location, length, False)
    )
    block.setPermissions(read, write, execute)
    if comment is not None:
        block.setComment(comment)
    return {"block": _block(block)}


@operation("memory.block.remove", kind="write", api="Memory.getBlock; Memory.removeBlock")
def block_remove(call: Call, name=None, address=None):
    if name is None and address is None:
        raise ValueError("Specify a block name or address")
    memory = call.program.getMemory()
    block = (
        memory.getBlock(resolve_address(call, address))
        if address is not None
        else memory.getBlock(name)
    )
    if block is None or (name is not None and str(block.getName()) != name):
        raise ValueError("Memory block not found or name/address do not identify the same block")
    result = _block(block)
    memory.removeBlock(block, call.monitor)
    return {"removed": result}


@operation("memory.read", api="Memory.getBytes")
def memory_read(call: Call, address, length):
    content = read_bytes(call, address, length)
    return {
        "address": str(resolve_address(call, address)),
        "length": len(content),
        "data_hex": content.hex(),
        "data_base64": base64.b64encode(content).decode("ascii"),
    }


@operation("memory.write", kind="write", api="Memory.setBytes")
def memory_write(call: Call, address, data_base64=None, data_hex=None):
    import jpype

    content = decode_bytes(data_base64=data_base64, data_hex=data_hex)
    location = resolve_address(call, address)
    if content:
        scope = address_range(call, location, length=len(content))
        if not call.program.getMemory().getAllInitializedAddressSet().contains(scope):
            raise ValueError("Write range must be initialized mapped memory")
        call.program.getMemory().setBytes(location, jpype.JArray(jpype.JByte)(content))
    return {"address": str(location), "length": len(content), "written": len(content)}


def _byte_matches(call, content, scope):
    import jpype

    pattern = jpype.JArray(jpype.JByte)(content)
    memory = call.program.getMemory()
    for region in scope.getAddressRanges():
        first, last = region.getMinAddress(), region.getMaxAddress()
        if region.getLength() < len(content):
            continue
        last_start = last.subtract(len(content) - 1)
        while first.compareTo(last_start) <= 0:
            _check(call)
            found = memory.findBytes(first, last, pattern, None, True, call.monitor)
            if found is None or found.compareTo(last_start) > 0:
                break
            yield {"address": str(found), "length": len(content), "data_hex": content.hex()}
            if found == last_start:
                break
            first = found.addNoWrap(1)


@operation(
    "search.bytes", api="Memory.findBytes(Address,Address,byte[],byte[],boolean,TaskMonitor)"
)
def search_bytes(
    call: Call, pattern_base64=None, pattern_hex=None, start=None, end=None, limit=100
):
    content = decode_bytes(data_base64=pattern_base64, data_hex=pattern_hex)
    if not content:
        raise ValueError("Search pattern must not be empty")
    return page(
        _byte_matches(call, content, _scope(call, start, end, initialized=True)),
        limit=limit,
        key="matches",
    )


def _strings(call, scope=None):
    listing = call.program.getListing()
    iterator = (
        listing.getDefinedData(True) if scope is None else listing.getDefinedData(scope, True)
    )
    for data in iterator:
        _check(call)
        if data.hasStringValue() and (
            scope is None or scope.contains(data.getMinAddress(), data.getMaxAddress())
        ):
            yield data


@operation(
    "search.defined_strings",
    api="Listing.getDefinedData; Data.hasStringValue; Data.getDefaultValueRepresentation",
    analysis=True,
)
def defined_strings(call: Call, offset=0, limit=100, query=None):
    return page(
        (
            _unit(data)
            for data in _strings(call)
            if query is None or query.casefold() in str(data.getValue()).casefold()
        ),
        offset,
        limit,
        key="strings",
    )


def _prefix_table(needle):
    prefix = [0] * len(needle)
    matched = 0
    for index in range(1, len(needle)):
        while matched and needle[index] != needle[matched]:
            matched = prefix[matched - 1]
        if needle[index] == needle[matched]:
            matched += 1
        prefix[index] = matched
    return prefix


def _text_matches(call, text, encoding, sensitive, scope):
    needle = text if sensitive else text.casefold()
    prefix = _prefix_table(needle)
    for region in scope.getAddressRanges():
        yield from _region_text_matches(call, text, encoding, sensitive, region, needle, prefix)


def _region_text_matches(call, text, encoding, sensitive, region, needle, prefix):
    # Incremental decoding retains byte addresses through split characters and case folds.
    byte_preserving = codecs.lookup(encoding).name in ("utf-8", "ascii")
    decoder = codecs.getincrementaldecoder(encoding)(
        errors="surrogateescape" if byte_preserving else "replace"
    )
    window = deque(maxlen=len(needle))
    first = region.getMinAddress()
    size = int(region.getLength())
    pending = 0
    matched = 0
    previous = None
    for offset in range(0, size, 65536):
        _check(call)
        content = read_bytes(call, first.addNoWrap(offset), min(65536, size - offset))
        for index, byte in enumerate(content, offset):
            decoded = decoder.decode(bytes((byte,)), final=index == size - 1)
            if not decoded:
                continue
            for character in decoded:
                finish_byte = (
                    pending + len(character.encode(encoding, errors="surrogateescape")) - 1
                    if byte_preserving
                    else index
                )
                for folded in character if sensitive else character.casefold():
                    window.append((pending, finish_byte))
                    while matched and folded != needle[matched]:
                        matched = prefix[matched - 1]
                    if folded == needle[matched]:
                        matched += 1
                    if matched == len(needle):
                        begin, finish = window[0][0], window[-1][1]
                        if (begin, finish) != previous:
                            yield {
                                "address": str(first.addNoWrap(begin)),
                                "length": finish - begin + 1,
                                "text": text,
                                "encoding": encoding,
                            }
                            previous = (begin, finish)
                        matched = prefix[matched - 1]
                pending = finish_byte + 1
            pending = index + 1


@operation(
    "search.text", api="Listing.getDefinedData; Data.getValue; Memory.getBytes", analysis=True
)
def search_text(
    call: Call,
    text,
    case_sensitive=False,
    defined_strings_only=False,
    encoding="utf-8",
    start=None,
    end=None,
    limit=100,
):
    if not text:
        raise ValueError("Search text must not be empty")
    codecs.lookup(encoding)
    # Encoding errors are consumer errors, never silently replaced patterns.
    text.encode(encoding)
    scope = _scope(call, start, end, initialized=True)
    if defined_strings_only:
        needle = text if case_sensitive else text.casefold()
        matches = (
            _unit(data)
            for data in _strings(call, scope)
            if needle
            in (str(data.getValue()) if case_sensitive else str(data.getValue()).casefold())
        )
    else:
        matches = _text_matches(call, text, encoding, case_sensitive, scope)
    return page(matches, limit=limit, key="matches")


@operation(
    "search.constants",
    api=(
        "Listing.getInstructions; Instruction.getOpObjects; "
        "Scalar.getSignedValue; Scalar.getUnsignedValue"
    ),
    analysis=True,
)
def search_constants(call: Call, value, start=None, end=None, limit=100):
    from ghidra.program.model.scalar import Scalar

    try:
        wanted = int(value, 0) if isinstance(value, str) else int(value)
    except ValueError as exc:
        raise ValueError(
            "Constant must be an integer or a decimal/hexadecimal integer string"
        ) from exc
    scope = _scope(call, start, end)

    def matches():
        for instruction in call.program.getListing().getInstructions(scope, True):
            _check(call)
            if not scope.contains(instruction.getMinAddress(), instruction.getMaxAddress()):
                continue
            for operand in range(instruction.getNumOperands()):
                for obj in instruction.getOpObjects(operand):
                    if isinstance(obj, Scalar) and wanted in (
                        int(obj.getSignedValue()),
                        int(obj.getUnsignedValue()),
                    ):
                        yield {
                            "address": str(instruction.getAddress()),
                            "operand": operand,
                            "value": int(obj.getUnsignedValue()),
                            "signed_value": int(obj.getSignedValue()),
                            "bits": int(obj.bitLength()),
                            "instruction": str(instruction),
                        }

    return page(matches(), limit=limit, key="matches")


def _instruction_search(
    call, query, case_sensitive, function_start, start, end, limit, *, pcode=False
):
    if not query:
        raise ValueError("Search query must not be empty")
    scope = _scope(call, start, end, function_start=function_start)
    needle = query if case_sensitive else query.casefold()

    def matches():
        for instruction in call.program.getListing().getInstructions(scope, True):
            _check(call)
            if not scope.contains(instruction.getMinAddress(), instruction.getMaxAddress()):
                continue
            if pcode:
                for index, op in enumerate(instruction.getPcode()):
                    text = str(op)
                    if needle in (text if case_sensitive else text.casefold()):
                        yield {
                            "address": str(instruction.getAddress()),
                            "op_index": index,
                            "mnemonic": str(op.getMnemonic()),
                            "pcode": text,
                            "instruction": str(instruction),
                        }
            elif needle in (str(instruction) if case_sensitive else str(instruction).casefold()):
                yield _unit(instruction)

    return page(matches(), limit=limit, key="matches")


@operation(
    "search.instructions", api="Listing.getInstructions; Instruction.toString", analysis=True
)
def search_instructions(
    call: Call, query, case_sensitive=False, function_start=None, start=None, end=None, limit=100
):
    return _instruction_search(call, query, case_sensitive, function_start, start, end, limit)


@operation(
    "search.pcode",
    api="Listing.getInstructions; Instruction.getPcode; PcodeOp.toString",
    analysis=True,
)
def search_pcode(
    call: Call, query, case_sensitive=False, function_start=None, start=None, end=None, limit=100
):
    return _instruction_search(
        call, query, case_sensitive, function_start, start, end, limit, pcode=True
    )


@operation(
    "search.resolve", api="AddressFactory.getAddress; SymbolTable.getSymbols; Memory.contains"
)
def search_resolve(call: Call, query):
    location = resolve_address(call, query)
    memory = call.program.getMemory()
    if not memory.contains(location):
        raise ValueError("Resolved address is not mapped memory")
    return {
        "query": query,
        "address": str(location),
        "block": str(memory.getBlock(location).getName()),
        "symbols": [
            str(symbol.getName(True))
            for symbol in call.program.getSymbolTable().getSymbols(location)
        ],
    }
