"""Persistent annotations and architecture-aware patches through public Ghidra APIs."""

from __future__ import annotations

import itertools
import json
import re

from .core import (
    MAX_BYTES,
    MAX_RESULTS,
    Call,
    address as resolve_address,
    address_range,
    function,
    operation,
    page,
    read_bytes,
)

_METADATA_OPTIONS = "Advanced MCP Metadata"
_COMMENT_TYPES = ("eol", "pre", "post", "plate", "repeatable")


def _text(value, name="text"):
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"{name} must be a string of at most {MAX_BYTES} UTF-8 bytes")
    return value


def _name(value, name="name"):
    text = _text(value, name)
    if not text.strip():
        raise ValueError(f"{name} must not be empty or blank")
    return text


def _integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _bytes(value):
    return bytes(int(item) & 255 for item in value)


def _jbytes(value):
    import jpype

    return jpype.JArray(jpype.JByte)(value)


def _bounds(call, start=None, end=None):
    if start is None and end is None:
        return call.program.getMemory()
    return address_range(
        call,
        start if start is not None else call.program.getMinAddress(),
        end if end is not None else call.program.getMaxAddress(),
    )


def _comment_type(name):
    from ghidra.program.model.listing import CommentType

    normalized = name.lower()
    if normalized not in _COMMENT_TYPES:
        raise ValueError(f"comment_type must be one of {', '.join(_COMMENT_TYPES)}")
    return getattr(CommentType, normalized.upper())


def _comment_location(call, address, function_start, scope):
    scope = scope.lower()
    if scope not in ("listing", "function", "decompiler"):
        raise ValueError("scope must be listing, function, or decompiler")
    fn = function(call, function_start) if function_start is not None else None
    if fn is None and (scope == "function" or (scope == "decompiler" and address is None)):
        fn = function(call, address)
    if fn is not None and address is not None:
        addr = resolve_address(call, address)
        if not fn.getBody().contains(addr):
            raise ValueError("address is outside the requested function")
    else:
        addr = (
            resolve_address(call, address)
            if address is not None
            else (fn.getEntryPoint() if fn is not None else None)
        )
    if addr is None:
        raise ValueError("address or function_start is required")
    # The decompiler reads listing comments and function comments directly. It does not
    # have a separate Python-side comment store.
    function_scope = scope == "function" or (scope == "decompiler" and address is None)
    if function_scope:
        addr = fn.getEntryPoint()
    return addr, fn, function_scope


@operation("comment.get", api="Listing.getComment; Function.getComment/getRepeatableComment")
def comment_get(call: Call, address=None, comment_type="eol", function_start=None, scope="listing"):
    kind = _comment_type(comment_type)
    addr, fn, function_scope = _comment_location(call, address, function_start, scope)
    function_storage = function_scope and comment_type.lower() in ("plate", "repeatable")
    if function_storage:
        value = (
            fn.getRepeatableComment() if comment_type.lower() == "repeatable" else fn.getComment()
        )
    else:
        value = call.program.getListing().getComment(kind, addr)
    return {
        "address": str(addr),
        "comment_type": comment_type.lower(),
        "scope": scope,
        "storage": "function" if function_storage else "listing",
        "comment": None if value is None else str(value),
    }


@operation(
    "comment.set", kind="write", api="Listing.setComment; Function.setComment/setRepeatableComment"
)
def comment_set(
    call: Call, comment, address=None, comment_type="eol", function_start=None, scope="listing"
):
    _text(comment, "comment")
    kind = _comment_type(comment_type)
    addr, fn, function_scope = _comment_location(call, address, function_start, scope)
    if function_scope and comment_type.lower() in ("plate", "repeatable"):
        if comment_type.lower() == "repeatable":
            fn.setRepeatableComment(comment or None)
        else:
            fn.setComment(comment or None)
    else:
        call.program.getListing().setComment(addr, kind, comment or None)
    return comment_get(call, address, comment_type, function_start, scope)


@operation("comment.get_all", api="Listing.getComment; Function.getComment/getRepeatableComment")
def comment_get_all(call: Call, address, include_function=True):
    addr = resolve_address(call, address)
    listing = call.program.getListing()
    result = {
        "address": str(addr),
        "comments": {
            name: None
            if (value := listing.getComment(_comment_type(name), addr)) is None
            else str(value)
            for name in _COMMENT_TYPES
        },
    }
    if include_function:
        fn = call.program.getFunctionManager().getFunctionContaining(addr)
        result["function"] = (
            None
            if fn is None
            else {
                "address": str(fn.getEntryPoint()),
                "comment": None if fn.getComment() is None else str(fn.getComment()),
                "repeatable": None
                if fn.getRepeatableComment() is None
                else str(fn.getRepeatableComment()),
            }
        )
    return result


@operation("comment.list", api="Listing.getCommentAddressIterator/getComment")
def comment_list(
    call: Call,
    start=None,
    end=None,
    comment_type=None,
    query=None,
    case_sensitive=False,
    offset=0,
    limit=100,
):
    listing = call.program.getListing()
    kinds = _COMMENT_TYPES if comment_type is None else (comment_type.lower(),)
    for kind in kinds:
        _comment_type(kind)
    needle = None if query is None else (query if case_sensitive else query.casefold())

    def rows():
        for addr in listing.getCommentAddressIterator(_bounds(call, start, end), True):
            for kind in kinds:
                value = listing.getComment(_comment_type(kind), addr)
                if value is None:
                    continue
                text = str(value)
                if needle is None or needle in (text if case_sensitive else text.casefold()):
                    yield {"address": str(addr), "comment_type": kind, "comment": text}

    return page(rows(), offset, limit, key="comments")


def _bookmark_type(name):
    from ghidra.program.model.listing import BookmarkType

    return str(getattr(BookmarkType, name.upper(), name))


def _bookmark(item):
    return {
        "id": int(item.getId()),
        "address": str(item.getAddress()),
        "bookmark_type": str(item.getTypeString()),
        "category": str(item.getCategory()),
        "comment": str(item.getComment()),
    }


@operation("bookmark.add", kind="write", api="BookmarkManager.setBookmark")
def bookmark_add(call: Call, address, category, comment, bookmark_type="NOTE"):
    item = call.program.getBookmarkManager().setBookmark(
        resolve_address(call, address),
        _bookmark_type(bookmark_type),
        _text(category, "category"),
        _text(comment, "comment"),
    )
    return _bookmark(item)


@operation("bookmark.list", api="BookmarkManager.getBookmarks/getBookmarksIterator")
def bookmark_list(call: Call, address=None, bookmark_type=None, offset=0, limit=100):
    manager = call.program.getBookmarkManager()
    if address is not None:
        items = manager.getBookmarks(resolve_address(call, address))
    else:
        items = manager.getBookmarksIterator()
    kind = None if bookmark_type is None else _bookmark_type(bookmark_type)
    return page(
        (_bookmark(item) for item in items if kind is None or str(item.getTypeString()) == kind),
        offset,
        limit,
        key="bookmarks",
    )


@operation("bookmark.remove", kind="write", api="BookmarkManager.removeBookmark")
def bookmark_remove(call: Call, address, bookmark_type=None, category=None):
    manager = call.program.getBookmarkManager()
    kind = None if bookmark_type is None else _bookmark_type(bookmark_type)
    count = 0
    for item in manager.getBookmarks(resolve_address(call, address)):
        if (kind is None or str(item.getTypeString()) == kind) and (
            category is None or str(item.getCategory()) == category
        ):
            manager.removeBookmark(item)
            count += 1
    return {"removed": count}


@operation(
    "bookmark.clear",
    kind="write",
    api="BookmarkManager.removeBookmarks(AddressSetView, TaskMonitor)",
)
def bookmark_clear(call: Call, start, end=None, length=None, bookmark_type=None):
    manager = call.program.getBookmarkManager()
    region = address_range(call, start, end, length)
    if bookmark_type is None:
        manager.removeBookmarks(region, call.monitor)
    else:
        manager.removeBookmarks(region, _bookmark_type(bookmark_type), call.monitor)
    return {
        "cleared": True,
        "start": str(region.getMinAddress()),
        "end": str(region.getMaxAddress()),
    }


def _tag(item, manager):
    return {
        "id": int(item.getId()),
        "name": str(item.getName()),
        "comment": str(item.getComment() or ""),
        "function_count": int(manager.getUseCount(item)),
    }


@operation(
    "tag.add",
    kind="write",
    api="FunctionTagManager.createFunctionTag; Function.addTag; FunctionTag.setComment",
)
def tag_add(call: Call, function_start, name, comment=""):
    manager = call.program.getFunctionManager().getFunctionTagManager()
    item = manager.createFunctionTag(_name(name, "name"), _text(comment, "comment"))
    fn = function(call, function_start)
    fn.addTag(name)
    return {"function": str(fn.getEntryPoint()), **_tag(item, manager)}


@operation("tag.list", api="FunctionTagManager.getAllFunctionTags; Function.getTags")
def tag_list(call: Call, function_start=None):
    manager = call.program.getFunctionManager().getFunctionTagManager()
    items = (
        manager.getAllFunctionTags()
        if function_start is None
        else function(call, function_start).getTags()
    )
    return page((_tag(item, manager) for item in items), limit=MAX_RESULTS, key="tags")


@operation("tag.remove", kind="write", api="Function.removeTag")
def tag_remove(call: Call, function_start, name):
    fn = function(call, function_start)
    present = any(str(item.getName()) == name for item in fn.getTags())
    fn.removeTag(name)
    return {"removed": present, "function": str(fn.getEntryPoint()), "name": name}


@operation("tag.stats", api="FunctionTagManager.getAllFunctionTags/getUseCount")
def tag_stats(call: Call):
    manager = call.program.getFunctionManager().getFunctionTagManager()
    tags = manager.getAllFunctionTags()
    result = page((_tag(item, manager) for item in tags), limit=MAX_RESULTS, key="tags")
    result["tag_count"] = int(tags.size())
    result["assignment_count"] = sum(int(manager.getUseCount(item)) for item in tags)
    return result


@operation("metadata.store", kind="write", api="Program.getOptions; Options.setString")
def metadata_store(call: Call, key, value):
    _text(key, "key")
    if not key or len(key.encode("utf-8")) > 1024:
        raise ValueError("key must contain between 1 and 1024 UTF-8 bytes")
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    _text(encoded, "serialized metadata")
    # Encode keys to prevent Options' dot-delimited child categories changing key identity.
    name = "json_" + key.encode("utf-8").hex()
    call.program.getOptions(_METADATA_OPTIONS).setString(name, encoded)
    return {"key": key, "value": json.loads(encoded), "persistent": True}


@operation(
    "metadata.query", api="Program.getOptionsNames/getOptions; Options.getOptionNames/getString"
)
def metadata_query(call: Call, key=None, prefix=None, offset=0, limit=100):
    def rows():
        if _METADATA_OPTIONS not in (str(name) for name in call.program.getOptionsNames()):
            return
        options = call.program.getOptions(_METADATA_OPTIONS)
        names = (
            ["json_" + key.encode("utf-8").hex()] if key is not None else options.getOptionNames()
        )
        for raw in names:
            name = str(raw)
            if not name.startswith("json_") or not options.contains(name):
                continue
            decoded = bytes.fromhex(name[5:]).decode("utf-8")
            if prefix is not None and not decoded.startswith(prefix):
                continue
            yield {"key": decoded, "value": json.loads(str(options.getString(name, None)))}

    return page(rows(), offset, limit, key="metadata")


def _source_file(item):
    return {
        "path": str(item.getPath()),
        "id_type": str(item.getIdType().name()),
        "identifier_hex": _bytes(item.getIdentifier()).hex(),
    }


def _source_files(call, path):
    from ghidra.program.database.sourcemap import SourceFile

    normalized = str(SourceFile(path).getPath())
    return (
        item
        for item in call.program.getSourceFileManager().getAllSourceFiles()
        if str(item.getPath()) == normalized
    )


def _unique_source(call, path):
    matches = list(itertools.islice(_source_files(call, path), 2))
    if len(matches) != 1:
        raise ValueError(
            f"Expected one source file for path {path!r}; found {'multiple' if matches else 'none'}"
        )
    return matches[0]


def _source_map(item):
    return {
        "path": str(item.getSourceFile().getPath()),
        "source_file": _source_file(item.getSourceFile()),
        "line_number": int(item.getLineNumber()),
        "base_address": str(item.getBaseAddress()),
        "length": int(item.getLength()),
    }


@operation(
    "source.file.add",
    kind="write",
    api="SourceFileManager.addSourceFile; SourceFile; SourceFileIdType",
)
def source_file_add(call: Call, path, id_type=None, identifier_hex=None):
    from ghidra.program.database.sourcemap import SourceFile, SourceFileIdType

    _text(path, "path")
    kind = SourceFileIdType.NONE if id_type is None else SourceFileIdType.valueOf(id_type.upper())
    if identifier_hex is not None and kind == SourceFileIdType.NONE:
        raise ValueError("identifier_hex requires a non-NONE id_type")
    if kind != SourceFileIdType.NONE and identifier_hex is None:
        raise ValueError("identifier_hex is required with id_type")
    if identifier_hex is not None and len(identifier_hex) > MAX_BYTES * 2:
        raise ValueError("Source identifier exceeds payload bound")
    identifier = None if identifier_hex is None else _jbytes(bytes.fromhex(identifier_hex))
    item = SourceFile(path, kind, identifier)
    added = call.program.getSourceFileManager().addSourceFile(item)
    return {**_source_file(item), "added": bool(added)}


@operation("source.file.list", api="SourceFileManager.getAllSourceFiles")
def source_file_list(call: Call):
    return page(
        (_source_file(item) for item in call.program.getSourceFileManager().getAllSourceFiles()),
        limit=MAX_RESULTS,
        key="files",
    )


@operation("source.file.remove", kind="write", api="SourceFileManager.removeSourceFile")
def source_file_remove(call: Call, path):
    manager = call.program.getSourceFileManager()
    count = 0
    for item in _source_files(call, path):
        count += bool(manager.removeSourceFile(item))
    return {"removed": count}


@operation("source.map.add", kind="write", api="SourceFileManager.addSourceMapEntry")
def source_map_add(call: Call, path, line_number, base_address, length):
    if not 0 <= line_number <= 2147483647 or not 0 <= length <= MAX_BYTES:
        raise ValueError("line_number must be nonnegative int32 and length between 0 and 1048576")
    item = call.program.getSourceFileManager().addSourceMapEntry(
        _unique_source(call, path), line_number, resolve_address(call, base_address), length
    )
    return _source_map(item)


@operation("source.map.list", api="SourceFileManager.getSourceMapEntries/getSourceMapEntryIterator")
def source_map_list(call: Call, address=None, path=None, min_line=None, max_line=None):
    lower = 0 if min_line is None else min_line
    upper = 2147483647 if max_line is None else max_line
    if not 0 <= lower <= upper <= 2147483647:
        raise ValueError("Invalid source line range")
    manager = call.program.getSourceFileManager()
    if address is not None:
        items = manager.getSourceMapEntries(resolve_address(call, address))
    elif path is not None:
        items = (
            entry
            for source in _source_files(call, path)
            for entry in manager.getSourceMapEntries(source, lower, upper)
        )
    else:
        items = manager.getSourceMapEntryIterator(call.program.getMinAddress(), True)
    if path is not None:
        from ghidra.program.database.sourcemap import SourceFile

        path = str(SourceFile(path).getPath())
    return page(
        (
            _source_map(item)
            for item in items
            if lower <= int(item.getLineNumber()) <= upper
            and (path is None or str(item.getSourceFile().getPath()) == path)
        ),
        limit=MAX_RESULTS,
        key="mappings",
    )


@operation("source.map.remove", kind="write", api="SourceFileManager.removeSourceMapEntry")
def source_map_remove(call: Call, path, line_number, base_address):
    manager = call.program.getSourceFileManager()
    addr = resolve_address(call, base_address)
    count = 0
    for source in _source_files(call, path):
        for item in manager.getSourceMapEntries(source, line_number):
            if item.getBaseAddress() == addr:
                count += bool(manager.removeSourceMapEntry(item))
    return {"removed": count}


def _relocation(item):
    data = item.getBytes()
    values = item.getValues()
    return {
        "address": str(item.getAddress()),
        "status": str(item.getStatus().name()),
        "type": int(item.getType()),
        "values": None if values is None else [int(v) for v in values],
        "byte_length": int(item.getLength()),
        "bytes_hex": None if data is None else _bytes(data).hex(),
        "symbol_name": None if item.getSymbolName() is None else str(item.getSymbolName()),
    }


@operation(
    "relocation.add",
    kind="write",
    api="RelocationTable.add(Address, Relocation.Status, int, long[], byte[]/int, String)",
)
def relocation_add(
    call: Call, address, status="APPLIED", type=0, values=None, byte_length=0, symbol_name=None
):
    import jpype
    from ghidra.program.model.reloc import Relocation

    state = Relocation.Status.valueOf(status.upper())
    if not 0 <= byte_length <= 8:
        raise ValueError("byte_length must be between 0 and 8")
    if byte_length and not state.hasBytes():
        raise ValueError(f"Status {status} does not retain affected bytes; byte_length must be 0")
    if values is not None and len(values) > MAX_RESULTS:
        raise ValueError("Too many relocation values")
    payload = None if values is None else jpype.JArray(jpype.JLong)(values)
    addr = resolve_address(call, address)
    table = call.program.getRelocationTable()
    # An explicit empty byte array preserves zero instead of Ghidra's default word size.
    length_or_bytes = jpype.JInt(byte_length) if byte_length else _jbytes(b"")
    item = table.add(addr, state, type, payload, length_or_bytes, symbol_name)
    if item is None:
        raise RuntimeError("Ghidra could not add relocation")
    return _relocation(item)


@operation("relocation.list", api="RelocationTable.getRelocations(AddressSetView)")
def relocation_list(call: Call, start=None, end=None):
    return page(
        (
            _relocation(item)
            for item in call.program.getRelocationTable().getRelocations(_bounds(call, start, end))
        ),
        limit=MAX_RESULTS,
        key="relocations",
    )


def _register(call, name):
    reg = call.program.getProgramContext().getRegister(name)
    if reg is None:
        raise ValueError(f"Unknown register: {name}")
    return reg


@operation("context.get", api="ProgramContext.getValue(Register, Address, boolean)")
def context_get(call: Call, register, address, signed=False):
    reg = _register(call, register)
    addr = resolve_address(call, address)
    value = call.program.getProgramContext().getValue(reg, addr, signed)
    return {
        "register": str(reg.getName()),
        "address": str(addr),
        "signed": signed,
        "value": None if value is None else int(str(value)),
        "bit_length": int(reg.getBitLength()),
    }


@operation("context.set", kind="write", api="ProgramContext.setValue/remove")
def context_set(call: Call, register, start, end=None, length=None, value=None, clear=False):
    from java.math import BigInteger

    reg = _register(call, register)
    region = address_range(call, start, end, length)
    context = call.program.getProgramContext()
    first, last = region.getMinAddress(), region.getMaxAddress()
    if clear:
        if value is not None:
            raise ValueError("value cannot be combined with clear")
        context.remove(first, last, reg)
    else:
        if value is None:
            raise ValueError("value is required unless clear=true")
        number = _integer(value)
        bits = int(reg.getBitLength())
        if not -(1 << (bits - 1)) <= number < (1 << bits):
            raise ValueError(f"value does not fit {bits}-bit register")
        context.setValue(reg, first, last, BigInteger(str(number)))
    return {
        "register": register,
        "start": str(first),
        "end": str(last),
        "cleared": clear,
        "value": context_get(call, register, first)["value"],
    }


@operation("context.ranges", api="ProgramContext.getRegisterValueAddressRanges/getValue")
def context_ranges(call: Call, register, start=None, end=None):
    reg = _register(call, register)
    context = call.program.getProgramContext()
    region = _bounds(call, start, end)
    items = context.getRegisterValueAddressRanges(
        reg, region.getMinAddress(), region.getMaxAddress()
    )
    return page(
        (
            {
                "start": str(item.getMinAddress()),
                "end": str(item.getMaxAddress()),
                "value": context_get(call, register, item.getMinAddress())["value"],
            }
            for item in items
        ),
        limit=MAX_RESULTS,
        key="ranges",
    )


def _equate(item, address=None, operand_index=None):
    refs = item.getReferences() if address is None else item.getReferences(address)
    result = page(
        (
            {
                "address": str(ref.getAddress()),
                "operand_index": int(ref.getOpIndex()),
                "dynamic_hash": int(ref.getDynamicHashValue()),
            }
            for ref in refs
            if operand_index is None or int(ref.getOpIndex()) == operand_index
        ),
        limit=MAX_RESULTS,
        key="references",
    )
    return {"name": str(item.getName()), "value": int(item.getValue()), **result}


def _operand(call, addr, index):
    unit = call.program.getListing().getCodeUnitAt(addr)
    if unit is None or index < 0 or index >= int(unit.getNumOperands()):
        raise ValueError("operand_index must identify an existing code-unit operand")


@operation(
    "equate.create", kind="write", api="EquateTable.createEquate/getEquate; Equate.addReference"
)
def equate_create(call: Call, address, name, value, operand_index=0):
    addr = resolve_address(call, address)
    _operand(call, addr, operand_index)
    number = _integer(value)
    if not -(1 << 63) <= number < (1 << 64):
        raise ValueError("Equate value must fit 64 bits")
    if number >= 1 << 63:
        number -= 1 << 64
    table = call.program.getEquateTable()
    item = table.getEquate(name)
    if item is not None and int(item.getValue()) != number:
        raise ValueError("An equate with this name already has a different value")
    if item is None:
        item = table.createEquate(_text(name, "name"), number)
    import jpype

    item.addReference(addr, jpype.JInt(operand_index))
    return _equate(item, addr, operand_index)


@operation("equate.list", api="EquateTable.getEquates/getEquate; Equate.getReferences")
def equate_list(call: Call, name=None, address=None, operand_index=None, offset=0, limit=100):
    table = call.program.getEquateTable()
    addr = None if address is None else resolve_address(call, address)
    if operand_index is not None and operand_index < 0:
        raise ValueError("operand_index must be nonnegative")
    if name is not None:
        item = table.getEquate(name)
        items = () if item is None else (item,)
    elif addr is not None:
        items = (
            table.getEquates(addr)
            if operand_index is None
            else table.getEquates(addr, operand_index)
        )
    else:
        items = table.getEquates()

    def rows():
        for item in items:
            row = _equate(item, addr, operand_index)
            if (addr is None and operand_index is None) or row["references"]:
                yield row

    return page(rows(), offset, limit, key="equates")


@operation("equate.delete", kind="write", api="EquateTable.removeEquate; Equate.removeReference")
def equate_delete(call: Call, name, address=None, operand_index=None):
    table = call.program.getEquateTable()
    item = table.getEquate(name)
    if operand_index is not None and operand_index < 0:
        raise ValueError("operand_index must be nonnegative")
    if item is None:
        return {"removed": 0}
    if address is None and operand_index is None:
        return {"removed": int(bool(table.removeEquate(name)))}
    addr = None if address is None else resolve_address(call, address)
    refs = item.getReferences() if addr is None else item.getReferences(addr)
    count = 0
    import jpype

    for ref in refs:
        if operand_index is None or int(ref.getOpIndex()) == operand_index:
            item.removeReference(ref.getAddress(), jpype.JInt(ref.getOpIndex()))
            count += 1
    return {"removed": count}


@operation(
    "equate.clear_range",
    kind="write",
    api="EquateTable.deleteAddressRange(Address, Address, TaskMonitor)",
)
def equate_clear_range(call: Call, start, end=None, length=None):
    region = address_range(call, start, end, length)
    call.program.getEquateTable().deleteAddressRange(
        region.getMinAddress(), region.getMaxAddress(), call.monitor
    )
    return {
        "cleared": True,
        "start": str(region.getMinAddress()),
        "end": str(region.getMaxAddress()),
    }


def _assembler(call):
    from ghidra.app.plugin.assembler import Assemblers

    return Assemblers.getAssembler(call.program)


def _instruction(item):
    return {
        "address": str(item.getAddress()),
        "mnemonic": str(item.getMnemonicString()),
        "instruction": str(item),
        "length": int(item.getLength()),
        "bytes_hex": _bytes(item.getBytes()).hex(),
    }


def _patch(call, addr, payload, assembler):
    if not payload or len(payload) > MAX_BYTES:
        raise ValueError("Patch must contain between 1 and 1048576 bytes")
    before = read_bytes(call, addr, len(payload))
    items = assembler.patchProgram(_jbytes(payload), addr)
    result = page((_instruction(item) for item in items), limit=MAX_RESULTS, key="instructions")
    return {
        "address": str(addr),
        "byte_length": len(payload),
        "before_hex": before.hex(),
        "after_hex": read_bytes(call, addr, len(payload)).hex(),
        **result,
    }


@operation(
    "patch.assemble",
    kind="write",
    api="Assemblers.getAssembler; Assembler.assembleLine/patchProgram",
    timeout=120.0,
)
def patch_assemble(call: Call, address, assembly):
    _text(assembly, "assembly")
    lines = [line.strip() for line in assembly.splitlines() if line.strip()]
    if not 1 <= len(lines) <= MAX_RESULTS:
        raise ValueError("assembly must contain between 1 and 1000 instruction lines")
    addr = resolve_address(call, address)
    assembler = _assembler(call)
    payload = bytearray()
    for line in lines:
        payload.extend(_bytes(assembler.assembleLine(addr.addNoWrap(len(payload)), line)))
        if len(payload) > MAX_BYTES:
            raise ValueError("Assembled patch exceeds payload bound")
    return _patch(call, addr, payload, assembler)


@operation(
    "patch.nop",
    kind="write",
    api="Assembler.assembleLine/patchProgram; Instruction.getLength",
    timeout=120.0,
)
def patch_nop(call: Call, address, count=1):
    if not 1 <= count <= MAX_RESULTS:
        raise ValueError("count must be between 1 and 1000 instructions")
    addr = resolve_address(call, address)
    listing = call.program.getListing()
    cursor = addr
    for _ in range(count):
        item = listing.getInstructionAt(cursor)
        if item is None:
            raise ValueError(f"No instruction at {cursor}")
        cursor = cursor.addNoWrap(item.getLength())
    length = int(cursor.subtract(addr))
    if length > MAX_BYTES:
        raise ValueError("NOP patch exceeds payload bound")
    assembler = _assembler(call)
    nop = "NOP" if str(call.program.getLanguage().getProcessor()).upper() == "X86" else "nop"
    payload = bytearray()
    while len(payload) < length:
        encoded = _bytes(assembler.assembleLine(addr.addNoWrap(len(payload)), nop))
        if not encoded or len(payload) + len(encoded) > length:
            raise ValueError("Target NOP encoding cannot exactly cover the selected instructions")
        payload.extend(encoded)
    return _patch(call, addr, payload, assembler)


_X86_INVERSE = {
    "JO": "JNO",
    "JNO": "JO",
    "JB": "JNC",
    "JC": "JNC",
    "JNAE": "JAE",
    "JAE": "JB",
    "JNB": "JB",
    "JNC": "JC",
    "JZ": "JNZ",
    "JE": "JNE",
    "JNZ": "JZ",
    "JNE": "JE",
    "JBE": "JA",
    "JNA": "JA",
    "JA": "JBE",
    "JNBE": "JBE",
    "JS": "JNS",
    "JNS": "JS",
    "JP": "JNP",
    "JPE": "JPO",
    "JNP": "JP",
    "JPO": "JPE",
    "JL": "JGE",
    "JNGE": "JGE",
    "JGE": "JL",
    "JNL": "JL",
    "JLE": "JG",
    "JNG": "JG",
    "JG": "JLE",
    "JNLE": "JLE",
}
_ARM_CONDITIONS = {
    "EQ": "NE",
    "NE": "EQ",
    "CS": "CC",
    "HS": "LO",
    "CC": "CS",
    "LO": "HS",
    "MI": "PL",
    "PL": "MI",
    "VS": "VC",
    "VC": "VS",
    "HI": "LS",
    "LS": "HI",
    "GE": "LT",
    "LT": "GE",
    "GT": "LE",
    "LE": "GT",
}


def _inverse_mnemonic(processor, mnemonic):
    upper = mnemonic.upper()
    if processor == "x86":
        return _X86_INVERSE.get(upper)
    if processor in ("ARM", "AARCH64"):
        if upper in ("CBZ", "CBNZ", "TBZ", "TBNZ"):
            return {"CBZ": "CBNZ", "CBNZ": "CBZ", "TBZ": "TBNZ", "TBNZ": "TBZ"}[upper]
        match = re.fullmatch(r"B\.?([A-Z]{2})(\.[NW])?", upper)
        if match and match[1] in _ARM_CONDITIONS:
            separator = "." if "." in upper[:2] else ""
            return "B" + separator + _ARM_CONDITIONS[match[1]] + (match[2] or "")
    return None


def _branch_assembly(item, inverse, target):
    operands = [
        str(item.getDefaultOperandRepresentation(index)) for index in range(item.getNumOperands())
    ]
    # Use the direct-flow address, not a symbol rendering or relocation placeholder.
    offset = int(target.getUnsignedOffset()) & ((1 << int(target.getAddressSpace().getSize())) - 1)
    operands[-1] = f"0x{offset:x}"
    if str(item.getMnemonicString())[0].islower():
        inverse = inverse.lower()
    return inverse + " " + ", ".join(operands)


def _resolved_branch_encoding(assembler, addr, assembly, length):
    context = assembler.getContextAt(addr)
    for candidate in assembler.resolveLine(addr, assembly):
        if candidate.isError() or candidate.hasBackfills():
            continue
        if candidate.getContext().combine(context) is None:
            continue
        if candidate.checkNotForbidden().isError():
            continue
        if int(candidate.getInstructionLength()) != length:
            continue
        concrete = next(iter(candidate.getInstruction().possibleVals()), None)
        if concrete is not None:
            return _bytes(concrete)
    raise ValueError("Inverse encoding cannot preserve the instruction footprint")


def _branch_encoding(assembler, addr, assembly, length):
    encoded = _bytes(assembler.assembleLine(addr, assembly))
    if len(encoded) == length:
        return encoded
    # x86 assemblers can prefer a short encoding for an existing near branch.
    return _resolved_branch_encoding(assembler, addr, assembly, length)


def _x86_branch_predicate(payload):
    # Jcc predicates are the low opcode nibble, independent of prefixes/displacement.
    for index, opcode in enumerate(payload):
        if opcode in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67):
            continue
        if 0x70 <= opcode <= 0x7F:
            return opcode & 15
        if opcode == 0x0F and index + 1 < len(payload) and 0x80 <= payload[index + 1] <= 0x8F:
            return payload[index + 1] & 15
        break
    raise ValueError("Unsupported x86 conditional branch encoding")


def _arm_branch_predicate(processor, mnemonic):
    upper = mnemonic.upper()
    if upper in ("CBZ", "CBNZ", "TBZ", "TBNZ"):
        return ("compare" if upper.startswith("CB") else "test", int("NZ" in upper))
    match = re.fullmatch(r"B\.?([A-Z]{2})(\.[NW])?", upper)
    conditions = (
        "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE",
    )
    if match:
        condition = {"HS": "CS", "LO": "CC"}.get(match[1], match[1])
        if condition in conditions:
            return (processor, conditions.index(condition))
    raise ValueError("Unsupported ARM conditional branch predicate")


def _branch_predicate(processor, mnemonic, payload):
    if processor == "X86":
        return ("x86", _x86_branch_predicate(payload))
    return _arm_branch_predicate(processor, mnemonic)


def _assert_inverse_branch(processor, before, changed, flows):
    if (
        changed is None
        or not changed.getFlowType().isConditional()
        or not changed.getFlowType().isJump()
        or list(changed.getFlows()) != list(flows)
        or int(changed.getLength()) != before["length"]
    ):
        raise RuntimeError("Assembled inverse did not preserve conditional branch target/footprint")
    original = _branch_predicate(processor, before["mnemonic"], bytes.fromhex(before["bytes_hex"]))
    patched = _branch_predicate(
        processor, str(changed.getMnemonicString()), _bytes(changed.getBytes())
    )
    if patched != (original[0], original[1] ^ 1):
        raise RuntimeError("Assembled branch did not invert the original predicate")


@operation(
    "patch.branch_invert",
    kind="write",
    api="Instruction.getFlowType/getFlows; Assembler.assembleLine/patchProgram",
    timeout=120.0,
)
def patch_branch_invert(call: Call, address):
    addr = resolve_address(call, address)
    item = call.program.getListing().getInstructionAt(addr)
    if item is None or not item.getFlowType().isConditional() or not item.getFlowType().isJump():
        raise ValueError("address must identify a conditional branch instruction")
    processor = str(call.program.getLanguage().getProcessor()).upper()
    inverse = _inverse_mnemonic(
        "x86" if processor == "X86" else processor, str(item.getMnemonicString())
    )
    if inverse is None:
        raise ValueError(
            f"Conditional branch inversion is unsupported for {processor} "
            f"{item.getMnemonicString()}"
        )
    before = _instruction(item)
    flows = item.getFlows()
    if len(flows) != 1:
        raise ValueError("Conditional branch must have one direct target")
    assembly = _branch_assembly(item, inverse, flows[0])
    assembler = _assembler(call)
    encoded = _branch_encoding(assembler, addr, assembly, before["length"])
    result = _patch(call, addr, encoded, assembler)
    changed = call.program.getListing().getInstructionAt(addr)
    _assert_inverse_branch(processor, before, changed, flows)
    return {**result, "original_instruction": before, "assembly": assembly}
