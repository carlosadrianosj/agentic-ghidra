"""Program data types and layouts, using the public Ghidra data model."""

from __future__ import annotations

import re

from .core import Call, address as resolve_address, datatype, operation, page


def _manager(call):
    return call.program.getDataTypeManager()


def _category(path):
    from ghidra.program.model.data import CategoryPath

    if not path or not path.startswith("/"):
        raise ValueError("Category path must be absolute")
    return CategoryPath(path)


def _resolve(call, path=None, name=None, expected=None):
    manager = _manager(call)
    if path is not None:
        if not path.startswith("/"):
            raise ValueError("Data type path must be absolute")
        item = (
            manager.getDataType(_category(path), name)
            if name is not None
            else manager.getDataType(path)
        )
        if item is None:
            raise ValueError(f"Data type not found: {path} {name or ''}")
    elif name is not None:
        matches = [item for item in manager.getAllDataTypes() if str(item.getName()) == name]
        if len(matches) != 1:
            raise ValueError(
                f"Expected one data type named {name!r}; found {len(matches)}; use an absolute path"
            )
        item = matches[0]
    else:
        raise ValueError("Specify a data type path or name")
    if expected is not None and not isinstance(item, expected):
        raise ValueError(f"Data type {item.getPathName()} is not a {expected.__name__}")
    return item


def _field_type(call, value):
    if not value or not value.strip():
        raise ValueError("A data type is required")
    text = value.strip()
    if text.startswith("/") and not any(character in text for character in "*[]"):
        return _resolve(call, path=text)
    # Reject ambiguous named bases before DataTypeParser can pick an arbitrary category.
    base = re.sub(r"(?:\s*\*|\s*\[[^]]*\])+$", "", text).strip()
    if not base.startswith("/"):
        matches = [item for item in _manager(call).getAllDataTypes() if str(item.getName()) == base]
        if len(matches) > 1:
            raise ValueError(f"Ambiguous data type {base!r}; use an absolute path")
    result = datatype(call, text)
    if result is None:
        raise ValueError(f"Data type not found: {text}")
    return result


def _length(item, length):
    from ghidra.program.model.data import Dynamic, FactoryDataType

    if isinstance(item, FactoryDataType):
        raise ValueError("Factory data types cannot be used as fields")
    actual = int(item.getLength())
    if length is not None and not 1 <= length <= 0x7FFFFFFF:
        raise ValueError("length must be a positive 32-bit integer")
    if isinstance(item, Dynamic):
        if not item.canSpecifyLength() or length is None:
            raise ValueError("This dynamic data type requires an explicit supported length")
        return length
    if actual <= 0:
        raise ValueError("Data type must have a positive fixed length")
    if length is not None and length != actual:
        raise ValueError(f"Fixed data type length is {actual}, not {length}")
    return actual


def _uid(value):
    return None if value is None else int(value.getValue())


def _component(item):
    data_type = item.getDataType()
    result = {
        "ordinal": int(item.getOrdinal()),
        "offset": int(item.getOffset()),
        "length": int(item.getLength()),
        "field_name": str(item.getFieldName() or item.getDefaultFieldName()),
        "explicit_name": None if item.getFieldName() is None else str(item.getFieldName()),
        "data_type": str(data_type.getPathName()),
        "comment": str(item.getComment() or ""),
        "bitfield": bool(item.isBitFieldComponent()),
    }
    if item.isBitFieldComponent():
        result.update(
            bit_offset=int(data_type.getBitOffset()),
            bit_size=int(data_type.getBitSize()),
            base_data_type=str(data_type.getBaseDataType().getPathName()),
        )
    return result


def _describe(call, item, details=True):
    from ghidra.program.model.data import Composite, Enum, Structure

    result = {
        "name": str(item.getName()),
        "path": str(item.getPathName()),
        "category": str(item.getCategoryPath()),
        "length": int(item.getLength()),
        "description": str(item.getDescription() or ""),
        "data_type_id": int(_manager(call).getID(item)),
        "universal_id": _uid(item.getUniversalID()),
        "kind": str(item.getClass().getSimpleName()),
        "source_archive_id": _uid(item.getSourceArchive().getSourceArchiveID())
        if item.getSourceArchive()
        else None,
    }
    if details and isinstance(item, Composite):
        components = (
            item.getDefinedComponents() if isinstance(item, Structure) else item.getComponents()
        )
        result.update(
            page((_component(component) for component in components), key="components", limit=1000)
        )
        result["component_count"] = int(item.getNumComponents())
        result["packing_enabled"] = bool(item.isPackingEnabled())
    if details and isinstance(item, Enum):
        result["members"] = [
            {
                "name": str(name),
                "value": int(item.getValue(name)),
                "comment": str(item.getComment(name) or ""),
            }
            for name in item.getNames()[:1000]
        ]
        result["member_count"] = int(item.getCount())
    return result


def _new(call, item):
    from ghidra.program.model.data import DataTypeConflictHandler

    manager = _manager(call)
    if manager.getDataType(item.getCategoryPath(), item.getName()) is not None:
        raise ValueError(f"Data type already exists: {item.getPathName()}")
    return manager.addDataType(item, DataTypeConflictHandler.DEFAULT_HANDLER)


def _structure(call, path, name):
    from ghidra.program.model.data import Structure

    return _resolve(call, path, name, Structure)


def _select_component(composite, offset=None, ordinal=None, field_name=None):
    if sum(value is not None for value in (offset, ordinal, field_name)) != 1:
        raise ValueError("Specify exactly one component offset, ordinal, or field name")
    if ordinal is not None:
        if not 0 <= ordinal < composite.getNumComponents():
            raise ValueError("Component ordinal is outside the layout")
        return composite.getComponent(ordinal)
    candidates = list(composite.getDefinedComponents())
    if offset is not None:
        if offset < 0:
            raise ValueError("Component offset must be nonnegative")
        candidates = [
            item for item in composite.getComponentsContaining(offset) if item.getOffset() == offset
        ]
    else:
        candidates = [
            item
            for item in candidates
            if str(item.getFieldName() or item.getDefaultFieldName()) == field_name
        ]
    if len(candidates) != 1:
        raise ValueError(
            f"Expected one component; found {len(candidates)}; "
            "use its ordinal for shared bitfield offsets"
        )
    return candidates[0]


@operation("type.get", api="DataTypeManager.getDataType/getAllDataTypes")
def type_get(call: Call, path=None, name=None):
    return _describe(call, _resolve(call, path, name))


@operation("type.list", api="DataTypeManager.getAllDataTypes")
def type_list(call: Call, offset=0, limit=100, query=None):
    return page(
        (
            _describe(call, item, False)
            for item in _manager(call).getAllDataTypes()
            if query is None or query.casefold() in str(item.getPathName()).casefold()
        ),
        offset,
        limit,
        key="types",
    )


@operation("type.get_by_id", api="DataTypeManager.getDataType/getSourceArchive/findDataTypeForID")
def type_get_by_id(call: Call, data_type_id=None, universal_id=None, source_archive_id=None):
    import jpype
    from ghidra.util import UniversalID

    manager = _manager(call)
    if (data_type_id is None) == (universal_id is None):
        raise ValueError("Specify exactly one data_type_id or universal_id")
    if data_type_id is not None:
        if source_archive_id is not None:
            raise ValueError("source_archive_id requires universal_id")
        item = manager.getDataType(jpype.JLong(data_type_id))
    elif source_archive_id is not None:
        archive = manager.getSourceArchive(UniversalID(jpype.JLong(source_archive_id)))
        if archive is None:
            raise ValueError("Source archive not found")
        item = manager.getDataType(archive, UniversalID(jpype.JLong(universal_id)))
    else:
        matches = [
            candidate
            for candidate in manager.getAllDataTypes()
            if _uid(candidate.getUniversalID()) == universal_id
        ]
        if len(matches) != 1:
            raise ValueError(
                f"Expected one universal ID match; found {len(matches)}; specify source_archive_id"
            )
        item = matches[0]
    if item is None:
        raise ValueError("Data type ID not found")
    return _describe(call, item)


def _parse(call, declaration, name, category):
    from ghidra.app.util.cparser.C import CParser

    if not declaration.strip():
        raise ValueError("C declaration cannot be empty")
    target_category = _category(category)
    parser = CParser(_manager(call))
    parser.setMonitor(call.monitor)
    item = parser.parse(declaration)
    if not parser.didParseSucceed() or item is None:
        raise ValueError(f"C declaration did not produce a data type: {parser.getParseMessages()}")
    if name is not None:
        if not name.strip():
            raise ValueError("Data type name cannot be empty")
        item.setName(name)
    item.setCategoryPath(target_category)
    item = _manager(call).resolve(item, None)
    result = _describe(call, item)
    result["parse_messages"] = str(parser.getParseMessages() or "")
    return result


@operation("type.parse_c", kind="write", api="CParser.parse; DataTypeManager.resolve")
def type_parse_c(call: Call, declaration, name=None, category="/"):
    return _parse(call, declaration, name, category)


@operation("type.define_c", kind="write", api="CParser.parse; DataTypeManager.resolve")
def type_define_c(call: Call, declaration, name=None, category="/"):
    return _parse(call, declaration, name, category)


@operation("type.rename", kind="write", api="DataType.setName")
def type_rename(call: Call, new_name, path=None, name=None):
    item = _resolve(call, path, name)
    item.setName(new_name)
    return _describe(call, item)


@operation("type.delete", kind="write", api="DataTypeManager.remove")
def type_delete(call: Call, path=None, name=None):
    item = _resolve(call, path, name)
    previous = _describe(call, item, False)
    if not _manager(call).remove(item, call.monitor):
        raise ValueError("Data type could not be deleted")
    return {"deleted": True, "type": previous}


@operation("type.category.create", kind="write", api="DataTypeManager.createCategory")
def category_create(call: Call, path):
    item = _manager(call).createCategory(_category(path))
    return {"path": str(item.getCategoryPath()), "id": int(item.getID())}


@operation("type.category.list", api="DataTypeManager.getCategory; Category.getCategories")
def category_list(call: Call, path="/", recursive=False):
    root = _manager(call).getCategory(_category(path))
    if root is None:
        raise ValueError(f"Category not found: {path}")
    rows, pending = [], list(root.getCategories())
    while pending:
        item = pending.pop(0)
        rows.append(
            {
                "path": str(item.getCategoryPath()),
                "id": int(item.getID()),
                "data_type_count": len(item.getDataTypes()),
            }
        )
        if recursive:
            pending.extend(item.getCategories())
    return {"path": path, "recursive": recursive, "categories": rows}


def _archives(call):
    from ghidra.program.model.data import DataTypeManager

    manager = _manager(call)
    archives = [
        manager.getLocalSourceArchive(),
        manager.getSourceArchive(DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID),
        *manager.getSourceArchives(),
    ]
    unique = {
        int(item.getSourceArchiveID().getValue()): item for item in archives if item is not None
    }
    return {
        "manager": str(manager.getName()),
        "archives": [
            {
                "id": identity,
                "name": str(item.getName()),
                "archive_type": str(item.getArchiveType()),
                "domain_file_id": None
                if item.getDomainFileID() is None
                else str(item.getDomainFileID()),
                "last_sync_time": int(item.getLastSyncTime()),
                "dirty": bool(item.isDirty()),
            }
            for identity, item in unique.items()
        ],
    }


@operation(
    "type.archives.list",
    api="DataTypeManager.getLocalSourceArchive/getSourceArchives; SourceArchive",
)
def archives_list(call: Call):
    return _archives(call)


@operation("type.source_archives.list", api="DataTypeManager.getSourceArchives; SourceArchive")
def source_archives_list(call: Call):
    return _archives(call)


@operation("type.apply_at", kind="write", api="Listing.clearCodeUnits/createData")
def type_apply_at(call: Call, address, data_type, length=None, clear_existing=True):
    from ghidra.program.model.data import DataUtilities

    item = _field_type(call, data_type)
    size = _length(item, length)
    start = resolve_address(call, address)
    end = start.addNoWrap(size - 1)
    if not call.program.getMemory().contains(start, end):
        raise ValueError("Applied data type must fit entirely within program memory")
    listing = call.program.getListing()
    if clear_existing:
        listing.clearCodeUnits(start, end, False)
    elif not DataUtilities.isUndefinedRange(call.program, start, end):
        raise ValueError("Existing code or defined data overlaps the requested range")
    created = listing.createData(start, item, size)
    return {
        "address": str(created.getAddress()),
        "length": int(created.getLength()),
        "data_type": str(created.getDataType().getPathName()),
    }


@operation(
    "layout.struct.create", kind="write", api="StructureDataType; DataTypeManager.addDataType"
)
def struct_create(call: Call, name, category="/", length=0):
    from ghidra.program.model.data import StructureDataType

    if not 0 <= length <= 0x7FFFFFFF:
        raise ValueError("Structure length must be a nonnegative 32-bit integer")
    return _describe(
        call, _new(call, StructureDataType(_category(category), name, length, _manager(call)))
    )


@operation("layout.struct.get", api="DataTypeManager.getDataType; Structure.getDefinedComponents")
def struct_get(call: Call, struct_path=None, struct_name=None):
    return _describe(call, _structure(call, struct_path, struct_name))


@operation("layout.struct.field.add", kind="write", api="Structure.add/insertAtOffset")
def struct_field_add(
    call: Call,
    data_type,
    struct_path=None,
    struct_name=None,
    field_name=None,
    offset=None,
    length=None,
    comment=None,
):
    item = _structure(call, struct_path, struct_name)
    data = _field_type(call, data_type)
    size = _length(data, length)
    if offset is None:
        component = item.add(data, size, field_name, comment)
    else:
        if not 0 <= offset <= item.getLength():
            raise ValueError("Insertion offset must be within the structure or its end")
        component = item.insertAtOffset(offset, data, size, field_name, comment)
    return {
        "path": str(item.getPathName()),
        "length": int(item.getLength()),
        "component": _component(component),
    }


@operation("layout.struct.field.replace", kind="write", api="Structure.replaceAtOffset")
def struct_field_replace(
    call: Call,
    offset,
    data_type,
    struct_path=None,
    struct_name=None,
    length=None,
    field_name=None,
    comment=None,
):
    item = _structure(call, struct_path, struct_name)
    previous = _select_component(item, offset=offset)
    if previous.isBitFieldComponent():
        raise ValueError(
            "Replacing a bitfield storage unit is ambiguous; clear the storage offset first"
        )
    data = _field_type(call, data_type)
    size = _length(data, length)
    if not item.isPackingEnabled():
        end = offset + size
        for other in item.getDefinedComponents():
            if (
                other.getOrdinal() != previous.getOrdinal()
                and other.getLength() > 0
                and other.getOffset() < end
                and other.getEndOffset() >= offset
            ):
                raise ValueError("Replacement would overlap another defined component")
    component = item.replaceAtOffset(
        offset,
        data,
        size,
        previous.getFieldName() if field_name is None else field_name,
        previous.getComment() if comment is None else comment,
    )
    return {
        "path": str(item.getPathName()),
        "length": int(item.getLength()),
        "component": _component(component),
    }


@operation("layout.struct.field.clear", kind="write", api="Structure.clearAtOffset")
def struct_field_clear(call: Call, offset, struct_path=None, struct_name=None):
    item = _structure(call, struct_path, struct_name)
    if not 0 <= offset < item.getLength():
        raise ValueError("Clear offset must be within the structure")
    previous = [_component(component) for component in item.getComponentsContaining(offset)]
    item.clearAtOffset(offset)
    return {"path": str(item.getPathName()), "cleared": previous, "length": int(item.getLength())}


@operation("layout.struct.field.rename", kind="write", api="DataTypeComponent.setFieldName")
def struct_field_rename(
    call: Call,
    new_name,
    struct_path=None,
    struct_name=None,
    old_name=None,
    offset=None,
    ordinal=None,
):
    item = _structure(call, struct_path, struct_name)
    component = _select_component(item, offset, ordinal, old_name)
    component.setFieldName(new_name)
    return _component(component)


@operation("layout.struct.field.comment.set", kind="write", api="DataTypeComponent.setComment")
def struct_field_comment(
    call: Call,
    comment,
    struct_path=None,
    struct_name=None,
    offset=None,
    ordinal=None,
    field_name=None,
):
    item = _structure(call, struct_path, struct_name)
    component = _select_component(item, offset, ordinal, field_name)
    component.setComment(comment)
    return _component(component)


@operation("layout.struct.resize", kind="write", api="Structure.setLength")
def struct_resize(call: Call, length, struct_path=None, struct_name=None):
    item = _structure(call, struct_path, struct_name)
    if not 0 <= length <= 0x7FFFFFFF:
        raise ValueError("Structure length must be a nonnegative 32-bit integer")
    if item.isPackingEnabled():
        raise ValueError("Explicit structure length requires packing disabled")
    for component in item.getDefinedComponents():
        if component.getOffset() + component.getLength() > length:
            raise ValueError("Resize would truncate a defined component; clear it first")
    item.setLength(length)
    return _describe(call, item)


@operation(
    "layout.struct.bitfield.add", kind="write", api="Structure.insertBitFieldAt; BitFieldDataType"
)
def struct_bitfield_add(
    call: Call,
    byte_offset,
    byte_width,
    bit_offset,
    data_type,
    bit_size,
    struct_path=None,
    struct_name=None,
    field_name=None,
    comment=None,
):
    from ghidra.program.model.data import BitFieldDataType

    item = _structure(call, struct_path, struct_name)
    if item.isPackingEnabled():
        raise ValueError("Precise bitfield offsets require packing disabled")
    if (
        byte_offset < 0
        or byte_width < 1
        or bit_offset < 0
        or bit_size < 0
        or bit_offset + bit_size > byte_width * 8
    ):
        raise ValueError("Bitfield must fit its nonnegative storage unit")
    base = _field_type(call, data_type)
    if bit_size > base.getLength() * 8:
        raise ValueError("Bitfield size exceeds the base data type width")
    BitFieldDataType.checkBaseDataType(base)
    component = item.insertBitFieldAt(
        byte_offset, byte_width, bit_offset, base, bit_size, field_name, comment
    )
    return {
        "path": str(item.getPathName()),
        "length": int(item.getLength()),
        "component": _component(component),
    }


@operation(
    "layout.struct.fill_from_decompiler",
    kind="write",
    analysis=True,
    api="FillOutStructureHelper.processStructure(HighVariable,Function,boolean,boolean,DecompInterface)",
)
def struct_fill_from_decompiler(
    call: Call,
    function_start,
    name,
    ordinal=None,
    storage=None,
    create_new_structure=True,
    create_class_if_needed=False,
    timeout_secs=30,
):
    import math
    import time

    from ghidra.app.decompiler.util import FillOutStructureHelper
    from ghidra.util.task import TimeoutTaskMonitor
    from java.util.concurrent import TimeUnit

    from .decompiler import decompiled_selection

    if timeout_secs < 1:
        raise ValueError("timeout_secs must be positive")
    deadline = time.monotonic() + timeout_secs
    with decompiled_selection(call, function_start, name, ordinal, storage, timeout_secs) as (
        decompiler,
        result,
        symbol,
    ):
        high = symbol.getHighVariable()
        if high is None:
            raise ValueError(
                "Selected symbol has no HighVariable; decompiler analysis is incomplete"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Structure inference timed out during decompilation")
        timed_monitor = TimeoutTaskMonitor.timeoutIn(
            max(1, math.ceil(remaining * 1000)), TimeUnit.MILLISECONDS, call.monitor
        )
        try:
            helper = FillOutStructureHelper(call.program, timed_monitor)
            item = helper.processStructure(
                high,
                result.getHighFunction().getFunction(),
                create_new_structure,
                create_class_if_needed,
                decompiler,
            )
            timed_monitor.checkCancelled()
        except Exception as exc:
            if timed_monitor.didTimeout():
                raise TimeoutError(f"Structure inference exceeded {timeout_secs} seconds") from exc
            raise
        finally:
            timed_monitor.finished()
        if item is None:
            raise ValueError("Decompiler found no structure accesses for the selected variable")
        item = _manager(call).resolve(item, None)
        described = _describe(call, item)
        described.update(
            selected_name=str(symbol.getName()),
            load_count=len(helper.getLoadPcodeOps()),
            store_count=len(helper.getStorePcodeOps()),
        )
        return described


@operation("layout.enum.create", kind="write", api="EnumDataType; DataTypeManager.addDataType")
def enum_create(call: Call, name, category="/", size=4):
    from ghidra.program.model.data import EnumDataType

    if not 1 <= size <= 8:
        raise ValueError("Enum size must be between 1 and 8 bytes")
    return _describe(
        call, _new(call, EnumDataType(_category(category), name, size, _manager(call)))
    )


def _enum(call, path, name):
    from ghidra.program.model.data import Enum

    return _resolve(call, path, name, Enum)


@operation("layout.enum.member.add", kind="write", api="Enum.add")
def enum_member_add(call: Call, name, value, enum_path=None, enum_name=None, comment=None):
    import jpype

    item = _enum(call, enum_path, enum_name)
    number = int(value, 0) if isinstance(value, str) else int(value)
    if not -(1 << 63) <= number < (1 << 64):
        raise ValueError("Enum value must fit 64 bits")
    if number >= (1 << 63):
        number -= 1 << 64
    item.add(name, jpype.JLong(number), comment)
    return _describe(call, item)


@operation("layout.enum.member.remove", kind="write", api="Enum.contains/remove")
def enum_member_remove(call: Call, name, enum_path=None, enum_name=None):
    item = _enum(call, enum_path, enum_name)
    if not item.contains(name):
        raise ValueError(f"Enum member not found: {name}")
    item.remove(name)
    return _describe(call, item)


@operation("layout.union.create", kind="write", api="UnionDataType; DataTypeManager.addDataType")
def union_create(call: Call, name, category="/"):
    from ghidra.program.model.data import UnionDataType

    return _describe(call, _new(call, UnionDataType(_category(category), name, _manager(call))))


def _union(call, path, name):
    from ghidra.program.model.data import Union

    return _resolve(call, path, name, Union)


@operation("layout.union.member.add", kind="write", api="Union.add")
def union_member_add(
    call: Call,
    data_type,
    union_path=None,
    union_name=None,
    field_name=None,
    length=None,
    comment=None,
):
    item = _union(call, union_path, union_name)
    data = _field_type(call, data_type)
    component = item.add(data, _length(data, length), field_name, comment)
    return {
        "path": str(item.getPathName()),
        "length": int(item.getLength()),
        "component": _component(component),
    }


@operation("layout.union.member.remove", kind="write", api="Union.delete")
def union_member_remove(
    call: Call, union_path=None, union_name=None, ordinal=None, field_name=None
):
    item = _union(call, union_path, union_name)
    component = _select_component(item, ordinal=ordinal, field_name=field_name)
    previous = _component(component)
    item.delete(component.getOrdinal())
    return {"path": str(item.getPathName()), "removed": previous, "length": int(item.getLength())}


@operation("layout.inspect.components", api="Composite.getDefinedComponents/getComponents")
def inspect_components(call: Call, path=None, name=None):
    from ghidra.program.model.data import Composite

    return _describe(call, _resolve(call, path, name, Composite))
