"""Real-Ghidra type/layout behavior driver; invoked by the integration harness.

The scratch mapping supplies an initialized ``address`` with at least 64 writable
bytes, and ``fill_function``/``fill_variable`` identifying a decompiler variable
that accesses a pointed structure. Optional ``fill_ordinal`` and ``fill_storage``
exercise disambiguation of the selected HighSymbol. No operation is mocked.
"""

from __future__ import annotations

import uuid


def smoke_types(runtime, owner, session_id, scratch):
    from java.lang import Object

    from pyghidra_mcp.advanced.registry import build_operations

    operations = build_operations()
    exercised = set()

    def invoke(operation_name, **arguments):
        result = runtime.invoke(
            operations[operation_name], {"session_id": session_id, **arguments}, owner
        )
        exercised.add(operation_name)
        return result

    def rejects(operation_name, **arguments):
        try:
            invoke(operation_name, **arguments)
        except (ValueError, RuntimeError):
            return
        raise AssertionError(f"{operation_name} accepted invalid or ambiguous input")

    token = uuid.uuid4().hex[:12]
    category = f"/advanced_types_{token}"
    structure = f"{category}/Record"
    enum = f"{category}/Mode"
    union = f"{category}/Choice"
    invoke("type.category.create", path=category + "/nested")
    assert any(item["path"] == category for item in invoke("type.category.list")["categories"])
    assert any(
        item["path"] == category + "/nested"
        for item in invoke("type.category.list", path=category, recursive=True)["categories"]
    )
    invoke("layout.struct.create", name="Record", category=category, length=16)
    assert invoke("layout.struct.get", struct_path=structure)["length"] == 16

    first = invoke(
        "layout.struct.field.add",
        struct_path=structure,
        data_type="int",
        field_name="counter",
        offset=0,
        comment="retained",
    )
    assert first["component"]["offset"] == 0
    second = invoke(
        "layout.struct.field.add",
        struct_path=structure,
        data_type="int *",
        field_name="pointer",
        offset=4,
        comment="pointer offset, not ordinal",
    )
    assert second["component"]["offset"] == 4
    assert second["component"]["ordinal"] != second["component"]["offset"]
    renamed = invoke(
        "layout.struct.field.rename", struct_path=structure, old_name="counter", new_name="count"
    )
    assert renamed["comment"] == "retained"
    commented = invoke(
        "layout.struct.field.comment.set",
        struct_path=structure,
        ordinal=second["component"]["ordinal"],
        comment="pointer comment",
    )
    assert commented["offset"] == 4 and commented["comment"] == "pointer comment"
    replacement = invoke(
        "layout.struct.field.replace", struct_path=structure, offset=0, data_type="uint"
    )
    assert replacement["component"]["field_name"] == "count"
    assert replacement["component"]["comment"] == "retained"
    rejects("layout.struct.field.replace", struct_path=structure, offset=0, data_type="longlong")
    assert (
        invoke("layout.struct.field.clear", struct_path=structure, offset=4)["cleared"][0][
            "comment"
        ]
        == "pointer comment"
    )
    invoke("layout.struct.resize", struct_path=structure, length=32)
    assert invoke("layout.struct.get", struct_path=structure)["length"] == 32
    rejects("layout.struct.resize", struct_path=structure, length=2)
    bitfield = invoke(
        "layout.struct.bitfield.add",
        struct_path=structure,
        byte_offset=8,
        byte_width=4,
        bit_offset=0,
        data_type="uint",
        bit_size=3,
        field_name="flags",
        comment="bit comment",
    )
    assert bitfield["component"]["bitfield"] and bitfield["component"]["bit_size"] == 3
    rejects(
        "layout.struct.bitfield.add",
        struct_path=structure,
        byte_offset=8,
        byte_width=1,
        bit_offset=7,
        data_type="uint",
        bit_size=3,
    )
    components = invoke("layout.inspect.components", path=structure)["components"]
    assert any(
        item["field_name"] == "flags" and item["comment"] == "bit comment" for item in components
    )

    parsed = invoke(
        "type.parse_c", declaration=f"typedef unsigned int Parsed_{token};", category=category
    )
    assert parsed["path"].startswith(category + "/")
    defined = invoke(
        "type.define_c",
        declaration=f"struct Decl_{token} {{ int item; short tag; }};",
        name="Declared",
        category=category,
    )
    assert len(defined["components"]) == 2
    description = invoke("type.get", path=structure)
    assert invoke("type.get_by_id", data_type_id=description["data_type_id"])["path"] == structure
    assert (
        invoke(
            "type.get_by_id",
            universal_id=description["universal_id"],
            source_archive_id=description["source_archive_id"],
        )["path"]
        == structure
    )
    assert invoke("type.get_by_id", universal_id=description["universal_id"])["path"] == structure
    assert any(item["path"] == structure for item in invoke("type.list", query=category)["types"])
    assert invoke("type.archives.list")["archives"]
    assert invoke("type.source_archives.list")["archives"]
    renamed_path = category + "/DeclaredRenamed"
    assert (
        invoke("type.rename", path=defined["path"], new_name="DeclaredRenamed")["path"]
        == renamed_path
    )
    assert invoke("type.delete", path=renamed_path)["deleted"]
    rejects("type.get", path=renamed_path)

    # Identical short names in different categories must not select an arbitrary type.
    invoke("layout.struct.create", name="Record", category=category + "/nested")
    rejects("type.get", name="Record")

    invoke("layout.enum.create", name="Mode", category=category, size=2)
    members = invoke(
        "layout.enum.member.add",
        enum_path=enum,
        name="ACTIVE",
        value="0x1234",
        comment="enum comment",
    )["members"]
    assert members == [{"name": "ACTIVE", "value": 0x1234, "comment": "enum comment"}]
    assert invoke("layout.enum.member.remove", enum_path=enum, name="ACTIVE")["member_count"] == 0
    invoke("layout.enum.member.add", enum_path=enum, name="PERSISTED", value=7)
    invoke("layout.union.create", name="Choice", category=category)
    rejects("layout.union.member.add", union_path=union, data_type="Record")
    member = invoke(
        "layout.union.member.add",
        union_path=union,
        data_type="int",
        field_name="number",
        comment="union comment",
    )
    assert member["component"]["offset"] == 0 and member["length"] == 4
    invoke("layout.union.member.add", union_path=union, data_type="short", field_name="small")
    removed = invoke(
        "layout.union.member.remove", union_path=union, ordinal=member["component"]["ordinal"]
    )
    assert removed["removed"]["comment"] == "union comment"
    assert invoke("type.get", path=union)["components"][0]["field_name"] == "small"
    invoke("layout.union.member.remove", union_path=union, field_name="small")

    applied = invoke(
        "type.apply_at", address=scratch["address"], data_type=structure, clear_existing=True
    )
    assert applied["length"] == 32 and applied["data_type"] == structure
    rejects("type.apply_at", address=scratch["address"], data_type="int", clear_existing=False)

    # Shared-runtime history must undo and redo real manager mutations.
    invoke("type.rename", path=structure, new_name="RecordHistory")
    invoke("transaction.undo")
    assert invoke("type.get", path=structure)["path"] == structure
    invoke("transaction.redo")
    assert invoke("type.get", path=category + "/RecordHistory")["name"] == "RecordHistory"
    invoke("type.rename", path=category + "/RecordHistory", new_name="Record")
    invoke("transaction.begin", description="type smoke rollback")
    invoke("layout.enum.member.add", enum_path=enum, name="ROLLED_BACK", value=8)
    invoke("transaction.revert")
    assert all(item["name"] != "ROLLED_BACK" for item in invoke("type.get", path=enum)["members"])

    filled = invoke(
        "layout.struct.fill_from_decompiler",
        function_start=scratch["fill_function"],
        name=scratch["fill_variable"],
        ordinal=scratch.get("fill_ordinal", 0),
        storage=scratch.get("fill_storage"),
        create_new_structure=True,
    )
    assert filled["components"] and filled["load_count"] + filled["store_count"] > 0
    assert invoke("type.get", path=filled["path"])["length"] == filled["length"]
    rejects(
        "layout.struct.fill_from_decompiler",
        function_start=scratch["fill_function"],
        name=scratch["fill_variable"],
        ordinal=-1,
    )
    extended = invoke(
        "layout.struct.fill_from_decompiler",
        function_start=scratch["fill_function"],
        name=scratch["fill_variable"],
        ordinal=scratch.get("fill_ordinal", 0),
        storage=scratch.get("fill_storage"),
        create_new_structure=False,
    )
    assert extended["components"] and extended["load_count"] + extended["store_count"] > 0

    invoke("program.save")
    session = runtime.registry.resolve(session_id, owner)
    consumer = Object()
    persisted = session.info.program.getDomainFile().getReadOnlyDomainObject(
        consumer, -1, runtime.monitor()
    )
    try:
        saved = persisted.getDataTypeManager().getDataType(structure)
        assert saved is not None and saved.getLength() == 32
        assert any(
            str(item.getFieldName()) == "flags" and str(item.getComment()) == "bit comment"
            for item in saved.getDefinedComponents()
        )
        saved_enum = persisted.getDataTypeManager().getDataType(enum)
        assert saved_enum.getValue("PERSISTED") == 7
        assert (
            persisted.getListing()
            .getDataAt(persisted.getAddressFactory().getAddress(applied["address"]))
            .getLength()
            == 32
        )
    finally:
        persisted.release(consumer)
    return {
        "operations": sorted(name for name in exercised if name.startswith(("type.", "layout."))),
        "category": category,
        "filled_structure": filled["path"],
        "persistence": True,
        "undo_redo": True,
    }
