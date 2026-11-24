"""Real-Ghidra annotation coverage with rollback and saved-project persistence.

The shared driver supplies a writable analyzed advanced_fixture program. The
scratch dictionary may override address (initialized 64-byte scratch),
function_start, branch_address, and register. Temporary annotations and patches
are rolled back. Check the committed persistence_probe with
smoke_annotations_reopen after saving, closing, and reopening the project.
"""

from __future__ import annotations

import uuid

from agenticghidra_mcp.advanced import annotations as operations
from agenticghidra_mcp.advanced.core import Call, address, function, read_bytes


def _conditional_branch(call, fn, options):
    listing = call.program.getListing()
    if options.get("branch_address") is not None:
        branch = listing.getInstructionAt(address(call, options["branch_address"]))
        if branch is None:
            raise ValueError("branch_address must identify an instruction")
        return branch
    processor = str(call.program.getLanguage().getProcessor()).upper()
    for item in listing.getInstructions(fn.getBody(), True):
        if (
            item.getFlowType().isConditional()
            and item.getFlowType().isJump()
            and operations._inverse_mnemonic(
                "x86" if processor == "X86" else processor, str(item.getMnemonicString())
            )
        ):
            return item
    raise ValueError(
        "Annotation smoke requires a supported conditional branch in advanced_add"
    )


def _persistent_annotations(invoke, prefix, second):
    key = prefix + ".persistent"
    value = {"nested": [1, True, None, {"unicode": "persistent é"}], "revision": 2}
    path = "/advanced_mcp_smoke/" + prefix + "_persistent.c"
    invoke("metadata.store", key=key, value=value)
    stable_file = invoke("source.file.add", path=path, id_type="SHA256", identifier_hex="12" * 32)
    assert stable_file["identifier_hex"] == "12" * 32
    stable_map = invoke("source.map.add", path=path, line_number=21, base_address=second, length=2)
    assert stable_map["length"] == 2
    assert invoke("metadata.query", key=key)["metadata"] == [{"key": key, "value": value}]
    return {
        "key": key,
        "value": value,
        "source_path": path,
        "identifier_hex": "12" * 32,
        "base_address": second,
    }


def _smoke_comments(invoke, expect_error, loc, fn_address, prefix):
    for kind in operations._COMMENT_TYPES:
        text = prefix + " MixedCase " + kind
        changed = invoke("comment.set", address=loc, comment_type=kind, comment=text)
        assert changed["comment"] == text
        assert invoke("comment.get", address=loc, comment_type=kind)["comment"] == text
    all_comments = invoke("comment.get_all", address=loc, include_function=False)
    assert "function" not in all_comments and len(all_comments["comments"]) == 5
    with_function = invoke("comment.get_all", address=fn_address, include_function=True)
    assert with_function["function"] is not None
    comments = invoke(
        "comment.list", start=loc, end=loc, query="mixedcase", case_sensitive=False, limit=2
    )
    assert len(comments["comments"]) == 2 and comments["has_more"]
    assert not invoke(
        "comment.list", start=loc, end=loc, query="mixedcase", case_sensitive=True
    )["comments"]
    assert len(invoke(
        "comment.list", start=loc, end=loc, comment_type="pre", query=prefix
    )["comments"]) == 1
    assert len(invoke(
        "comment.list", start=loc, end=loc, query=prefix, offset=2, limit=2
    )["comments"]) == 2
    for kind in operations._COMMENT_TYPES:
        text = prefix + " function " + kind
        invoke(
            "comment.set", function_start=fn_address, scope="function", comment_type=kind,
            comment=text,
        )
        assert invoke(
            "comment.get", function_start=fn_address, scope="function", comment_type=kind
        )["comment"] == text
    invoke(
        "comment.set", address=fn_address, function_start=fn_address, scope="decompiler",
        comment_type="pre", comment=prefix,
    )
    assert invoke(
        "comment.get", address=fn_address, scope="decompiler", comment_type="pre"
    )["comment"] == prefix
    invoke("comment.set", address=loc, comment_type="eol", comment="")
    assert invoke("comment.get", address=loc, comment_type="eol")["comment"] is None
    expect_error("comment.set", address=loc, comment_type="invalid", comment=prefix)


def _smoke_bookmarks(invoke, loc, second, prefix):
    created = invoke(
        "bookmark.add", address=loc, category=prefix, comment="first", bookmark_type="NOTE"
    )
    updated = invoke(
        "bookmark.add", address=loc, category=prefix, comment="updated", bookmark_type="NOTE"
    )
    assert created["id"] == updated["id"] and updated["comment"] == "updated"
    invoke(
        "bookmark.add", address=loc, category=prefix + "_second", comment="second",
        bookmark_type="WARNING",
    )
    assert any(
        row["category"] == prefix
        for row in invoke("bookmark.list", address=loc, bookmark_type="NOTE")["bookmarks"]
    )
    assert invoke(
        "bookmark.remove", address=loc, bookmark_type="NOTE", category=prefix
    )["removed"] == 1
    invoke("bookmark.clear", start=loc, length=1, bookmark_type="WARNING")
    assert not any(
        row["category"].startswith(prefix)
        for row in invoke("bookmark.list", address=loc)["bookmarks"]
    )
    invoke("bookmark.add", address=second, category=prefix, comment="clear all")
    invoke("bookmark.clear", start=second, end=second)
    assert not invoke("bookmark.list", address=second)["bookmarks"]


def _smoke_tags(invoke, fn_address, prefix):
    invoke("tag.add", function_start=fn_address, name=prefix, comment="tag description")
    updated = invoke("tag.add", function_start=fn_address, name=prefix, comment="changed")
    assert updated["comment"] == "changed" and updated["function_count"] == 1
    assert any(
        row["name"] == prefix for row in invoke("tag.list", function_start=fn_address)["tags"]
    )
    assert any(row["name"] == prefix for row in invoke("tag.list")["tags"])
    assert any(
        row["name"] == prefix and row["function_count"] == 1
        for row in invoke("tag.stats")["tags"]
    )
    assert invoke("tag.remove", function_start=fn_address, name=prefix)["removed"]
    assert not any(
        row["name"] == prefix for row in invoke("tag.list", function_start=fn_address)["tags"]
    )


def _smoke_metadata_sources(invoke, loc, location, prefix, key):
    invoke("metadata.store", key=prefix + ".a", value=["first"])
    invoke("metadata.store", key=prefix + ".b", value={"second": 2})
    metadata = invoke("metadata.query", prefix=prefix, offset=1, limit=1)
    assert len(metadata["metadata"]) == 1 and metadata["has_more"]
    assert not invoke("metadata.query", key=key, prefix="does_not_match")["metadata"]
    path = "/advanced_mcp_smoke/" + prefix + ".c"
    item = invoke("source.file.add", path=path, id_type="MD5", identifier_hex="ab" * 16)
    assert item["id_type"] == "MD5" and item["identifier_hex"] == "ab" * 16
    assert any(row["path"] == path for row in invoke("source.file.list")["files"])
    invoke("source.map.add", path=path, line_number=7, base_address=loc, length=4)
    invoke("source.map.add", path=path, line_number=8, base_address=loc, length=4)
    by_address = invoke(
        "source.map.list", address=str(location.add(2)), path=path, min_line=7, max_line=7,
    )
    assert len(by_address["mappings"]) == 1 and by_address["mappings"][0]["line_number"] == 7
    assert len(invoke("source.map.list", path=path, min_line=7, max_line=8)["mappings"]) == 2
    assert any(row["path"] == path for row in invoke("source.map.list")["mappings"])
    assert invoke("source.map.remove", path=path, line_number=7, base_address=loc)["removed"] == 1
    assert not invoke("source.map.list", path=path, min_line=7, max_line=7)["mappings"]
    assert invoke("source.file.remove", path=path)["removed"] == 1
    assert not invoke("source.map.list", path=path)["mappings"]


def _smoke_relocations(invoke, loc, second, prefix):
    zero = invoke(
        "relocation.add", address=loc, status="APPLIED", type=23, values=[-1, 4],
        byte_length=0, symbol_name=prefix,
    )
    assert zero["byte_length"] == 0 and zero["values"] == [-1, 4]
    exact = invoke(
        "relocation.add", address=second, status="APPLIED_OTHER", type=24, values=[],
        byte_length=2, symbol_name=prefix,
    )
    assert exact["byte_length"] == 2 and len(exact["bytes_hex"]) == 4
    for status in (
        "UNKNOWN", "SKIPPED", "UNSUPPORTED", "FAILURE", "PARTIAL", "APPLIED", "APPLIED_OTHER",
    ):
        result = invoke("relocation.add", address=loc, status=status, byte_length=0)
        assert result["status"] == status and result["byte_length"] == 0
    assert any(
        row["symbol_name"] == prefix
        for row in invoke("relocation.list", start=loc, end=second)["relocations"]
    )


def _smoke_context(invoke, program, register, loc, location):
    reg = program.getProgramContext().getRegister(register)
    bits = int(reg.getBitLength())
    invoke("context.set", register=register, start=loc, length=4, value=-1)
    assert invoke("context.get", register=register, address=loc, signed=True)["value"] == -1
    unsigned = invoke("context.get", register=register, address=loc, signed=False)
    assert unsigned["value"] == (1 << bits) - 1
    assert any(
        row["value"] == (1 << bits) - 1
        for row in invoke(
            "context.ranges", register=register, start=loc, end=str(location.add(3))
        )["ranges"]
    )
    invoke("context.set", register=register, start=loc, end=str(location.add(3)), clear=True)
    assert program.getProgramContext().getNonDefaultValue(reg, location) is None


def _smoke_patches_equates(invoke, expect_error, program, loc, location, prefix):
    # Assemble target-native instructions in initialized writable scratch data.
    processor = str(program.getLanguage().getProcessor()).upper()
    moves = {"X86": "MOV EAX,0x2a", "AARCH64": "mov x0,#0x2a", "ARM": "mov r0,#0x2a"}
    assembled = invoke("patch.assemble", address=loc, assembly=moves[processor])
    assert assembled["after_hex"] != assembled["before_hex"]
    assert assembled["instructions"] and "mov" in assembled["instructions"][0]["mnemonic"].lower()
    instruction = program.getListing().getInstructionAt(location)
    scalar_index = next(
        index for index in range(instruction.getNumOperands())
        if instruction.getScalar(index) is not None
    )
    equate = invoke(
        "equate.create", address=loc, name=prefix, value="0x2a", operand_index=scalar_index
    )
    assert equate["value"] == 42
    assert invoke(
        "equate.list", name=prefix, address=loc, operand_index=scalar_index
    )["equates"][0]["references"]
    assert invoke(
        "equate.delete", name=prefix, address=loc, operand_index=scalar_index
    )["removed"] == 1
    invoke("equate.create", address=loc, name=prefix, value=42, operand_index=scalar_index)
    invoke("equate.clear_range", start=loc, length=instruction.getLength())
    assert not invoke("equate.list", address=loc, operand_index=scalar_index)["equates"]
    invoke("equate.delete", name=prefix)
    assert not invoke("equate.list", name=prefix)["equates"]
    nopped = invoke("patch.nop", address=loc, count=1)
    assert nopped["after_hex"] != assembled["after_hex"]
    assert all(row["mnemonic"].lower() == "nop" for row in nopped["instructions"])
    expect_error("patch.branch_invert", address=loc)


def _smoke_branch_inverse(invoke, call, branch):
    branch_address = str(branch.getAddress())
    before = read_bytes(call, branch_address, branch.getLength())
    original_mnemonic = str(branch.getMnemonicString())
    original_target = [str(target) for target in branch.getFlows()]
    processor = str(call.program.getLanguage().getProcessor()).upper()
    original_predicate = operations._branch_predicate(processor, original_mnemonic, before)
    inverted = invoke("patch.branch_invert", address=branch_address)
    changed = call.program.getListing().getInstructionAt(address(call, branch_address))
    after = read_bytes(call, branch_address, changed.getLength())
    assert inverted["before_hex"] == before.hex() and inverted["after_hex"] == after.hex()
    assert after != before and str(changed.getMnemonicString()) != original_mnemonic
    assert operations._branch_predicate(processor, str(changed.getMnemonicString()), after) == (
        original_predicate[0], original_predicate[1] ^ 1
    )
    assert [str(target) for target in changed.getFlows()] == original_target
    assert changed.getFlowType().isConditional() and changed.getLength() == len(before)
    restored = invoke("patch.branch_invert", address=branch_address)
    assert restored["after_hex"] == before.hex()
    return {
        "address": branch_address,
        "mnemonic": original_mnemonic,
        "before_hex": before.hex(),
        "inverse_hex": after.hex(),
        "restored_hex": restored["after_hex"],
        "target": original_target,
        "predicate_inverted": True,
    }


def smoke_annotations(runtime, owner, session_id, scratch):
    session = runtime.registry.resolve(session_id, owner)
    program = session.info.program
    options = scratch if isinstance(scratch, dict) else {}
    handlers = {
        value.__operation__.name: value.__operation__
        for value in vars(operations).values()
        if callable(value) and hasattr(value, "__operation__")
    }
    exercised = set()

    def invoke(operation_name, **arguments):
        result = runtime.invoke(
            handlers[operation_name], {"session_id": session_id, **arguments}, owner
        )
        exercised.add(operation_name)
        return result

    def expect_error(operation_name, **arguments):
        try:
            invoke(operation_name, **arguments)
        except (ValueError, RuntimeError):
            return
        raise AssertionError(f"{operation_name} accepted invalid input")

    call = Call(runtime, session.context, owner, session, runtime.monitor())
    fn = function(call, options.get("function_start", "advanced_add"))
    fn_address = str(fn.getEntryPoint())
    location = address(call, options.get("address", "advanced_scratch"))
    loc = str(location)
    second = str(location.addNoWrap(8))
    branch = _conditional_branch(call, fn, options)
    register = options.get("register") or str(program.getCompilerSpec().getStackPointer().getName())
    prefix = "advanced_annotations_" + uuid.uuid4().hex
    # Commit outside the rollback transaction to prove real saved-project persistence.
    probe = _persistent_annotations(invoke, prefix, second)
    with runtime.program_lock(program):
        runtime.begin(session, owner, "Advanced annotations smoke rollback")
    try:
        _smoke_comments(invoke, expect_error, loc, fn_address, prefix)
        _smoke_bookmarks(invoke, loc, second, prefix)
        _smoke_tags(invoke, fn_address, prefix)
        _smoke_metadata_sources(invoke, loc, location, prefix, probe["key"])
        _smoke_relocations(invoke, loc, second, prefix)
        _smoke_context(invoke, program, register, loc, location)
        _smoke_patches_equates(invoke, expect_error, program, loc, location, prefix)
        branch_probe = _smoke_branch_inverse(invoke, call, branch)
    finally:
        with runtime.program_lock(program):
            runtime.finish(session, owner, False)
    assert exercised == set(handlers), sorted(set(handlers) - exercised)
    probe_bytes = read_bytes(
        call, branch_probe["address"], len(bytes.fromhex(branch_probe["before_hex"]))
    )
    assert probe_bytes.hex() == branch_probe["before_hex"]
    return {
        "operations": sorted(exercised),
        "operation_count": len(exercised),
        "rolled_back": True,
        "branch_probe": branch_probe,
        "persistence_probe": probe,
    }


def smoke_annotations_reopen(runtime, owner, session_id, probe):
    """Assert committed metadata and SourceFileManager records after a real reopen."""

    def invoke(handler, **arguments):
        return runtime.invoke(handler.__operation__, {"session_id": session_id, **arguments}, owner)

    assert invoke(operations.metadata_query, key=probe["key"])["metadata"] == [
        {"key": probe["key"], "value": probe["value"]}
    ]
    files = invoke(operations.source_file_list)["files"]
    assert any(
        item["path"] == probe["source_path"] and item["identifier_hex"] == probe["identifier_hex"]
        for item in files
    )
    maps = invoke(operations.source_map_list, path=probe["source_path"], min_line=21, max_line=21)[
        "mappings"
    ]
    assert (
        len(maps) == 1
        and maps[0]["base_address"] == probe["base_address"]
        and maps[0]["length"] == 2
    )
    return {"metadata_survives_reopen": True, "source_state_survives_reopen": True}
