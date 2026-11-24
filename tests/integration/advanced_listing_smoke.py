"""Real-Ghidra coverage for listing, memory, and instruction-level searches."""

from __future__ import annotations

import base64

from agenticghidra_mcp.advanced import listing_memory
from agenticghidra_mcp.advanced.core import operation


def _scratch_base(program, scratch):
    factory = program.getAddressFactory()
    candidate = scratch.get("address") if isinstance(scratch, dict) else scratch
    base = (
        factory.getAddress(hex(candidate) if isinstance(candidate, int) else str(candidate))
        if candidate is not None
        else None
    )
    if base is not None:
        alignment = int(program.getLanguage().getInstructionAlignment())
        base = base.addNoWrap(-int(base.getUnsignedOffset()) % alignment)
    if base is None or program.getMemory().contains(base):
        space = factory.getDefaultAddressSpace()
        highest = max(
            int(block.getEnd().getUnsignedOffset())
            for block in program.getMemory().getBlocks()
            if block.getStart().getAddressSpace() == space
        )
        base = space.getAddress((highest + 0x1FFF) & ~0xFFF)
    return base


def _scalar_operand(instruction):
    from ghidra.program.model.scalar import Scalar

    for operand in range(instruction.getNumOperands()):
        for obj in instruction.getOpObjects(operand):
            if isinstance(obj, Scalar):
                return instruction, int(obj.getUnsignedValue())
    return None


def _fixture_instructions(program):
    fixture_function = fixture_instruction = fixture_pcode = fixture_scalar = None
    for target in program.getFunctionManager().getFunctions(True):
        for instruction in program.getListing().getInstructions(target.getBody(), True):
            if fixture_instruction is None:
                fixture_function, fixture_instruction = target, instruction
            if fixture_pcode is None and len(instruction.getPcode()):
                fixture_pcode = (target, instruction, instruction.getPcode()[0])
            if fixture_scalar is None:
                fixture_scalar = _scalar_operand(instruction)
            if (
                fixture_instruction is not None
                and fixture_pcode is not None
                and fixture_scalar is not None
            ):
                return fixture_function, fixture_instruction, fixture_pcode, fixture_scalar
    raise ValueError(
        "Fixture requires analyzed instructions, interpreted P-code, and a scalar operand"
    )


def _listing_operations(name, base):
    """Build the private smoke write/read handlers bound to one scratch base."""
    annotation_register = [None]
    context_baseline = [None]

    @operation(
        "smoke.listing.annotations",
        kind="write",
        api=(
            "Listing.setComment; SymbolTable.createLabel; "
            "ReferenceManager.addMemoryReference; BookmarkManager.setBookmark"
        ),
    )
    def annotations(call):
        from ghidra.program.model.listing import CodeUnit
        from ghidra.program.model.symbol import RefType, SourceType

        location = base.addNoWrap(512)
        call.program.getListing().setComment(
            location, CodeUnit.EOL_COMMENT, "selective clear comment"
        )
        call.program.getSymbolTable().createLabel(
            location, name + "_label", SourceType.USER_DEFINED
        )
        for index, source in enumerate(
            (SourceType.USER_DEFINED, SourceType.ANALYSIS, SourceType.IMPORTED, SourceType.DEFAULT)
        ):
            call.program.getReferenceManager().addMemoryReference(
                location, base.addNoWrap(640 + index), RefType.DATA, source, index
            )
        call.program.getBookmarkManager().setBookmark(
            location, "Note", "advanced smoke", "selective clear bookmark"
        )
        from java.math import BigInteger
        from jpype import JInt

        properties = call.program.getUsrPropertyManager()
        properties.createIntPropertyMap(name + "_property").add(location, JInt(42))
        call.program.getEquateTable().createEquate(name + "_equate", 42).addReference(location, 0)
        context = call.program.getProgramContext()
        register = next(reg for reg in context.getRegisters() if not reg.isProcessorContext())
        context.setValue(register, location, location, BigInteger("42"))
        annotation_register[0] = register
        context_register = context.getBaseContextRegister()
        if context_register is not None:
            baseline = context.getValue(context_register, location, False)
            context_baseline[0] = str(baseline)
            changed = (0 if baseline is None else int(str(baseline))) ^ 1
            context.setValue(context_register, location, location, BigInteger(str(changed)))
        return {}

    @operation("smoke.listing.function", kind="write", api="FunctionManager.createFunction")
    def fixture_function_create(call):
        from ghidra.program.model.address import AddressSet
        from ghidra.program.model.symbol import SourceType

        location = base.addNoWrap(512)
        call.program.getFunctionManager().createFunction(
            name + "_function", location, AddressSet(location, location), SourceType.USER_DEFINED
        )
        return {}

    @operation(
        "smoke.listing.state",
        api=(
            "Listing.getComment; SymbolTable.getSymbols; "
            "ReferenceManager.getReferencesFrom; BookmarkManager.getBookmarks"
        ),
    )
    def state(call):
        return _annotation_state(call, name, base, annotation_register[0])

    @operation(
        "smoke.listing.cleanup",
        kind="write",
        api="PropertyMapManager.removePropertyMap; EquateTable.removeEquate",
    )
    def cleanup(call):
        call.program.getUsrPropertyManager().removePropertyMap(name + "_property")
        call.program.getEquateTable().removeEquate(name + "_equate")
        return {}

    return annotations, fixture_function_create, state, cleanup, context_baseline


def _annotation_state(call, name, base, annotation_register):
    from ghidra.program.model.listing import CodeUnit

    location = base.addNoWrap(512)
    properties = call.program.getUsrPropertyManager().getIntPropertyMap(name + "_property")
    context = call.program.getProgramContext()
    context_register = context.getBaseContextRegister()
    return {
        "comment": call.program.getListing().getComment(CodeUnit.EOL_COMMENT, location),
        "labels": [
            str(symbol.getName())
            for symbol in call.program.getSymbolTable().getSymbols(location)
        ],
        "references": sorted(
            str(ref.getSource())
            for ref in call.program.getReferenceManager().getReferencesFrom(location)
        ),
        "bookmarks": len(call.program.getBookmarkManager().getBookmarks(location)),
        "property": properties is not None and bool(properties.hasProperty(location)),
        "equates": len(call.program.getEquateTable().getEquates(location)),
        "function": call.program.getFunctionManager().getFunctionAt(location) is not None,
        "register": str(context.getValue(annotation_register, location, False)),
        "context": str(context.getValue(context_register, location, False))
        if context_register is not None
        else None,
    }


def smoke_listing(runtime, owner, session_id, scratch):
    """Exercise all 25 operations in a writable, analyzed native-code session.

    ``scratch`` may provide an unmapped address directly or as ``{"address": ...}``.
    A filesystem scratch path is also accepted; the block is then placed after
    the highest mapped address in the default address space. No fixture bytes
    are modified, and temporary blocks are removed in a finally clause.
    """
    operations = {
        value.__operation__.name: value.__operation__
        for value in vars(listing_memory).values()
        if hasattr(value, "__operation__")
    }
    exercised = set()

    def invoke(operation_name, **arguments):
        result = runtime.invoke(
            operations[operation_name], {"session_id": session_id, **arguments}, owner
        )
        exercised.add(operation_name)
        return result

    session = runtime.registry.resolve(session_id, owner)
    program = session.info.program
    base = _scratch_base(program, scratch)

    def at(offset):
        return str(base.addNoWrap(offset))

    name = "advanced_listing_smoke_" + str(base).replace(":", "_")
    created = []

    fixture_function, fixture_instruction, fixture_pcode, fixture_scalar = _fixture_instructions(
        program
    )

    annotations, fixture_function_create, state, cleanup, context_baseline = _listing_operations(
        name, base
    )

    def private(handler):
        return runtime.invoke(handler.__operation__, {"session_id": session_id}, owner)


    def selective_clear_checks():
        invoke("listing.data.create", address=at(512), data_type="byte", clear_existing=True)
        private(annotations)
        before = private(state)
        assert before["references"] == ["ANALYSIS", "DEFAULT", "IMPORTED", "USER_DEFINED"]
        invoke("listing.clear", start=at(512), length=1)
        after = private(state)
        assert after == before, {"before": before, "after": after}
        assert not invoke("listing.data.at", address=at(512))["data"]["defined"]
        private(fixture_function_create)
        before = private(state)
        assert before["function"]
        invoke(
            "listing.clear",
            start=at(512),
            end=at(512),
            clear_comments=True,
            clear_analysis_references=True,
            clear_bookmarks=True,
        )
        partial = private(state)
        assert partial["comment"] is None and partial["bookmarks"] == 0
        assert partial["labels"] == before["labels"]
        assert partial["references"] == ["DEFAULT", "IMPORTED", "USER_DEFINED"]
        invoke("listing.clear", start=at(512), length=1, clear_context=True)
        context_cleared = private(state)
        assert context_cleared["register"] == before["register"]
        if context_cleared["context"] is not None:
            assert context_cleared["context"] == context_baseline[0]
        invoke(
            "listing.clear",
            start=at(512),
            length=1,
            clear_symbols=True,
            clear_user_references=True,
            clear_import_references=True,
            clear_default_references=True,
            clear_properties=True,
            clear_functions=True,
            clear_registers=True,
            clear_equates=True,
            clear_context=True,
        )
        cleared = private(state)
        assert cleared["references"] == [] and not cleared["labels"]
        assert not cleared["property"] and not cleared["equates"] and not cleared["function"]
        assert cleared["register"] == "None"

    def instruction_search_checks():
        assert invoke("search.resolve", query=at(96))["address"] == at(96)
        address = str(fixture_instruction.getAddress())
        function_address = str(fixture_function.getEntryPoint())
        assert invoke("listing.disassemble.function", address=function_address, limit=1)[
            "instructions"
        ]
        assert (
            invoke(
                "listing.disassemble.range",
                start=address,
                length=int(fixture_instruction.getLength()),
            )["instructions"][0]["address"]
            == address
        )
        mnemonic = str(fixture_instruction.getMnemonicString())
        assert invoke(
            "search.instructions",
            query=mnemonic.lower(),
            function_start=function_address,
            start=address,
            end=str(fixture_instruction.getMaxAddress()),
            limit=1,
        )["matches"]
        ptarget, pinstruction, pop = fixture_pcode
        assert invoke(
            "search.pcode",
            query=str(pop.getMnemonic()).lower(),
            function_start=str(ptarget.getEntryPoint()),
            start=str(pinstruction.getAddress()),
            end=str(pinstruction.getMaxAddress()),
            limit=1,
        )["matches"]
        sinstruction, scalar = fixture_scalar
        assert invoke(
            "search.constants",
            value=hex(scalar),
            start=str(sinstruction.getAddress()),
            end=str(sinstruction.getMaxAddress()),
            limit=1,
        )["matches"]
        code = invoke("memory.read", address=address, length=int(fixture_instruction.getLength()))[
            "data_hex"
        ]
        invoke("memory.write", address=at(256), data_hex=code)
        seeded = invoke("listing.disassemble.seed", address=at(256), limit=1, clear_existing=True)
        assert seeded["instructions"] and seeded["instructions"][0]["address"] == at(256)
        unit = invoke("listing.code_unit.at", address=at(256))["code_unit"]
        assert unit["kind"] == "instruction"

    def search_and_navigation_checks(payload):
        assert invoke("search.bytes", pattern_hex="11223344", start=at(96), end=at(99))[
            "matches"
        ][0]["address"] == at(96)
        assert not invoke("search.bytes", pattern_hex="11223344", start=at(96), end=at(98))[
            "matches"
        ]
        assert not invoke("search.bytes", pattern_hex="00", start=at(8192), end=at(8223))[
            "matches"
        ]
        byte_page = invoke(
            "search.bytes",
            pattern_base64=base64.b64encode(b"Alpha").decode(),
            start=at(0),
            end=at(len(payload) - 1),
            limit=1,
        )
        assert byte_page["has_more"] and len(byte_page["matches"]) == 1
        insensitive = invoke(
            "search.text", text="ALPHA", start=at(0), end=at(len(payload) - 1), limit=10
        )
        assert len(insensitive["matches"]) == 3
        sensitive = invoke(
            "search.text",
            text="ALPHA",
            case_sensitive=True,
            start=at(0),
            end=at(len(payload) - 1),
        )
        assert not sensitive["matches"]
        assert not invoke("search.text", text="Alpha", start=at(0), end=at(3))["matches"]
        encoded = "Straße Ω".encode("utf-16-le")
        invoke("memory.write", address=at(128), data_hex=encoded.hex())
        unicode_matches = invoke(
            "search.text",
            text="STRASSE",
            encoding="utf-16-le",
            start=at(128),
            end=at(128 + len(encoded) - 1),
        )
        assert unicode_matches["matches"][0]["address"] == at(128)
        invoke("memory.write", address=at(192), data_hex="c3416c706861")
        invalid_prefix = invoke("search.text", text="Alpha", start=at(192), end=at(197))
        assert invalid_prefix["matches"][0]["address"] == at(193)
        invoke("listing.data.create", address=at(0), data_type="string", length=12)
        invoke("listing.data.create", address=at(12), data_type="string", length=12)
        assert invoke("listing.data.at", address=at(0))["data"]["defined"]
        assert invoke("listing.data.list", limit=1)["data"]
        strings = invoke("search.defined_strings", query="alpha smoke", limit=1)
        assert strings["strings"] and strings["has_more"]
        strings_next = invoke("search.defined_strings", query="alpha smoke", offset=1, limit=1)
        assert strings_next["strings"][0]["address"] != strings["strings"][0]["address"]
        defined_only = invoke(
            "search.text", text="ALPHA", defined_strings_only=True, start=at(0), end=at(23)
        )
        assert len(defined_only["matches"]) == 2
        defined_sensitive = invoke(
            "search.text",
            text="ALPHA",
            defined_strings_only=True,
            case_sensitive=True,
            start=at(0),
            end=at(23),
        )
        assert not defined_sensitive["matches"]
        assert invoke("listing.code_unit.at", address=at(0))["code_unit"]["length"] == 12
        containing = invoke("listing.code_unit.containing", address=at(1))["code_unit"]
        assert containing["address"] == at(0)
        assert invoke("listing.code_unit.after", address=at(0))["code_unit"]["address"] == at(12)
        assert invoke("listing.code_unit.before", address=at(12))["code_unit"]["address"] == at(0)
        units = invoke("listing.code_units.list", start=at(0), end=at(23), limit=1)
        assert units["has_more"]
        second = invoke("listing.code_units.list", start=at(0), end=at(23), offset=1, limit=1)
        assert second["code_units"][0]["address"] == at(12) and not second["has_more"]
        reverse = invoke("listing.code_units.list", start=at(0), end=at(23), forward=False)
        assert reverse["code_units"][0]["address"] == at(12)
        assert not invoke("listing.code_units.list", start=at(1), end=at(10))["code_units"]
        invoke("listing.data.clear", address=at(0), length=12)
        assert not invoke("listing.data.at", address=at(0))["data"]["defined"]

    try:
        block = invoke(
            "memory.block.create",
            name=name,
            address=at(0),
            length=4096,
            initialized=True,
            fill=0xCC,
            read=True,
            write=True,
            execute=True,
            comment="Temporary advanced listing smoke",
        )
        created.append(name)
        assert block["block"]["read"] and block["block"]["write"] and block["block"]["execute"]
        assert block["block"]["comment"] == "Temporary advanced listing smoke"
        assert any(block["name"] == name for block in invoke("memory.blocks.list")["blocks"])
        assert invoke("memory.read", address=at(0), length=4)["data_hex"] == "cccccccc"
        payload = b"Alpha smoke\0alpha smoke\0Alpha smoke\0"
        assert invoke("memory.write", address=at(0), data_hex=payload.hex())["written"] == len(
            payload
        )
        assert (
            invoke("memory.read", address=at(0), length=len(payload))["data_hex"] == payload.hex()
        )
        invoke(
            "memory.write",
            address=at(96),
            data_base64=base64.b64encode(b"\x11\x22\x33\x44").decode(),
        )
        assert invoke("memory.read", address=at(96), length=4)["data_hex"] == "11223344"
        other = name + "_uninitialized"
        uninitialized = invoke(
            "memory.block.create",
            name=other,
            address=at(8192),
            length=32,
            initialized=False,
            read=False,
            write=False,
            execute=False,
        )
        created.append(other)
        assert not uninitialized["block"]["initialized"] and not uninitialized["block"]["read"]
        search_and_navigation_checks(payload)
        selective_clear_checks()
        instruction_search_checks()
    finally:
        private(cleanup)
        for block_name in reversed(created):
            invoke("memory.block.remove", name=block_name)
    assert exercised == set(operations), sorted(set(operations) - exercised)
    assert not any(block["name"] in created for block in invoke("memory.blocks.list")["blocks"])
    return {
        "operations": sorted(exercised),
        "count": len(exercised),
        "scratch_address": str(base),
        "verified": [
            "byte changes",
            "initialized and uninitialized permissions",
            "typed strings",
            "navigation",
            "pagination",
            "search bounds",
            "Unicode encoding and case folding",
            "selective clear",
            "real instruction P-code and constants",
            "seed materialization",
            "block removal",
        ],
    }
