"""Native control-flow graphs and instruction/SSA p-code inspection.

These graphs expose the analyzed program, including flattened/OLLVM control flow;
they do not claim to recover an unobfuscated program.
"""

from __future__ import annotations

from .core import address as resolve_address, function, java_iter, operation

MAX_ITEMS = 1000


def bounded(rows, limit=MAX_ITEMS, key="items"):
    if not 1 <= limit <= MAX_ITEMS:
        raise ValueError("limit must be between 1 and 1000")
    result = []
    for row in rows:
        if len(result) == limit:
            return {key: result, "truncated": True, "limit": limit}
        result.append(row)
    return {key: result, "truncated": False, "limit": limit}


def monitor(call):
    if call.monitor is not None:
        return call.monitor
    from ghidra.util.task import TaskMonitor

    return TaskMonitor.DUMMY


def checked_function(call, value):
    item = function(call, value)
    if item is None:
        raise ValueError(f"Function not found: {value}")
    return item


def blocks(call, item):
    from ghidra.program.model.block import BasicBlockModel

    return BasicBlockModel(call.program).getCodeBlocksContaining(item.getBody(), monitor(call))


def block_dict(block):
    return {
        "id": str(block.getFirstStartAddress()),
        "name": str(block.getName()),
        "start": str(block.getMinAddress()),
        "end": str(block.getMaxAddress()),
        "entries": [str(value) for value in block.getStartAddresses()],
        "flow_type": str(block.getFlowType()),
    }


@operation("graph.basic_blocks", api="BasicBlockModel.getCodeBlocksContaining", analysis=True)
def basic_blocks(call, function_start):
    item = checked_function(call, function_start)
    return {
        "function": str(item.getEntryPoint()),
        **bounded((block_dict(block) for block in blocks(call, item)), key="blocks"),
    }


@operation(
    "graph.cfg.edges",
    api="CodeBlock.getDestinations / CodeBlockReference.getFlowType",
    analysis=True,
)
def cfg_edges(call, function_start):
    item = checked_function(call, function_start)

    def rows():
        for block in blocks(call, item):
            monitor(call).checkCancelled()
            for ref in java_iter(block.getDestinations(monitor(call))):
                flow = ref.getFlowType()
                yield {
                    "source": str(ref.getSourceAddress()),
                    "target": str(ref.getDestinationAddress()),
                    "callsite": str(ref.getReferent()),
                    "reference": str(ref.getReference()),
                    "flow_type": str(flow),
                    "call": bool(flow.isCall()),
                    "conditional": bool(flow.isConditional()),
                    "computed": bool(flow.isComputed()),
                }

    return {"function": str(item.getEntryPoint()), **bounded(rows(), key="edges")}


@operation("graph.call_paths", api="Function.getCalledFunctions", analysis=True)
def call_paths(call, source_function, target_function, max_depth=4, limit=10):
    if not 0 <= max_depth <= 100:
        raise ValueError("max_depth must be between 0 and 100")
    if not 1 <= limit <= MAX_ITEMS:
        raise ValueError("limit must be between 1 and 1000")
    source = checked_function(call, source_function)
    target = checked_function(call, target_function)
    target_id = str(target.getEntryPoint())
    paths = []
    pending = [(source, [str(source.getEntryPoint())])]
    visited_states = 0
    cycles = 0
    depth_limited = False
    exploration_capped = False
    # Bound exploration as well as returned paths on very wide call graphs.
    while pending and len(paths) <= limit and visited_states < 10000:
        monitor(call).checkCancelled()
        current, path = pending.pop()
        visited_states += 1
        if path[-1] == target_id:
            paths.append(path)
            continue
        if len(path) - 1 >= max_depth:
            depth_limited = True
            continue
        callees = sorted(
            current.getCalledFunctions(monitor(call)), key=lambda fn: str(fn.getEntryPoint())
        )
        for callee in reversed(callees):
            entry = str(callee.getEntryPoint())
            if entry in path:
                cycles += 1
                continue
            pending.append((callee, [*path, entry]))
            if len(pending) >= 10000:
                exploration_capped = True
                break
    return {
        "source": str(source.getEntryPoint()),
        "target": target_id,
        "paths": paths[:limit],
        "max_depth": max_depth,
        "limit": limit,
        "cycles_skipped": cycles,
        "depth_limited": depth_limited,
        "truncated": len(paths) > limit or bool(pending) or exploration_capped,
        "states_examined": visited_states,
    }


def varnode_dict(node):
    if node is None:
        return None
    result = {
        "text": str(node),
        "space": str(node.getAddress().getAddressSpace().getName()),
        "address": str(node.getAddress()),
        "offset": int(node.getOffset()),
        "size": int(node.getSize()),
        "constant": bool(node.isConstant()),
        "register": bool(node.isRegister()),
        "unique": bool(node.isUnique()),
    }
    if hasattr(node, "getUniqueId"):
        result["id"] = int(node.getUniqueId())
        high = node.getHigh()
        if high is not None:
            result["name"] = str(high.getName())
            result["data_type"] = str(high.getDataType())
    return result


def op_id(op):
    seq = op.getSeqnum()
    return f"{seq.getTarget()}:{seq.getTime()}"


def op_dict(op):
    return {
        "id": op_id(op),
        "address": str(op.getSeqnum().getTarget()),
        "sequence": int(op.getSeqnum().getTime()),
        "opcode": int(op.getOpcode()),
        "mnemonic": str(op.getMnemonic()),
        "output": varnode_dict(op.getOutput()),
        "inputs": [varnode_dict(op.getInput(i)) for i in range(op.getNumInputs())],
    }


def instruction_ops(instructions, call):
    for instruction in instructions:
        monitor(call).checkCancelled()
        for op in instruction.getPcode():
            yield op_dict(op)


@operation("pcode.op.at", api="Listing.getInstructionAt / Instruction.getPcode", analysis=True)
def op_at(call, address):
    location = resolve_address(call, address)
    instruction = call.program.getListing().getInstructionAt(location)
    if instruction is None:
        raise ValueError(f"No instruction starts at {location}")
    return {"address": str(location), **bounded(instruction_ops([instruction], call), key="ops")}


@operation(
    "pcode.block",
    api="BasicBlockModel.getFirstCodeBlockContaining / Instruction.getPcode",
    analysis=True,
)
def pcode_block(call, address):
    from ghidra.program.model.block import BasicBlockModel

    location = resolve_address(call, address)
    block = BasicBlockModel(call.program).getFirstCodeBlockContaining(location, monitor(call))
    if block is None:
        raise ValueError(f"No basic block contains {location}")
    instructions = call.program.getListing().getInstructions(block, True)
    return {"block": block_dict(block), **bounded(instruction_ops(instructions, call), key="ops")}


@operation("pcode.function", api="Listing.getInstructions / Instruction.getPcode", analysis=True)
def pcode_function(call, function_start, limit=200):
    item = checked_function(call, function_start)
    instructions = call.program.getListing().getInstructions(item.getBody(), True)
    return {
        "function": str(item.getEntryPoint()),
        **bounded(instruction_ops(instructions, call), limit, "ops"),
    }


def varnode_selection_address(call, address, space):
    factory = call.program.getAddressFactory()
    selected_space = None if space is None else factory.getAddressSpace(space)
    if space is not None and selected_space is None:
        raise ValueError(f"Unknown address space: {space}")
    selected_address = None
    if address is not None:
        text = hex(address) if isinstance(address, int) else str(address)
        if selected_space is not None and ":" not in text and "[" not in text:
            selected_address = selected_space.getAddress(text)
        else:
            # Wrapped forms such as Stack[-0x14] and Unique[...] are only
            # understood by the address factory, never by a single space.
            selected_address = resolve_address(call, address)
        if selected_address is None:
            raise ValueError(f"Invalid varnode address: {address}")
    return selected_space, selected_address


def matches_varnode(node, varnode, selected_address, selected_space, size):
    if selected_space is not None and node.getAddress().getAddressSpace() != selected_space:
        return False
    if selected_address is not None and node.getAddress() != selected_address:
        return False
    if size is not None and node.getSize() != size:
        return False
    # IDs are the decompiled SSA varnode IDs emitted by this module.
    return varnode is None or str(varnode) in (
        str(node),
        str(node.getUniqueId()),
        f"id:{node.getUniqueId()}",
    )


@operation(
    "pcode.varnode_uses",
    api="HighFunction.getVarnodes / VarnodeAST.getDef / getDescendants",
    analysis=True,
)
def varnode_uses(
    call, function_start, varnode=None, address=None, space=None, size=None, timeout_secs=30
):
    from .decompiler import decompile

    if size is not None and size < 1:
        raise ValueError("size must be positive")
    selected_space, selected_address = varnode_selection_address(call, address, space)
    with decompile(call, function_start, timeout_secs) as (_, result):
        high = result.getHighFunction()

        def rows():
            for node in high.locRange():
                monitor(call).checkCancelled()
                if not matches_varnode(node, varnode, selected_address, selected_space, size):
                    continue
                definition = node.getDef()
                uses = bounded((op_dict(op) for op in node.getDescendants()), key="uses")
                yield {
                    "varnode": varnode_dict(node),
                    "definition": None if definition is None else op_dict(definition),
                    **uses,
                }

        return bounded(rows(), key="varnodes")
