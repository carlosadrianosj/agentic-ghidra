"""Pooled decompilation, Clang syntax trees, SSA def-use, and database commits."""

from __future__ import annotations

import math
import time
from collections import deque
from contextlib import contextmanager

from .control_flow import bounded, checked_function, monitor, op_dict, op_id, varnode_dict
from .core import address, datatype, operation, source_type, variable_dict


@contextmanager
def decompile(call, function_start, timeout_secs=30):
    """Keep result-owned Clang/HighFunction objects inside the pool lease."""
    from ghidra.util.task import TimeoutTaskMonitor
    from java.util.concurrent import TimeUnit

    from pyghidra_mcp.telemetry import measure

    if (
        not isinstance(timeout_secs, (int, float))
        or not math.isfinite(timeout_secs)
        or timeout_secs <= 0
    ):
        raise ValueError("timeout_secs must be positive and finite")
    item = checked_function(call, function_start)
    deadline = time.monotonic() + timeout_secs
    task_monitor = monitor(call)
    task_monitor.checkCancelled()
    with call.info.decompiler_pool.acquire(timeout=timeout_secs) as interface:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the decompiler pool")
        timed_monitor = TimeoutTaskMonitor.timeoutIn(
            max(1, math.ceil(remaining * 1000)), TimeUnit.MILLISECONDS, task_monitor
        )
        try:
            with measure("decompile"):
                result = interface.decompileFunction(
                    item, max(1, math.ceil(remaining)), timed_monitor
                )
        except Exception as exc:
            if timed_monitor.didTimeout():
                raise TimeoutError(f"Decompilation exceeded {timeout_secs} seconds") from exc
            raise
        finally:
            timed_monitor.finished()
        if timed_monitor.didTimeout():
            raise TimeoutError(f"Decompilation exceeded {timeout_secs} seconds")
        task_monitor.checkCancelled()
        if result is None:
            raise RuntimeError("Decompiler returned no result")
        if result.isTimedOut():
            raise TimeoutError(f"Decompilation exceeded {timeout_secs} seconds")
        if not result.decompileCompleted():
            raise RuntimeError(f"Decompilation failed: {result.getErrorMessage()}")
        if result.getHighFunction() is None:
            raise RuntimeError(
                "Decompiler returned no HighFunction; syntax tree generation is required"
            )
        yield interface, result


def high_symbol_dict(symbol):
    return {
        "id": int(symbol.getId()),
        "name": str(symbol.getName()),
        "data_type": str(symbol.getDataType()),
        "size": int(symbol.getSize()),
        "storage": str(symbol.getStorage()),
        "global": bool(symbol.isGlobal()),
        "parameter": bool(symbol.isParameter()),
        "ordinal": int(symbol.getCategoryIndex()) if symbol.isParameter() else None,
        "name_locked": bool(symbol.isNameLocked()),
        "type_locked": bool(symbol.isTypeLocked()),
    }


def high_symbols(high):
    seen = set()
    for mapping in (high.getLocalSymbolMap(), high.getGlobalSymbolMap()):
        for symbol in mapping.getSymbols():
            identity = int(symbol.getId())
            if identity not in seen:
                seen.add(identity)
                yield symbol


def select_high_symbol(high, name, ordinal=None, storage=None, global_only=False):
    if ordinal is not None and ordinal < 0:
        raise ValueError("ordinal must be nonnegative")
    matches = []
    for symbol in high_symbols(high):
        if str(symbol.getName()) != name:
            continue
        if global_only and not symbol.isGlobal():
            continue
        if ordinal is not None and (
            not symbol.isParameter() or symbol.getCategoryIndex() != ordinal
        ):
            continue
        if storage is not None and str(symbol.getStorage()) != storage:
            continue
        matches.append(symbol)
    if not matches:
        raise ValueError(
            f"No decompiled {'global ' if global_only else ''}symbol matches "
            f"name/ordinal/storage: {name}"
        )
    if len(matches) != 1:
        choices = [high_symbol_dict(symbol) for symbol in matches[:20]]
        raise ValueError(f"Ambiguous decompiled symbol {name}; specify ordinal/storage: {choices}")
    return matches[0]


@contextmanager
def decompiled_selection(call, function_start, name, ordinal=None, storage=None, timeout_secs=30):
    with decompile(call, function_start, timeout_secs) as (interface, result):
        symbol = select_high_symbol(result.getHighFunction(), name, ordinal, storage)
        if symbol.getHighVariable() is None:
            raise ValueError(f"Symbol has no HighVariable in this decompilation: {name}")
        yield interface, result, symbol


@operation(
    "decomp.function",
    api="DecompInterface.decompileFunction / DecompileResults.getDecompiledFunction",
    analysis=True,
)
def decompile_function(call, function_start, timeout_secs=30):
    with decompile(call, function_start, timeout_secs) as (_, result):
        output = result.getDecompiledFunction()
        if output is None:
            raise RuntimeError("Decompiler produced no C markup")
        return {
            "function": str(result.getHighFunction().getFunction().getEntryPoint()),
            "signature": str(output.getSignature()),
            "code": str(output.getC()),
            "warnings": str(result.getErrorMessage() or ""),
        }


def clang_nodes(root):
    # Iterative traversal keeps malformed/deep markup from exhausting Python's stack.
    if root is None:
        raise RuntimeError("Decompiler returned no Clang syntax tree")
    pending = [(root, None, 0)]
    index = 0
    while pending:
        node, parent, depth = pending.pop()
        yield index, parent, depth, node
        for child in range(node.numChildren() - 1, -1, -1):
            pending.append((node.Child(child), index, depth + 1))
        index += 1


def clang_dict(index, parent, depth, node, high):
    from ghidra.app.decompiler import ClangToken

    row = {
        "id": index,
        "parent": parent,
        "depth": depth,
        "kind": str(node.getClass().getSimpleName()),
        "children": int(node.numChildren()),
        "min_address": None if node.getMinAddress() is None else str(node.getMinAddress()),
        "max_address": None if node.getMaxAddress() is None else str(node.getMaxAddress()),
    }
    if isinstance(node, ClangToken):
        row.update(
            text=str(node.getText()),
            syntax_type=int(node.getSyntaxType()),
            variable_reference=bool(node.isVariableRef()),
        )
        varnode = node.getVarnode()
        if varnode is not None:
            row["varnode"] = varnode_dict(varnode)
        op = node.getPcodeOp()
        if op is not None:
            row["pcode_op"] = op_id(op)
        symbol = node.getHighSymbol(high)
        if symbol is not None:
            row["symbol"] = high_symbol_dict(symbol)
    return row


@operation("decomp.ast", api="DecompileResults.getCCodeMarkup / ClangNode.Child", analysis=True)
def ast(call, function_start, timeout_secs=30):
    with decompile(call, function_start, timeout_secs) as (_, result):
        high = result.getHighFunction()

        def rows():
            for index, parent, depth, node in clang_nodes(result.getCCodeMarkup()):
                monitor(call).checkCancelled()
                yield clang_dict(index, parent, depth, node, high)

        return {
            "function": str(high.getFunction().getEntryPoint()),
            "representation": "Clang AST preorder",
            **bounded(rows(), key="nodes"),
        }


@operation("decomp.tokens", api="ClangToken AST traversal / getVarnode / getPcodeOp", analysis=True)
def tokens(call, function_start, timeout_secs=30):
    from ghidra.app.decompiler import ClangToken

    with decompile(call, function_start, timeout_secs) as (_, result):
        high = result.getHighFunction()

        def rows():
            for index, parent, depth, node in clang_nodes(result.getCCodeMarkup()):
                monitor(call).checkCancelled()
                if isinstance(node, ClangToken):
                    yield clang_dict(index, parent, depth, node, high)

        return {
            "function": str(high.getFunction().getEntryPoint()),
            **bounded(rows(), key="tokens"),
        }


@operation(
    "decomp.high_function.summary",
    api="HighFunction / PcodeBlockBasic / HighSymbol / VarnodeAST",
    analysis=True,
)
def high_function_summary(call, function_start, timeout_secs=30):
    with decompile(call, function_start, timeout_secs) as (_, result):
        high = result.getHighFunction()

        def block_rows():
            for block in high.getBasicBlocks():
                monitor(call).checkCancelled()
                edges = [
                    {"target": int(block.getOut(i).getIndex()), "slot": i}
                    for i in range(block.getOutSize())
                ]
                yield {
                    "id": int(block.getIndex()),
                    "start": str(block.getStart()),
                    "end": str(block.getStop()),
                    **bounded(edges, key="edges"),
                }

        prototype = high.getFunctionPrototype()
        return {
            "function": str(high.getFunction().getEntryPoint()),
            "prototype": {
                "calling_convention": str(prototype.getModelName()),
                "return_type": str(prototype.getReturnType()),
                "return_storage": str(prototype.getReturnStorage()),
                "parameter_count": int(prototype.getNumParams()),
                "varargs": bool(prototype.isVarArg()),
                "noreturn": bool(prototype.hasNoReturn()),
            },
            "varnode_count": int(high.getNumVarnodes()),
            "blocks": bounded(block_rows(), key="blocks"),
            "symbols": bounded(
                (high_symbol_dict(symbol) for symbol in high_symbols(high)), key="symbols"
            ),
            "varnodes": bounded((varnode_dict(node) for node in high.locRange()), key="varnodes"),
            "pcode": bounded((op_dict(op) for op in high.getPcodeOps()), key="ops"),
        }


def callsite_function(call, function_start, callsite):
    item = checked_function(call, function_start)
    location = address(call, callsite)
    if not item.getBody().contains(location):
        raise ValueError("callsite must be inside the specified function")
    instruction = call.program.getListing().getInstructionAt(location)
    if instruction is None or not instruction.getFlowType().isCall():
        raise ValueError("callsite must be a call instruction")
    return item, location


@operation(
    "decomp.override.get",
    api="HighFunction.findOverrideSpace / HighFunctionDBUtil.readOverride",
    analysis=True,
)
def override_get(call, function_start, callsite):
    from ghidra.program.model.pcode import HighFunction, HighFunctionDBUtil

    item, location = callsite_function(call, function_start, callsite)
    namespace = HighFunction.findOverrideSpace(item)
    rows = []
    if namespace is not None:
        for symbol in call.program.getSymbolTable().getSymbols(namespace):
            if symbol.getAddress() != location:
                continue
            override = HighFunctionDBUtil.readOverride(symbol)
            if override is not None:
                value = override.getDataType()
                rows.append(
                    {
                        "symbol": str(symbol.getName()),
                        "signature": str(value.getPrototypeString()),
                        "data_type": str(value.getPathName()),
                        "return_type": str(value.getReturnType()),
                        "arguments": [
                            {"name": str(arg.getName()), "data_type": str(arg.getDataType())}
                            for arg in value.getArguments()
                        ],
                        "calling_convention": str(value.getCallingConventionName()),
                        "varargs": bool(value.hasVarArgs()),
                        "noreturn": bool(value.hasNoReturn()),
                    }
                )
    return {
        "function": str(item.getEntryPoint()),
        "callsite": str(location),
        "overrides": rows,
        "found": bool(rows),
    }


@operation(
    "decomp.override.set",
    kind="write",
    api="FunctionSignatureParser / HighFunctionDBUtil.writeOverride",
    analysis=True,
)
def override_set(call, function_start, callsite, signature):
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.program.model.pcode import HighFunctionDBUtil

    item, location = callsite_function(call, function_start, callsite)
    parser = FunctionSignatureParser(call.program.getDataTypeManager(), None)
    definition = parser.parse(None, signature)
    if definition is None:
        raise ValueError("Invalid callsite signature")
    HighFunctionDBUtil.writeOverride(item, location, definition)
    return override_get(call, function_start, callsite)


@operation(
    "decomp.writeback.params",
    kind="write",
    api="HighFunctionDBUtil.commitParamsToDatabase",
    analysis=True,
)
def writeback_params(
    call, function_start, use_data_types=True, commit_return=False, timeout_secs=30
):
    from ghidra.program.model.pcode import HighFunctionDBUtil

    with decompile(call, function_start, timeout_secs) as (_, result):
        high = result.getHighFunction()
        option = (
            HighFunctionDBUtil.ReturnCommitOption.COMMIT
            if commit_return
            else HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT
        )
        HighFunctionDBUtil.commitParamsToDatabase(high, use_data_types, option, source_type())
        item = high.getFunction()
        return {
            "function": str(item.getEntryPoint()),
            "signature": str(item.getSignature()),
            "use_data_types": use_data_types,
            "commit_return": commit_return,
            "parameters": [variable_dict(value) for value in item.getParameters()],
        }


@operation(
    "decomp.writeback.locals",
    kind="write",
    api="HighFunctionDBUtil.commitLocalNamesToDatabase",
    analysis=True,
)
def writeback_locals(call, function_start, timeout_secs=30):
    from ghidra.program.model.pcode import HighFunctionDBUtil

    with decompile(call, function_start, timeout_secs) as (_, result):
        high = result.getHighFunction()
        HighFunctionDBUtil.commitLocalNamesToDatabase(high, source_type())
        item = high.getFunction()
        return {
            "function": str(item.getEntryPoint()),
            "locals": [variable_dict(value) for value in item.getLocalVariables()],
        }


def trace_related_operations(node, direction):
    if direction == "backward":
        definition = node.getDef()
        return [] if definition is None else [definition]
    return node.getDescendants()


def trace_next_nodes(op, direction):
    if direction == "backward":
        return [op.getInput(i) for i in range(op.getNumInputs())]
    output = op.getOutput()
    return [] if output is None else [output]


def append_trace_operations(node, direction, pending, visited, operations, edges):
    """Append one node's dataflow, stopping before either output exceeds its bound."""
    identity = int(node.getUniqueId())
    for op in trace_related_operations(node, direction):
        key = op_id(op)
        if key not in operations:
            if len(operations) >= 1000:
                return True
            operations[key] = op_dict(op)
        for next_node in trace_next_nodes(op, direction):
            if len(edges) >= 1000:
                return True
            next_id = int(next_node.getUniqueId())
            edges.append(
                {
                    "source": identity if direction == "forward" else next_id,
                    "target": next_id if direction == "forward" else identity,
                    "operation": key,
                }
            )
            if next_id not in visited:
                pending.append(next_node)
    return False


def trace_graph(call, high_variable, direction):
    """Traverse SSA instances breadth-first, deduplicating cycles by varnode ID."""
    pending = deque(high_variable.getInstances())
    visited = set()
    nodes = []
    operations = {}
    edges = []
    truncated = False
    while pending:
        monitor(call).checkCancelled()
        node = pending.popleft()
        identity = int(node.getUniqueId())
        if identity in visited:
            continue
        if len(nodes) >= 1000:
            truncated = True
            break
        visited.add(identity)
        nodes.append(varnode_dict(node))
        truncated = append_trace_operations(node, direction, pending, visited, operations, edges)
        if truncated:
            break
    return {
        "nodes": nodes,
        "operations": list(operations.values()),
        "edges": edges,
        "truncated": truncated or bool(pending),
        "limit": 1000,
    }


def trace_type(call, function_start, name, ordinal, storage, timeout_secs, direction):
    with decompiled_selection(call, function_start, name, ordinal, storage, timeout_secs) as (
        _,
        _,
        symbol,
    ):
        high_variable = symbol.getHighVariable()
        graph = trace_graph(call, high_variable, direction)
        return {
            "direction": direction,
            "symbol": high_symbol_dict(symbol),
            "data_type": str(high_variable.getDataType()),
            **graph,
        }


@operation(
    "decomp.trace_type.backward",
    api="HighVariable.getInstances / VarnodeAST.getDef / PcodeOp.getInput",
    analysis=True,
)
def trace_type_backward(call, function_start, name, ordinal=None, storage=None, timeout_secs=30):
    return trace_type(call, function_start, name, ordinal, storage, timeout_secs, "backward")


@operation(
    "decomp.trace_type.forward",
    api="HighVariable.getInstances / VarnodeAST.getDescendants / PcodeOp.getOutput",
    analysis=True,
)
def trace_type_forward(call, function_start, name, ordinal=None, storage=None, timeout_secs=30):
    return trace_type(call, function_start, name, ordinal, storage, timeout_secs, "forward")


def update_global(call, function_start, name, storage, timeout_secs, new_name=None, data_type=None):
    from ghidra.program.model.pcode import HighFunctionDBUtil

    if new_name is not None and not new_name.strip():
        raise ValueError("new_name must not be empty")
    with decompile(call, function_start, timeout_secs) as (_, result):
        symbol = select_high_symbol(
            result.getHighFunction(), name, storage=storage, global_only=True
        )
        before = high_symbol_dict(symbol)
        value = None if data_type is None else datatype(call, data_type)
        HighFunctionDBUtil.updateDBVariable(symbol, new_name, value, source_type())
        location = symbol.getStorage().getFirstVarnode().getAddress()
        db_symbol = call.program.getSymbolTable().getPrimarySymbol(location)
        db_data = call.program.getListing().getDataAt(location)
        return {
            "before": before,
            "address": str(location),
            "name": None if db_symbol is None else str(db_symbol.getName()),
            "data_type": None if db_data is None else str(db_data.getDataType()),
        }


@operation(
    "decomp.global.rename",
    kind="write",
    api="HighSymbol / HighFunctionDBUtil.updateDBVariable",
    analysis=True,
)
def global_rename(call, function_start, name, new_name, storage=None, timeout_secs=30):
    return update_global(call, function_start, name, storage, timeout_secs, new_name=new_name)


@operation(
    "decomp.global.retype",
    kind="write",
    api="HighSymbol / HighFunctionDBUtil.updateDBVariable",
    analysis=True,
)
def global_retype(call, function_start, name, data_type, storage=None, timeout_secs=30):
    return update_global(call, function_start, name, storage, timeout_secs, data_type=data_type)
