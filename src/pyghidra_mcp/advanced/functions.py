"""Function, parameter, local-variable and stack-frame operations.

Storage selectors are exclusive. Explicit parameter storage switches the function
into custom-storage mode; adding to an already-custom signature requires storage.
Variable names are not unique across scopes: ordinal/storage refine selection,
and an unresolved ambiguity is an error rather than an arbitrary first match.
"""

from __future__ import annotations

import time

from .core import (
    Call,
    address as resolve_address,
    address_range,
    datatype,
    function,
    function_dict,
    operation,
    page,
    source_type,
    variable_dict,
)


def _record(fn):
    result = function_dict(fn)
    result.update(
        calling_convention=str(fn.getCallingConventionName()),
        return_type=str(fn.getReturnType()),
        varargs=bool(fn.hasVarArgs()),
        inline=bool(fn.isInline()),
        noreturn=bool(fn.hasNoReturn()),
        custom_storage=bool(fn.hasCustomVariableStorage()),
    )
    return result


def _storage_serialization(storage):
    from ghidra.program.model.listing import VariableStorage

    # An explicit Varnode[] selects the static overload instead of JPype varargs binding.
    return str(VariableStorage.getSerializationString(storage.getVarnodes()))


def _variable_record(var):
    result = variable_dict(var)
    storage = var.getVariableStorage()
    result["storage_serialized"] = _storage_serialization(storage)
    result["size"] = int(var.getLength())
    result["parameter"] = bool(hasattr(var, "getOrdinal"))
    if var.isStackVariable():
        result["stack_offset"] = int(var.getStackOffset())
    return result


def select_variable(call, function_start, name, ordinal=None, storage=None):
    """Select one DB variable, requiring every supplied selector to match.

    Ordinals identify parameters only. Storage accepts the displayed storage or
    its public VariableStorage serialization. Names can be omitted by internal
    parameter operations, but at least one selector is always required.
    """
    if name is None and ordinal is None and storage is None:
        raise ValueError("Specify a variable name, ordinal, or storage")
    if ordinal is not None and ordinal < 0:
        raise ValueError("Parameter ordinal must be nonnegative")
    fn = function(call, function_start)
    variables = list(fn.getParameters())
    if ordinal is None:
        variables.extend(fn.getLocalVariables())
    matches = []
    for var in variables:
        if name is not None and str(var.getName()) != name:
            continue
        if ordinal is not None and int(var.getOrdinal()) != ordinal:
            continue
        location = var.getVariableStorage()
        if storage is not None and storage not in (
            str(location),
            _storage_serialization(location),
        ):
            continue
        matches.append(var)
    if not matches:
        raise ValueError(
            f"Variable not found: name={name!r}, ordinal={ordinal}, storage={storage!r}"
        )
    if len(matches) != 1:
        choices = "; ".join(
            f"{var.getName()} ordinal={var.getOrdinal() if hasattr(var, 'getOrdinal') else None} "
            f"storage={var.getVariableStorage()} first_use_offset={var.getFirstUseOffset()}"
            for var in matches
        )
        raise ValueError(f"Ambiguous variable selection; specify ordinal or storage: {choices}")
    return matches[0]


def _fixed_type(call, name):
    result = datatype(call, name)
    if int(result.getLength()) <= 0:
        raise ValueError("Variable data type must have a positive fixed length")
    return result


def _storage(call, data_type, stack_offset=None, register=None, storage_address=None):
    from ghidra.program.model.listing import VariableStorage

    selectors = sum(value is not None for value in (stack_offset, register, storage_address))
    if selectors != 1:
        raise ValueError("Specify exactly one of stack_offset, register, or storage_address")
    size = int(data_type.getLength())
    if stack_offset is not None:
        return VariableStorage(call.program, stack_offset, size)
    if register is not None:
        reg = call.program.getRegister(register)
        if reg is None:
            raise ValueError(f"Unknown register: {register}")
        width = int(reg.getMinimumByteSize())
        if size > width:
            raise ValueError(
                f"Data type of {size} bytes does not fit register {register} ({width} bytes)"
            )
        location = reg.getAddress()
        if call.program.getLanguage().isBigEndian():
            location = location.add(width - size)
    else:
        location = resolve_address(call, storage_address)
    return VariableStorage(call.program, location, size)


def _parameters(fn, call):
    from ghidra.program.model.listing import ParameterImpl

    parameters = []
    for var in fn.getParameters():
        if not var.isAutoParameter():
            copied = ParameterImpl(var, call.program)
            copied.setComment(var.getComment())
            parameters.append(copied)
    return parameters


def _replace_parameters(fn, parameters):
    from ghidra.program.model.listing import Function
    from java.util import ArrayList

    mode = (
        Function.FunctionUpdateType.CUSTOM_STORAGE
        if fn.hasCustomVariableStorage()
        else Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS
    )
    values = ArrayList()
    comments = []
    for parameter in parameters:
        if not fn.hasCustomVariableStorage() and str(parameter.getName()) in (
            Function.THIS_PARAM_NAME,
            Function.RETURN_PTR_PARAM_NAME,
        ):
            raise ValueError("Reserved auto-parameter names require custom storage")
        values.add(parameter)
        comments.append(parameter.getComment())
    fn.replaceParameters(values, mode, False, source_type())
    # Keep comments attached to the logical parameters, including after a move.
    for parameter, comment in zip(
        (var for var in fn.getParameters() if not var.isAutoParameter()),
        comments,
        strict=True,
    ):
        parameter.setComment(comment)


def _parameter(call, fn, ordinal=None, name=None):
    var = select_variable(call, fn.getEntryPoint(), name, ordinal=ordinal)
    if not hasattr(var, "getOrdinal"):
        raise ValueError("Selected variable is a local, not a parameter")
    if var.isAutoParameter():
        raise ValueError(
            "Auto-parameters cannot be edited directly; use a formal signature or custom storage"
        )
    return var


def _parameter_index(fn, ordinal, *, insertion=False):
    first = int(fn.getAutoParameterCount())
    count = int(fn.getParameterCount())
    last = count if insertion else count - 1
    if not first <= ordinal <= last:
        raise ValueError(f"Ordinal must identify a formal parameter in [{first}, {last}]")
    return ordinal - first


def _iter_functions(call, query=None):
    needle = query.casefold() if query else None
    for fn in call.program.getFunctionManager().getFunctions(True):
        if call.monitor is not None:
            call.monitor.checkCancelled()
        if needle is None or needle in str(fn.getName()).casefold():
            yield fn


@operation("function.list", api="FunctionManager.getFunctions", analysis=True)
def list_functions(call: Call, offset=0, limit=100, query=None):
    return page(
        (_record(fn) for fn in _iter_functions(call, query)), offset, limit, key="functions"
    )


@operation("function.at", api="FunctionManager.getFunctionAt/getFunctionContaining", analysis=True)
def function_at(call: Call, address):
    location = resolve_address(call, address)
    manager = call.program.getFunctionManager()
    fn = manager.getFunctionAt(location) or manager.getFunctionContaining(location)
    if fn is None:
        raise ValueError(f"No function at or containing {location}")
    return _record(fn)


@operation("function.by_name", api="FunctionManager.getFunctions; Function.getName", analysis=True)
def function_by_name(call: Call, name, exact=False, limit=20):
    matches = (
        fn
        for fn in _iter_functions(call, None if exact else name)
        if not exact or str(fn.getName()) == name or str(fn.getName(True)) == name
    )
    return page((_record(fn) for fn in matches), 0, limit, key="functions")


@operation("function.create", kind="write", api="CreateFunctionCmd.applyTo; Function.setName")
def create_function(call: Call, address, name=None):
    from ghidra.app.cmd.function import CreateFunctionCmd

    location = resolve_address(call, address)
    if call.program.getFunctionManager().getFunctionContaining(location) is not None:
        raise ValueError(f"A function already contains {location}")
    command = CreateFunctionCmd(location)
    if not command.applyTo(call.program, call.monitor):
        raise ValueError(f"Cannot create function: {command.getStatusMsg()}")
    fn = call.program.getFunctionManager().getFunctionAt(location)
    if fn is None:
        raise ValueError("Function creation did not produce an entry-point function")
    if name is not None:
        fn.setName(name, source_type())
    return _record(fn)


@operation("function.delete", kind="write", api="FunctionManager.removeFunction")
def delete_function(call: Call, function_start):
    fn = function(call, function_start)
    entry = fn.getEntryPoint()
    if not call.program.getFunctionManager().removeFunction(entry):
        raise ValueError(f"Unable to delete function at {entry}")
    return {"address": str(entry), "deleted": True}


@operation("function.rename", kind="write", api="Function.setName(SourceType.USER_DEFINED)")
def rename_function(call: Call, function_start, name):
    fn = function(call, function_start)
    fn.setName(name, source_type())
    return _record(fn)


@operation("function.body.set", kind="write", api="Function.setBody")
def set_function_body(call: Call, function_start, start, end=None, length=None):
    fn = function(call, function_start)
    body = address_range(call, start, end, length)
    if not body.contains(fn.getEntryPoint()):
        raise ValueError("Function body must contain its entry point")
    fn.setBody(body)
    return _record(fn)


@operation(
    "function.flags.set",
    kind="write",
    api="Function.setVarArgs/setInline/setNoReturn/setCustomVariableStorage",
)
def set_function_flags(
    call: Call, function_start, varargs=None, inline=None, noreturn=None, custom_storage=None
):
    fn = function(call, function_start)
    for value, setter in (
        (varargs, fn.setVarArgs),
        (inline, fn.setInline),
        (noreturn, fn.setNoReturn),
        (custom_storage, fn.setCustomVariableStorage),
    ):
        if value is not None:
            setter(value)
    return _record(fn)


@operation("function.calling_conventions.list", api="FunctionManager.getCallingConventionNames")
def calling_conventions(call: Call):
    names = [str(name) for name in call.program.getFunctionManager().getCallingConventionNames()]
    return {"calling_conventions": ["default", "unknown", *names]}


@operation("function.calling_convention.set", kind="write", api="Function.setCallingConvention")
def set_calling_convention(call: Call, function_start, name):
    fn = function(call, function_start)
    fn.setCallingConvention(name)
    return _record(fn)


@operation("function.thunk.set", kind="write", api="Function.setThunkedFunction")
def set_thunk(call: Call, function_start, thunk_target):
    fn = function(call, function_start)
    target = function(call, thunk_target)
    if fn == target:
        raise ValueError("A function cannot thunk to itself")
    fn.setThunkedFunction(target)
    return {**_record(fn), "thunk_target": str(target.getEntryPoint())}


@operation(
    "function.return_type.set", kind="write", api="Function.setReturnType(SourceType.USER_DEFINED)"
)
def set_return_type(call: Call, function_start, data_type):
    fn = function(call, function_start)
    fn.setReturnType(datatype(call, data_type), source_type())
    return _record(fn)


@operation("function.signature.get", api="Function.getSignature/getParameters", analysis=True)
def get_signature(call: Call, function_start):
    fn = function(call, function_start)
    return {
        **_record(fn),
        "parameters": [_variable_record(var) for var in fn.getParameters()],
        "signature_source": str(fn.getSignatureSource()),
    }


@operation(
    "function.signature.set",
    kind="write",
    api="FunctionSignatureParser (DataTypeParser); ApplyFunctionSignatureCmd",
)
def set_signature(call: Call, function_start, signature):
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser

    fn = function(call, function_start)
    parser = FunctionSignatureParser(call.program.getDataTypeManager(), None)
    parsed = parser.parse(fn.getSignature(), signature)
    command = ApplyFunctionSignatureCmd(fn.getEntryPoint(), parsed, source_type(), False, True)
    if not command.applyTo(call.program, call.monitor):
        raise ValueError(f"Cannot apply function signature: {command.getStatusMsg()}")
    return get_signature(call, fn.getEntryPoint())


@operation("function.variables", api="Function.getParameters/getLocalVariables", analysis=True)
def function_variables(call: Call, function_start):
    fn = function(call, function_start)
    return {
        "function": str(fn.getEntryPoint()),
        "parameters": [_variable_record(var) for var in fn.getParameters()],
        "locals": [_variable_record(var) for var in fn.getLocalVariables()],
    }


@operation("function.callers", api="Function.getCallingFunctions", analysis=True)
def function_callers(call: Call, function_start):
    fn = function(call, function_start)
    callers = sorted(
        fn.getCallingFunctions(call.monitor), key=lambda item: str(item.getEntryPoint())
    )
    return page((_record(item) for item in callers), limit=1000, key="functions")


@operation("function.callees", api="Function.getCalledFunctions", analysis=True)
def function_callees(call: Call, function_start):
    fn = function(call, function_start)
    callees = sorted(
        fn.getCalledFunctions(call.monitor), key=lambda item: str(item.getEntryPoint())
    )
    return page((_record(item) for item in callees), limit=1000, key="functions")


@operation(
    "function.report",
    api="Function; StackFrame; Function.getCallingFunctions/getCalledFunctions",
    analysis=True,
)
def function_report(call: Call, function_start):
    fn = function(call, function_start)
    return {
        **get_signature(call, fn.getEntryPoint()),
        "variables": function_variables(call, fn.getEntryPoint()),
        "stackframe": stackframe_variables(call, fn.getEntryPoint()),
        "callers": function_callers(call, fn.getEntryPoint()),
        "callees": function_callees(call, fn.getEntryPoint()),
    }


@operation(
    "function.batch.run",
    api="FunctionManager.getFunctions; explicit read-only function operations",
    analysis=True,
)
def batch_functions(call: Call, action, query=None, offset=0, limit=50, timeout_secs=30):
    """Run the seven published batch actions, never arbitrary Python or mutation."""
    from . import decompiler, listing_memory

    actions = {
        "decomp.function": lambda entry: decompiler.decompile_function(
            call, entry, timeout_secs=timeout_secs
        ),
        "disasm.function": lambda entry: listing_memory.disassemble_function(call, entry),
        "function.signature.get": lambda entry: get_signature(call, entry),
        "function.variables": lambda entry: function_variables(call, entry),
        "function.callers": lambda entry: function_callers(call, entry),
        "function.callees": lambda entry: function_callees(call, entry),
        "report.function_summary": lambda entry: function_report(call, entry),
    }
    if action not in actions:
        raise ValueError(f"Unsupported batch action {action!r}; supported: {', '.join(actions)}")
    if timeout_secs <= 0:
        raise ValueError("timeout_secs must be positive")
    deadline = time.monotonic() + timeout_secs
    result = page(_iter_functions(call, query), offset, limit)
    selected = result["items"]
    result["action"] = action
    result["items"] = []
    for fn in selected:
        if call.monitor is not None:
            call.monitor.checkCancelled()
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Function batch exceeded {timeout_secs} seconds")
        entry = str(fn.getEntryPoint())
        payload = actions[action](entry)
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Function batch exceeded {timeout_secs} seconds")
        result["items"].append({"function": _record(fn), "status": "ok", "result": payload})
    return result


@operation("variable.rename", kind="write", api="Variable.setName(SourceType.USER_DEFINED)")
def rename_variable(call: Call, function_start, name, new_name, ordinal=None, storage=None):
    var = select_variable(call, function_start, name, ordinal, storage)
    var.setName(new_name, source_type())
    return _variable_record(var)


@operation("variable.retype", kind="write", api="Variable.setDataType(SourceType.USER_DEFINED)")
def retype_variable(call: Call, function_start, name, data_type, ordinal=None, storage=None):
    var = select_variable(call, function_start, name, ordinal, storage)
    var.setDataType(_fixed_type(call, data_type), False, False, source_type())
    return _variable_record(var)


@operation("variable.comment.set", kind="write", api="Variable.setComment")
def comment_variable(call: Call, function_start, name, comment, ordinal=None, storage=None):
    var = select_variable(call, function_start, name, ordinal, storage)
    var.setComment(comment)
    return _variable_record(var)


@operation(
    "variable.local.create",
    kind="write",
    api="VariableStorage; LocalVariableImpl; Function.addLocalVariable",
)
def create_local(
    call: Call,
    function_start,
    name,
    data_type,
    first_use_offset=0,
    stack_offset=None,
    register=None,
    storage_address=None,
    comment=None,
):
    from ghidra.program.model.listing import LocalVariableImpl

    fn = function(call, function_start)
    dt = _fixed_type(call, data_type)
    storage = _storage(call, dt, stack_offset, register, storage_address)
    var = LocalVariableImpl(name, first_use_offset, dt, storage, False, call.program, source_type())
    var.setComment(comment)
    added = fn.addLocalVariable(var, source_type())
    return _variable_record(added)


@operation("variable.local.remove", kind="write", api="Function.removeVariable")
def remove_local(call: Call, function_start, name, storage=None):
    fn = function(call, function_start)
    var = select_variable(call, function_start, name, storage=storage)
    if hasattr(var, "getOrdinal"):
        raise ValueError("Selected variable is a parameter; use parameter.remove")
    previous = _variable_record(var)
    fn.removeVariable(var)
    return {"deleted": True, "variable": previous}


@operation("parameter.add", kind="write", api="ParameterImpl; Function.replaceParameters")
def add_parameter(
    call: Call, function_start, name, data_type, ordinal=None, stack_offset=None, register=None
):
    from ghidra.program.model.listing import ParameterImpl

    fn = function(call, function_start)
    dt = _fixed_type(call, data_type)
    explicit = stack_offset is not None or register is not None
    if explicit:
        storage = _storage(call, dt, stack_offset, register)
        fn.setCustomVariableStorage(True)
        var = ParameterImpl(name, dt, storage, call.program, source_type())
    else:
        if fn.hasCustomVariableStorage():
            raise ValueError("Custom-storage parameters require stack_offset or register")
        var = ParameterImpl(name, dt, call.program, source_type())
    ordinal = int(fn.getParameterCount()) if ordinal is None else ordinal
    index = _parameter_index(fn, ordinal, insertion=True)
    parameters = _parameters(fn, call)
    parameters.insert(index, var)
    _replace_parameters(fn, parameters)
    return get_signature(call, fn.getEntryPoint())


@operation("parameter.remove", kind="write", api="Function.replaceParameters")
def remove_parameter(call: Call, function_start, ordinal=None, name=None):
    fn = function(call, function_start)
    var = _parameter(call, fn, ordinal, name)
    index = _parameter_index(fn, int(var.getOrdinal()))
    parameters = _parameters(fn, call)
    del parameters[index]
    _replace_parameters(fn, parameters)
    return get_signature(call, fn.getEntryPoint())


@operation("parameter.move", kind="write", api="ParameterImpl; Function.replaceParameters")
def move_parameter(call: Call, function_start, ordinal, new_ordinal):
    fn = function(call, function_start)
    old_index = _parameter_index(fn, ordinal)
    new_index = _parameter_index(fn, new_ordinal)
    parameters = _parameters(fn, call)
    parameters.insert(new_index, parameters.pop(old_index))
    _replace_parameters(fn, parameters)
    return get_signature(call, fn.getEntryPoint())


@operation(
    "parameter.replace",
    kind="write",
    api="ParameterImpl; Variable.setDataType; Function.replaceParameters",
)
def replace_parameter(
    call: Call,
    function_start,
    ordinal=None,
    name=None,
    new_name=None,
    data_type=None,
    stack_offset=None,
    register=None,
):
    from ghidra.program.model.listing import ParameterImpl

    fn = function(call, function_start)
    var = _parameter(call, fn, ordinal, name)
    target_ordinal = int(var.getOrdinal())
    dt = _fixed_type(call, data_type) if data_type is not None else var.getDataType()
    explicit = stack_offset is not None or register is not None
    storage = _storage(call, dt, stack_offset, register) if explicit else None
    if explicit:
        # Materialize auto-parameters before replacing so no existing storage is lost.
        fn.setCustomVariableStorage(True)
    index = _parameter_index(fn, target_ordinal)
    parameters = _parameters(fn, call)
    replacement = parameters[index]
    if new_name is not None:
        replacement.setName(new_name, source_type())
    if storage is not None:
        stored = ParameterImpl(str(replacement.getName()), dt, storage, call.program, source_type())
        stored.setComment(replacement.getComment())
        parameters[index] = stored
    elif data_type is not None:
        replacement.setDataType(dt, False, False, source_type())
    _replace_parameters(fn, parameters)
    return get_signature(call, fn.getEntryPoint())


@operation(
    "stackframe.variables",
    api="Function.getStackFrame; StackFrame.getStackVariables",
    analysis=True,
)
def stackframe_variables(call: Call, function_start):
    fn = function(call, function_start)
    frame = fn.getStackFrame()
    return {
        "function": str(fn.getEntryPoint()),
        "frame_size": int(frame.getFrameSize()),
        "local_size": int(frame.getLocalSize()),
        "parameter_size": int(frame.getParameterSize()),
        "parameter_offset": int(frame.getParameterOffset()),
        "return_address_offset": int(frame.getReturnAddressOffset()),
        "grows_negative": bool(frame.growsNegative()),
        "variables": [_variable_record(var) for var in frame.getStackVariables()],
    }


@operation(
    "stackframe.variable.create",
    kind="write",
    api="StackFrame.createVariable(SourceType.USER_DEFINED)",
)
def create_stack_variable(call: Call, function_start, name, stack_offset, data_type):
    fn = function(call, function_start)
    var = fn.getStackFrame().createVariable(
        name, stack_offset, _fixed_type(call, data_type), source_type()
    )
    return _variable_record(var)


@operation(
    "stackframe.variable.clear", kind="write", api="StackFrame.getVariableContaining/clearVariable"
)
def clear_stack_variable(call: Call, function_start, stack_offset):
    frame = function(call, function_start).getStackFrame()
    var = frame.getVariableContaining(stack_offset)
    if var is None:
        raise ValueError(f"No stack variable contains offset {stack_offset}")
    previous = _variable_record(var)
    frame.clearVariable(stack_offset)
    return {"deleted": True, "variable": previous}
