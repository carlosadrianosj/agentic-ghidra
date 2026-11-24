"""Opt-in, session-bound execution in a trusted local Ghidra runtime, not a sandbox."""

from __future__ import annotations

import ast
import builtins
import io
import logging
import os
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from agenticghidra_mcp.advanced.core import MAX_RESULTS, Call, json_value, operation

logger = logging.getLogger(__name__)
MAX_SOURCE_BYTES = 1024 * 1024
MAX_OUTPUT_CHARS = 65536


class _Output(io.StringIO):
    def write(self, text):
        if self.tell() + len(text) > MAX_OUTPUT_CHARS:
            raise ValueError(f"Script output exceeds {MAX_OUTPUT_CHARS} characters")
        return super().write(text)


def _policy(call: Call, action: str, write: bool) -> float:
    if os.environ.get("GHIDRA_ADVANCED_TRUSTED_CODE") != "1":
        raise PermissionError(
            "Trusted execution is disabled; explicitly enable --trusted-code locally"
        )
    if call.session is None:
        raise ValueError("Trusted execution requires an owned program session")
    if write and call.session.read_only:
        raise PermissionError("The program session is read-only")
    timeout = float(os.environ.get("GHIDRA_ADVANCED_CODE_TIMEOUT", "30"))
    if not 0 < timeout <= 300:
        raise ValueError("GHIDRA_ADVANCED_CODE_TIMEOUT must be between 0 and 300 seconds")
    logger.warning(
        "Trusted %s owner=%s session=%s write=%s deadline=%ss",
        action,
        call.owner,
        call.session.session_id,
        write,
        timeout,
    )
    return timeout


@contextmanager
def _deadline(call: Call, timeout: float):
    deadline = time.monotonic() + timeout
    previous = sys.gettrace()
    expired = threading.Event()

    def cancel():
        expired.set()
        if call.monitor is not None:
            call.monitor.cancel()

    def trace(frame, event, arg):
        if expired.is_set() or time.monotonic() >= deadline:
            raise TimeoutError("Trusted execution deadline exceeded")
        if call.monitor is not None and call.monitor.isCancelled():
            raise TimeoutError("Trusted execution was cancelled")
        return trace

    timer = threading.Timer(timeout, cancel)
    timer.daemon = True
    timer.start()
    sys.settrace(trace)
    try:
        yield
        if expired.is_set():
            raise TimeoutError("Trusted execution completed after its deadline")
    finally:
        sys.settrace(previous)
        timer.cancel()


def _environment(call: Call, output: _Output, script_args=None, filename="<ghidra.eval>"):
    def safe_print(*args, **kwargs):
        return builtins.print(*args, **{**kwargs, "file": output})

    return {
        "__builtins__": {**vars(builtins), "print": safe_print},
        "__name__": "__main__",
        "__file__": filename,
        "currentProgram": call.program,
        "program": call.program,
        "currentAddress": call.program.getMinAddress(),
        "flat_api": call.flat,
        "monitor": call.monitor,
        "script_args": script_args or [],
        "args": script_args or [],
        "getScriptArgs": lambda: list(script_args or []),
        "println": lambda value="": safe_print(value),
    }


def _execute_python(
    call: Call, code: str, timeout: float, *, filename="<ghidra.eval>", script_args=None
):
    if len(code.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Python source exceeds one MiB")
    tree = ast.parse(code, filename=filename, mode="exec")
    last_expression = tree.body.pop() if tree.body and isinstance(tree.body[-1], ast.Expr) else None
    output = _Output()
    scope = _environment(call, output, script_args, filename)
    with _deadline(call, timeout):
        exec(compile(tree, filename, "exec"), scope)
        result = (
            eval(compile(ast.Expression(last_expression.value), filename, "eval"), scope)
            if last_expression
            else scope.get("result")
        )
    return {"result": _java_json(result), "stdout": output.getvalue()}


def _java_json(value):
    if value is None or isinstance(value, (str, bool, int, float, dict, list, tuple, bytes)):
        return json_value(value)
    from java.lang import Boolean, Number
    from java.util import Collection, Map

    if isinstance(value, Boolean):
        return bool(value.booleanValue())
    if isinstance(value, Number):
        text = str(value)
        return (
            float(text)
            if any(mark in text.lower() for mark in (".", "e", "nan", "inf"))
            else int(text)
        )
    if isinstance(value, Map):
        if value.size() > MAX_RESULTS:
            raise ValueError("Java map result exceeds the output item limit")
        return {str(item.getKey()): _java_json(item.getValue()) for item in value.entrySet()}
    if isinstance(value, Collection):
        if value.size() > MAX_RESULTS:
            raise ValueError("Java collection result exceeds the output item limit")
        return [_java_json(item) for item in value]
    return str(value)


@operation("ghidra.info", api="Application.getApplicationVersion", program=False)
def info(call: Call):
    import jpype
    from ghidra.framework import Application

    return {
        "ghidra_version": str(Application.getApplicationVersion()),
        "application": str(Application.getName()),
        "java_version": str(jpype.java.lang.System.getProperty("java.version")),
        "trusted_code_enabled": os.environ.get("GHIDRA_ADVANCED_TRUSTED_CODE") == "1",
        "trusted_code_is_sandboxed": False,
    }


@operation(
    "ghidra.eval", kind="script", api="Python compile/exec against owned Program", timeout=30
)
def evaluate(call: Call, code: str, write: bool = False):
    timeout = _policy(call, "eval", write)
    return _execute_python(call, code, timeout)


@operation(
    "ghidra.call", kind="script", api="JPype JClass and owned Program public methods", timeout=30
)
def call_api(call: Call, target: str, args=None, kwargs=None, write: bool = False):
    import jpype

    timeout = _policy(call, "call", write)
    if not isinstance(target, str) or "." not in target:
        raise ValueError("target must be a qualified method name")
    owner_name, method = target.rsplit(".", 1)
    if method.startswith("_"):
        raise ValueError("A public method is required")
    roots = {
        "program": call.program,
        "currentProgram": call.program,
        "flat_api": call.flat,
        "monitor": call.monitor,
    }
    root, _, suffix = owner_name.partition(".")
    if root in roots:
        owner = roots[root]
        for component in suffix.split(".") if suffix else []:
            if component.startswith("_"):
                raise ValueError("A public API path is required")
            owner = getattr(owner, component)
    else:
        if not owner_name.startswith(("ghidra.", "java.", "javax.")):
            raise ValueError("Static calls must target a Ghidra or Java class")
        owner = jpype.JClass(owner_name)
    function = getattr(owner, method)
    if not callable(function):
        raise ValueError("target is not callable")
    with _deadline(call, timeout):
        result = function(*(args or []), **(kwargs or {}))
    return {"result": _java_json(result)}


@operation(
    "ghidra.script", kind="script", api="GhidraScriptProvider/GhidraScript.execute", timeout=30
)
def script(call: Call, path: str, script_args=None, write: bool = False):
    timeout = _policy(call, "script", write)
    source = Path(path).expanduser().resolve(strict=True)
    if not source.is_file() or source.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("Script must be a regular file of at most one MiB")
    if source.suffix.lower() == ".py":
        return _execute_python(
            call,
            source.read_text(encoding="utf-8"),
            timeout,
            filename=str(source),
            script_args=script_args,
        )
    from generic.jar import ResourceFile
    from ghidra.app.script import GhidraScriptUtil

    from agenticghidra_mcp.context import PyGhidraContext

    with PyGhidraContext._analysis_bundle_host_lock:
        host = GhidraScriptUtil.acquireBundleHostReference()
        source_directory = ResourceFile(str(source.parent))
        added = host.getGhidraBundle(source_directory) is None
        try:
            if added:
                host.add(source_directory, True, False)
            return _execute_java(call, source, script_args, timeout)
        finally:
            try:
                if added:
                    host.remove(source_directory)
            finally:
                GhidraScriptUtil.releaseBundleHostReference()


def _execute_java(call, source, script_args, timeout):
    import jpype
    from generic.jar import ResourceFile
    from ghidra.app.script import GhidraScriptUtil, GhidraState, ScriptControls
    from ghidra.program.util import ProgramLocation
    from java.io import PrintWriter, StringWriter

    script_file = ResourceFile(str(source))
    provider = GhidraScriptUtil.getProvider(script_file)
    if provider is None:
        raise ValueError(f"No Ghidra script provider accepts {source.name}")
    output = StringWriter()
    writer = PrintWriter(output)
    instance = provider.getScriptInstance(script_file, writer)
    if instance is None:
        raise ValueError(f"Ghidra could not compile/load {source.name}: {output}")
    instance.setScriptArgs(jpype.JArray(jpype.JString)(script_args or []))
    location = ProgramLocation(call.program, call.program.getMinAddress())
    project = call.context.project
    if hasattr(project, "getProject"):
        project = project.getProject()
    state = GhidraState(None, project, call.program, location, None, None)
    with _deadline(call, timeout):
        instance.execute(state, ScriptControls(writer, writer, call.monitor))
    writer.flush()
    text = str(output)
    if len(text) > MAX_OUTPUT_CHARS:
        raise ValueError("Script output exceeds the output limit")
    return {"path": str(source), "stdout": text, "result": None}
