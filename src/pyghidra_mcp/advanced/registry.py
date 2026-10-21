"""Schema-preserving registration for the independently implemented public catalog.

Only decorated handlers in the fixed module list are eligible for registration.
The reference snapshot describes interfaces, not implementation or test status.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import importlib
import inspect
import json
import math
import threading
import time
import uuid
import weakref
from pathlib import Path
from typing import Any, ClassVar

import anyio
from jsonschema import Draft202012Validator
from mcp.server.fastmcp.tools.base import Tool
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase, FuncMetadata
from mcp.types import Tool as PublicTool, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, create_model, model_validator

from pyghidra_mcp.telemetry import measure

from .core import Operation, json_value

MODULES = (
    "lifecycle",
    "listing_memory",
    "control_flow",
    "decompiler",
    "functions",
    "types_layout",
    "annotations",
    "symbols_references",
    "trusted",
)
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
OUTPUT_SCHEMA = {"type": "object", "additionalProperties": True}
_RUNTIME_LOCK = threading.Lock()
_OWNER_LOCK = threading.Lock()
# Weak references prevent a disconnected transport retaining its project/session graph.
_OWNERS: dict[int, tuple[weakref.ReferenceType, str]] = {}
_CONNECTION_SCOPE: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "advanced_mcp_connection", default=None
)


def reference_catalog() -> dict:
    return json.loads(Path(__file__).with_name("reference_catalog.json").read_text())


def input_schema(spec: dict) -> dict:
    schema = {
        "type": "object",
        "properties": copy.deepcopy(spec["properties"]),
        "required": list(spec["required"]),
        "additionalProperties": False,
    }
    for name, default in spec.get("defaults", {}).items():
        schema["properties"][name]["default"] = copy.deepcopy(default)
    return schema


def _module_operations(module):
    for handler in vars(module).values():
        definition = getattr(handler, "__operation__", None)
        if definition is None or getattr(handler, "__module__", None) != module.__name__:
            continue
        if not isinstance(definition, Operation) or definition.handler is not handler:
            raise ValueError(f"Invalid operation metadata in {module.__name__}")
        yield definition


def _validate_operation_metadata(definition: Operation) -> None:
    if definition.kind not in {"read", "write", "project", "script"}:
        raise ValueError(f"Invalid operation kind: {definition.name}")
    if (
        not definition.api.strip()
        or not math.isfinite(definition.timeout)
        or definition.timeout <= 0
    ):
        raise ValueError(f"Missing API evidence or invalid deadline: {definition.name}")
    if not isinstance(definition.version, str) or not definition.version.strip():
        raise ValueError(f"Missing API version: {definition.name}")


def _validate_handler_parameters(definition: Operation, spec: dict) -> None:
    parameters = inspect.signature(definition.handler).parameters
    if "call" not in parameters:
        raise ValueError(f"Missing Call parameter: {definition.name}")
    accepts_extra = any(p.kind == p.VAR_KEYWORD for p in parameters.values())
    public = set(spec["properties"]) - {"session_id"}
    explicit = {
        name
        for name, parameter in parameters.items()
        if name != "call" and parameter.kind != parameter.VAR_KEYWORD
    }
    if explicit - public or (public - explicit and not accepts_extra):
        raise ValueError(
            f"Handler parameters differ from source: {definition.name}: "
            f"missing={sorted(public - explicit)}, extra={sorted(explicit - public)}"
        )
    if definition.program and "session_id" not in spec["properties"]:
        raise ValueError(f"Program operation has no source session_id: {definition.name}")


def build_operations(*, strict: bool = True) -> dict[str, Operation]:
    """Discover handlers and validate source signatures and implementation metadata."""
    operations = {}
    specs = {item["name"]: item for item in reference_catalog()["tools"]}
    if len(specs) != 212:
        raise ValueError("The pinned reference must contain exactly 212 distinct tools")
    for suffix in MODULES:
        module = importlib.import_module(f"{__package__}.{suffix}")
        for definition in _module_operations(module):
            if definition.name in operations:
                raise ValueError(f"Duplicate operation: {definition.name}")
            if definition.name not in specs:
                raise ValueError(f"Unknown public operation: {definition.name}")
            _validate_operation_metadata(definition)
            _validate_handler_parameters(definition, specs[definition.name])
            operations[definition.name] = definition
    missing = set(specs) - set(operations)
    if strict and missing:
        raise ValueError(f"Missing public handlers ({len(missing)}): {', '.join(sorted(missing))}")
    return operations


def owner_from_context(context) -> str:
    """Return an unforgeable connection identity, never a caller-supplied session ID."""
    try:
        session = context.request_context.session
    except (AttributeError, LookupError, ValueError) as exc:
        raise ValueError("An active MCP request context and session are required") from exc
    return owner_from_session(session)


def owner_from_session(session) -> str:
    """Resolve a raw ServerSession for request dispatch and transport cleanup."""
    if session is None:
        raise ValueError("An active MCP transport session is required")
    identity = id(session)
    with _OWNER_LOCK:
        entry = _OWNERS.get(identity)
        if entry is not None and entry[0]() is session:
            return entry[1]
        try:
            reference = weakref.ref(session, lambda ref: _release_owner(identity, ref))
        except TypeError as exc:
            raise ValueError(
                "MCP transport session must support connection identity tracking"
            ) from exc
        token = uuid.uuid4().hex
        _OWNERS[identity] = (reference, token)
        return token


def _release_owner(identity, reference):
    with _OWNER_LOCK:
        entry = _OWNERS.get(identity)
        if entry is not None and entry[0] is reference:
            del _OWNERS[identity]


def track_owner(runtime, owner: str) -> None:
    scope = _CONNECTION_SCOPE.get()
    if scope is not None:
        scope[(id(runtime), owner)] = (runtime, owner)


def install_owner_cleanup(server) -> None:
    """Revoke sessions and revert pending changes when their MCP transport ends."""
    backend = server._mcp_server
    if getattr(backend, "_advanced_owner_cleanup", False):
        return
    original_run = backend.run

    async def run_connection(*args, **kwargs):
        scope = {}
        token = _CONNECTION_SCOPE.set(scope)
        try:
            return await original_run(*args, **kwargs)
        finally:
            _CONNECTION_SCOPE.reset(token)
            cancelled = False
            with anyio.CancelScope(shield=True):
                for runtime, owner in scope.values():
                    cleanup = asyncio.create_task(asyncio.to_thread(runtime.close_owner, owner))
                    while True:
                        try:
                            await asyncio.shield(cleanup)
                            break
                        except asyncio.CancelledError:
                            cancelled = True
                            if cleanup.done():
                                cleanup.result()
                                break
            if cancelled:
                raise asyncio.CancelledError

    backend.run = run_connection
    backend._advanced_owner_cleanup = True


def get_runtime(context):
    """Initialize runtime state only when a real request needs it."""
    from .runtime import AdvancedRuntime

    with _RUNTIME_LOCK:
        runtime = getattr(context, "_advanced_runtime", None)
        if runtime is None:
            runtime = AdvancedRuntime(context)
            context._advanced_runtime = runtime
        return runtime


async def settled_thread_call(function, *args):
    """Never abandon a live JVM operation on request cancellation.

    The runtime keeps its lock/transaction until the worker completes. Cancellation
    is propagated only afterwards, including repeated cancellation requests.
    """
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    cancelled = False
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            cancelled = True
            if task.done():
                # Retrieve a worker exception even when cancellation wins the race.
                result = task.result()
                break
    if cancelled:
        raise asyncio.CancelledError
    return result


def normalize_result(result) -> dict:
    result = json_value(result)
    output = result if isinstance(result, dict) else {"result": result}
    if len(json.dumps(output, ensure_ascii=False, allow_nan=False).encode()) > MAX_OUTPUT_BYTES:
        raise ValueError(
            f"Result exceeds the {MAX_OUTPUT_BYTES}-byte response limit; narrow the query"
        )
    return output


class _SourceArguments(ArgModelBase):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_schema: ClassVar[dict] = {}

    def model_dump_one_level(self):
        return {
            field.alias or name: getattr(self, name)
            for name, field in type(self).model_fields.items()
        }

    @model_validator(mode="before")
    @classmethod
    def validate_source(cls, value):
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
        if len(encoded) > MAX_INPUT_BYTES:
            raise ValueError(f"Arguments exceed the {MAX_INPUT_BYTES}-byte request limit")
        errors = sorted(
            Draft202012Validator(cls.source_schema).iter_errors(value),
            key=lambda error: str(list(error.absolute_path)),
        )
        if errors:
            error = errors[0]
            location = ".".join(map(str, error.absolute_path)) or "arguments"
            raise ValueError(f"{location}: {error.message}")
        return value


class _SourceMetadata(FuncMetadata):
    def pre_parse_json(self, data):
        # JSON strings are not silently coerced to arrays/objects against the public schema.
        return data

    async def call_fn_with_arg_validation(self, *args, **kwargs):
        with measure("mcp_request"):
            return await super().call_fn_with_arg_validation(*args, **kwargs)


class _ObjectOutput(BaseModel):
    model_config = ConfigDict(extra="allow")


def _python_type(schema):
    types = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "object": dict[str, Any],
        "array": list[Any],
        "null": type(None),
    }
    kind = schema.get("type")
    if isinstance(kind, list):
        annotation = types.get(kind[0], Any)
        for alternative in kind[1:]:
            annotation = annotation | types.get(alternative, Any)
        return annotation
    alternatives = schema.get("oneOf", schema.get("anyOf"))
    if alternatives:
        annotation = _python_type(alternatives[0])
        for alternative in alternatives[1:]:
            annotation = annotation | _python_type(alternative)
        return annotation
    return types.get(kind, Any)


def make_tool(definition: Operation, spec: dict) -> Tool:
    """Build a FastMCP Tool with exact public names, source schemas and strict inputs."""
    schema = input_schema(spec)
    fields = {}
    for name, prop in spec["properties"].items():
        annotation = _python_type(prop)
        default = ... if name in spec["required"] else spec.get("defaults", {}).get(name)
        if default is None:
            annotation = annotation | None
        fields[f"argument_{name}"] = (annotation, Field(default=default, alias=name))
    arguments = create_model(
        definition.name.replace(".", "_") + "Arguments", __base__=_SourceArguments, **fields
    )
    arguments.source_schema = schema

    async def invoke_tool(_mcp_context=None, **arguments):
        owner = owner_from_context(_mcp_context)
        context = _mcp_context.request_context.lifespan_context
        if context is None:
            raise ValueError("The MCP lifespan has no Ghidra context")
        runtime = get_runtime(context)
        track_owner(runtime, owner)
        started = time.monotonic()
        result = await settled_thread_call(runtime.invoke, definition, arguments, owner)
        # A deadline is reported after the operation settles, never while a Java
        # mutation can still run without its enclosing program lock.
        if time.monotonic() - started > definition.timeout:
            raise TimeoutError(
                f"{definition.name} exceeded its {definition.timeout:g}-second deadline; "
                "the operation has completed; inspect state before retrying"
            )
        return normalize_result(result)

    return Tool(
        name=definition.name,
        fn=invoke_tool,
        description=(
            inspect.getdoc(definition.handler)
            or f"Invoke {definition.name} through {definition.api}."
        ),
        parameters=schema,
        fn_metadata=_SourceMetadata(
            arg_model=arguments, output_schema=OUTPUT_SCHEMA, output_model=_ObjectOutput
        ),
        is_async=True,
        context_kwarg="_mcp_context",
        annotations=ToolAnnotations(
            readOnlyHint=definition.kind == "read",
            destructiveHint=definition.kind in {"write", "script"},
            openWorldHint=definition.kind in {"project", "script"},
        ),
        meta={
            "source_revision": reference_catalog()["source_revision"],
            "api": definition.api,
            "api_version": definition.version,
            "kind": definition.kind,
            "timeout_seconds": definition.timeout,
            "max_output_bytes": MAX_OUTPUT_BYTES,
        },
    )


def register_advanced_tools(server) -> None:
    operations = build_operations()
    specs = {item["name"]: item for item in reference_catalog()["tools"]}
    tools = [make_tool(definition, specs[name]) for name, definition in operations.items()]
    for tool in tools:
        if server._tool_manager.get_tool(tool.name) is not None:
            raise ValueError(f"Tool already registered: {tool.name}")
    # FastMCP 1.x has no public API for inserting an already constructed Tool.
    for tool in tools:
        server._tool_manager._tools[tool.name] = tool
    install_owner_cleanup(server)


def static_tool_catalog() -> list[PublicTool]:
    """Discover worker tools without opening a project or starting a JVM."""
    from .legacy import legacy_tools

    specs = {item["name"]: item for item in reference_catalog()["tools"]}
    tools = legacy_tools() + [
        make_tool(operation, specs[name]) for name, operation in build_operations().items()
    ]
    return [
        PublicTool(
            name=tool.name,
            description=tool.description,
            inputSchema=tool.parameters,
            outputSchema=tool.output_schema,
            annotations=tool.annotations,
            _meta=tool.meta,
        )
        for tool in tools
    ]


def equivalence_matrix(*, evidence_path: str | Path | None = None) -> list[dict]:
    """Describe capabilities separately from registration and observed runtime proof.

    Evidence is supplied by the real-Ghidra runner. Missing evidence is null, not
    a successful test claim. Rows are always keyed by the 212 original names.
    """
    from .legacy import LEGACY_CAPABILITIES

    operations = build_operations(strict=False)
    evidence = {}
    if evidence_path is not None:
        document = json.loads(Path(evidence_path).read_text())
        evidence = document.get("tools", {})
        if not isinstance(evidence, dict):
            raise ValueError("Runtime evidence must contain a tools object keyed by public name")
    rows = []
    for spec in reference_catalog()["tools"]:
        name = spec["name"]
        definition = operations.get(name)
        equivalents = [
            {
                "name": legacy,
                "relationship": capability["relationship"],
                "capability": capability["capability"],
            }
            for legacy, capability in LEGACY_CAPABILITIES.items()
            if name in capability["advanced"]
        ]
        rows.append(
            {
                "original_name": name,
                "public_name": name if definition else None,
                "existing_equivalent": equivalents,
                "api": definition.api if definition else None,
                "api_version": definition.version if definition else None,
                "kind": definition.kind if definition else None,
                "input": input_schema(spec),
                "output": copy.deepcopy(OUTPUT_SCHEMA),
                "state": "implemented" if definition else "missing",
                "real_test": evidence.get(name),
            }
        )
    return rows
