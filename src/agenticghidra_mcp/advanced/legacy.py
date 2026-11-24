"""Original public tools with unchanged signatures and shared runtime protection."""

from __future__ import annotations

import functools
import inspect
import json

from mcp.server.fastmcp.tools.base import Tool

from .core import json_value
from .registry import (
    MAX_OUTPUT_BYTES,
    get_runtime,
    owner_from_context,
    settled_thread_call,
    track_owner,
)

# Capability relationships are semantic, not aliases and not extra public tools.
# "overlap" deliberately does not assert equal parameters or identical behavior.
LEGACY_CAPABILITIES = {
    "decompile_function": {
        "advanced": ("decomp.function",),
        "relationship": "overlap",
        "capability": "function decompilation with legacy batch/enrichment",
    },
    "search_symbols_by_name": {
        "advanced": ("symbol.list", "symbol.by_name", "function.list"),
        "relationship": "overlap",
        "capability": "regular-expression symbol search",
    },
    "search_code": {
        "advanced": ("search.text",),
        "relationship": "overlap",
        "capability": "literal decompiled-code search; semantic vector search remains legacy-only",
    },
    "list_project_binaries": {
        "advanced": ("project.files.list",),
        "relationship": "overlap",
        "capability": "project program enumeration with legacy analysis status",
    },
    "list_project_binary_metadata": {
        "advanced": ("program.summary", "program.report"),
        "relationship": "overlap",
        "capability": "program architecture, hashes and analysis metadata",
    },
    "rename_function": {
        "advanced": ("function.rename",),
        "relationship": "equivalent_capability",
        "capability": "function rename",
    },
    "rename_variable": {
        "advanced": ("variable.rename",),
        "relationship": "equivalent_capability",
        "capability": "parameter or local variable rename",
    },
    "save": {
        "advanced": ("program.save",),
        "relationship": "overlap",
        "capability": "legacy saves every open program rather than one session",
    },
    "set_variable_type": {
        "advanced": ("variable.retype",),
        "relationship": "equivalent_capability",
        "capability": "parameter or local variable type change",
    },
    "set_function_prototype": {
        "advanced": ("function.signature.set",),
        "relationship": "equivalent_capability",
        "capability": "C function prototype application",
    },
    "set_comment": {
        "advanced": ("comment.set",),
        "relationship": "equivalent_capability",
        "capability": "listing/decompiler comment update",
    },
    "delete_project_binary": {
        "advanced": (),
        "relationship": "legacy_only",
        "capability": "delete a persisted program from the project, not merely close a session",
    },
    "list_exports": {
        "advanced": ("external.exports.list",),
        "relationship": "equivalent_capability",
        "capability": "exported symbol enumeration",
    },
    "list_imports": {
        "advanced": ("external.imports.list",),
        "relationship": "equivalent_capability",
        "capability": "imported symbol enumeration",
    },
    "list_xrefs": {
        "advanced": ("reference.to",),
        "relationship": "overlap",
        "capability": "incoming references with legacy name resolution/batching",
    },
    "search_strings": {
        "advanced": ("search.defined_strings",),
        "relationship": "equivalent_capability",
        "capability": "defined string search",
    },
    "read_bytes": {
        "advanced": ("memory.read",),
        "relationship": "equivalent_capability",
        "capability": "raw program-memory byte read",
    },
    "disassemble": {
        "advanced": ("listing.code_units.list",),
        "relationship": "overlap",
        "capability": "read existing instructions; does not create disassembly",
    },
    "gen_callgraph": {
        "advanced": ("function.callers", "function.callees", "graph.call_paths"),
        "relationship": "overlap",
        "capability": "legacy Mermaid multi-layer call graph rendering",
    },
    "import_binary": {
        "advanced": ("program.open",),
        "relationship": "overlap",
        "capability": "background file import versus explicit program session open",
    },
}


def _protected_handler(function):
    signature = inspect.signature(function)

    @functools.wraps(function)
    async def protected(*args, **kwargs):
        from agenticghidra_mcp.telemetry import measure

        with measure("mcp_request"):
            arguments = signature.bind(*args, **kwargs)
            arguments.apply_defaults()
            context = arguments.arguments["ctx"]
            owner = owner_from_context(context)
            lifespan = context.request_context.lifespan_context
            if lifespan is None:
                raise ValueError("The MCP lifespan has no Ghidra context")
            runtime = get_runtime(lifespan)
            track_owner(runtime, owner)
            result = await settled_thread_call(
                runtime.legacy_call, function, dict(arguments.arguments), owner
            )
            if (
                len(json.dumps(json_value(result), ensure_ascii=False, allow_nan=False).encode())
                > MAX_OUTPUT_BYTES
            ):
                raise ValueError(
                    f"Result exceeds the {MAX_OUTPUT_BYTES}-byte response limit; narrow the query"
                )
            return result

    # FastMCP inspects this signature, retaining all old parameters and output models.
    protected.__signature__ = signature
    return protected


def legacy_tools() -> list[Tool]:
    from agenticghidra_mcp import mcp_tools

    return [
        Tool.from_function(_protected_handler(getattr(mcp_tools, name)), name=name)
        for name in LEGACY_CAPABILITIES
    ]


def register_legacy_tools(server) -> None:
    tools = legacy_tools()
    for tool in tools:
        if server._tool_manager.get_tool(tool.name) is not None:
            raise ValueError(f"Tool already registered: {tool.name}")
    for tool in tools:
        server._tool_manager._tools[tool.name] = tool
