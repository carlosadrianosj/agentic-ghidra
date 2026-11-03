"""One MCP endpoint routing explicitly to isolated, owned Ghidra worker processes."""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import os
import signal
import sys
from asyncio.streams import FlowControlMixin
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import anyio
import click
import uvicorn
from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.routing import Route

from pyghidra_mcp import __version__
from pyghidra_mcp.rest_api import create_api_routes
from pyghidra_mcp.supervisor_runtime import (
    SupervisorConfig,
    SupervisorRuntime,
    load_config,
    reserve_port,
)
from pyghidra_mcp.telemetry import METRICS, measure

logger = logging.getLogger(__name__)


def routed_tool(tool: types.Tool) -> types.Tool:
    """Keep the original schema and metadata, adding only explicit worker routing."""
    schema = copy.deepcopy(tool.inputSchema)
    properties = schema.setdefault("properties", {})
    if "worker_id" in properties:
        raise ValueError(f"Worker tool {tool.name} already declares worker_id")
    properties["worker_id"] = {
        "type": "string",
        "minLength": 1,
        "description": (
            "Explicit target worker ID from worker_status; never automatically rerouted."
        ),
    }
    schema["required"] = [*schema.get("required", []), "worker_id"]
    return tool.model_copy(update={"inputSchema": schema}, deep=True)


def _result(value: dict[str, Any]) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(value))],
        structuredContent=value,
    )

def _error(message: str, kind: str | None = None) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        structuredContent={"error": message, "kind": kind} if kind else None,
        isError=True,
    )


_transport_owners: ContextVar[set[object] | None] = ContextVar(
    "supervisor_transport_owners", default=None
)


class _OwnedServer(Server):
    """Release upstream ownership when the downstream MCP transport finishes."""

    def __init__(self, runtime: SupervisorRuntime):
        super().__init__("agentic-ghidra", version=__version__)
        self.runtime = runtime

    async def run(self, *args, **kwargs) -> None:
        owners: set[object] = set()
        token = _transport_owners.set(owners)
        try:
            await super().run(*args, **kwargs)
        finally:
            _transport_owners.reset(token)
            # HTTP DELETE cancels an AnyIO scope; shield against its level
            # cancellation as well as direct asyncio task cancellation.
            with anyio.CancelScope(shield=True):
                cleanup = asyncio.gather(
                    *(self.runtime.release_owner(owner) for owner in owners)
                )
                while True:
                    try:
                        await asyncio.shield(cleanup)
                        break
                    except asyncio.CancelledError:
                        if cleanup.done():
                            cleanup.result()
                            break


def _management_tools() -> list[types.Tool]:
    """Describe supervisor-only controls without coupling schema construction to routing."""
    status_tool = types.Tool(
        name="worker_status",
        description=(
            "Inspect owned workers, project identities, process state, logs and recent failures."
        ),
        inputSchema={
            "type": "object",
            "properties": {"worker_id": {"type": "string", "minLength": 1}},
            "additionalProperties": False,
        },
        annotations=types.ToolAnnotations(readOnlyHint=True),
    )
    restart_tool = types.Tool(
        name="worker_restart",
        description=(
            "Explicitly stop, save and close one worker, then reconnect a replacement for the same "
            "project. Refuses active or queued calls unless force=true explicitly accepts unknown "
            "outcomes. Requests are never replayed or rerouted; shutdown save failures "
            "are reported."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "worker_id": {"type": "string", "minLength": 1},
                "force": {
                    "type": "boolean",
                    "default": False,
                    "description": "Override busy refusal; in-flight outcomes may be unknown.",
                },
            },
            "required": ["worker_id"],
            "additionalProperties": False,
        },
        annotations=types.ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=False
        ),
    )
    lifecycle_tools = [
        types.Tool(
            name=name,
            description=description,
            inputSchema={
                "type": "object",
                "properties": {
                    "worker_id": {"type": "string", "minLength": 1},
                    **(
                        {
                            "force": {
                                "type": "boolean",
                                "default": False,
                                "description": "Override busy refusal with unknown-outcome risk.",
                            }
                        }
                        if name == "worker_stop"
                        else {}
                    ),
                },
                "required": ["worker_id"],
                "additionalProperties": False,
            },
            annotations=types.ToolAnnotations(readOnlyHint=False, destructiveHint=False),
        )
        for name, description in (
            (
                "worker_start",
                "Start the explicitly selected worker on demand, respecting the active JVM cap.",
            ),
            (
                "worker_stop",
                "Save and close the selected worker. Refuses busy workers unless "
                "force=true; never evicts others.",
            ),
        )
    ]
    investigation_tools = [
        types.Tool(
            name="investigation.create",
            description=(
                "Snapshot one binary once and create isolated per-team projects, indexes "
                "and workers. Teams investigate the same immutable source independently; "
                "original source is never mutated."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "minLength": 1},
                    "teams": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 2,
                        "uniqueItems": True,
                    },
                    "name": {"type": ["string", "null"], "default": None},
                    "start": {"type": "boolean", "default": True},
                },
                "required": ["binary_path", "teams"],
                "additionalProperties": False,
            },
            annotations=types.ToolAnnotations(readOnlyHint=False, destructiveHint=False),
        ),
        types.Tool(
            name="investigation.list",
            description="List persisted investigations and their isolated team workers.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
            annotations=types.ToolAnnotations(readOnlyHint=True),
        ),
        types.Tool(
            name="investigation.status",
            description=(
                "Inspect one investigation's immutable source identity and per-team worker states."
            ),
            inputSchema={
                "type": "object",
                "properties": {"investigation_id": {"type": "string", "minLength": 1}},
                "required": ["investigation_id"],
                "additionalProperties": False,
            },
            annotations=types.ToolAnnotations(readOnlyHint=True),
        ),
    ]
    return [status_tool, restart_tool, *lifecycle_tools, *investigation_tools]


async def _dispatch(
    runtime: SupervisorRuntime, name: str, arguments: dict[str, Any], owner: object
) -> types.CallToolResult:
    try:
        if name == "worker_status":
            if "worker_id" in arguments:
                return _result(runtime.worker(arguments["worker_id"]).status())
            return _result(
                {
                    "workers": [worker.status() for worker in runtime.workers.values()],
                    "max_active_workers": runtime.config.max_active_workers,
                    "metrics": METRICS.snapshot(),
                }
            )
        if name in {"worker_start", "worker_stop", "worker_restart"}:
            method = {
                "worker_start": runtime.start_worker,
                "worker_stop": runtime.stop_worker,
                "worker_restart": runtime.restart,
            }[name]
            options = {} if name == "worker_start" else {"force": arguments.get("force", False)}
            return _result(await method(arguments.get("worker_id"), **options))
        if name.startswith("investigation."):
            return await _dispatch_investigation(runtime, name, arguments)
        if not any(tool.name == name for tool in runtime.tools):
            return _error(f"Unknown tool: {name}")
        # Ownership comes only from MCP transport session identity, never caller metadata.
        return await runtime.call(name, arguments, owner=owner)
    except Exception as exc:
        return _error(str(exc), type(exc).__name__)


async def _dispatch_investigation(
    runtime: SupervisorRuntime, name: str, arguments: dict[str, Any]
) -> types.CallToolResult:
    if name == "investigation.create":
        return _result(
            await runtime.investigations.create(
                arguments.get("binary_path"),
                arguments.get("teams"),
                name=arguments.get("name"),
                start=arguments.get("start", True),
            )
        )
    if name == "investigation.list":
        return _result(runtime.investigations.list())
    if name == "investigation.status":
        return _result(await runtime.investigations.status(arguments.get("investigation_id")))
    return _error(f"Unknown tool: {name}")


def create_server(runtime: SupervisorRuntime) -> Server:
    server = _OwnedServer(runtime)
    management_tools = _management_tools()

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            *(routed_tool(tool) for tool in runtime.tools),
            *management_tools,
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        owner = server.request_context.session
        owners = _transport_owners.get()
        if owners is None:
            raise RuntimeError("Supervisor request has no owning MCP transport")
        owners.add(owner)
        with measure("mcp_request"):
            result = await _dispatch(runtime, name, arguments, owner)
            if result.isError:
                METRICS.error("mcp_request")
            return result

    return server


class _HTTPApp:
    def __init__(self, manager: StreamableHTTPSessionManager):
        self.manager = manager

    async def __call__(self, scope, receive, send) -> None:
        await self.manager.handle_request(scope, receive, send)


def create_http_app(
    server: Server, host: str, port: int, runtime: SupervisorRuntime | None = None,
    rest_api_key: str | None = None,
) -> Starlette:
    advertised_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    allowed = {
        f"{advertised_host}:{port}",
        f"127.0.0.1:{port}",
        f"localhost:{port}",
        f"[::1]:{port}",
    }
    manager = StreamableHTTPSessionManager(
        app=server,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=sorted(allowed),
            allowed_origins=sorted(f"http://{value}" for value in allowed),
        ),
    )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with manager.run():
            yield

    routes = [Route("/mcp", _HTTPApp(manager), methods=["GET", "POST", "DELETE"])]
    if runtime is not None:
        routes.extend(
            create_api_routes(
                runtime, _dispatch, _management_tools(), api_key=rest_api_key
            )
        )
    return Starlette(routes=routes, lifespan=lifespan)


class _StdinLines:
    def __init__(self, reader: asyncio.StreamReader):
        self.reader = reader

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        line = await self.reader.readline()
        if not line:
            raise StopAsyncIteration
        return line.decode("utf-8")


class _StdoutLines:
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer

    async def write(self, text: str) -> None:
        self.writer.write(text.encode("utf-8"))
        await self.writer.drain()

    async def flush(self) -> None:
        await self.writer.drain()


@asynccontextmanager
async def _stdio_streams():
    # MCP's default stdin reader uses an uncancellable blocking worker thread.
    # Native pipe transports keep Ctrl+C responsive even with an idle client.
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=sys.maxsize)
    read_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer
    )
    write_transport = None
    try:
        write_transport, protocol = await loop.connect_write_pipe(
            lambda: FlowControlMixin(loop=loop), sys.stdout.buffer
        )
        writer = asyncio.StreamWriter(write_transport, protocol, reader, loop)
        async with stdio_server(stdin=_StdinLines(reader), stdout=_StdoutLines(writer)) as streams:
            yield streams
    finally:
        read_transport.close()
        if write_transport is not None:
            write_transport.close()


async def _close_after_cancellation(runtime: SupervisorRuntime) -> None:
    # Cleanup has its own task so uvicorn/stdio cancellation cannot interrupt JVM saving.
    cleanup = asyncio.create_task(runtime.close(), name="supervisor-shutdown")
    while True:
        try:
            await asyncio.shield(cleanup)
            return
        except asyncio.CancelledError:
            if cleanup.done():
                cleanup.result()
                return
            logger.warning("Shutdown is still saving worker projects; waiting for owned processes")


async def run_supervisor(
    config: SupervisorConfig, host: str, port: int, transport: str, rest_api_key: str | None = None
) -> None:
    if os.environ.get("GHIDRA_ADVANCED_TRUSTED_CODE", "").lower() in {"1", "true", "yes"}:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host.lower() == "localhost"
        if not loopback:
            raise ValueError("Trusted code execution requires a loopback-only supervisor")
    runtime = SupervisorRuntime(config)
    listener = reserve_port(host, port) if transport == "streamable-http" else None
    loop = asyncio.get_running_loop()
    current = asyncio.current_task()
    signal_installed = False
    if current is not None:
        try:
            loop.add_signal_handler(signal.SIGTERM, current.cancel)
            signal_installed = True
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await runtime.start()
        server = create_server(runtime)
        if transport == "stdio":
            async with _stdio_streams() as (read_stream, write_stream):
                await server.run(read_stream, write_stream, server.create_initialization_options())
        else:
            app = create_http_app(server, host, port, runtime=runtime, rest_api_key=rest_api_key)
            http_server = uvicorn.Server(
                uvicorn.Config(
                    app, host=host, port=port, log_level="info", timeout_graceful_shutdown=10
                )
            )
            logger.info("Supervisor MCP endpoint: http://%s:%s/mcp", host, port)
            logger.info("Supervisor REST API: http://%s:%s/api/v1/tools", host, port)
            await http_server.serve(sockets=[listener])
    finally:
        await _close_after_cancellation(runtime)
        if listener is not None:
            listener.close()
        if signal_installed:
            loop.remove_signal_handler(signal.SIGTERM)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__)
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=29840, type=click.IntRange(1, 65535), show_default=True)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "streamable-http"]),
    default="streamable-http",
    show_default=True,
)
@click.option(
    "--rest-api-key",
    "rest_api_key",
    default=None,
    envvar="GHIDRA_ADVANCED_REST_API_KEY",
    help=(
        "SHA-256 hex digest required as Bearer token or X-API-Key on /api/v1 routes. "
        "Unset means trusted dev mode with a shared local owner."
    ),
)
def main(
    config_path: Path, host: str, port: int, transport: str, rest_api_key: str | None
) -> None:
    """Serve existing Ghidra tools through explicitly selected isolated workers.

    Config paths are relative to the JSON file. Each worker requires worker_id,
    port and project_path; project_name defaults to my_project, max_workers to 1
    and input_paths to []. Workers start only on explicitly routed demand; schema
    discovery does not start a JVM. Use separate, non-nested project directories.
    max_active_workers defaults to 2; decompiler_pool_size per worker defaults to 2.
    max_queued_calls per worker defaults to 32. Background import candidate capacity
    defaults to 8 (PYGHIDRA_MCP_MAX_PENDING_IMPORTS). Stop/restart refuse active calls,
    queued work, background tasks or pending transactions unless force=true.
    Analysis task capacity defaults to 32 (PYGHIDRA_MCP_MAX_PENDING_TASKS).
    investigation_directory defaults to runtime/investigations beside the config.
    investigation.create snapshots one source binary and makes independent per-team
    projects/indexes; persisted investigations load without starting their workers.
    Optional log_directory defaults to .runtime/logs; startup_timeout defaults to
    180s and shutdown_timeout to 60s. Shutdown first sends SIGINT to save and close
    each project, then escalates with an unsaved-changes warning if the deadline expires.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    try:
        config = load_config(config_path, supervisor_port=port)
        asyncio.run(run_supervisor(config, host, port, transport, rest_api_key))
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Supervisor stopped; owned workers have been shut down")
    except (OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


if __name__ == "__main__":
    main()
