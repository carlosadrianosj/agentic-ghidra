"""One MCP endpoint routing explicitly to isolated, owned Ghidra worker processes."""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import signal
import sys
from asyncio.streams import FlowControlMixin
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

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
from pyghidra_mcp.supervisor_runtime import (
    SupervisorConfig,
    SupervisorRuntime,
    load_config,
    reserve_port,
)

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


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], isError=True
    )


def create_server(runtime: SupervisorRuntime) -> Server:
    server = Server("ghidra-advanced-mcp", version=__version__)
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
            "project. In-flight requests may fail and are never replayed or rerouted. "
            "Forced shutdown is reported because it risks unsaved changes."
        ),
        inputSchema={
            "type": "object",
            "properties": {"worker_id": {"type": "string", "minLength": 1}},
            "required": ["worker_id"],
            "additionalProperties": False,
        },
        annotations=types.ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=False
        ),
    )

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [*(routed_tool(tool) for tool in runtime.tools), status_tool, restart_tool]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        try:
            if name == "worker_status":
                if "worker_id" in arguments:
                    return _result(runtime.worker(arguments["worker_id"]).status())
                return _result(
                    {"workers": [worker.status() for worker in runtime.workers.values()]}
                )
            if name == "worker_restart":
                return _result(await runtime.restart(arguments.get("worker_id")))
            if name not in {tool.name for tool in runtime.tools}:
                return _error(f"Unknown tool: {name}")
            # Return the original result object: content, structuredContent, isError and metadata.
            return await runtime.call(name, arguments)
        except Exception as exc:
            return _error(str(exc))

    return server


class _HTTPApp:
    def __init__(self, manager: StreamableHTTPSessionManager):
        self.manager = manager

    async def __call__(self, scope, receive, send) -> None:
        await self.manager.handle_request(scope, receive, send)


def create_http_app(server: Server, host: str, port: int) -> Starlette:
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

    return Starlette(
        routes=[Route("/mcp", _HTTPApp(manager), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )


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


async def run_supervisor(config: SupervisorConfig, host: str, port: int, transport: str) -> None:
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
            app = create_http_app(server, host, port)
            http_server = uvicorn.Server(
                uvicorn.Config(
                    app, host=host, port=port, log_level="info", timeout_graceful_shutdown=10
                )
            )
            logger.info("Supervisor MCP endpoint: http://%s:%s/mcp", host, port)
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
def main(config_path: Path, host: str, port: int, transport: str) -> None:
    """Serve existing Ghidra tools through explicitly selected isolated workers.

    Config paths are relative to the JSON file. Each worker requires worker_id,
    port and project_path; project_name defaults to my_project, max_workers to 1
    and input_paths to []. Use separate, non-nested project directories. Optional
    log_directory defaults to .runtime/logs; startup_timeout defaults to 180s and
    shutdown_timeout to 60s. Shutdown first sends SIGINT to save and close each
    project, then escalates with an unsaved-changes warning if the deadline expires.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    try:
        config = load_config(config_path, supervisor_port=port)
        asyncio.run(run_supervisor(config, host, port, transport))
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Supervisor stopped; owned workers have been shut down")
    except (OSError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


if __name__ == "__main__":
    main()
