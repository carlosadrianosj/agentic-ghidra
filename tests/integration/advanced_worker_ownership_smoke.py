"""Real-Ghidra multi-client ownership regression through the HTTP supervisor.

Call ``await smoke_worker_ownership(binary, scratch_directory)`` with a native
fixture and a new non-hidden scratch directory. No existing server is contacted.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack, asynccontextmanager, nullcontext
from pathlib import Path

import anyio
import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.project_spec import ProjectSpec
from pyghidra_mcp.supervisor import create_http_app, create_server
from pyghidra_mcp.supervisor_runtime import (
    SupervisorConfig,
    SupervisorRuntime,
    WorkerConfig,
    reserve_port,
)


def _value(response):
    if response.isError:
        raise AssertionError(
            "; ".join(getattr(item, "text", repr(item)) for item in response.content)
        )
    if response.structuredContent is not None:
        return response.structuredContent
    return json.loads(response.content[0].text)


async def _wait_ready(server, serving):
    with anyio.fail_after(15):
        while not server.started:
            if serving.done():
                await serving
                raise RuntimeError("Supervisor exited before readiness")
            await asyncio.sleep(0.02)


@asynccontextmanager
async def _owned_supervisor(scratch, result):
    with reserve_port("127.0.0.1", 0) as reservation:
        worker_port = reservation.getsockname()[1]
    worker = WorkerConfig(
        "ownership", worker_port, ProjectSpec.from_cli(scratch / "project", "ownership"), 4, ()
    )
    runtime = SupervisorRuntime(SupervisorConfig((worker,), scratch / "logs"))
    listener = reserve_port("127.0.0.1", 0)
    supervisor_port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            create_http_app(create_server(runtime), "127.0.0.1", supervisor_port),
            host="127.0.0.1",
            port=supervisor_port,
            log_level="warning",
        )
    )
    server.capture_signals = nullcontext
    serving = None
    try:
        await runtime.start()
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        await _wait_ready(server, serving)
        yield runtime, f"http://127.0.0.1:{supervisor_port}/mcp"
    finally:
        server.should_exit = True
        if serving is not None:
            await serving
        listener.close()
        await runtime.close()
        process = runtime.worker("ownership").process
        if process is not None and process.returncode is None:
            raise AssertionError("Ownership smoke left its worker process running")
        # Rebinding both owned ports proves cleanup, not just a state-label change.
        with reserve_port("127.0.0.1", supervisor_port):
            with reserve_port("127.0.0.1", worker_port):
                result["process_cleanup_releases_ports"] = True


async def _connect(stack, url):
    http = await stack.enter_async_context(
        httpx.AsyncClient(timeout=httpx.Timeout(10, read=None), trust_env=False)
    )
    reader, writer, _ = await stack.enter_async_context(
        streamable_http_client(url, http_client=http, terminate_on_close=True)
    )
    client = await stack.enter_async_context(ClientSession(reader, writer))
    await client.initialize()
    return client


async def _open_reader(client, binary):
    opened = _value(await client.call_tool(
        "program.open",
        {"worker_id": "ownership", "path": str(binary),
         "read_only": True, "update_analysis": False},
    ))
    return opened, {"worker_id": "ownership", "session_id": opened["session_id"]}


async def _assert_capability_privacy(first, second, target):
    _value(await first.call_tool("program.summary", target))
    denied = await second.call_tool("program.summary", target)
    if not denied.isError:
        raise AssertionError("Client B read client A's program capability through supervisor")
    visible = _value(await second.call_tool("program.list_open", {"worker_id": "ownership"}))
    if target["session_id"] in json.dumps(visible):
        raise AssertionError("program.list_open leaked another client's session")


async def _assert_shared_readers(first, opened, target, other_clients, binary):
    peers = []
    for client in other_clients:
        peer, peer_target = await _open_reader(client, binary)
        if (peer["project_id"], peer["binary_name"]) != (
            opened["project_id"], opened["binary_name"]
        ):
            raise AssertionError("Shared readers were rerouted to a different project/program")
        peers.append((client, peer_target))
    if len({target["session_id"], *(row["session_id"] for _, row in peers)}) != 3:
        raise AssertionError("Clients did not receive distinct read-only capabilities")
    reads = await asyncio.gather(
        first.call_tool("program.summary", target),
        *(client.call_tool("program.summary", peer_target) for client, peer_target in peers),
    )
    for response in reads:
        _value(response)
    return peers


async def _assert_transaction_isolation(first, second, target, peers):
    _value(await first.call_tool("program.mode.set", {**target, "read_only": False}))
    _value(await first.call_tool(
        "transaction.begin", {**target, "description": "ownership regression"},
    ))
    denied_commit = await second.call_tool("transaction.commit", target)
    if not denied_commit.isError:
        raise AssertionError("Client B committed client A's transaction")
    conflicts = await asyncio.gather(
        *(client.call_tool("program.summary", peer_target) for client, peer_target in peers)
    )
    if not all(response.isError for response in conflicts):
        raise AssertionError("A peer read through a coordinator-owned explicit transaction")
    _value(await first.call_tool("transaction.revert", target))
    for client, peer_target in peers:
        _value(await client.call_tool("program.summary", peer_target))


async def _assert_disconnected(runtime):
    # MCP DELETE closes Server.run, whose finally releases upstream ownership.
    for _ in range(200):
        if runtime.worker("ownership").status()["client_sessions"] == 0:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Disconnected downstream clients retained upstream sessions")


async def smoke_worker_ownership(binary, scratch_directory):
    binary = Path(binary).resolve(strict=True)
    scratch = Path(scratch_directory).resolve()
    scratch.mkdir(parents=True, exist_ok=False)
    result = {}
    async with _owned_supervisor(scratch, result) as (runtime, url):
        async with AsyncExitStack() as stack:
            first = await _connect(stack, url)
            second = await _connect(stack, url)
            third = await _connect(stack, url)
            opened, target = await _open_reader(first, binary)
            await _assert_capability_privacy(first, second, target)
            peers = await _assert_shared_readers(first, opened, target, (second, third), binary)
            await _assert_transaction_isolation(first, second, target, peers)
            if runtime.worker("ownership").status()["client_sessions"] != 3:
                raise AssertionError("Expected three distinct owned upstream transport sessions")
        await _assert_disconnected(runtime)
        result.update({
            "two_client_session_isolation": True,
            "transaction_isolation": True,
            "three_client_shared_readers": True,
            "peer_transaction_conflicts": True,
            "list_open_privacy": True,
            "disconnect_releases_sessions": True,
        })
    return result
