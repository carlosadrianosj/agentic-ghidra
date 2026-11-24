import asyncio
import json
import socket
import sys

import pytest

from agenticghidra_mcp.supervisor_runtime import (
    SupervisorRuntime,
    WorkerConfig,
    load_config,
    reserve_port,
)


def write_config(tmp_path, workers=None, **settings):
    if workers is None:
        workers = [
            {
                "worker_id": "analysis_a",
                "port": 29842,
                "project_path": "projects/a",
                "project_name": "analysis_a",
            },
            {
                "worker_id": "analysis_b",
                "port": 29843,
                "project_path": "projects/b",
                "project_name": "analysis_b",
            },
        ]
    path = tmp_path / "workers.json"
    path.write_text(json.dumps({"workers": workers, **settings}), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("worker_id", "analysis_a", "Duplicate worker_id"),
        ("port", 29842, "Duplicate port"),
        ("port", 29840, "supervisor port collision"),
        ("project_path", "projects/a", "share project paths"),
        ("project_path", "projects/a/nested", "share project paths"),
    ],
)
def test_rejects_nonisolated_worker_config(tmp_path, field, value, message):
    path = write_config(tmp_path)
    data = json.loads(path.read_text())
    data["workers"][1][field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=message):
        load_config(path)


def test_resolves_paths_against_config_and_accepts_gpr_convention(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    path = write_config(
        tmp_path,
        workers=[
            {
                "worker_id": "analysis_a",
                "port": 29842,
                "project_path": "projects/a/example.gpr",
                "input_paths": ["sample.bin"],
            }
        ],
    )
    config = load_config(path)
    worker = config.workers[0]
    assert worker.project.gpr_path == tmp_path / "projects/a/example.gpr"
    assert worker.project.project_name == "example"
    assert worker.project.agenticghidra_mcp_dir == tmp_path / "projects/a/example-agenticghidra-mcp"
    assert worker.input_paths == (binary,)
    assert config.log_directory == tmp_path / ".runtime/logs"


def test_rejects_symlinked_artifact_directory_shared_with_another_worker(tmp_path):
    first = tmp_path / "projects/a"
    second = tmp_path / "projects/b"
    first.mkdir(parents=True)
    second.mkdir()
    (first / "analysis_a-agenticghidra-mcp").symlink_to(second, target_is_directory=True)
    with pytest.raises(ValueError, match="artifact directories"):
        load_config(write_config(tmp_path))


def test_rejects_occupied_port_without_attaching():
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        with pytest.raises(ValueError, match="refusing to attach"):
            reserve_port("127.0.0.1", occupied.getsockname()[1])


def test_reserved_port_remains_exclusive_with_address_reuse():
    with reserve_port("127.0.0.1", 0) as reserved:
        with pytest.raises(ValueError, match="refusing to attach"):
            reserve_port("127.0.0.1", reserved.getsockname()[1])


@pytest.mark.asyncio
async def test_unknown_worker_never_falls_back_to_another_worker(tmp_path):
    runtime = SupervisorRuntime(load_config(write_config(tmp_path)))
    with pytest.raises(ValueError, match="Unknown worker_id"):
        await runtime.call("save", {"worker_id": "missing", "binary_name": "sample"})
    with pytest.raises(ValueError, match="Unknown worker_id"):
        await runtime.restart("missing")


# A real MCP subprocess, without a JVM, exercises ownership, session replacement,
# concurrency and shutdown through the same public runtime API as the CLI.
MCP_WORKER = r"""
import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path

import uvicorn
from mcp import types
from mcp.server import Server
from agenticghidra_mcp.supervisor import create_http_app

port = int(sys.argv[1])
worker_id = sys.argv[2]
if len(sys.argv) > 3 and sys.argv[3] == "ignore-interrupt":
    signal.signal(signal.SIGINT, signal.SIG_IGN)
server = Server("agenticghidra-mcp:" + os.environ["AGENTICGHIDRA_MCP_WORKER_TOKEN"])

@server.list_tools()
async def list_tools():
    return [types.Tool(name="probe", inputSchema={
        "type": "object",
        "properties": {
            "barrier": {"type": "string"},
        },
        "additionalProperties": False,
    })]

@server.call_tool()
async def probe(name, arguments):
    if "barrier" in arguments:
        barrier = Path(arguments["barrier"])
        (barrier / worker_id).touch()
        for _ in range(100):
            if all((barrier / name).exists() for name in ("analysis_a", "analysis_b")):
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("Other worker could not operate concurrently")
    return types.CallToolResult(
        content=[],
        structuredContent={"worker": worker_id, "pid": os.getpid()},
    )

http_server = uvicorn.Server(uvicorn.Config(
    create_http_app(server, "127.0.0.1", port), host="127.0.0.1", port=port, log_level="warning"
))
if len(sys.argv) > 3 and sys.argv[3] == "ignore-interrupt":
    http_server.capture_signals = contextlib.nullcontext
http_server.run()
"""


def dynamic_config(tmp_path, count=2, **settings):
    # Keep sockets bound while choosing ports so the two workers cannot get one port.
    reservations = [socket.socket() for _ in range(count)]
    try:
        for reservation in reservations:
            reservation.bind(("127.0.0.1", 0))
        workers = [
            {
                "worker_id": f"analysis_{chr(97 + index)}",
                "port": reservation.getsockname()[1],
                "project_path": f"projects/{index}",
                "project_name": f"analysis_{chr(97 + index)}",
            }
            for index, reservation in enumerate(reservations)
        ]
        return load_config(write_config(tmp_path, workers, startup_timeout=15, **settings))
    finally:
        for reservation in reservations:
            reservation.close()


@pytest.fixture
def probe_catalog(monkeypatch):
    from mcp import types

    from agenticghidra_mcp.advanced import registry
    monkeypatch.setattr(registry, "static_tool_catalog", lambda: [
        types.Tool(name="probe", inputSchema={
            "type": "object", "properties": {"barrier": {"type": "string"}},
            "additionalProperties": False,
        })
    ])


@pytest.mark.asyncio
async def test_workers_run_concurrently_and_restart_selected_project(
    tmp_path, monkeypatch, probe_catalog
):
    config = dynamic_config(tmp_path)
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [sys.executable, "-c", MCP_WORKER, str(worker.port), worker.worker_id],
    )
    runtime = SupervisorRuntime(config)
    try:
        await runtime.start()
        barrier = tmp_path / "barrier"
        barrier.mkdir()
        results = await asyncio.gather(
            *(
                runtime.call(
                    "probe",
                    {"worker_id": worker.worker_id, "barrier": str(barrier)},
                )
                for worker in config.workers
            )
        )
        assert all(not result.isError for result in results)
        assert {result.structuredContent["worker"] for result in results} == {
            "analysis_a",
            "analysis_b",
        }
        assert len({result.structuredContent["pid"] for result in results}) == 2
        original = runtime.worker("analysis_a").process
        untouched_pid = runtime.worker("analysis_b").status()["pid"]
        restarted = await runtime.restart("analysis_a")
        assert original.returncode is not None
        assert restarted["pid"] != original.pid
        assert restarted["project_name"] == "analysis_a"
        assert runtime.worker("analysis_b").status()["pid"] == untouched_pid
        result = await runtime.call("probe", {"worker_id": "analysis_a"})
        assert result.structuredContent["pid"] == restarted["pid"]
        await runtime.worker("analysis_a").stop()
        stopped_pid = runtime.worker("analysis_a").process.pid
        resumed = await runtime.call("probe", {"worker_id": "analysis_a"})
        assert resumed.structuredContent["pid"] != stopped_pid
    finally:
        await runtime.close()
    assert all(worker.process.returncode is not None for worker in runtime.workers.values())


@pytest.mark.asyncio
async def test_failed_demand_does_not_stop_another_worker(tmp_path, monkeypatch, probe_catalog):
    config = dynamic_config(tmp_path)
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: (
            [sys.executable, "-c", "raise SystemExit(7)"]
            if worker.worker_id == "analysis_b"
            else [sys.executable, "-c", MCP_WORKER, str(worker.port), worker.worker_id]
        ),
    )
    runtime = SupervisorRuntime(config)
    await runtime.start()
    try:
        await runtime.start_worker("analysis_a")
        with pytest.raises(RuntimeError, match="startup failed"):
            await runtime.start_worker("analysis_b")
        assert runtime.worker("analysis_a").status()["state"] == "ready"
    finally:
        await runtime.close()
    assert all(worker.process.returncode is not None for worker in runtime.workers.values())
    assert runtime.worker("analysis_b").status()["state"] == "failed"
    assert "exit 7" in runtime.worker("analysis_b").status()["recent_failure"]


@pytest.mark.asyncio
async def test_startup_refuses_endpoint_with_wrong_ownership_token(
    tmp_path, monkeypatch, probe_catalog
):
    config = dynamic_config(tmp_path, count=1)
    wrong_worker = MCP_WORKER.replace(
        'os.environ["AGENTICGHIDRA_MCP_WORKER_TOKEN"]', '"not-the-owned-worker"'
    )
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [sys.executable, "-c", wrong_worker, str(worker.port), worker.worker_id],
    )
    runtime = SupervisorRuntime(config)
    await runtime.start()
    try:
        with pytest.raises(RuntimeError, match="startup failed"):
            await runtime.start_worker("analysis_a")
    finally:
        await runtime.close()
    assert runtime.worker("analysis_a").process.returncode is not None
    assert runtime.worker("analysis_a").status()["state"] == "failed"


@pytest.mark.asyncio
async def test_forced_shutdown_reports_unsaved_change_risk(tmp_path, monkeypatch, probe_catalog):
    config = dynamic_config(tmp_path, count=1, shutdown_timeout=0.1)
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [
            sys.executable,
            "-c",
            MCP_WORKER,
            str(worker.port),
            worker.worker_id,
            "ignore-interrupt",
        ],
    )
    runtime = SupervisorRuntime(config)
    try:
        await runtime.start()
        await runtime.start_worker("analysis_a")
        await runtime.worker("analysis_a").stop()
        status = runtime.worker("analysis_a").status()
        assert status["returncode"] is not None
        assert "risks unsaved project changes" in status["recent_failure"]
    finally:
        await runtime.close()


@pytest.mark.parametrize("project_path", [".runtime/projects/a", "projects/.hidden/a"])
def test_rejects_hidden_project_path_components_before_startup(tmp_path, project_path):
    path = write_config(
        tmp_path,
        workers=[
            {
                "worker_id": "analysis_a",
                "port": 29842,
                "project_path": project_path,
            }
        ],
    )
    with pytest.raises(ValueError, match="hidden path components"):
        load_config(path)


@pytest.mark.asyncio
async def test_transport_owners_keep_distinct_upstream_sessions_and_release_only_their_own(
    tmp_path, monkeypatch, probe_catalog
):
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [sys.executable, "-c", MCP_WORKER, str(worker.port), worker.worker_id],
    )
    runtime = SupervisorRuntime(dynamic_config(tmp_path, count=1))
    first, second = object(), object()
    try:
        await runtime.start()
        await runtime.call("probe", {"worker_id": "analysis_a"}, owner=first)
        await runtime.call("probe", {"worker_id": "analysis_a"}, owner=second)
        worker = runtime.worker("analysis_a")
        assert worker.status()["client_sessions"] == 2
        first_connection = await worker.client(first)
        second_connection = await worker.client(second)
        assert first_connection.session is not second_connection.session
        await runtime.release_owner(first)
        assert first_connection.task.done()
        assert not second_connection.task.done()
        assert worker.status()["client_sessions"] == 1
        await runtime.call("probe", {"worker_id": "analysis_a"}, owner=second)
        await runtime.release_owner(second)
        assert second_connection.task.done()
        assert worker.status()["client_sessions"] == 0
    finally:
        await runtime.close()
    with reserve_port("127.0.0.1", worker.config.port):
        assert worker.process.returncode is not None


@pytest.mark.asyncio
async def test_background_worker_health_prevents_unsafe_stop_and_restart(
    tmp_path, monkeypatch, probe_catalog
):
    from mcp import types

    from agenticghidra_mcp.advanced import registry

    catalog = registry.static_tool_catalog()
    health_tool = types.Tool(
        name="health.ping", inputSchema={"type": "object", "properties": {}}
    )
    monkeypatch.setattr(registry, "static_tool_catalog", lambda: [*catalog, health_tool])
    source = MCP_WORKER.replace(
        "    })]",
        '    }), types.Tool(name="health.ping", '
        'inputSchema={"type": "object", "properties": {}})]',
        1,
    ).replace(
        '    if "barrier" in arguments:',
        '    if name == "health.ping":\n'
        '        return types.CallToolResult(content=[], '
        'structuredContent={"active_tasks": 1})\n'
        '    if "barrier" in arguments:',
        1,
    )
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [sys.executable, "-c", source, str(worker.port), worker.worker_id],
    )
    runtime = SupervisorRuntime(dynamic_config(tmp_path, count=1))
    try:
        await runtime.start()
        await runtime.start_worker("analysis_a")
        worker = runtime.worker("analysis_a")
        original_pid = worker.process.pid
        with pytest.raises(RuntimeError, match=r"active_tasks.*1"):
            await runtime.stop_worker("analysis_a")
        with pytest.raises(RuntimeError, match=r"active_tasks.*1"):
            await runtime.restart("analysis_a")
        assert worker.process.pid == original_pid
        assert worker.state == "ready"
    finally:
        await runtime.close()
