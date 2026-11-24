"""Consumer-visible demand, resource cap and unknown-outcome boundaries."""

import asyncio
import sys
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from agenticghidra_mcp.supervisor_runtime import SupervisorRuntime, WorkerConfig
from agenticghidra_mcp.telemetry import Metrics

from . import test_analysis_concurrency as analysis_fixtures, test_supervisor as supervisor_fixtures

# Explicitly register the shared fixtures without importing fixture names that
# pytest test parameters intentionally shadow.
context_factory = analysis_fixtures.context_factory
probe_catalog = supervisor_fixtures.probe_catalog
MCP_WORKER = supervisor_fixtures.MCP_WORKER
dynamic_config = supervisor_fixtures.dynamic_config


@pytest.fixture
def probe_process(monkeypatch):
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [
            sys.executable,
            "-c",
            MCP_WORKER,
            str(worker.port),
            worker.worker_id,
        ],
    )


@pytest.mark.asyncio
async def test_discovery_starts_no_process_and_demand_starts_only_target(
    tmp_path, probe_catalog, probe_process
):
    runtime = SupervisorRuntime(dynamic_config(tmp_path))
    try:
        await runtime.start()
        assert {worker.status()["state"] for worker in runtime.workers.values()} == {"stopped"}
        assert all(worker.process is None for worker in runtime.workers.values())
        result = await runtime.call("probe", {"worker_id": "analysis_b"})
        assert result.structuredContent["worker"] == "analysis_b"
        assert runtime.worker("analysis_a").process is None
        assert runtime.worker("analysis_b").status()["completed_calls"] == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_cap_never_evicts_live_project(tmp_path, probe_catalog, probe_process):
    runtime = SupervisorRuntime(replace(dynamic_config(tmp_path), max_active_workers=1))
    try:
        await runtime.start()
        await runtime.start_worker("analysis_a")
        pid = runtime.worker("analysis_a").process.pid
        with pytest.raises(RuntimeError, match="max_active_workers"):
            await runtime.call("probe", {"worker_id": "analysis_b"})
        assert runtime.worker("analysis_a").process.pid == pid
        assert runtime.worker("analysis_a").state == "ready"
        assert runtime.worker("analysis_b").process is None
        await runtime.stop_worker("analysis_a")
        result = await runtime.call("probe", {"worker_id": "analysis_b"})
        assert result.structuredContent["worker"] == "analysis_b"
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_explicit_demand_restarts_failed_worker_before_send(
    tmp_path, probe_catalog, probe_process
):
    runtime = SupervisorRuntime(dynamic_config(tmp_path, count=1))
    try:
        await runtime.start()
        await runtime.start_worker("analysis_a")
        worker = runtime.worker("analysis_a")
        pid = worker.process.pid
        worker.process.kill()
        await worker.process.wait()
        await worker._task
        result = await runtime.call("probe", {"worker_id": "analysis_a"})
        assert result.structuredContent["pid"] != pid
        assert worker.completed_calls == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_queue_depth_and_active_calls_reflect_real_requests(
    tmp_path, probe_catalog, probe_process
):
    config = dynamic_config(tmp_path, count=1)
    runtime = SupervisorRuntime(
        replace(config, workers=(replace(config.workers[0], max_queued_calls=1),))
    )
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    first = second = None
    try:
        await runtime.start()
        first = asyncio.create_task(
            runtime.call(
                "probe",
                {
                    "worker_id": "analysis_a",
                    "barrier": str(barrier),
                },
            )
        )
        for _ in range(400):
            if (barrier / "analysis_a").exists():
                break
            await asyncio.sleep(0.01)
        assert (barrier / "analysis_a").exists()
        second = asyncio.create_task(runtime.call("probe", {"worker_id": "analysis_a"}))
        for _ in range(100):
            if runtime.worker("analysis_a").queued_calls:
                break
            await asyncio.sleep(0.01)
        status = runtime.worker("analysis_a").status()
        assert status["active_calls"] == 1
        assert status["queued_calls"] == 1
        with pytest.raises(RuntimeError, match="queue is full; request not sent"):
            await runtime.call("probe", {"worker_id": "analysis_a"})
        assert runtime.worker("analysis_a").queued_calls == 1
        (barrier / "analysis_b").touch()
        await asyncio.gather(first, second)
        status = runtime.worker("analysis_a").status()
        assert status["active_calls"] == status["queued_calls"] == 0
        assert status["completed_calls"] == 2
    finally:
        (barrier / "analysis_b").touch()
        await asyncio.gather(
            *(task for task in (first, second) if task is not None), return_exceptions=True
        )
        await runtime.close()


@pytest.mark.asyncio
async def test_queued_request_never_moves_to_replacement_session(
    tmp_path, probe_catalog, probe_process
):
    runtime = SupervisorRuntime(dynamic_config(tmp_path, count=1))
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    pending = []
    try:
        await runtime.start()
        first = asyncio.create_task(
            runtime.call(
                "probe",
                {
                    "worker_id": "analysis_a",
                    "barrier": str(barrier),
                },
            )
        )
        pending.append(first)
        for _ in range(400):
            if (barrier / "analysis_a").exists():
                break
            await asyncio.sleep(0.01)
        assert (barrier / "analysis_a").exists()
        worker = runtime.worker("analysis_a")
        old_pid = worker.process.pid
        queued = asyncio.create_task(runtime.call("probe", {"worker_id": "analysis_a"}))
        pending.append(queued)
        for _ in range(100):
            if worker.queued_calls:
                break
            await asyncio.sleep(0.01)
        assert worker.queued_calls == 1
        with pytest.raises(RuntimeError, match="active or queued work"):
            await runtime.restart("analysis_a")
        with pytest.raises(RuntimeError, match="active or queued work"):
            await runtime.stop_worker("analysis_a")
        assert worker.process.pid == old_pid
        assert worker.state == "ready"
        restart = asyncio.create_task(runtime.restart("analysis_a", force=True))
        pending.append(restart)
        for _ in range(100):
            if worker.state == "stopping":
                break
            await asyncio.sleep(0.01)
        assert worker.state == "stopping"
        (barrier / "analysis_b").touch()
        with pytest.raises(RuntimeError, match="changed session; request not sent"):
            await queued
        await asyncio.gather(first, return_exceptions=True)
        replacement = await restart
        assert replacement["pid"] != old_pid
        assert worker.completed_calls <= 1
        assert worker.queued_calls == 0
    finally:
        (barrier / "analysis_b").touch()
        await asyncio.gather(*pending, return_exceptions=True)
        await runtime.close()


@pytest.mark.asyncio
async def test_sent_write_unknown_outcome_is_never_replayed(tmp_path, monkeypatch, probe_catalog):
    ledger = tmp_path / "write-ledger"
    source = MCP_WORKER.replace(
        'if "barrier" in arguments:',
        f'Path({str(ledger)!r}).open("a").write("sent\\n")\n'
        '    os._exit(9)\n    if "barrier" in arguments:',
    )
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [
            sys.executable,
            "-c",
            source,
            str(worker.port),
            worker.worker_id,
        ],
    )
    runtime = SupervisorRuntime(dynamic_config(tmp_path, count=1))
    try:
        await runtime.start()
        with pytest.raises(RuntimeError, match="not retried"):
            await runtime.call("probe", {"worker_id": "analysis_a"})
        assert ledger.read_text().splitlines() == ["sent"]
        assert runtime.worker("analysis_a").failed_calls == 1
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_task_and_session_handles_are_worker_and_generation_affine(
    tmp_path, probe_catalog, probe_process
):
    runtime = SupervisorRuntime(dynamic_config(tmp_path))
    try:
        await runtime.start()
        first = runtime.worker("analysis_a")
        second = runtime.worker("analysis_b")
        handles = runtime._scoped({"task_id": "one", "session_id": "two"}, first, incoming=False)
        assert runtime._scoped(handles, first, incoming=True) == {
            "task_id": "one",
            "session_id": "two",
        }
        with pytest.raises(ValueError, match="another worker"):
            await runtime.call("probe", {"worker_id": second.config.worker_id, **handles})
        assert second.process is None
        await runtime.start_worker(first.config.worker_id)
        with pytest.raises(ValueError, match="generation"):
            await runtime.call("probe", {"worker_id": first.config.worker_id, **handles})
        assert first.completed_calls == 0
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_shutdown_cancels_startup_and_refuses_queued_restart(
    tmp_path, monkeypatch, probe_catalog
):
    monkeypatch.setattr(
        WorkerConfig,
        "command",
        lambda worker: [
            sys.executable,
            "-c",
            "import time; time.sleep(120)",
        ],
    )
    runtime = SupervisorRuntime(dynamic_config(tmp_path, count=1))
    await runtime.start()
    startup = asyncio.create_task(runtime.start_worker("analysis_a"))
    while runtime.worker("analysis_a").process is None:
        await asyncio.sleep(0.01)
    shutdown = asyncio.create_task(runtime.close())
    with pytest.raises(RuntimeError):
        await startup
    await shutdown
    assert runtime.worker("analysis_a").process.returncode is not None
    with pytest.raises(RuntimeError, match="shutting down"):
        await runtime.restart("analysis_a")


def test_metric_samples_are_bounded_and_failures_recorded():
    metrics = Metrics(capacity=3)
    for value in range(10):
        metrics.observe("work", value, error=value == 9)
    metrics.queue("work", 2)
    metrics.queue("work", -1)
    result = metrics.snapshot()["stages"]["work"]
    assert result["count"] == 10
    assert result["errors"] == 1
    assert result["sample_count"] == 3
    assert result["p50_seconds"] == 8
    assert result["p95_seconds"] == 9
    assert result["queued"] == 1
    assert result["queue_peak"] == 2


def test_completed_index_submission_cannot_deadlock_its_completion_callback(context_factory):
    context = context_factory()
    context._index_program = type(context)._index_program.__get__(context, type(context))
    program = SimpleNamespace(
        name="index-fixture",
        analysis_complete=True,
        code_collection=None,
        strings=None,
    )
    executor = context.index_executor

    class CompletedBeforeReturn:
        def submit(self, function, *args, **kwargs):
            future = executor.submit(function, *args, **kwargs)
            future.result(timeout=2)
            return future

    def populate_strings(info):
        info.strings = ["completed-index"]

    context.index_executor = CompletedBeforeReturn()
    context._lookup_program_info = lambda name: program
    context._init_strings_for_program = populate_strings
    finished = threading.Event()
    outcomes = []

    def schedule():
        try:
            outcomes.append(context.schedule_indexing(program.name, code=False))
        finally:
            finished.set()

    thread = threading.Thread(target=schedule, daemon=True)
    try:
        thread.start()
        assert finished.wait(2), "A completed indexing future deadlocked its callback"
        assert outcomes == [True]
        assert program.strings == ["completed-index"]
        assert not context._index_futures
        assert not context.schedule_indexing(program.name, code=False)
    finally:
        context.index_executor = executor
        context.close(save=False)


def test_background_import_capacity_rejects_without_partial_enqueue(
    context_factory, monkeypatch, tmp_path
):
    import agenticghidra_mcp.context as context_module

    context = context_factory()
    context.max_pending_imports = 1
    binary = tmp_path / "fixture.bin"
    binary.write_bytes(b"import-scheduler-fixture")
    monkeypatch.setattr(
        context_module,
        "build_import_plan",
        lambda paths: SimpleNamespace(
            candidates=[SimpleNamespace(path=binary, relative_path=None)],
            skipped=[],
        ),
    )
    running = threading.Event()
    release = threading.Event()

    def importing(candidates, *, analyze):
        running.set()
        if not release.wait(5):
            raise TimeoutError("Import scheduler test was not released")
        return []

    context._import_candidates = importing
    try:
        first = context.import_binary_backgrounded(binary)
        assert first.queued_count == 1
        assert running.wait(5)
        assert context._pending_imports == 1
        with pytest.raises(RuntimeError, match="no imports queued"):
            context.import_binary_backgrounded(binary)
        assert context._pending_imports == 1
    finally:
        release.set()
        context.close(save=False)
    assert context._pending_imports == 0


@pytest.mark.asyncio
async def test_dynamic_worker_group_is_inserted_atomically_without_starting(
    tmp_path, probe_catalog
):
    config = dynamic_config(tmp_path, count=3)
    runtime = SupervisorRuntime(replace(config, workers=config.workers[:1]))
    try:
        await runtime.start()
        states = await runtime.add_workers(config.workers[1:], start=False)
        assert len(states) == 2
        assert all(state["state"] == "stopped" and state["pid"] is None for state in states)
        assert len(runtime.workers) == 3
        await runtime.remove_workers(tuple(worker.worker_id for worker in config.workers[1:]))
        assert tuple(runtime.workers) == (config.workers[0].worker_id,)
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_dynamic_worker_group_cannot_partially_insert_overlapping_projects(
    tmp_path, probe_catalog
):
    config = dynamic_config(tmp_path, count=3)
    runtime = SupervisorRuntime(replace(config, workers=config.workers[:1]))
    try:
        await runtime.start()
        first = config.workers[1]
        overlapping = replace(config.workers[2], project=first.project)
        with pytest.raises(ValueError, match="share project paths"):
            await runtime.add_workers((first, overlapping))
        assert tuple(runtime.workers) == (config.workers[0].worker_id,)
        assert runtime.worker(config.workers[0].worker_id).process is None
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_dynamic_worker_group_rejects_over_budget_start_before_insertion(
    tmp_path, probe_catalog
):
    config = dynamic_config(tmp_path, count=3)
    runtime = SupervisorRuntime(replace(config, workers=config.workers[:1], max_active_workers=1))
    try:
        await runtime.start()
        with pytest.raises(RuntimeError, match="no workers added"):
            await runtime.add_workers(config.workers[1:], start=True)
        assert tuple(runtime.workers) == (config.workers[0].worker_id,)
        assert runtime.worker(config.workers[0].worker_id).process is None
    finally:
        await runtime.close()
