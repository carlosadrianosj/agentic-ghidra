#!/usr/bin/env python3
"""Measure isolated local JVM workers; no performance result is synthesized.

Example:
  GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/benchmark_workers.py \
      --binary /path/to/native/fixture --counts 1 2 4 --iterations 12
Artifacts and projects default to runtime/worker-benchmarks (never hidden projects).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

from pyghidra_mcp.project_spec import ProjectSpec
from pyghidra_mcp.supervisor_runtime import SupervisorConfig, SupervisorRuntime, WorkerConfig


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * fraction) - 1] if ordered else None


def unpack(result):
    if result.isError:
        raise RuntimeError("; ".join(getattr(item, "text", repr(item)) for item in result.content))
    value = result.structuredContent
    if value is None:
        texts = [item.text for item in result.content if getattr(item, "type", None) == "text"]
        if len(texts) != 1:
            raise RuntimeError("Expected one structured JSON result")
        value = json.loads(texts[0])
    # FastMCP wraps non-object return values in a result property.
    return value


def ports(count):
    held = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            held.append(sock)
        return [sock.getsockname()[1] for sock in held]
    finally:
        for sock in held:
            sock.close()


def contains_value(value, needle):
    if isinstance(value, dict):
        return any(contains_value(item, needle) for item in value.values())
    if isinstance(value, list):
        return any(contains_value(item, needle) for item in value)
    return value == needle


async def finish_worker(item, task, *, args, root, runtime, invoke):
    """Await real analysis, save a mutation, and prove it survives a safe restart."""
    worker = item["worker_id"]
    deadline = time.monotonic() + args.analysis_timeout
    while True:
        state = await invoke(worker, "task.status", task_id=task["task_id"])
        if state["status"] in {"succeeded", "completed", "failed", "cancelled", "done"}:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("Analysis task exceeded benchmark deadline")
        await asyncio.sleep(0.1)
    item["analysis_result"] = await invoke(worker, "task.result", task_id=task["task_id"])
    if item["analysis_result"]["status"] != "succeeded":
        raise RuntimeError(f"Analysis did not succeed: {item['analysis_result']}")
    item["telemetry"] = await invoke(worker, "health.ping")
    marker = f"worker-benchmark:{root.name}:{worker}"
    await invoke(
        worker,
        "comment.set",
        session_id=item["session_id"],
        address=item["function_address"],
        comment=marker,
    )
    await invoke(worker, "program.save", session_id=item["session_id"])
    item["telemetry_after_save"] = await invoke(worker, "health.ping")
    await wait_for_quiescence(worker, args.analysis_timeout, invoke)
    item["before_restart"] = runtime.worker(worker).status()
    await runtime.restart(worker)
    reopened = await invoke(
        worker,
        "program.open",
        path=str(args.binary),
        update_analysis=False,
        read_only=False,
    )
    comment = await invoke(
        worker,
        "comment.get",
        session_id=reopened["session_id"],
        address=item["function_address"],
    )
    if not contains_value(comment, marker):
        raise AssertionError(f"Saved comment did not survive worker restart: {comment}")
    item["save_reopen_integrity"] = True
    item["after_restart"] = runtime.worker(worker).status()


async def wait_for_quiescence(worker, timeout, invoke):
    deadline = time.monotonic() + timeout
    fields = (
        "active_tasks",
        "pending_transactions",
        "pending_imports",
        "analysis_pending",
        "indexing_pending",
    )
    while True:
        health = await invoke(worker, "health.ping")
        if not any(health.get(field, 0) for field in fields):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("Worker did not become quiescent before safe restart")
        await asyncio.sleep(0.1)


async def prepare_worker(config, *, args, directory, runtime, invoke):
    worker = config.worker_id
    started = time.perf_counter()
    await runtime.start_worker(worker)
    boot_seconds = time.perf_counter() - started
    started = time.perf_counter()
    opened = await invoke(
        worker,
        "program.open",
        path=str(args.binary),
        update_analysis=False,
        read_only=False,
    )
    cold_seconds = time.perf_counter() - started
    session = opened["session_id"]
    started = time.perf_counter()
    await invoke(worker, "analysis.update_and_wait", session_id=session)
    analysis_seconds = time.perf_counter() - started
    started = time.perf_counter()
    warm = await invoke(
        worker,
        "program.open",
        path=str(args.binary),
        update_analysis=False,
        read_only=False,
    )
    warm_seconds = time.perf_counter() - started
    if warm["session_id"] != session:
        await invoke(worker, "program.close", session_id=warm["session_id"])
    listing = await invoke(worker, "function.list", session_id=session, limit=100)
    functions = [item for item in listing["functions"] if not item.get("external")]
    if not functions:
        raise RuntimeError("Fixture analysis produced no nonexternal functions")
    target = next(
        (item for item in functions if item["name"] in {"main", "_main"}), functions[0]
    )["address"]
    # A separately named copy ensures another program needs real initial analysis.
    copy = directory / f"analysis-{worker}{args.binary.suffix}"
    shutil.copy2(args.binary, copy)
    other = await invoke(
        worker, "program.open", path=str(copy), update_analysis=False, read_only=False
    )
    return {
        "worker_id": worker,
        "session_id": session,
        "analysis_session_id": other["session_id"],
        "function_address": target,
        "boot_seconds": boot_seconds,
        "cold_import_seconds": cold_seconds,
        "initial_analysis_seconds": analysis_seconds,
        "warm_import_seconds": warm_seconds,
    }


async def short_reads(item, task, *, iterations, invoke, latencies):
    item["analysis_overlap_observations"] = []
    for _ in range(iterations):
        state = await invoke(item["worker_id"], "task.status", task_id=task["task_id"])
        before = time.perf_counter()
        await invoke(
            item["worker_id"],
            "decomp.function",
            session_id=item["session_id"],
            function_start=item["function_address"],
            timeout_secs=30,
        )
        duration = time.perf_counter() - before
        latencies.append(duration)
        after = await invoke(item["worker_id"], "task.status", task_id=task["task_id"])
        item["analysis_overlap_observations"].append(
            {
                "analysis_state_before_request": state["status"],
                "analysis_state_after_request": after["status"],
                "decompile_seconds": duration,
            }
        )


async def benchmark(count, args, root):
    directory = root / f"workers-{count}"
    directory.mkdir()
    configs = tuple(
        WorkerConfig(
            f"bench-{index}",
            port,
            ProjectSpec.from_cli(directory / f"project-{index}", f"bench_{index}"),
            args.max_workers,
            (),
            args.decompiler_pool_size,
        )
        for index, port in enumerate(ports(count))
    )
    runtime = SupervisorRuntime(
        SupervisorConfig(
            configs,
            directory / "logs",
            startup_timeout=args.startup_timeout,
            shutdown_timeout=120,
            max_active_workers=count,
        )
    )
    result = {"worker_count": count, "workers": [], "requests": [], "success": False}

    async def invoke(worker, operation, **arguments):
        started = time.perf_counter()
        try:
            response = unpack(await runtime.call(operation, {"worker_id": worker, **arguments}))
        except BaseException as exc:
            result["requests"].append(
                {
                    "worker_id": worker,
                    "operation": operation,
                    "seconds": time.perf_counter() - started,
                    "error": str(exc),
                }
            )
            raise
        result["requests"].append(
            {
                "worker_id": worker,
                "operation": operation,
                "seconds": time.perf_counter() - started,
                "error": None,
            }
        )
        return response

    try:
        await runtime.start()
        result["initial_status"] = [worker.status() for worker in runtime.workers.values()]
        if any(worker.process is not None for worker in runtime.workers.values()):
            raise AssertionError("Schema discovery unexpectedly started a worker")

        prepared = await asyncio.gather(
            *(
                prepare_worker(
                    config, args=args, directory=directory, runtime=runtime, invoke=invoke
                )
                for config in configs
            )
        )
        result["workers"] = prepared
        # Prime the decompiler separately from the concurrent request measurement.
        await asyncio.gather(
            *(
                invoke(
                    item["worker_id"],
                    "decomp.function",
                    session_id=item["session_id"],
                    function_start=item["function_address"],
                )
                for item in prepared
            )
        )
        tasks = await asyncio.gather(
            *(
                invoke(
                    item["worker_id"],
                    "task.analysis_update",
                    session_id=item["analysis_session_id"],
                )
                for item in prepared
            )
        )
        started = time.perf_counter()
        latencies = []

        await asyncio.gather(
            *(
                short_reads(
                    item, task, iterations=args.iterations, invoke=invoke, latencies=latencies
                )
                for item, task in zip(prepared, tasks, strict=True)
            )
        )
        elapsed = time.perf_counter() - started
        result["concurrent_decompile"] = {
            "count": len(latencies),
            "elapsed_seconds": elapsed,
            "throughput_per_second": len(latencies) / elapsed,
            "p50_seconds": percentile(latencies, 0.5),
            "p95_seconds": percentile(latencies, 0.95),
        }
        for item, task in zip(prepared, tasks, strict=True):
            await finish_worker(
                item, task, args=args, root=root, runtime=runtime, invoke=invoke
            )
        result["observed_analysis_overlap"] = any(
            observation["analysis_state_before_request"]
            == observation["analysis_state_after_request"]
            == "running"
            for item in prepared
            for observation in item["analysis_overlap_observations"]
        )
        if not result["observed_analysis_overlap"]:
            raise RuntimeError(
                "No running-analysis overlap was observed; use a fixture with longer analysis"
            )
        result["success"] = True
    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError)):
            raise
    finally:
        await runtime.close()
        result["final_status"] = [worker.status() for worker in runtime.workers.values()]
    return result


async def run(args):
    root = Path(tempfile.mkdtemp(prefix="run-", dir=args.output_directory))
    artifact = root / "measurements.json"
    payload = {
        "binary": str(args.binary),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "ghidra_install_dir": os.environ["GHIDRA_INSTALL_DIR"],
        "iterations": args.iterations,
        "max_workers_per_process": args.max_workers,
        "decompiler_pool_size": args.decompiler_pool_size,
        "created_at_unix": time.time(),
        "runs": [],
    }
    try:
        for count in args.counts:
            payload["runs"].append(await benchmark(count, args, root))
            artifact.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    finally:
        artifact.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(artifact)
    if args.cleanup_projects:
        # Only directories created by this invocation under its unique root are eligible.
        for count in args.counts:
            directory = root / f"workers-{count}"
            for index in range(count):
                project = directory / f"project-{index}"
                if project.is_dir() and project.parent == directory:
                    shutil.rmtree(project)
    return 0 if all(item["success"] for item in payload["runs"]) else 1


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--counts", type=int, nargs="+", default=[1, 2, 4], choices=[1, 2, 4])
    parser.add_argument("--iterations", type=int, default=12)
    parser.add_argument("--startup-timeout", type=float, default=240)
    parser.add_argument("--analysis-timeout", type=float, default=600)
    parser.add_argument("--decompiler-pool-size", type=int, default=2)
    parser.add_argument(
        "--max-workers",
        type=int,
        default=3,
        help=(
            "Per-process routed concurrency; use 1 for starvation comparison "
            "or 3 for shared readers."
        ),
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "runtime" / "worker-benchmarks",
    )
    parser.add_argument("--cleanup-projects", action="store_true")
    args = parser.parse_args()
    args.binary = args.binary.expanduser().resolve(strict=True)
    args.output_directory = args.output_directory.expanduser().resolve()
    if any(part.startswith(".") for part in args.output_directory.parts):
        parser.error(
            "Output directory must not contain hidden components (Ghidra projects live here)"
        )
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        parser.error("Set GHIDRA_INSTALL_DIR explicitly")
    if args.iterations < 1 or not 1 <= args.decompiler_pool_size <= 32:
        parser.error("iterations must be positive and decompiler pool size between 1 and 32")
    if not 1 <= args.max_workers <= 32:
        parser.error("max-workers must be between 1 and 32")
    if len(set(args.counts)) != len(args.counts):
        parser.error("counts must not repeat")
    args.output_directory.mkdir(parents=True, exist_ok=True)
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
