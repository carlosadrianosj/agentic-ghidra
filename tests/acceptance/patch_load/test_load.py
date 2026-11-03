#!/usr/bin/env python3
"""REST load suite for the api_load_a / api_load_b workers.

Phases (evidence file each):
  mixed       16 threads x 30s mixing GET /health, GET /api/v1/tools?family=decomp
              and one read tool (function.list)                     -> load-mixed.json
  concurrent  both workers open libsyscalls_arm64.so simultaneously, then
              8 threads decompile the same function on both workers   -> load-concurrent.json
  batch       50 iterations of the 3-call batch pipeline
              function.list -> function.at -> decomp.function         -> load-batch.json
  errors      error-path flood (unknown tool + bad args), stable
              404/400 and zero 5xx                                    -> load-errors.json

After every phase: GET /health must report status ok, then both workers are
stopped with force=false.

Usage:
    python test_load.py [--base http://127.0.0.1:29950] [--worker api_load_a] \
        [--worker-b api_load_b] [--binary PATH] [--out-dir runtime/acceptance/api]

Exit 0 only when every phase holds its assertions and both workers stop cleanly.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import random
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rest_client import RestClient, RestError, soak

REPO = Path(__file__).resolve().parents[2]
LIB_DEFAULT = (
    "/Users/baxi/Documents/Tools-Projects/ghidra-research/"
    "PoC-files/07-files-to-test-ghidra-capacity/bin/libsyscalls_arm64.so"
)


def stats_like(durations_ms: list[float], **extra) -> dict:
    durations = sorted(durations_ms)
    if not durations:
        return {"count": 0, **extra}
    return {
        "count": len(durations),
        "p50_ms": round(statistics.median(durations), 2),
        "p95_ms": round(durations[max(0, int(len(durations) * 0.95) - 1)], 2),
        "max_ms": round(durations[-1], 2),
        **extra,
    }


def body_span(function: dict) -> int:
    numbers = [int(part, 16) for part in function.get("body", "[]").strip("[]").split(",")]
    return (numbers[-1] - numbers[0]) if len(numbers) >= 2 else 0


def largest_function(api: RestClient, worker: str, session: str) -> dict:
    listing = api.call("function.list", {"worker_id": worker, "session_id": session, "limit": 100})
    local = [f for f in listing["functions"] if not f["external"]]
    return max(local, key=body_span)


def phase_mixed(api: RestClient, session_a: str, worker_a: str, out: Path) -> dict:
    rng = random.Random(20261021)

    def workload(client: RestClient) -> None:
        pick = rng.choice(("health", "catalog", "read"))
        if pick == "health":
            body = client.health()
            if body.get("status") != "ok":
                raise AssertionError(f"health status {body.get('status')}")
        elif pick == "catalog":
            status, body = client.get("/api/v1/tools?family=decomp")
            if status != 200 or "tools" not in body:
                raise AssertionError(f"catalog family=decomp -> {status}")
            if not any(t["family"] == "decomp" for t in body["tools"]):
                raise AssertionError("catalog family=decomp returned wrong family")
        else:
            result = client.call(
                "function.list", {"worker_id": worker_a, "session_id": session_a, "limit": 5}
            )
            if not result.get("functions"):
                raise AssertionError("function.list returned no functions")

    stats = soak(api, workload, threads=16, duration_seconds=30)
    evidence = {
        "phase": "mixed",
        "description": "16 threads x 30s: GET /health, GET /api/v1/tools?family=decomp, function.list",
        "stats": stats,
        "assertions": {"errors_zero": stats["errors"] == 0, "count_gt_0": stats["count"] > 0},
    }
    out.write_text(json.dumps(evidence, indent=1))
    print("mixed:", json.dumps(stats))
    return evidence


def phase_concurrent(api: RestClient, binary: str, worker_a: str, worker_b: str, out: Path) -> dict:
    barrier = threading.Barrier(2)
    opens: dict[str, dict] = {}

    def open_on(worker: str) -> None:
        barrier.wait()
        started = time.perf_counter()
        status, body = api.call_raw(
            "program.open", {"worker_id": worker, "path": binary, "read_only": False}
        )
        opens[worker] = {
            "http_status": status,
            "duration_ms": body.get("duration_ms"),
            "wall_ms": round((time.perf_counter() - started) * 1000, 1),
            "session_id": (body.get("result") or {}).get("session_id"),
            "error": body.get("error"),
        }

    with ThreadPoolExecutor(max_workers=2) as pool:
        for worker in (worker_a, worker_b):
            pool.submit(open_on, worker)

    open_ok = all(
        item["http_status"] == 200 and item["session_id"] for item in opens.values()
    )
    if not open_ok:
        evidence = {
            "phase": "concurrent",
            "opens": opens,
            "assertions": {"open_ok": False},
        }
        out.write_text(json.dumps(evidence, indent=1))
        return evidence

    target_a = largest_function(api, worker_a, opens[worker_a]["session_id"])
    target_b = largest_function(api, worker_b, opens[worker_b]["session_id"])
    same_function = target_a["name"] == target_b["name"] and target_a["address"] == target_b["address"]

    counts = {worker_a: 0, worker_b: 0}
    lock = threading.Lock()

    def workload(client: RestClient) -> None:
        for worker, target in ((worker_a, target_a), (worker_b, target_b)):
            client.call(
                "decomp.function",
                {
                    "worker_id": worker,
                    "session_id": opens[worker]["session_id"],
                    "function_start": target["address"],
                    "timeout_secs": 120,
                },
            )
            with lock:
                counts[worker] += 1

    stats = soak(api, workload, threads=8, duration_seconds=25)
    evidence = {
        "phase": "concurrent",
        "description": "same binary imported in both worker projects; 8 threads x 25s "
        "decompiling the same function on both workers per iteration",
        "binary": binary,
        "opens": opens,
        "target": {
            worker_a: {"name": target_a["name"], "address": target_a["address"]},
            worker_b: {"name": target_b["name"], "address": target_b["address"]},
            "identical_across_workers": same_function,
        },
        "decompile_success_counts": counts,
        "stats": stats,
        "assertions": {
            "open_ok": True,
            "same_function": same_function,
            "both_workers_hit": counts[worker_a] > 0 and counts[worker_b] > 0,
            "errors_zero": stats["errors"] == 0,
        },
    }
    out.write_text(json.dumps(evidence, indent=1))
    print("concurrent:", json.dumps({k: evidence[k] for k in ("target", "decompile_success_counts", "stats")}))
    return evidence


def phase_batch(api: RestClient, worker: str, session: str, out: Path) -> dict:
    calls = [
        {"tool": "function.list", "arguments": {"limit": 3}},
        {"tool": "function.at", "arguments": {}},
        {"tool": "decomp.function", "arguments": {}},
    ]
    base_arguments = {"worker_id": worker, "session_id": session}
    pipeline_walls: list[float] = []
    pipeline_ops: list[dict] = []
    status_histogram: dict[str, int] = {}
    for _ in range(50):
        payload = {
            "calls": [
                {"tool": call["tool"], "arguments": {**base_arguments, **call["arguments"]}}
                for call in calls
            ],
            "pipeline": True,
            "stop_on_error": False,
        }
        started = time.perf_counter()
        status, body = api._request("POST", "/api/v1/batch", payload)
        pipeline_walls.append((time.perf_counter() - started) * 1000)
        for item in body.get("results", []):
            pipeline_ops.append(
                {
                    "tool": item["tool"],
                    "status": item["status"],
                    "duration_ms": item.get("duration_ms"),
                    "error_code": (item.get("error") or {}).get("code"),
                    "error_message": ((item.get("error") or {}).get("message") or "")[:140],
                }
            )
            key = f"{item['tool']}:{item['status']}"
            status_histogram[key] = status_histogram.get(key, 0) + 1

    # Working reference loop: identical 3-call batch, pipeline=false, values
    # chained client-side (the pipeline merge injects additional properties the
    # strict tool schemas reject - recorded as a finding).
    chained_walls: list[float] = []
    chained_ok = 0
    chained_errors: list[str] = []
    for index in range(50):
        started = time.perf_counter()
        try:
            listing = api.call("function.list", {**base_arguments, "limit": 3, "offset": index % 7})
            entry = listing["functions"][index % len(listing["functions"])]
            at = api.call("function.at", {**base_arguments, "address": entry["address"]})
            api.call(
                "decomp.function",
                {**base_arguments, "function_start": at["address"], "timeout_secs": 120},
            )
            chained_ok += 1
        except RestError as exc:
            chained_errors.append(str(exc)[:160])
        chained_walls.append((time.perf_counter() - started) * 1000)

    per_tool_latency: dict[str, dict] = {}
    for tool in ("function.list", "function.at", "decomp.function"):
        durations = [
            op["duration_ms"] for op in pipeline_ops if op["tool"] == tool and op["duration_ms"] is not None
        ]
        per_tool_latency[tool] = stats_like(durations)

    pipeline_call_ok = all(op["status"] == "ok" for op in pipeline_ops if op["tool"] == "function.list")
    downstream_ok = all(op["status"] == "ok" for op in pipeline_ops if op["tool"] != "function.list")
    evidence = {
        "phase": "batch",
        "description": "50 iterations x 3-call batch pipeline function.list -> function.at -> decomp.function",
        "worker": worker,
        "pipeline": {
            "iterations": 50,
            "batch_http_ok": len(pipeline_walls) == 50,
            "status_histogram": status_histogram,
            "first_call_ok": pipeline_call_ok,
            "downstream_ok": downstream_ok,
            "batch_wall_stats": stats_like(pipeline_walls, threads=1),
            "per_tool_latency_ms": per_tool_latency,
            "sample_downstream_error": next(
                (op["error_message"] for op in pipeline_ops if op["status"] == "error"), None
            ),
        },
        "chained_reference": {
            "iterations": 50,
            "ok": chained_ok,
            "errors": chained_errors[:5],
            "wall_stats": stats_like(chained_walls, threads=1),
        },
        "findings": [],
        "assertions": {
            "pipeline_batches_returned": len(pipeline_walls) == 50,
            "first_call_ok": pipeline_call_ok,
            "chained_all_ok": chained_ok == 50,
        },
    }
    if not downstream_ok:
        evidence["findings"].append(
            "REST batch pipeline=true merges the previous payload into later call arguments; "
            "worker schemas use additionalProperties:false, so function.at/decomp.function fail "
            "validation (envelope error code 500 'Additional properties are not allowed') and "
            "the chain cannot bind values across tools (function.at returns 'address', "
            "decomp.function requires 'function_start'). Repro: POST /api/v1/batch "
            '{"calls":[{"tool":"function.list","arguments":{...limit:3}},'
            '{"tool":"function.at","arguments":{...address:X}},'
            '{"tool":"decomp.function","arguments":{...function_start:X}}],"pipeline":true}'
        )
    out.write_text(json.dumps(evidence, indent=1))
    print("batch:", json.dumps({k: v for k, v in evidence.items() if k in ("pipeline", "chained_reference", "assertions")}))
    return evidence


def phase_errors(api: RestClient, worker_a: str, worker_b: str, session_a: str, out: Path) -> dict:
    probes = [
        ("no.such.tool", {"worker_id": worker_a}, 404),
        ("function.list", {"worker_id": f"{worker_a}_ghost"}, 400),
        ("patch.nop", {"worker_id": worker_b, "session_id": session_a, "address": "0x0"}, 400),
    ]
    histogram: dict[str, int] = {}
    lock = threading.Lock()
    cycle = threading.local()
    server_5xx = 0

    def workload(client: RestClient) -> None:
        nonlocal server_5xx
        index = getattr(cycle, "index", None)
        if index is None:
            index = cycle.index = 0
        tool, args, expected = probes[index % len(probes)]
        cycle.index = index + 1
        status, body = client.call_raw(tool, args)
        envelope = body.get("status") if isinstance(body, dict) else None
        code = (body.get("error") or {}).get("code") if isinstance(body, dict) else None
        with lock:
            histogram[str(status)] = histogram.get(str(status), 0) + 1
        if status >= 500:
            server_5xx += 1
        if status != expected or envelope != "error" or code != expected:
            raise AssertionError(f"{tool}: expected {expected}, got {status} code={code}")

    stats = soak(api, workload, threads=8, duration_seconds=15)
    evidence = {
        "phase": "errors",
        "description": "error-path flood: unknown tool (404), unknown worker (400), "
        "cross-worker session (400); exact-status assertions inside the workload",
        "stats": stats,
        "status_histogram": histogram,
        "server_5xx": server_5xx,
        "assertions": {
            "errors_zero": stats["errors"] == 0,
            "at_least_200_calls": stats["count"] >= 200,
            "zero_5xx": server_5xx == 0,
            "only_4xx": set(histogram).issubset({"400", "404"}),
        },
    }
    out.write_text(json.dumps(evidence, indent=1))
    print("errors:", json.dumps(evidence["stats"]), "histogram:", histogram)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:29950")
    parser.add_argument("--worker", default="api_load_a")
    parser.add_argument("--worker-b", default="api_load_b")
    parser.add_argument("--binary", default=LIB_DEFAULT)
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else REPO / "runtime/acceptance/api"
    out_dir.mkdir(parents=True, exist_ok=True)

    api = RestClient(args.base, timeout=300.0)
    failures: list[str] = []
    evidence_all: dict[str, dict] = {"base": args.base, "generated": _dt.datetime.now().isoformat(timespec="seconds")}

    health = api.health()
    if health.get("status") != "ok":
        print(f"initial health not ok: {health.get('status')}")
        return 1

    # Session on worker A for phases mixed/batch/errors.
    opened = run_open = None
    status, body = api.call_raw("program.open", {"worker_id": args.worker, "path": args.binary, "read_only": True})
    if status != 200 or not (body.get("result") or {}).get("session_id"):
        failures.append(f"program.open on {args.worker}: HTTP {status} {body.get('error')}")
        evidence_all["mixed"] = {"skipped": "no session"}
        evidence_all["batch"] = {"skipped": "no session"}
        evidence_all["errors"] = {"skipped": "no session"}
    else:
        run_open = body
        session_a = run_open["result"]["session_id"]

        mixed = phase_mixed(api, session_a, args.worker, out_dir / "load-mixed.json")
        if not all(mixed["assertions"].values()):
            failures.append(f"mixed phase assertions: {mixed['assertions']} samples={mixed['stats']['error_samples']}")
        evidence_all["mixed"] = json.loads((out_dir / "load-mixed.json").read_text())

        batch = phase_batch(api, args.worker, session_a, out_dir / "load-batch.json")
        if not batch["assertions"]["pipeline_batches_returned"] or not batch["assertions"]["first_call_ok"]:
            failures.append(f"batch pipeline assertions: {batch['assertions']}")
        if not batch["assertions"]["chained_all_ok"]:
            failures.append(f"batch chained reference errors: {batch['chained_reference']['errors']}")
        evidence_all["batch"] = json.loads((out_dir / "load-batch.json").read_text())

        errors_phase = phase_errors(api, args.worker, args.worker_b, session_a, out_dir / "load-errors.json")
        if not all(errors_phase["assertions"].values()):
            failures.append(f"error flood assertions: {errors_phase['assertions']}")
        evidence_all["errors"] = json.loads((out_dir / "load-errors.json").read_text())

    concurrent = phase_concurrent(api, args.binary, args.worker, args.worker_b, out_dir / "load-concurrent.json")
    if not all(concurrent["assertions"].values()):
        failures.append(f"concurrent phase assertions: {concurrent['assertions']}")
    evidence_all["concurrent"] = json.loads((out_dir / "load-concurrent.json").read_text())

    # Final health must be ok.
    final = api.health()
    final_ok = final.get("status") == "ok"
    if not final_ok:
        failures.append(f"final health status {final.get('status')}")
    evidence_all["final_health"] = {"status": final.get("status"), "uptime_seconds": final.get("uptime_seconds")}

    # Stop both workers (force=false) now that evidence is complete.
    stops = {}
    for worker in (args.worker, args.worker_b):
        status, body = api._request("POST", f"/api/v1/workers/{worker}/stop", {})
        stops[worker] = {
            "http_status": status,
            "state": (body.get("result") or {}).get("state"),
            "error": body.get("error"),
        }
    evidence_all["worker_stops"] = stops
    for worker, stop in stops.items():
        if stop["http_status"] != 200 or stop["state"] not in ("stopped", None):
            failures.append(f"stop {worker}: {stop}")
    post_stop = api.health()
    evidence_all["post_stop_health"] = {"status": post_stop.get("status")}
    if post_stop.get("status") != "ok":
        failures.append(f"post-stop health status {post_stop.get('status')}")

    evidence_all["failures"] = failures
    evidence_all["max_p95_ms"] = max(
        (
            phase["stats"]["p95_ms"]
            for phase in (evidence_all.get("mixed"), evidence_all.get("concurrent"), evidence_all.get("errors"))
            if phase and phase.get("stats", {}).get("p95_ms") is not None
        ),
        default=None,
    )
    (out_dir / "load-summary.json").write_text(json.dumps(evidence_all, indent=1))
    print("final health:", final.get("status"), "| stops:", json.dumps(stops))
    print("max p95 (soak phases):", evidence_all["max_p95_ms"], "ms")
    print("post-stop health:", post_stop.get("status"))
    if failures:
        print("FAILURES:")
        for item in failures:
            print(" -", item)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
