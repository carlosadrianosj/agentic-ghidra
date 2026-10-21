"""Chain REST calls into one reverse-engineering pass; no MCP client needed.

Usage:
    python examples/rest_pipeline.py <base-url> <worker-id> <binary> [evidence.json]

Example:
    python examples/rest_pipeline.py http://127.0.0.1:29950 rest_smoke \\
        ../PoC-files/07-files-to-test-ghidra-capacity/bin/libcompute_arm64.so
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:29950"
WORKER = sys.argv[2] if len(sys.argv) > 2 else "rest_smoke"
BINARY = sys.argv[3] if len(sys.argv) > 3 else "runtime/acceptance/fixtures/native"
EVIDENCE = sys.argv[4] if len(sys.argv) > 4 else "runtime/acceptance/rest-smoke.json"


def call(tool: str, arguments: dict, expected: int = 200):
    request = urllib.request.Request(
        f"{BASE}/api/v1/tools/{tool}",
        data=json.dumps(arguments).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        body = json.loads(response.read())
        if response.status != expected or body.get("status") != "ok":
            raise SystemExit(f"{tool} failed: HTTP {response.status} {body}")
    print(f"{tool:28s} {body['duration_ms']:6d} ms")
    return body["result"]


def main() -> None:
    started = time.monotonic()
    with urllib.request.urlopen(f"{BASE}/health", timeout=30) as response:
        health = json.loads(response.read())
    print(f"health: auth={health['auth']} workers={len(health['workers']['workers'])}")

    call("worker_start", {"worker_id": WORKER})
    opened = call(
        "program.open",
        {"worker_id": WORKER, "path": BINARY, "read_only": False},
    )
    session = opened["session_id"]
    listing = call(
        "function.list",
        {"worker_id": WORKER, "session_id": session, "limit": 5},
    )
    target = listing["functions"][0]
    decompiled = call(
        "decomp.function",
        {"worker_id": WORKER, "session_id": session, "function_start": target["address"]},
    )
    constants = call(
        "search.constants",
        {
            "worker_id": WORKER,
            "session_id": session,
            "value": "0x2a",
            "start": target["address"],
            "limit": 3,
        },
    )
    summary = call(
        "program.summary",
        {"worker_id": WORKER, "session_id": session},
    )
    call("program.close", {"worker_id": WORKER, "session_id": session})
    call("worker_stop", {"worker_id": WORKER})

    functions = listing.get("functions", [])
    evidence = {
        "base": BASE,
        "binary": BINARY,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "functions_seen": listing.get("count", len(functions)),
        "first_function": functions[0] if functions else None,
        "decompiled_lines": len(decompiled["code"].splitlines()),
        "decompiled_head": "\n".join(decompiled["code"].splitlines()[:12]),
        "constants_0x2a": len(constants["matches"]),
        "memory_blocks": len(summary["memory_blocks"]) if summary.get("memory_blocks") else 0,
    }
    with open(EVIDENCE, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=1)
    print(json.dumps(evidence, indent=1))


if __name__ == "__main__":
    main()
