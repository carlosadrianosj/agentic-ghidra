"""API infra acceptance: program/project/task/analysis/transaction/memory/listing over REST.

Exercises every catalog tool in the health, mcp, program, project, task,
analysis, transaction, memory and listing families against one real binary per
run and writes per-op evidence with REST envelope latencies.

Usage:
    python tests/acceptance/infra/test_infra.py \
        --base http://127.0.0.1:29950 --worker api_infra \
        --binary ../PoC-files/02-elf-native/audio.primary.vbox86_32.so \
        --label audio32 [--soak] [--stop-worker]
"""

from __future__ import annotations

import argparse
import base64
import json
import statistics
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from rest_client import RestClient, soak

CATALOG = [
    "health.ping", "mcp.response_format",
    "program.open", "program.open_bytes", "program.list_open", "program.close",
    "program.mode.get", "program.mode.set", "program.summary", "program.report",
    "program.save", "program.save_as", "program.image_base.set", "program.export_binary",
    "project.file.info", "project.files.list", "project.folders.list",
    "project.search.programs", "project.program.open", "project.program.open_existing", "project.export",
    "task.analysis_update", "task.status", "task.result", "task.cancel",
    "analysis.options.list", "analysis.options.get", "analysis.options.set",
    "analysis.analyzers.list", "analysis.analyzers.set", "analysis.clear_cache",
    "analysis.status", "analysis.update", "analysis.update_and_wait",
    "transaction.begin", "transaction.commit", "transaction.revert",
    "transaction.status", "transaction.undo", "transaction.redo",
    "memory.blocks.list", "memory.block.create", "memory.block.remove",
    "memory.read", "memory.write",
    "listing.code_unit.at", "listing.code_unit.before", "listing.code_unit.after",
    "listing.code_unit.containing", "listing.code_units.list", "listing.data.at",
    "listing.data.list", "listing.data.create", "listing.data.clear", "listing.clear",
    "listing.disassemble.function", "listing.disassemble.range", "listing.disassemble.seed",
]

TERMINAL_TASK_STATES = {"succeeded", "failed", "cancelled"}


class Recorder:
    """Records one entry per exercised op with the REST envelope duration.

    expect="ok": pass on HTTP 200 + status ok.
    expect="error": pass on a mapped non-OK envelope.
    expect="any": pass on either a well-formed OK envelope or a mapped 4xx
    (used where the tool-level outcome is itself a recorded finding).
    """

    def __init__(self, api: RestClient, worker: str):
        self.api = api
        self.worker = worker
        self.ops: list[dict] = []

    def call(self, tool: str, args: dict, phase: str, expect: str = "ok", note: str = ""):
        payload = {"worker_id": self.worker, **args}
        status, body = self.api.call_raw(tool, payload)
        ok_envelope = status == 200 and isinstance(body, dict) and body.get("status") == "ok"
        mapped_error = (
            not ok_envelope
            and isinstance(body, dict)
            and isinstance(body.get("error"), dict)
            and body["error"].get("code") == status
            and status in (400, 403, 404, 409, 504)
        )
        if expect == "ok":
            passed = ok_envelope
        elif expect == "error":
            passed = mapped_error
        else:
            passed = ok_envelope or mapped_error
        duration = body.get("duration_ms") if isinstance(body, dict) else None
        detail = ""
        if not ok_envelope:
            detail = body.get("error", {}).get("message", "") if isinstance(body, dict) else str(body)[:200]
        self.ops.append({
            "tool": tool,
            "phase": phase,
            "ok": bool(passed),
            "http_status": status,
            "duration_ms": duration,
            "expect": expect,
            "note": (note + " | " + detail[:200]) if (note and detail) else (note or detail[:200]),
        })
        if not passed:
            print(f"FAIL {tool} [{phase}] HTTP {status}: {detail[:200]}", file=sys.stderr)
        return (body.get("result") if ok_envelope else body), self.ops[-1]

    def failures(self):
        return [op for op in self.ops if not op["ok"]]


def pick_block(blocks: list[dict], **want) -> dict:
    for block in blocks:
        if all(block.get(key) is value for key, value in want.items()):
            return block
    return blocks[0]


def wait_task(rec: Recorder, task_id: str, timeout: float = 300.0) -> str:
    """Poll task.status until terminal; only first and final polls are recorded."""
    result, _ = rec.call("task.status", {"task_id": task_id}, "task")
    polls = 0
    deadline = time.monotonic() + timeout
    while result.get("status") not in TERMINAL_TASK_STATES and time.monotonic() < deadline:
        time.sleep(1.0)
        polls += 1
        result, _ = rec.call(
            "task.status", {"task_id": task_id}, "task-poll",
            expect="any" if polls > 1 else "ok",
        )
    return result.get("status", "unknown")


def _errmsg(body) -> str:
    if isinstance(body, dict):
        return str(body.get("error", {}).get("message", ""))[:200]
    return str(body)[:200]


def run_binary(api: RestClient, worker: str, binary: Path, label: str,
               do_soak: bool, soak_seconds: float, soak_threads: int) -> dict:
    rec = Recorder(api, worker)
    t0 = time.monotonic()
    out_dir = HERE.parent.parent / "runtime" / "acceptance" / "api"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = "%s-%d" % (label, int(time.time()))
    # Reruns must not collide with leftover project files (FileInUseException).
    for stale in api.call("program.list_open", {"worker_id": worker}).get("programs", []):
        try:
            api.call("program.close", {"worker_id": worker, "session_id": stale["session_id"]})
        except Exception:
            pass

    # ---- families health + mcp (first call demand-starts the worker JVM) ----
    rec.call("health.ping", {}, "health")
    rec.call("mcp.response_format", {}, "mcp")

    # ---- family program: main session, read_only=False ----------------------
    opened, _ = rec.call("program.open",
                         {"path": str(binary), "read_only": False, "update_analysis": True},
                         "program", note="main session")
    session = opened["session_id"]
    progs, _ = rec.call("program.list_open", {}, "program")
    assert any(p.get("session_id") == session for p in progs["programs"]), "open session not listed"
    rec.call("program.mode.get", {"session_id": session}, "program")
    summary, _ = rec.call("program.summary", {"session_id": session}, "program")
    report, _ = rec.call("program.report", {"session_id": session}, "program")

    # ---- discovery strictly through REST listing/memory tools ----------------
    blocks, _ = rec.call("memory.blocks.list", {"session_id": session}, "memory")
    block_list = blocks["blocks"]
    exec_block = pick_block(block_list, execute=True, initialized=True)
    data_block = pick_block(block_list, write=True, initialized=True)
    exec_start = exec_block["start"]
    data_addr = data_block["start"]
    parseable_ends = [int(b["end"], 16) for b in block_list if "::" not in b["end"]]
    free_base = max(parseable_ends) if parseable_ends else int(data_addr, 16)
    free_addr = "0x%X" % ((free_base + 0x10000) & ~0xFFF)
    units, _ = rec.call("listing.code_units.list",
                        {"session_id": session, "start": exec_start, "limit": 5}, "listing")
    unit_addr = units["code_units"][0]["address"]
    datas, _ = rec.call("listing.data.list", {"session_id": session, "limit": 5}, "listing")
    data_unit = datas["data"][0]["address"] if datas["data"] else unit_addr

    # ---- family listing: read ops -------------------------------------------
    rec.call("listing.code_unit.at", {"session_id": session, "address": unit_addr}, "listing")
    rec.call("listing.code_unit.before", {"session_id": session, "address": unit_addr}, "listing")
    rec.call("listing.code_unit.after", {"session_id": session, "address": unit_addr}, "listing")
    rec.call("listing.code_unit.containing", {"session_id": session, "address": unit_addr}, "listing")
    rec.call("listing.data.at", {"session_id": session, "address": data_unit}, "listing")
    rec.call("listing.disassemble.range",
             {"session_id": session, "start": exec_start, "length": 64, "limit": 16}, "listing")
    more_units, _ = rec.call("listing.code_units.list",
                             {"session_id": session, "start": exec_start, "limit": 40}, "listing")
    candidates = [u["address"] for u in [units["code_units"][0], *more_units["code_units"]]]
    fn_entry, _ = rec.call("listing.disassemble.function",
                           {"session_id": session, "address": candidates[0], "limit": 16},
                           "listing", expect="any",
                           note="first .text code unit; containment is a tool-level outcome")
    if fn_entry.get("error") or not isinstance(fn_entry.get("instructions"), list):
        for candidate in candidates[1:6]:
            fn_entry, entry_op = rec.call("listing.disassemble.function",
                                          {"session_id": session, "address": candidate, "limit": 16},
                                          "listing", expect="any", note="fallback code unit")
            if isinstance(fn_entry.get("instructions"), list):
                break

    # ---- family memory: read -------------------------------------------------
    mem, _ = rec.call("memory.read", {"session_id": session, "address": data_addr, "length": 16}, "memory")
    original_hex = mem["data_hex"][:8]

    # ---- family analysis: reads ----------------------------------------------
    options, _ = rec.call("analysis.options.list", {"session_id": session, "limit": 200}, "analysis")
    scalar_option = next(
        (o for o in options["options"] if isinstance(o.get("value"), (int, float, str))), None)
    option = scalar_option or options["options"][0]
    rec.call("analysis.options.get", {"session_id": session, "name": option["name"]}, "analysis")
    analyzers, _ = rec.call("analysis.analyzers.list", {"session_id": session, "limit": 200}, "analysis")
    analyzer = analyzers["analyzers"][0]
    rec.call("analysis.status", {"session_id": session}, "analysis")

    # ---- family project: reads -------------------------------------------------
    files, _ = rec.call("project.files.list", {"session_id": session, "recursive": True}, "project")
    rec.call("project.folders.list", {"session_id": session, "recursive": True}, "project")
    rec.call("project.search.programs", {"session_id": session, "query": label}, "project")
    prog_path = files["files"][0]["path"] if files.get("files") else f"/{summary.get('name', 'program')}"
    rec.call("project.file.info", {"session_id": session, "path": prog_path}, "project")

    # ---- family task -------------------------------------------------------------
    submitted, _ = rec.call("task.analysis_update", {"session_id": session}, "task")
    task_id = submitted["task_id"]
    final_state = wait_task(rec, task_id)
    rec.call("task.result", {"task_id": task_id}, "task",
             expect="ok" if final_state == "succeeded" else "any",
             note=f"final task state {final_state}")
    rec.call("task.cancel", {"task_id": task_id}, "task", expect="any",
             note="cancel after terminal state is a tool-level outcome")

    # analysis writes / updates (self-managed transactions, not program content)
    rec.call("analysis.update", {"session_id": session}, "analysis")
    rec.call("analysis.update_and_wait", {"session_id": session}, "analysis")
    rec.call("analysis.clear_cache", {"session_id": session}, "analysis")

    # ---- family transaction --------------------------------------------------------
    proofs: dict[str, dict] = {}
    rec.call("transaction.status", {"session_id": session}, "transaction")

    # Proof A (assignment shape): begin -> analysis.options.set -> revert.
    rec.call("transaction.begin", {"session_id": session, "description": "infra revert proof"}, "transaction")
    rec.call("analysis.options.set",
             {"session_id": session, "name": option["name"], "value": option["value"]}, "transaction")
    rec.call("analysis.analyzers.set",
             {"session_id": session, "name": analyzer["name"], "enabled": bool(analyzer["enabled"])}, "transaction")
    flipped = bytes(b ^ 0xFF for b in bytes.fromhex(original_hex)).hex()
    rec.call("memory.write", {"session_id": session, "address": data_addr, "data_hex": flipped}, "transaction")
    rec.call("transaction.revert", {"session_id": session}, "transaction")
    after, _ = rec.call("memory.read", {"session_id": session, "address": data_addr, "length": 4}, "transaction")
    proofs["revert_discards_writes"] = {"restored": after["data_hex"] == original_hex}

    # Proof B: memory.block.create / memory.block.remove inside reverted transactions.
    rec.call("transaction.begin", {"session_id": session, "description": "infra block create proof"}, "transaction")
    rec.call("memory.block.create",
             {"session_id": session, "name": "apitest_blk", "address": free_addr, "length": 64,
              "initialized": True, "fill": 65, "read": True, "write": True}, "transaction")
    rec.call("transaction.revert", {"session_id": session}, "transaction")
    blocks_b, _ = rec.call("memory.blocks.list", {"session_id": session}, "transaction")
    proofs["block_create_reverted"] = {
        "absent": all(b["name"] != "apitest_blk" for b in blocks_b["blocks"])}

    rec.call("transaction.begin", {"session_id": session, "description": "infra block remove proof"}, "transaction")
    rec.call("memory.block.create",
             {"session_id": session, "name": "apitest_blk_a", "address": free_addr, "length": 32,
              "initialized": True, "fill": 66, "read": True, "write": True}, "transaction")
    rec.call("memory.block.create",
             {"session_id": session, "name": "apitest_blk_b",
              "address": "0x%X" % (int(free_addr, 16) + 0x100), "length": 32,
              "initialized": True, "fill": 67, "read": True, "write": True}, "transaction")
    rec.call("memory.block.remove", {"session_id": session, "name": "apitest_blk_a"}, "transaction")
    rec.call("memory.block.remove",
             {"session_id": session, "address": "0x%X" % (int(free_addr, 16) + 0x100)}, "transaction")
    rec.call("transaction.revert", {"session_id": session}, "transaction")
    blocks_c, _ = rec.call("memory.blocks.list", {"session_id": session}, "transaction")
    proofs["block_remove"] = {
        "absent": all(b["name"] not in ("apitest_blk_a", "apitest_blk_b") for b in blocks_c["blocks"])}

    # Proof C: listing write ops inside a reverted transaction; code units restored.
    data_next = "0x%X" % (int(data_addr, 16) + 16)
    rec.call("transaction.begin", {"session_id": session, "description": "infra listing proof"}, "transaction")
    rec.call("listing.data.create", {"session_id": session, "address": data_next, "data_type": "byte"}, "transaction")
    rec.call("listing.data.clear", {"session_id": session, "address": data_next, "length": 1}, "transaction")
    rec.call("listing.clear",
             {"session_id": session, "start": exec_start, "length": 8, "clear_context": True}, "transaction")
    rec.call("listing.disassemble.seed",
             {"session_id": session, "address": exec_start, "limit": 8, "clear_existing": False}, "transaction")
    rec.call("transaction.revert", {"session_id": session}, "transaction")
    restored_unit, _ = rec.call("listing.code_unit.at",
                                {"session_id": session, "address": exec_start}, "transaction")
    proofs["listing_writes_reverted"] = {
        "code_unit_restored": bool(restored_unit.get("code_unit") or restored_unit.get("unit")
                                   or restored_unit.get("address")),
    }

    # Proof D: commit -> undo -> redo -> undo on a one-byte write.
    one = mem["data_hex"][0:2]
    one_flipped = "%02x" % (int(one, 16) ^ 0xFF)
    rec.call("transaction.begin", {"session_id": session, "description": "infra commit proof"}, "transaction")
    rec.call("memory.write", {"session_id": session, "address": data_addr, "data_hex": one_flipped}, "transaction")
    rec.call("transaction.commit", {"session_id": session}, "transaction")
    v_commit, _ = rec.call("memory.read", {"session_id": session, "address": data_addr, "length": 1}, "transaction")
    rec.call("transaction.undo", {"session_id": session}, "transaction")
    v_undo, _ = rec.call("memory.read", {"session_id": session, "address": data_addr, "length": 1}, "transaction")
    rec.call("transaction.redo", {"session_id": session}, "transaction")
    v_redo, _ = rec.call("memory.read", {"session_id": session, "address": data_addr, "length": 1}, "transaction")
    rec.call("transaction.undo", {"session_id": session}, "transaction")
    v_restore, _ = rec.call("memory.read", {"session_id": session, "address": data_addr, "length": 1}, "transaction")
    proofs["commit_undo_redo"] = {
        "original": one, "written": one_flipped,
        "values": [v_commit["data_hex"], v_undo["data_hex"], v_redo["data_hex"], v_restore["data_hex"]],
        "commit_visible": v_commit["data_hex"] == one_flipped,
        "undo_restores": v_undo["data_hex"] == one.lower(),
        "redo_reapplies": v_redo["data_hex"] == one_flipped,
        "undo_final": v_restore["data_hex"] == one.lower(),
    }

    # ---- family program: management writes on a scratch session -------------------
    # Real ELF bytes so the Ghidra loader recognizes the format; raw arbitrary
    # bytes raise LoadException (observed as HTTP 500, recorded as a finding).
    payload = binary.read_bytes()[:4096]
    opened2, _ = rec.call("program.open_bytes",
                          {"data_base64": base64.b64encode(payload).decode(),
                           "filename": f"infra_{run_id}_scratch.bin",
                           "read_only": False, "update_analysis": False}, "program")
    scratch = opened2["session_id"]
    scratch_blocks = api.call("memory.blocks.list",
                              {"worker_id": worker, "session_id": scratch})["blocks"]
    scratch_addr = pick_block(scratch_blocks, initialized=True)["start"]
    rec.call("memory.write", {"session_id": scratch, "address": scratch_addr, "data_hex": "deadbeef"}, "program")
    rec.call("program.mode.set", {"session_id": scratch, "deterministic": True}, "program")
    rec.call("program.image_base.set",
             {"session_id": scratch, "image_base": "0x%X" % (int(scratch_addr, 16) + 0x1000),
              "commit": True}, "program")
    rec.call("program.save", {"session_id": scratch}, "program")
    renamed, _ = rec.call("program.save_as",
                          {"session_id": scratch, "program_name": f"infra_{run_id}_renamed",
                           "folder_path": "/", "overwrite": True}, "program")
    rec.call("project.file.info", {"session_id": session, "path": renamed["path"]}, "project")
    rec.call("program.export_binary",
             {"session_id": scratch, "path": str(out_dir / f"infra-{run_id}-export.bin"),
              "format": "original_file"}, "program")
    rec.call("project.export",
             {"session_id": scratch, "destination": str(out_dir / f"infra-{run_id}-project.gzf")}, "project")
    rec.call("program.close", {"session_id": scratch}, "program")

    # project.program.open / open_existing reuse the saved project copy
    opened3, _ = rec.call("project.program.open",
                          {"session_id": session, "path": renamed["path"],
                           "read_only": True, "update_analysis": False}, "project")
    rec.call("program.close", {"session_id": opened3["session_id"]}, "project")
    worker_info = next(w for w in api.health()["workers"]["workers"] if w["worker_id"] == worker)
    opened4, _ = rec.call("project.program.open_existing",
                          {"project_location": worker_info["project_path"],
                           "project_name": worker_info["project_name"],
                           "program_path": renamed["path"],
                           "read_only": True, "update_analysis": False}, "project")
    rec.call("program.close", {"session_id": opened4["session_id"]}, "project")

    # ---- expected-rejection probes -----------------------------------------------
    probes = []
    for probe, tool, args, expected in [
        ("unknown tool", "definitely.not.a.tool", {}, 404),
        ("bad address (ValueError->400)", "memory.read",
         {"session_id": session, "address": "not-an-address", "length": 4}, 400),
        ("missing required session_id", "program.close", {}, 400),
        ("limit=1001 listing.code_units.list", "listing.code_units.list",
         {"session_id": session, "limit": 1001}, 400),
        ("limit=1001 project.files.list", "project.files.list",
         {"session_id": session, "limit": 1001}, 400),
        ("commit without active transaction", "transaction.commit", {"session_id": session}, 400),
    ]:
        status, body = api.call_raw(tool, {"worker_id": worker, **args})
        probes.append({"probe": probe, "tool": tool, "http_status": status, "expected": expected,
                       "pass": status == expected, "message": _errmsg(body)})

    # ---- soak ----------------------------------------------------------------------
    soak_report = None
    if do_soak:
        def workload(client: RestClient):
            client.health()
            client.get("/api/v1/tools?family=listing")
            client.call("transaction.status", {"worker_id": worker, "session_id": session})
        soak_report = soak(api, workload, soak_threads, soak_seconds)
        soak_report["workload"] = "health + GET /api/v1/tools?family=listing + transaction.status"

    # ---- close main session ----------------------------------------------------------
    rec.call("program.close", {"session_id": session}, "program")

    durations = [op["duration_ms"] for op in rec.ops if op["duration_ms"] is not None]
    evidence = {
        "binary": str(binary),
        "label": label,
        "worker": worker,
        "base": api.base,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": round(time.monotonic() - t0, 1),
        "session_id": session,
        "discovered": {"exec_block": exec_block["name"], "data_block": data_block["name"],
                       "exec_start": exec_start, "data_addr": data_addr, "free_addr": free_addr},
        "task_final_state": final_state,
        "ops_total": len(rec.ops),
        "ops_passed": len(rec.ops) - len(rec.failures()),
        "ops_failed": len(rec.failures()),
        "probes": probes,
        "probes_failed": [p for p in probes if not p["pass"]],
        "transaction_proofs": proofs,
        "latency_ms": {
            "p50": round(statistics.median(durations), 1) if durations else None,
            "p95": round(sorted(durations)[int(len(durations) * 0.95) - 1], 1) if durations else None,
            "max": max(durations) if durations else None,
        },
        "ops": rec.ops,
    }
    if soak_report is not None:
        evidence["soak"] = soak_report
    return evidence


def catalog_coverage(evidence: dict) -> list[str]:
    seen = {op["tool"] for op in evidence["ops"]}
    return [tool for tool in CATALOG if tool not in seen]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:29950")
    parser.add_argument("--worker", default="api_infra")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--label", default=None, help="evidence name (default: binary stem)")
    parser.add_argument("--evidence-dir",
                        default=str(HERE.parent.parent / "runtime" / "acceptance" / "api"))
    parser.add_argument("--soak", action="store_true",
                        help="run the light soak before closing the session")
    parser.add_argument("--soak-threads", type=int, default=4)
    parser.add_argument("--soak-seconds", type=float, default=20.0)
    parser.add_argument("--stop-worker", action="store_true",
                        help="stop the worker (force=false) after the run")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2
    label = args.label or binary.stem
    api = RestClient(args.base)

    evidence = run_binary(api, args.worker, binary, label,
                          args.soak, args.soak_seconds, args.soak_threads)
    missing = catalog_coverage(evidence)
    evidence["catalog_missing"] = missing

    out = Path(args.evidence_dir) / f"infra-{label}.json"
    out.write_text(json.dumps(evidence, indent=2))
    if args.soak and evidence.get("soak"):
        (Path(args.evidence_dir) / "infra-soak.json").write_text(
            json.dumps({"label": label, "binary": str(binary), "worker": args.worker,
                        "session_id": evidence["session_id"], "soak": evidence["soak"]}, indent=2))

    failed = evidence["ops_failed"] + len(evidence["probes_failed"]) + len(missing)
    print(f"{label}: ops {evidence['ops_passed']}/{evidence['ops_total']} ok, "
          f"probes {len(evidence['probes']) - len(evidence['probes_failed'])}/{len(evidence['probes'])} ok, "
          f"proofs {json.dumps(evidence['transaction_proofs'])}, "
          f"missing catalog ops: {missing or 'none'} -> {out}")

    if args.stop_worker:
        request = urllib.request.Request(
            f"{args.base}/api/v1/workers/{args.worker}/stop",
            data=json.dumps({"force": False}).encode(),
            headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=120) as response:
            body = json.loads(response.read())
        print(f"worker {args.worker} stop: HTTP {response.status} {json.dumps(body)[:200]}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
