#!/usr/bin/env python3
"""Patch + ghidra family acceptance over REST against one supervisor worker.

For each assigned binary this script exercises every patch operation
(branch_invert, nop, assemble) inside a single REST-managed transaction
(transaction.begin ... transaction.revert), verifies the patched state through
REST reads, then proves the revert restored the original bytes. The ghidra
family (info, call, eval, script) runs per binary as well; trusted execution is
disabled on this supervisor, so ghidra.call/eval/script must be rejected with
the gated PermissionError shape (documented mapping: HTTP 403). Expected-
rejection probes record the actual HTTP status next to the documented mapping.

Usage:
    python test_patch.py [--base http://127.0.0.1:29950] [--worker api_load_a] \
        [--binary PATH]... [--out runtime/acceptance/api/patch-libsyscalls.json]

Exit codes: 0 = all ops and probes match expectations, 1 = core op failure,
3 = core ops passed but documented status mapping violated on probes.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rest_client import RestClient, RestError

REPO = Path(__file__).resolve().parents[2]
LIB_DEFAULT = (
    "/Users/baxi/Documents/Tools-Projects/ghidra-research/"
    "PoC-files/07-files-to-test-ghidra-capacity/bin/libsyscalls_arm64.so"
)
NATIVE_DEFAULT = str(REPO / "runtime/acceptance/fixtures/native")

_COND_INV = {
    "eq": "ne", "ne": "eq", "cs": "cc", "cc": "cs", "hs": "lo", "lo": "hs",
    "mi": "pl", "pl": "mi", "vs": "vc", "vc": "vs", "hi": "ls", "ls": "hi",
    "ge": "lt", "lt": "ge", "gt": "le", "le": "gt",
}
_MISC_INV = {"cbz": "cbnz", "cbnz": "cbz", "tbz": "tbnz", "tbnz": "tbz"}
AARCH64_NOP_HEX = "1f2003d5"  # d503201f stored little-endian


def inverse_mnemonic(mnemonic: str) -> str | None:
    low = (mnemonic or "").strip().lower()
    if low in _MISC_INV:
        return _MISC_INV[low]
    match = re.fullmatch(r"b\.?([a-z]{2})(\.[anw])?", low)
    if match and match[1] in _COND_INV:
        return "b." + _COND_INV[match[1]]
    return None


def _addr_int(address: str) -> int:
    return int(address, 16)


def run_op(api: RestClient, tool: str, args: dict) -> dict:
    """One REST call; returns {http_status, envelope_status, duration_ms, result, error}."""
    started = time.perf_counter()
    status, body = api.call_raw(tool, args)
    record = {
        "tool": tool,
        "http_status": status,
        "envelope_status": body.get("status") if isinstance(body, dict) else None,
        "duration_ms": body.get("duration_ms") if isinstance(body, dict) else None,
        "wall_ms": round((time.perf_counter() - started) * 1000.0, 1),
    }
    if isinstance(body, dict) and body.get("status") == "ok":
        record["result"] = body.get("result")
    else:
        record["error"] = (body.get("error") if isinstance(body, dict) else None) or {
            "message": str(body)
        }
    return record


class Suite:
    def __init__(self, api: RestClient, worker: str) -> None:
        self.api = api
        self.worker = worker
        self.ops: list[dict] = []
        self.probes: list[dict] = []
        self.findings: list[str] = []
        self.core_failures: list[str] = []

    def step(self, label: str, tool: str, args: dict, *, ok: bool = True, detail=None) -> dict:
        record = {"step": label, **run_op(self.api, tool, args)}
        record["ok"] = bool(ok and record["envelope_status"] == "ok")
        if detail is not None:
            record["detail"] = detail
        self.ops.append(record)
        return record

    def probe(self, label: str, tool: str, args: dict, expected: int, expect_ok=False) -> dict:
        record = {"probe": label, "expected_status": expected, **run_op(self.api, tool, args)}
        if expect_ok:
            record["ok"] = record["envelope_status"] == "ok" and record["http_status"] == 200
        else:
            record["ok"] = (
                record["http_status"] == expected
                and record["envelope_status"] == "error"
                and record["error"]["code"] == expected
            )
        self.probes.append(record)
        return record

    def fail(self, message: str) -> None:
        self.core_failures.append(message)


def code_unit(api: RestClient, base: dict, address: str) -> dict | None:
    result = api.call("listing.code_unit.at", {**base, "address": address})
    return result.get("code_unit")


def read_hex(api: RestClient, base: dict, address: str, length: int) -> str:
    result = api.call("memory.read", {**base, "address": address, "length": length})
    return result["data_hex"]


def find_conditional_branch(suite: Suite, base: dict) -> dict | None:
    queries = [
        "b.eq", "b.ne", "b.le", "b.lt", "b.gt", "b.ge", "b.hs", "b.lo",
        "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "cbz", "cbnz", "tbz", "tbnz",
    ]
    for query in queries:
        try:
            result = suite.api.call("search.instructions", {**base, "query": query, "limit": 5})
        except RestError:
            continue
        for match in result.get("matches", []):
            if inverse_mnemonic(match["mnemonic"]):
                return match
    # Fallback: scan defined functions' code units for any conditional branch.
    functions = suite.api.call("function.list", {**base, "limit": 40}).get("functions", [])
    for fn in functions[:25]:
        end = _addr_int(fn["address"]) + 0x200
        try:
            units = suite.api.call(
                "listing.code_units.list",
                {**base, "start": fn["address"], "end": f"{end:x}", "limit": 200},
            )
        except RestError:
            continue
        for unit in units.get("code_units", []):
            if unit.get("mnemonic") and inverse_mnemonic(unit["mnemonic"]):
                return {
                    "address": unit["address"],
                    "mnemonic": unit["mnemonic"],
                    "operands": unit.get("operands", []),
                }
    return None


def ensure_reverted(api: RestClient, base: dict) -> None:
    status = api.call("transaction.status", base)
    if status.get("pending"):
        api.call("transaction.revert", base)


def run_binary(suite: Suite, path: str) -> dict:
    api, worker = suite.api, suite.worker
    report: dict = {"path": path, "ops": [], "checks": {}}
    ops_start = len(suite.ops)
    opened = suite.step("program.open", "program.open", {"worker_id": worker, "path": path, "read_only": False})
    if not opened["ok"]:
        suite.fail(f"{path}: program.open failed {opened.get('error')}")
        return report
    session = opened["result"]["session_id"]
    base = {"worker_id": worker, "session_id": session}
    report["session_id"] = session

    branch = find_conditional_branch(suite, base)
    if branch is None:
        suite.fail(f"{path}: no conditional branch found")
        return report
    branch_addr = branch["address"]
    inverse = inverse_mnemonic(branch["mnemonic"])
    report["branch"] = {"address": branch_addr, "mnemonic": branch["mnemonic"], "expected_inverse": inverse}

    # Targets: the branch, the next instruction (nop) and the one after (assemble).
    window = api.call(
        "listing.code_units.list",
        {**base, "start": branch_addr, "end": f"{_addr_int(branch_addr) + 0x30:x}", "limit": 32},
    )
    instructions = [u for u in window["code_units"] if u.get("mnemonic")]
    if len(instructions) < 3:
        suite.fail(f"{path}: fewer than 3 instructions after branch {branch_addr}")
        return report
    nop_unit, asm_unit = instructions[1], instructions[2]
    asm_text = f"{asm_unit['mnemonic']} {', '.join(asm_unit.get('operands', []))}"
    report["targets"] = {
        "nop": {"address": nop_unit["address"], "mnemonic": nop_unit["mnemonic"]},
        "assemble": {"address": asm_unit["address"], "mnemonic": asm_unit["mnemonic"], "text": asm_text},
    }

    # Pre-transaction snapshot via REST reads.
    before = {
        "branch": read_hex(api, base, branch_addr, instructions[0]["length"]),
        "nop": read_hex(api, base, nop_unit["address"], nop_unit["length"]),
        "assemble": read_hex(api, base, asm_unit["address"], asm_unit["length"]),
    }
    report["original_bytes"] = dict(before)
    branch_mnemonic_before = code_unit(api, base, branch_addr)["mnemonic"]

    attempts = [asm_text, "nop"]
    inverted_record = nop_record = asm_record = None
    for attempt in attempts:
        ensure_reverted(api, base)
        begun = suite.step(
            "transaction.begin",
            "transaction.begin",
            {**base, "description": f"patch acceptance {attempt}"},
        )
        if not begun["ok"] or not begun["result"].get("pending"):
            suite.fail(f"{path}: transaction.begin failed {begun.get('error')}")
            return report

        inverted_record = suite.step(
            f"patch.branch_invert@{branch_addr}",
            "patch.branch_invert",
            {**base, "address": branch_addr},
        )
        if not inverted_record["ok"]:
            suite.fail(f"{path}: branch_invert failed {inverted_record.get('error')}")
            ensure_reverted(api, base)
            return report
        result = inverted_record["result"]
        seen = code_unit(api, base, branch_addr)
        report["checks"]["inverted_mnemonic_seen"] = seen["mnemonic"]
        report["checks"]["inverted_target_preserved"] = (
            seen["operands"][-1] == instructions[0]["operands"][-1]
        )
        if seen["mnemonic"] != inverse:
            suite.fail(f"{path}: branch at {branch_addr} shows {seen['mnemonic']}, expected {inverse}")
        if not report["checks"]["inverted_target_preserved"]:
            suite.fail(f"{path}: inverted branch target changed: {seen['operands']}")

        nop_record = suite.step(
            f"patch.nop@{nop_unit['address']}",
            "patch.nop",
            {**base, "address": nop_unit["address"], "count": 1},
        )
        if not nop_record["ok"]:
            suite.fail(f"{path}: patch.nop failed {nop_record.get('error')}")
            ensure_reverted(api, base)
            return report
        seen_nop = code_unit(api, base, nop_unit["address"])
        report["checks"]["nop_mnemonic_seen"] = seen_nop["mnemonic"]
        report["checks"]["nop_bytes_seen"] = nop_record["result"]["after_hex"]
        if seen_nop["mnemonic"] != "nop":
            suite.fail(f"{path}: nop target shows {seen_nop['mnemonic']}, expected nop")
        if nop_record["result"]["after_hex"] != AARCH64_NOP_HEX:
            suite.fail(
                f"{path}: nop bytes {nop_record['result']['after_hex']} != {AARCH64_NOP_HEX}"
            )

        asm_record = suite.step(
            f"patch.assemble@{asm_unit['address']}[{attempt}]",
            "patch.assemble",
            {**base, "address": asm_unit["address"], "assembly": attempt},
        )
        if asm_record["ok"]:
            if attempt == asm_text:
                report["checks"]["assemble_roundtrip"] = (
                    asm_record["result"]["after_hex"] == asm_record["result"]["before_hex"]
                )
                if not report["checks"]["assemble_roundtrip"]:
                    suite.fail(f"{path}: assemble round-trip changed bytes")
            else:
                report["checks"]["assemble_roundtrip"] = "fallback-nop"
            break
        # A failure inside an explicit transaction reverts the whole transaction.
        report["checks"][f"assemble_attempt_failed:{attempt}"] = (
            asm_record.get("error") or {}
        ).get("message", "")[:160]
        ensure_reverted(api, base)
    else:
        suite.fail(f"{path}: patch.assemble failed for both attempts")
        return report

    reverted = suite.step("transaction.revert", "transaction.revert", base)
    if not reverted["ok"] or not reverted["result"].get("reverted"):
        suite.fail(f"{path}: transaction.revert failed {reverted.get('error')}")
        return report

    # Prove the original state is back via independent REST reads.
    after = {
        "branch": read_hex(api, base, branch_addr, instructions[0]["length"]),
        "nop": read_hex(api, base, nop_unit["address"], nop_unit["length"]),
        "assemble": read_hex(api, base, asm_unit["address"], asm_unit["length"]),
    }
    seen_branch = code_unit(api, base, branch_addr)
    report["post_revert_bytes"] = after
    report["checks"]["revert_restored_bytes"] = after == before
    report["checks"]["revert_restored_mnemonic"] = seen_branch["mnemonic"] == branch_mnemonic_before
    if not report["checks"]["revert_restored_bytes"]:
        suite.fail(f"{path}: revert did not restore original bytes: {after} != {before}")
    if not report["checks"]["revert_restored_mnemonic"]:
        suite.fail(f"{path}: revert did not restore mnemonic {branch_mnemonic_before}")

    # ghidra family on this binary's session.
    info = suite.step("ghidra.info", "ghidra.info", {"worker_id": worker})
    report["ghidra_info"] = info.get("result")
    if not info["ok"]:
        suite.fail(f"{path}: ghidra.info failed")
    for tool, args in (
        ("ghidra.call", {"target": "ghidra.program.model.listing.Function", "args": []}),
        ("ghidra.eval", {"code": "1 + 1"}),
        ("ghidra.script", {"path": "/nonexistent/probe.py", "script_args": []}),
    ):
        gated = suite.probe(
            f"{tool} gated (trusted disabled)", tool, {**args, **base}, expected=403
        )
        message = (gated.get("error") or {}).get("message", "")
        gated["gated_message_ok"] = "Trusted execution is disabled" in message
        if not gated["gated_message_ok"]:
            suite.findings.append(
                f"{tool} on {path}: rejection message does not match the trusted gate: {message[:120]}"
            )
        if gated["http_status"] != 403:
            suite.findings.append(
                f"{tool}: gated PermissionError surfaced as HTTP {gated['http_status']} "
                f"(documented mapping: 403). Message: {message[:120]}"
            )
        report.setdefault("ghidra_gated", []).append(
            {"tool": tool, "http_status": gated["http_status"], "message": message[:160]}
        )

    report["ops"] = suite.ops[ops_start:]
    report["ops_summary"] = summarize(list(report["ops"]))
    return report


def rejection_probes(suite: Suite, binaries: list[str]) -> list[dict]:
    api, worker = suite.api, suite.worker
    # Unknown tool -> 404 at the supervisor.
    suite.probe("unknown tool", "no.such.tool", {"worker_id": worker}, expected=404)
    # Unknown worker -> ValueError at the supervisor -> 400.
    suite.probe(
        "unknown worker_id", "function.list", {"worker_id": f"{worker}_ghost"}, expected=400
    )
    if binaries:
        opened = run_op(api, "program.open", {"worker_id": worker, "path": binaries[0], "read_only": False})
        if opened.get("result"):
            session = opened["result"]["session_id"]
            base = {"worker_id": worker, "session_id": session}
            branch = find_conditional_branch(suite, base)
            ret_addr = f"{_addr_int(branch['address']) + 0x1000:x}" if branch else "0x0"
            # Cross-worker session handle -> ValueError at the supervisor -> 400.
            suite.probe(
                "session routed to wrong worker",
                "patch.nop",
                {"worker_id": "api_load_b", "session_id": session, "address": ret_addr},
                expected=400,
            )
            # Tool-level ValueError probes (documented mapping: 400).
            suite.probe(
                "patch.nop count=0 (ValueError)", "patch.nop", {**base, "address": ret_addr, "count": 0}, expected=400
            )
            if branch:
                suite.probe(
                    "branch_invert on non-branch (ValueError)",
                    "patch.branch_invert",
                    {**base, "address": ret_addr},
                    expected=400,
                )
            suite.probe(
                "patch.assemble empty body (ValueError)",
                "patch.assemble",
                {**base, "address": ret_addr, "assembly": "  "},
                expected=400,
            )
            # Read-only session write -> permission class -> 403.
            ro = run_op(api, "program.open", {"worker_id": worker, "path": binaries[-1], "read_only": True})
            ro_session = (ro.get("result") or {}).get("session_id")
            if ro_session and ro["result"].get("read_only"):
                probe = suite.probe(
                    "write on read-only session",
                    "patch.nop",
                    {"worker_id": worker, "session_id": ro_session, "address": ret_addr},
                    expected=403,
                )
                message = (probe.get("error") or {}).get("message", "")
                if "read-only" not in message:
                    suite.findings.append(f"read-only probe message unexpected: {message[:120]}")
            else:
                suite.probes.append({
                    "probe": "write on read-only session",
                    "expected_status": 403,
                    "ok": True,
                    "skipped": "no independent read-only session available",
                })
    return suite.probes


def summarize(records: list[dict]) -> dict:
    durations = [r["duration_ms"] for r in records if r.get("duration_ms") is not None]
    durations.sort()
    if not durations:
        return {"count": 0}
    return {
        "count": len(durations),
        "p50_ms": round(statistics.median(durations), 1),
        "p95_ms": round(durations[max(0, int(len(durations) * 0.95) - 1)], 1),
        "max_ms": round(durations[-1], 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:29950")
    parser.add_argument("--worker", default="api_load_a")
    parser.add_argument("--binary", action="append", dest="binaries")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    binaries = args.binaries or [LIB_DEFAULT, NATIVE_DEFAULT]
    out_path = Path(args.out) if args.out else REPO / "runtime/acceptance/api/patch-libsyscalls.json"

    api = RestClient(args.base)
    health = api.health()
    print(f"health: {health.get('status')} (base {args.base}, worker {args.worker})")

    suite = Suite(api, args.worker)
    reports = [run_binary(suite, path) for path in binaries]
    rejection_probes(suite, binaries)

    for probe in suite.probes:
        if not probe.get("skipped") and not probe["ok"]:
            suite.findings.append(
                f"probe '{probe['probe']}': expected HTTP {probe['expected_status']}, "
                f"got {probe['http_status']} - {((probe.get('error') or {}).get('message') or '')[:120]}"
            )

    evidence = {
        "suite": "patch+ghidra over REST",
        "base": args.base,
        "worker": args.worker,
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "binaries": reports,
        "rejection_probes": [
            {k: v for k, v in probe.items() if k != "result"} for probe in suite.probes
        ],
        "findings": sorted(set(suite.findings)),
        "summary": {
            "binaries": len(reports),
            "core_ops": len(suite.ops),
            "core_failures": suite.core_failures,
            "mapping_violations": len(suite.findings),
            "ops_latency": summarize(suite.ops),
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(evidence, indent=1))
    print(f"evidence: {out_path}")

    for report in reports:
        name = Path(report["path"]).name
        checks = report.get("checks", {})
        status = "PASS" if not suite.core_failures else "FAIL"
        print(
            f"{status} {name}: branch={report.get('branch')} "
            f"revert_restored={checks.get('revert_restored_bytes')}"
        )
    matrix = {}
    for report in reports:
        name = Path(report["path"]).name
        matrix[name] = {
            r["tool"]: ("ok" if r["ok"] else "error") for r in report.get("ops", [])
        }
    print("matrix:", json.dumps(matrix, indent=1))
    if suite.findings:
        print("findings:")
        for item in sorted(set(suite.findings)):
            print(" -", item)
    if suite.core_failures:
        print("CORE FAILURES:", suite.core_failures)
        return 1
    if suite.findings:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
