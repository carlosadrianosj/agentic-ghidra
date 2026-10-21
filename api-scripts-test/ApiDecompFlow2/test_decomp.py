#!/usr/bin/env python3
"""REST acceptance matrix for the decomp/pcode/graph/search/reference/annotation families.

Exercises every catalog tool of the assigned families against one binary through
the shared REST client (rest_client.py): reads freely, writes strictly inside
transaction.begin -> transaction.revert, plus expected-rejection probes whose
HTTP status must match the exception mapping (ValueError -> 400, ...).

Usage:
  test_decomp.py --binary <path> --label libaes          # op matrix for one binary
  test_decomp.py --soak --binary <path>                  # 8x30s decomp.function soak
  test_decomp.py --stop-worker                           # stop the worker (force=false)

Exit codes: 0 clean, 1 op failures, 2 usage/transport, 3 probe status mismatches.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import threading
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CLIENT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(CLIENT_DIR))

from rest_client import RestClient, RestError, soak

REPO_ROOT = CLIENT_DIR.parent
DEFAULT_OUT = REPO_ROOT / "runtime" / "acceptance" / "api"

# AES Te0[0] = 0xc66363a5 stored little-endian (found twice in libAes.so .rodata).
AES_TE0_LE = "a5 63 63 c6"
# Literal pattern from the assignment brief; recorded as a probe (expected 0 hits).
AES_BRIEF_LITERAL = "c3 66 63 c5"
# AArch64 prologue: stp x29, x30, [sp, #-0x10]!
ARM64_PROLOGUE = "fd 7b bf a9"

# Tools that mutate program state; never auto-retried.
WRITE_TOOLS = {
    "comment.set",
    "bookmark.add",
    "bookmark.clear",
    "bookmark.remove",
    "tag.add",
    "tag.remove",
    "metadata.store",
    "source.file.add",
    "source.file.remove",
    "source.map.add",
    "source.map.remove",
    "relocation.add",
    "context.set",
    "reference.create.memory",
    "reference.create.stack",
    "reference.create.register",
    "reference.create.external",
    "reference.association.set",
    "reference.association.remove",
    "reference.primary.set",
    "reference.delete",
    "reference.clear_from",
    "reference.clear_to",
    "decomp.global.rename",
    "decomp.global.retype",
    "decomp.override.set",
    "decomp.writeback.locals",
    "decomp.writeback.params",
    "transaction.begin",
    "transaction.revert",
    "program.open",
    "program.close",
    "program.mode.set",
}


class Runner:
    """Wraps the shared client, records per-op outcome + envelope duration."""

    def __init__(self, api: RestClient, worker: str) -> None:
        self.api = api
        self.worker = worker
        self.records: list[dict] = []
        self.findings: list[str] = []

    def raw(self, tool: str, arguments: dict, phase: str, expect: str = "ok", _retried=False):
        arguments = {"worker_id": self.worker, **arguments}
        started = time.perf_counter()
        try:
            status, body = self.api.call_raw(tool, arguments)
        except Exception as exc:  # transport failure
            self.records.append(
                {
                    "tool": tool,
                    "phase": phase,
                    "arguments": _slim(arguments),
                    "outcome": "fail",
                    "http_status": None,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    "error": f"transport: {type(exc).__name__}: {exc}",
                }
            )
            return None, False
        duration = body.get("duration_ms") if isinstance(body, dict) else None
        record = {
            "tool": tool,
            "phase": phase,
            "arguments": _slim(arguments),
            "http_status": status,
            "duration_ms": duration,
            "client_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        ok = status == 200 and isinstance(body, dict) and body.get("status") == "ok"
        if expect == "ok":
            record["outcome"] = "pass" if ok else "fail"
            if not ok:
                record["error"] = _errtext(body)
        else:  # expected rejection
            wanted = int(expect)
            record["expected_status"] = wanted
            record["outcome"] = "expected_reject" if status == wanted else "status_mismatch"
            record["rejected"] = status != 200
            if status != wanted:
                record["error"] = _errtext(body)
        self.records.append(record)
        if (
            not _retried
            and record["outcome"] == "fail"
            and tool not in WRITE_TOOLS
            and "deadline" in str(record.get("error", ""))
        ):
            retry = self.raw(tool, dict(arguments), phase, expect, _retried=True)
            if retry[1]:
                record["retried_ok"] = True
                return retry[0], True
        result = body.get("result") if isinstance(body, dict) else None
        return result, record["outcome"] in ("pass", "expected_reject")

    def call(self, tool: str, arguments: dict, phase: str):
        result, ok = self.raw(tool, arguments, phase)
        if not ok:
            raise RuntimeError(f"{tool} failed; see records")
        return result

    def note(self, text: str) -> None:
        self.findings.append(text)


def _slim(arguments: dict) -> dict:
    slim = dict(arguments)
    for key in ("worker_id",):
        slim.pop(key, None)
    return slim


def _errtext(body) -> str:
    if isinstance(body, dict):
        return str(body.get("error", {}).get("message", body))
    return str(body)[:300]


def _body_size(function: dict) -> int:
    numbers = [int(x, 16) for x in re.findall(r"[0-9a-f]{6,}", function.get("body", ""))]
    return sum(b - a + 1 for a, b in zip(numbers[0::2], numbers[1::2])) if numbers else 0


def pick_functions(runner: Runner, session: str) -> dict:
    """f_big: largest body, f_mid: large with >=1 param, f_small: smallest >=0x24."""
    functions, offset = [], 0
    while True:
        page = runner.call(
            "function.list", {"session_id": session, "limit": 1000, "offset": offset}, "setup"
        )
        functions.extend(page["functions"])
        if not page.get("has_more"):
            break
        offset = page["next_offset"]
    real = [
        f
        for f in functions
        if not f["thunk"] and not f["external"] and _body_size(f) >= 0x18
    ]
    if len(real) < 3:
        raise RuntimeError(f"only {len(real)} real functions found")
    ordered = sorted(real, key=_body_size, reverse=True)
    f_big = ordered[0]
    with_params = [f for f in ordered if f["parameter_count"] >= 1]
    f_mid = with_params[0] if with_params else ordered[min(3, len(ordered) - 1)]
    f_small = ordered[-1]
    chosen = {f_big["address"], f_mid["address"], f_small["address"]}
    sample = [f for f in ordered if f["address"] not in chosen][:12]
    return {
        "f_big": f_big,
        "f_mid": f_mid,
        "f_small": f_small,
        "more": sample,
        "function_count": len(functions),
        "real_count": len(real),
    }

def find_callsite(runner: Runner, session: str, functions: list[dict]) -> tuple[str, str] | None:
    """(function_start, call instruction address) for the first function with a call."""
    for function in functions:
        edges = runner.call(
            "graph.cfg.edges",
            {"session_id": session, "function_start": function["address"]},
            "setup",
        )
        for edge in edges.get("edges", []):
            if edge.get("call") and edge.get("callsite"):
                return function["address"], str(edge["callsite"])
        result = runner.call(
            "search.instructions",
            {
                "session_id": session,
                "query": "BL",
                "function_start": function["address"],
                "limit": 1,
            },
            "setup",
        )
        matches = result.get("matches", [])
        if matches:
            return function["address"], str(matches[0]["address"])
    return None



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:29950")
    parser.add_argument("--worker", default="api_decomp")
    parser.add_argument("--binary", help="binary path for matrix or soak mode")
    parser.add_argument("--label", help="evidence label (default: derived from file name)")
    parser.add_argument("--soak", action="store_true", help="run the decomp soak")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--duration", type=int, default=30, help="soak seconds")
    parser.add_argument("--stop-worker", action="store_true")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    api = RestClient(args.base)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.binary and not args.stop_worker:
        parser.error("--binary is required unless --stop-worker is used")

    exit_code = 0
    if args.binary:
        label = args.label or Path(args.binary).stem.lower().replace("_arm64", "")
        runner = Runner(api, args.worker)
        try:
            if args.soak:
                exit_code = soak_mode(runner, args, label)
            else:
                exit_code = matrix_mode(runner, args, label)
        except Exception as exc:
            import traceback

            runner.note(f"abort: {type(exc).__name__}: {exc}\n{traceback.format_exc(limit=8)}")
            exit_code = 1
        evidence = {
            "mode": "soak" if args.soak else "matrix",
            "base": args.base,
            "worker": args.worker,
            "binary": args.binary,
            "label": label,
            "records": runner.records,
            "findings": runner.findings,
            "summary": summarize(runner.records),
        }
        suffix = "soak" if args.soak else label
        path = out_dir / f"decomp-{suffix}.json"
        path.write_text(json.dumps(evidence, indent=1))
        print(f"evidence: {path}")
        failures = evidence["summary"]["ops_failed"]
        mismatches = evidence["summary"]["probe_mismatches"]
        print(f"ops passed={evidence['summary']['ops_passed']} failed={failures} probe_mismatches={mismatches}")
        if exit_code == 0 and failures:
            exit_code = 1
        if exit_code == 0 and mismatches:
            exit_code = 3

    if args.stop_worker:
        runner = Runner(api, args.worker)
        runner.raw("worker_stop", {"worker_id": args.worker, "force": False}, "teardown")
        print(f"worker {args.worker} stop requested")
        if runner.records[-1]["outcome"] != "pass":
            exit_code = exit_code or 1
    return exit_code


def summarize(records: list[dict]) -> dict:
    ops = [r for r in records if r["outcome"] in ("pass", "fail")]
    probes = [r for r in records if r["outcome"] in ("expected_reject", "status_mismatch")]
    families: dict[str, dict] = {}
    for record in records:
        family = record["tool"].split(".")[0]
        slot = families.setdefault(family, {"passed": 0, "failed": 0, "mismatch": 0})
        if record["outcome"] == "pass":
            slot["passed"] += 1
        elif record["outcome"] == "fail":
            slot["failed"] += 1
        elif record["outcome"] == "status_mismatch":
            slot["mismatch"] += 1
    durations = [r["duration_ms"] for r in ops if r.get("duration_ms") is not None]
    return {
        "ops_total": len(ops),
        "ops_passed": sum(1 for r in ops if r["outcome"] == "pass"),
        "ops_failed": sum(1 for r in ops if r["outcome"] == "fail"),
        "probes_total": len(probes),
        "probe_mismatches": sum(1 for r in probes if r["outcome"] == "status_mismatch"),
        "distinct_tools_exercised": len({r["tool"] for r in records}),
        "latency_ms": {
            "p50": round(statistics.median(durations), 2) if durations else None,
            "p95": round(sorted(durations)[max(0, int(len(durations) * 0.95) - 1)], 2)
            if durations
            else None,
            "max": max(durations) if durations else None,
            "sum": round(sum(durations), 2) if durations else None,
        },
        "families": families,
    }


# --------------------------------------------------------------------------- matrix


def matrix_mode(runner: Runner, args, label: str) -> int:
    print(f"[{label}] opening {args.binary}")
    opened = runner.call(
        "program.open",
        {"path": args.binary, "read_only": False, "update_analysis": True},
        "setup",
    )
    session = opened["session_id"]
    if opened.get("read_only"):
        runner.call("program.mode.set", {"session_id": session, "read_only": False}, "setup")

    try:
        picks = pick_functions(runner, session)
        f_big, f_mid, f_small = picks["f_big"], picks["f_mid"], picks["f_small"]
        print(
            f"[{label}] {picks['function_count']} functions; "
            f"big={f_big['name']}@{f_big['address']} mid={f_mid['name']}@{f_mid['address']} "
            f"small={f_small['name']}@{f_small['address']}"
        )

        decomp_reads(runner, session, picks)
        pcode_reads(runner, session, picks)
        graph_reads(runner, session, picks)
        search_reads(runner, session, picks, label)
        reference_reads(runner, session, picks, label)

        annotation_group(runner, session, picks, label)
        source_group(runner, session, picks, label)
        reloc_context_group(runner, session, picks, label)
        reference_write_group(runner, session, picks, label)
        decomp_write_group(runner, session, picks, label)

        rejection_probes(runner, session, picks)
    finally:
        result, ok = runner.raw("program.close", {"session_id": session}, "teardown")
        if ok:
            print(f"[{label}] closed session")
    return 0


def decomp_reads(runner: Runner, session: str, picks: dict) -> None:
    """12 decomp reads (4 tools x 3 functions) through /api/v1/batch."""
    targets = [picks["f_big"], picks["f_mid"], picks["f_small"]]
    codes = []
    for tool in ("decomp.function", "decomp.tokens", "decomp.ast", "decomp.high_function.summary"):
        calls = [
            {
                "tool": tool,
                "arguments": {
                    "worker_id": runner.worker,
                    "session_id": session,
                    "function_start": f["address"],
                },
            }
            for f in targets
        ]
        started = time.perf_counter()
        pairs: list[tuple[dict, dict | None]] = []
        try:
            envelopes = runner.api.batch(calls, pipeline=False, stop_on_error=False)
            pairs = list(zip(calls, envelopes))
        except RestError as exc:
            runner.note(f"batch[{tool} x3] failed ({exc}); retrying as singleton batches")
            for call in calls:
                try:
                    single = runner.api.batch([call], pipeline=False, stop_on_error=False)
                    pairs.append((call, single[0] if single else None))
                except RestError as inner:
                    runner.note(f"singleton batch {tool} failed: {inner}")
                    pairs.append((call, None))
        wall_ms = round((time.perf_counter() - started) * 1000, 2)
        for index, (call, envelope) in enumerate(pairs):
            function_start = call["arguments"]["function_start"]
            if envelope is None:
                runner.records.append(
                    {
                        "tool": tool,
                        "phase": "decomp",
                        "arguments": {"function_start": function_start},
                        "outcome": "fail",
                        "http_status": None,
                        "duration_ms": None,
                        "error": "no envelope (batch and singleton both failed)",
                    }
                )
                continue
            record = {
                "tool": tool,
                "phase": "decomp",
                "arguments": {"function_start": function_start},
                "http_status": 200 if envelope["status"] == "ok" else 500,
                "duration_ms": envelope.get("duration_ms"),
                "outcome": "pass" if envelope["status"] == "ok" else "fail",
            }
            if envelope["status"] != "ok":
                record["error"] = str(envelope.get("error"))[:300]
            else:
                result = envelope.get("result") or {}
                if tool == "decomp.function":
                    codes.append(result.get("code"))
                elif tool == "decomp.tokens" and not result.get("tokens"):
                    runner.note(f"decomp.tokens empty for {function_start}")
                elif tool == "decomp.ast" and not result.get("nodes"):
                    runner.note(f"decomp.ast empty for {function_start}")
                elif (
                    tool == "decomp.high_function.summary"
                    and result.get("varnode_count", 0) <= 0
                ):
                    runner.note(f"high_function.summary varnode_count<=0 for {function_start}")
            runner.records.append(record)
        runner.records[-1]["batch_wall_ms"] = wall_ms
        runner.records[-1]["batch_size"] = len(calls)
    if not codes or not all(isinstance(c, str) and "{" in c for c in codes):
        runner.note("decomp.function results missing C code bodies")


def pcode_reads(runner: Runner, session: str, picks: dict) -> None:
    f_big, f_small = picks["f_big"], picks["f_small"]
    result, _ = runner.raw(
        "pcode.function",
        {"session_id": session, "function_start": f_small["address"], "limit": 40},
        "pcode",
    )
    if result and not result.get("ops"):
        runner.note("pcode.function returned zero ops")
    runner.raw("pcode.block", {"session_id": session, "address": f_small["address"]}, "pcode")
    result, _ = runner.raw("pcode.op.at", {"session_id": session, "address": f_big["address"]}, "pcode")
    if result and not result.get("ops"):
        runner.note("pcode.op.at returned zero ops at function entry")
    runner.raw(
        "pcode.varnode_uses", {"session_id": session, "function_start": f_small["address"]}, "pcode"
    )


def graph_reads(runner: Runner, session: str, picks: dict) -> None:
    f_big, f_mid = picks["f_big"], picks["f_mid"]
    result, _ = runner.raw(
        "graph.cfg.edges", {"session_id": session, "function_start": f_big["address"]}, "graph"
    )
    if result and not result.get("edges"):
        runner.note(f"graph.cfg.edges empty for {f_big['name']}")

    result, _ = runner.raw(
        "graph.basic_blocks", {"session_id": session, "function_start": f_big["address"]}, "graph"
    )
    if result and len(result.get("blocks", [])) < 2:
        runner.note(f"graph.basic_blocks <2 blocks for {f_big['name']}")

    pairs = []
    for source in [f_big, f_mid, picks.get("f_small"), *(picks.get("more") or [])][:12]:
        callees = runner.call(
            "function.callees", {"session_id": session, "function_start": source["address"]}, "setup"
        )
        inner = [
            c
            for c in callees.get("functions", [])
            if not c["external"] and c["address"] != source["address"]
        ]
        if inner:
            pairs.append((source["address"], inner[0]["address"]))
        if len(pairs) >= 3:
            break
    if not pairs:
        pairs = [(f_big["address"], f_mid["address"])]
        runner.note("no internal callees found; call_paths probed with big->mid")
    found_paths = False
    for source, target in pairs:
        result, ok = runner.raw(
            "graph.call_paths",
            {
                "session_id": session,
                "source_function": source,
                "target_function": target,
                "max_depth": 4,
                "limit": 10,
            },
            "graph",
        )
        if ok and result.get("paths"):
            found_paths = True
            break
        runner.note(f"graph.call_paths {source}->{target} returned no paths")
    if not found_paths and pairs:
        runner.note("graph.call_paths found no paths for any candidate pair (leaf-heavy call graph)")


def search_reads(runner: Runner, session: str, picks: dict, label: str) -> None:
    f_big = picks["f_big"]
    is_aes = "libaes" in label.lower()
    patterns = [AES_TE0_LE, AES_BRIEF_LITERAL] if is_aes else [ARM64_PROLOGUE]
    for pattern in patterns:
        result, ok = runner.raw(
            "search.bytes", {"session_id": session, "pattern_hex": pattern, "limit": 20}, "search"
        )
        if ok:
            hits = len(result.get("matches", []))
            if pattern == AES_TE0_LE and hits == 0:
                runner.note("AES Te0 LE pattern not found (expected >=1)")
            if pattern == AES_BRIEF_LITERAL and hits:
                runner.note(f"brief literal pattern found {hits}x (unexpected)")

    result, ok = runner.raw(
        "search.constants", {"session_id": session, "value": 16, "limit": 10}, "search"
    )
    if ok and not result.get("matches"):
        runner.note("search.constants value=16 found no immediates")

    strings, ok = runner.raw(
        "search.defined_strings", {"session_id": session, "limit": 10}, "search"
    )
    sample = None
    if ok:
        items = strings.get("strings", strings.get("matches", []))
        if not items:
            runner.note("search.defined_strings found none")
        else:
            first = items[0]
            sample = (first.get("value") or first.get("text") or "")[:8] or None

    result, ok = runner.raw(
        "search.instructions", {"session_id": session, "query": "BL", "limit": 10}, "search"
    )
    if ok and not result.get("matches"):
        runner.note("search.instructions 'BL' found none")

    result, ok = runner.raw(
        "search.pcode",
        {"session_id": session, "query": "INT_XOR" if is_aes else "INT_ADD", "limit": 10},
        "search",
    )
    if ok and not result.get("matches"):
        runner.note("search.pcode found none")

    result, ok = runner.raw(
        "search.resolve", {"session_id": session, "query": f"0x{f_big['address']}"}, "search"
    )
    if ok and result.get("address") != f"00{f_big['address']}":
        # address echoes canonical Ghidra form; accept any exact parse
        if str(result.get("address", "")).lower().endswith(f_big["address"].lower()) is False:
            runner.note(f"search.resolve echoed {result.get('address')} for 0x{f_big['address']}")

    text = sample or "AES"
    result, ok = runner.raw(
        "search.text",
        {"session_id": session, "text": text, "defined_strings_only": True, "limit": 10},
        "search",
    )
    if ok and not result.get("matches"):
        runner.note(f"search.text '{text}' (defined strings) found none")


def reference_reads(runner: Runner, session: str, picks: dict, label: str) -> None:
    f_big, f_mid = picks["f_big"], picks["f_mid"]
    export = find_export(runner, session)
    target = export or f_big["address"]
    result, ok = runner.raw(
        "reference.to", {"session_id": session, "address": target, "limit": 50}, "reference"
    )
    if ok:
        refs = result.get("references", [])
        if not refs:
            runner.note(f"reference.to on {target} found no xrefs")
    runner.raw(
        "reference.from", {"session_id": session, "address": f_mid["address"], "limit": 20}, "reference"
    )


def find_export(runner: Runner, session: str) -> str | None:
    symbols = runner.call(
        "symbol.list", {"session_id": session, "limit": 500, "include_dynamic": False}, "setup"
    )
    for symbol in symbols.get("symbols", []):
        if symbol.get("type") == "Function" and not symbol.get("external"):
            return str(symbol["address"])
    return None


def annotation_group(runner: Runner, session: str, picks: dict, label: str) -> None:
    f_mid = picks["f_mid"]
    addr = f_mid["address"]
    marker = f"ACC-REST {label}"

    def verify_empty_comment():
        result, ok = runner.raw("comment.get", {"session_id": session, "address": addr}, "revert_check")
        return ok and result.get("comment") is None

    runner.call("transaction.begin", {"session_id": session, "description": f"annotations {label}"}, "tx")
    try:
        result = runner.call(
            "comment.set",
            {"session_id": session, "address": addr, "comment": marker, "comment_type": "eol"},
            "comment",
        )
        if result.get("comment") != marker:
            runner.note("comment.set did not echo the stored comment")

        result = runner.call(
            "comment.get", {"session_id": session, "address": addr}, "comment"
        )
        if result.get("comment") != marker:
            runner.note("comment.get did not read back the eol comment")

        result = runner.call("comment.get_all", {"session_id": session, "address": addr}, "comment")
        if result.get("comments", {}).get("eol") != marker:
            runner.note("comment.get_all missing eol marker")

        result = runner.call(
            "comment.list", {"session_id": session, "query": "ACC-REST", "limit": 10}, "comment"
        )
        if not any(marker in str(c.get("comment", "")) for c in result.get("comments", [])):
            runner.note("comment.list query=ACC-REST missing marker")

        result = runner.call(
            "comment.set",
            {"session_id": session, "function_start": addr, "scope": "function", "comment": marker, "comment_type": "plate"},
            "comment",
        )
        if result.get("comment") != marker:
            runner.note("function-scope comment.set did not store plate comment")

        runner.call(
            "bookmark.add",
            {"session_id": session, "address": addr, "category": "acceptance", "comment": marker},
            "bookmark",
        )
        result = runner.call(
            "bookmark.list", {"session_id": session, "address": addr}, "bookmark"
        )
        if not result.get("bookmarks"):
            runner.note("bookmark.list missing the added bookmark")
        runner.call(
            "bookmark.add",
            {"session_id": session, "address": _plus(addr, 4), "category": "acceptance2", "comment": marker},
            "bookmark",
        )
        runner.call(
            "bookmark.clear",
            {"session_id": session, "start": addr, "length": 16},
            "bookmark",
        )
        result = runner.call("bookmark.list", {"session_id": session, "address": addr}, "bookmark")
        if result.get("bookmarks"):
            runner.note("bookmark.clear left bookmarks behind")
        runner.call(
            "bookmark.add",
            {"session_id": session, "address": addr, "category": "acceptance", "comment": marker},
            "bookmark",
        )
        result = runner.call(
            "bookmark.remove", {"session_id": session, "address": addr}, "bookmark"
        )
        if not result.get("removed"):
            runner.note("bookmark.remove removed=0")

        tag_name = f"acc-{label}"
        runner.call(
            "tag.add",
            {"session_id": session, "function_start": addr, "name": tag_name, "comment": marker},
            "tag",
        )
        result = runner.call("tag.list", {"session_id": session, "function_start": addr}, "tag")
        if not any(t["name"] == tag_name for t in result.get("tags", [])):
            runner.note("tag.list missing added tag")
        result = runner.call("tag.stats", {"session_id": session}, "tag")
        if tag_name not in {t["name"] for t in result.get("tags", [])}:
            runner.note("tag.stats missing added tag")
        result = runner.call(
            "tag.remove", {"session_id": session, "function_start": addr, "name": tag_name}, "tag"
        )
        if not result.get("removed"):
            runner.note("tag.remove removed=False")

        key = f"acceptance.decomp.{label}"
        runner.call(
            "metadata.store",
            {"session_id": session, "key": key, "value": {"marker": marker, "ok": True}},
            "metadata",
        )
        result = runner.call("metadata.query", {"session_id": session, "key": key}, "metadata")
        if not any(entry.get("key") == key for entry in result.get("metadata", [])):
            runner.note("metadata.query did not return the stored key")
    finally:
        revert(runner, session)
    if not verify_empty_comment():
        runner.note("revert check: eol comment survived the revert")


def source_group(runner: Runner, session: str, picks: dict, label: str) -> None:
    addr = picks["f_mid"]["address"]
    path = f"/virtual/acceptance/{label}.c"
    runner.call("transaction.begin", {"session_id": session, "description": f"source {label}"}, "tx")
    try:
        runner.call("source.file.add", {"session_id": session, "path": path}, "source")
        result = runner.call("source.file.list", {"session_id": session}, "source")
        if not any(f.get("path") == path for f in result.get("files", [])):
            runner.note("source.file.list missing the added file")
        result = runner.call(
            "source.map.add",
            {"session_id": session, "path": path, "line_number": 1, "base_address": addr, "length": 16},
            "source",
        )
        if str(result.get("base_address", "")).lower().endswith(addr.lower()) is False:
            runner.note("source.map.add echoed unexpected base_address")
        result = runner.call("source.map.list", {"session_id": session, "address": addr}, "source")
        if not result.get("mappings"):
            runner.note("source.map.list missing the mapping")
        result = runner.call(
            "source.map.remove",
            {"session_id": session, "path": path, "line_number": 1, "base_address": addr},
            "source",
        )
        if not result.get("removed"):
            runner.note("source.map.remove removed=0")
        result = runner.call("source.file.remove", {"session_id": session, "path": path}, "source")
        if not result.get("removed"):
            runner.note("source.file.remove removed=0")
    finally:
        revert(runner, session)
    result, ok = runner.raw("source.file.list", {"session_id": session}, "revert_check")
    if ok and any(f.get("path") == path for f in result.get("files", [])):
        runner.note("revert check: source file survived the revert")


def reloc_context_group(runner: Runner, session: str, picks: dict, label: str) -> None:
    addr = picks["f_mid"]["address"]
    runner.call("transaction.begin", {"session_id": session, "description": f"reloc+context {label}"}, "tx")
    try:
        runner.call(
            "relocation.add",
            {
                "session_id": session,
                "address": addr,
                "status": "APPLIED",
                "type": 1,
                "values": [4096, 1],
                "symbol_name": f"acc_reloc_{label}",
            },
            "relocation",
        )
        result = runner.call(
            "relocation.list",
            {"session_id": session, "start": addr, "end": _plus(addr, 8)},
            "relocation",
        )
        if not any(r.get("symbol_name") == f"acc_reloc_{label}" for r in result.get("relocations", [])):
            runner.note("relocation.list missing the added relocation")

        result = runner.call(
            "context.set",
            {"session_id": session, "register": "x0", "start": addr, "length": 16, "value": 1},
            "context",
        )
        if result.get("value") != 1:
            runner.note("context.set did not echo value=1")
        result = runner.call(
            "context.get", {"session_id": session, "register": "x0", "address": addr}, "context"
        )
        if result.get("value") != 1:
            runner.note("context.get did not read back x0=1")
        runner.call(
            "context.ranges", {"session_id": session, "register": "x0", "start": addr, "end": _plus(addr, 16)}, "context"
        )
    finally:
        revert(runner, session)
    result, ok = runner.raw(
        "relocation.list", {"session_id": session, "start": addr, "end": _plus(addr, 8)}, "revert_check"
    )
    if ok and any(r.get("symbol_name") == f"acc_reloc_{label}" for r in result.get("relocations", [])):
        runner.note("revert check: relocation survived the revert")


def reference_write_group(runner: Runner, session: str, picks: dict, label: str) -> None:
    f_big, f_mid = picks["f_big"], picks["f_mid"]
    src, dst = f_mid["address"], f_big["address"]
    src2, src3 = _plus(src, 0x10), _plus(src, 0x20)
    runner.call("transaction.begin", {"session_id": session, "description": f"references {label}"}, "tx")
    try:
        runner.call(
            "reference.create.memory",
            {"session_id": session, "from_address": src, "to_address": dst},
            "reference",
        )
        result = runner.call(
            "reference.from", {"session_id": session, "address": src, "limit": 10}, "reference"
        )
        if not any(r.get("to_address", "").lower().endswith(dst.lower()) for r in result.get("references", [])):
            runner.note("reference.from missing created memory reference")
        result = runner.call(
            "reference.to", {"session_id": session, "address": dst, "limit": 50}, "reference"
        )
        if not any(r.get("from_address", "").lower().endswith(src.lower()) for r in result.get("references", [])):
            runner.note("reference.to missing created memory reference")

        runner.call(
            "reference.create.stack",
            {"session_id": session, "from_address": src2, "stack_offset": 8},
            "reference",
        )
        runner.call(
            "reference.create.register",
            {"session_id": session, "from_address": src3, "register": "x0"},
            "reference",
        )
        runner.call(
            "reference.create.external",
            {
                "session_id": session,
                "from_address": _plus(src, 0x30),
                "library_name": "libacceptance.so",
                "label": f"acc_fn_{label}",
            },
            "reference",
        )
        symbol_addr = find_export(runner, session) or dst
        runner.call(
            "reference.association.set",
            {"session_id": session, "from_address": src, "to_address": dst, "symbol_address": symbol_addr},
            "reference",
        )
        runner.call(
            "reference.primary.set",
            {"session_id": session, "from_address": src, "to_address": dst},
            "reference",
        )
        result = runner.call(
            "reference.association.remove",
            {"session_id": session, "from_address": src, "to_address": dst},
            "reference",
        )
        runner.call(
            "reference.delete",
            {"session_id": session, "from_address": src, "to_address": dst},
            "reference",
        )
        result = runner.call(
            "reference.from", {"session_id": session, "address": src, "limit": 10}, "reference"
        )
        if any(r.get("to_address", "").lower().endswith(dst.lower()) for r in result.get("references", [])):
            runner.note("reference.delete left the memory reference behind")
        runner.call(
            "reference.clear_from",
            {"session_id": session, "from_address": src2, "end_address": _plus(src2, 0x10)},
            "reference",
        )
        runner.call(
            "reference.clear_to",
            {"session_id": session, "to_address": symbol_addr},
            "reference",
        )
    finally:
        revert(runner, session)


def _rows(container, key: str) -> list:
    """bounded() pages return {key: [...], truncated, limit}; plain lists pass through."""
    if isinstance(container, dict):
        return container.get(key, [])
    return container if isinstance(container, list) else []


def scan_high_symbols(runner: Runner, session: str, picks: dict) -> dict:
    """Scan candidate functions for a decompiled global and a traceable symbol."""
    result = {"global": None, "trace": None}
    candidates = [picks["f_mid"], picks["f_big"], picks["f_small"], *(picks.get("more") or [])]
    for function in candidates:
        summary = runner.call(
            "decomp.high_function.summary",
            {"session_id": session, "function_start": function["address"]},
            "setup",
        )
        for symbol in _rows(summary.get("symbols"), "symbols"):
            name = symbol.get("name")
            if not name:
                continue
            if symbol.get("global") and not symbol.get("parameter") and not result["global"]:
                result["global"] = (function["address"], name)
            if symbol.get("parameter") and not result["trace"]:
                result["trace"] = (function["address"], name, symbol.get("ordinal"))
            if result["global"] and result["trace"]:
                return result
    return result


def retype_target(symbol: dict | None) -> str | None:
    """A data type that keeps the symbol mappable: pointers to void*, wide ints by size."""
    if symbol is None:
        return "long"
    current = str(symbol.get("data_type", ""))
    if current.endswith("*"):
        return "void *"
    size = int(symbol.get("size", 8) or 8)
    if size == 1:
        return current or "char"
    return {2: "ushort", 4: "int", 8: "long"}.get(size, "long")


def ensure_tx(runner: Runner, session: str, description: str) -> None:
    """Re-begin the explicit transaction after an in-batch failure auto-reverted it."""
    try:
        status = runner.call("transaction.status", {"session_id": session}, "tx")
        if not status.get("pending"):
            runner.call(
                "transaction.begin", {"session_id": session, "description": description}, "tx"
            )
    except RuntimeError:
        runner.note("ensure_tx could not restore the transaction")


def decomp_write_group(runner: Runner, session: str, picks: dict, label: str) -> None:
    f_mid = picks["f_mid"]
    addr = f_mid["address"]
    candidates = [f_mid, picks["f_big"], picks["f_small"], *(picks.get("more") or [])]

    scan = scan_high_symbols(runner, session, picks)
    trace_fn_addr, trace_name = (None, None)
    if scan["trace"]:
        trace_fn_addr, trace_name, _ordinal = scan["trace"]

    callsite = find_callsite(runner, session, candidates)
    global_symbol = scan["global"]
    description = f"decomp writes {label}"
    runner.call("transaction.begin", {"session_id": session, "description": description}, "tx")
    try:
        if global_symbol:
            g_addr, g_name = global_symbol
            _, ok = runner.raw(
                "decomp.global.rename",
                {
                    "session_id": session,
                    "function_start": g_addr,
                    "name": g_name,
                    "new_name": "acc_renamed",
                },
                "decomp",
            )
            if not ok:
                ensure_tx(runner, session, description)
            summary = runner.call(
                "decomp.high_function.summary",
                {"session_id": session, "function_start": g_addr},
                "decomp",
            )
            symbol = next(
                (
                    s
                    for s in _rows(summary.get("symbols"), "symbols")
                    if s.get("name") == "acc_renamed"
                ),
                None,
            )
            _, ok = runner.raw(
                "decomp.global.retype",
                {
                    "session_id": session,
                    "function_start": g_addr,
                    "name": "acc_renamed",
                    "data_type": retype_target(symbol),
                },
                "decomp",
            )
            if not ok:
                ensure_tx(runner, session, description)
        else:
            runner.note("no decompiled global symbol found in any candidate function")

        if trace_name and trace_fn_addr:
            runner.raw(
                "decomp.trace_type.backward",
                {
                    "session_id": session,
                    "function_start": trace_fn_addr,
                    "name": trace_name,
                    "ordinal": 0,
                },
                "decomp",
            )
            runner.raw(
                "decomp.trace_type.forward",
                {"session_id": session, "function_start": trace_fn_addr, "name": trace_name},
                "decomp",
            )
        else:
            runner.note("no traceable symbol found; trace ops skipped")

        runner.raw(
            "decomp.writeback.locals", {"session_id": session, "function_start": addr}, "decomp"
        )
        runner.raw(
            "decomp.writeback.params",
            {"session_id": session, "function_start": addr, "use_data_types": True},
            "decomp",
        )
        if callsite:
            callsite_fn, callsite_addr = callsite
            runner.raw(
                "decomp.override.set",
                {
                    "session_id": session,
                    "function_start": callsite_fn,
                    "callsite": callsite_addr,
                    "signature": "undefined acc_stub(void)",
                },
                "decomp",
            )
            result, ok = runner.raw(
                "decomp.override.get",
                {"session_id": session, "function_start": callsite_fn, "callsite": callsite_addr},
                "decomp",
            )
            if ok and not result.get("found"):
                runner.note("decomp.override.get found=false after override.set")
        else:
            runner.note("no call instruction found in any candidate; override skipped")
    finally:
        revert(runner, session)


def rejection_probes(runner: Runner, session: str, picks: dict) -> None:
    f_big, f_mid = picks["f_big"], picks["f_mid"]
    probes = [
        ("search.bytes", {"session_id": session}, 400, "no pattern -> ValueError"),
        ("comment.get", {"session_id": session, "address": f_mid["address"], "comment_type": "bogus"}, 400, "bad comment_type -> ValueError"),
        ("context.set", {"session_id": session, "register": "zz9", "start": f_mid["address"], "value": 1}, 400, "unknown register -> ValueError"),
        ("context.set", {"session_id": session, "register": "x0", "start": f_mid["address"]}, 400, "value required -> ValueError"),
        ("pcode.varnode_uses", {"session_id": session, "function_start": f_small_addr(picks), "size": 0}, 400, "size must be positive -> ValueError"),
        ("tag.add", {"session_id": session, "function_start": f_mid["address"], "name": ""}, 400, "empty tag name -> ValueError"),
        ("metadata.store", {"session_id": session, "key": ""}, 400, "empty key -> ValueError"),
        ("relocation.add", {"session_id": session, "address": f_mid["address"], "byte_length": 99}, 400, "byte_length out of range -> ValueError"),
        ("decomp.override.set", {"session_id": session, "function_start": f_big["address"], "callsite": f_big["address"], "signature": "undefined f(void)"}, 400, "callsite not a call -> ValueError"),
        ("search.resolve", {"session_id": session, "query": "0xfff000000000"}, 400, "unmapped address -> ValueError"),
        ("decomp.no_such_tool", {"session_id": session}, 404, "unknown tool"),
    ]
    for tool, arguments, expected, why in probes:
        result, _ = runner.raw(tool, arguments, "probe", expect=str(expected))
        record = runner.records[-1]
        record["why"] = why
        if record["outcome"] == "status_mismatch":
            runner.note(
                f"probe {tool}: expected HTTP {expected}, got {record['http_status']} ({record.get('error', '')[:120]})"
            )
        if tool == "tag.add" and record.get("http_status") == 200:
            # Validation gap: the empty tag was created and auto-committed; undo it.
            runner.raw(
                "tag.remove",
                {"session_id": session, "function_start": f_mid["address"], "name": ""},
                "probe_cleanup",
            )
            runner.note("tag.add empty-name probe created a tag (auto-commit); removed afterwards")


def f_small_addr(picks: dict) -> str:
    return picks["f_small"]["address"]


def revert(runner: Runner, session: str) -> None:
    status = runner.call("transaction.status", {"session_id": session}, "tx")
    if status.get("pending"):
        runner.call("transaction.revert", {"session_id": session}, "tx")
    else:
        runner.note("transaction auto-reverted after an in-batch failure")


def _plus(address: str, delta: int) -> str:
    return f"{int(address, 16) + delta:0{len(address)}x}"


# --------------------------------------------------------------------------- soak


def soak_mode(runner: Runner, args, label: str) -> int:
    api = runner.api
    print(f"[{label}-soak] opening {args.binary}")
    opened = runner.call("program.open", {"path": args.binary, "update_analysis": True}, "setup")
    session = opened["session_id"]
    try:
        _soak_body(runner, args, label, session)
    finally:
        result, ok = runner.raw("program.close", {"session_id": session}, "teardown")
        if ok:
            print(f"[{label}-soak] closed session")
    soak_record = next(
        (r for r in reversed(runner.records) if r.get("phase") == "soak" and "soak" in r), None
    )
    if soak_record is None:
        return 1
    return 0 if not soak_record["soak"]["errors"] else 1


def _soak_body(runner: Runner, args, label: str, session: str) -> None:
    api = runner.api
    picks = pick_functions(runner, session)
    fast = picks["f_small"]
    print(f"[{label}-soak] fast function {fast['name']} @ {fast['address']}")

    runner.call(
        "decomp.function",
        {"session_id": session, "function_start": fast["address"]},
        "warmup",
    )

    envelope_ms: list[float] = []
    lock = threading.Lock()

    def workload(client: RestClient):
        status, body = client.call_raw(
            "decomp.function",
            {"worker_id": args.worker, "session_id": session, "function_start": fast["address"]},
        )
        if status != 200 or not isinstance(body, dict) or body.get("status") != "ok":
            raise RuntimeError(f"HTTP {status}: {str(body)[:120]}")
        with lock:
            envelope_ms.append(float(body["duration_ms"]))

    stats = soak(api, workload, args.threads, args.duration)
    envelope_ms.sort()
    envelope_stats = {
        "count": len(envelope_ms),
        "p50_ms": round(statistics.median(envelope_ms), 2) if envelope_ms else None,
        "p95_ms": round(envelope_ms[max(0, int(len(envelope_ms) * 0.95) - 1)], 2) if envelope_ms else None,
        "max_ms": round(envelope_ms[-1], 2) if envelope_ms else None,
    }
    stats["envelope_duration_ms"] = envelope_stats
    stats["overhead_ms"] = (
        {
            "p50": round(stats["p50_ms"] - envelope_stats["p50_ms"], 2),
            "p95": round(stats["p95_ms"] - envelope_stats["p95_ms"], 2),
        }
        if envelope_stats["count"]
        else None
    )
    stats["throughput_ops_per_sec"] = round(stats["count"] / args.duration, 2)
    stats["function"] = {"name": fast["name"], "address": fast["address"]}
    runner.records.append(
        {
            "tool": "soak(decomp.function)",
            "phase": "soak",
            "outcome": "fail" if stats["errors"] else "pass",
            "http_status": 200,
            "duration_ms": stats["p50_ms"],
            "soak": stats,
        }
    )
    if stats["errors"]:
        runner.note(f"soak errors: {stats['error_samples']}")
    print(
        f"[{label}-soak] count={stats['count']} errors={stats['errors']} "
        f"client p50/p95={stats['p50_ms']}/{stats['p95_ms']}ms "
        f"envelope p50/p95={envelope_stats['p50_ms']}/{envelope_stats['p95_ms']}ms "
        f"throughput={stats['throughput_ops_per_sec']}/s"
    )



if __name__ == "__main__":
    sys.exit(main())
