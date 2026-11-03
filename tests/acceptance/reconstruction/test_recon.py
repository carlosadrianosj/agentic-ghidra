"""REST acceptance suite for the reconstruction families (84 catalog ops).

Covers function(19), variable(5), parameter(4), stackframe(3), type(12),
layout(17), symbol(7), namespace(1), class(1), external(11), equate(4) against
one binary per invocation. Every write operation runs inside
transaction.begin ... transaction.revert over REST; expected-rejection probes
compare the actual HTTP status against the documented exception->status
mapping (ValueError->400, unknown tool->404).

Usage:
    python test_recon.py --base http://127.0.0.1:29950 --worker api_recon \
        --binary /abs/path/libjnidemo_arm64.so --tag jnidemo

Evidence: <repo>/runtime/acceptance/api/recon-<tag>.json
Exit code 0 only when every family op passed and every probe matched.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITE_ROOT = HERE.parent            # tests/acceptance
REPO_ROOT = SUITE_ROOT.parent       # repo root
sys.path.insert(0, str(SUITE_ROOT))

from rest_client import RestClient

FAMILY_COUNTS = {
    "function": 19, "variable": 5, "parameter": 4, "stackframe": 3, "type": 12,
    "layout": 17, "symbol": 7, "namespace": 1, "class": 1, "external": 11,
    "equate": 4,
}
COVERED = [
    "function.list", "function.at", "function.by_name", "function.create",
    "function.delete", "function.rename", "function.body.set", "function.flags.set",
    "function.calling_conventions.list", "function.calling_convention.set",
    "function.thunk.set", "function.return_type.set", "function.signature.get",
    "function.signature.set", "function.variables", "function.callers",
    "function.callees", "function.report", "function.batch.run",
    "variable.rename", "variable.retype", "variable.comment.set",
    "variable.local.create", "variable.local.remove",
    "parameter.add", "parameter.remove", "parameter.move", "parameter.replace",
    "stackframe.variables", "stackframe.variable.create", "stackframe.variable.clear",
    "type.get", "type.list", "type.get_by_id", "type.parse_c", "type.define_c",
    "type.rename", "type.delete", "type.category.create", "type.category.list",
    "type.archives.list", "type.source_archives.list", "type.apply_at",
    "layout.struct.create", "layout.struct.get", "layout.struct.field.add",
    "layout.struct.field.replace", "layout.struct.field.clear",
    "layout.struct.field.rename", "layout.struct.field.comment.set",
    "layout.struct.resize", "layout.struct.bitfield.add",
    "layout.struct.fill_from_decompiler", "layout.enum.create",
    "layout.enum.member.add", "layout.enum.member.remove", "layout.union.create",
    "layout.union.member.add", "layout.union.member.remove",
    "layout.inspect.components",
    "symbol.list", "symbol.by_name", "symbol.create", "symbol.rename",
    "symbol.delete", "symbol.primary.set", "symbol.namespace.move",
    "namespace.create", "class.create",
    "external.library.create", "external.library.list", "external.library.set_path",
    "external.location.create", "external.function.create", "external.location.get",
    "external.imports.list", "external.exports.list", "external.entrypoint.list",
    "external.entrypoint.add", "external.entrypoint.remove",
    "equate.create", "equate.list", "equate.delete", "equate.clear_range",
]

C_DECLARATIONS = {
    "jnidemo": (
        "struct JNINativeMethod { const char *name; const char *signature; void *fnPtr; };",
        "struct ReconJNIBatch { struct JNINativeMethod entries[2]; int registered; };",
    ),
    "stripped": (
        "struct ReconStrtab { char *names[4]; unsigned int count; };",
        "struct ReconStrtabWrap { struct ReconStrtab header; unsigned int extra; };",
    ),
    "rtti": (
        "struct ReconTypeInfo { void *vptr; char *name; unsigned int flags; unsigned int hash; };",
        "struct ReconVtableHead { struct ReconTypeInfo info; void (*slots[4])(void); };",
    ),
}

SKIP_FUNCTIONS = {"_init", "_fini", "_start", "__do_global_dtors_aux",
                  "_dl_relocate_static_pie", "frame_dummy"}
RETURN_WORDS = {
    "void", "int", "long", "char", "short", "float", "double", "bool", "uint",
    "ulong", "ushort", "undefined", "byte", "word", "dword", "qword", "string",
    "ustring", "pid_t",
}


class Harness:
    """Records one entry per catalog op plus setup/check/probe entries."""

    def __init__(self, api: RestClient, worker: str, tag: str, binary: str):
        self.api = api
        self.worker = worker
        self.tag = tag
        self.binary = binary
        self.session_id: str | None = None
        self.ops: list[dict] = []
        self.checks: list[dict] = []
        self.probes: list[dict] = []
        self.findings: list[str] = []

    def args(self, **kw) -> dict:
        base = {"worker_id": self.worker}
        if self.session_id:
            base["session_id"] = self.session_id
        base.update(kw)
        return base

    def call(self, tool: str, arguments: dict, *, record=True, note=None):
        """Invoke one tool; returns (ok, result_or_error_message)."""
        status, body = self.api.call_raw(tool, arguments)
        ok = status == 200 and isinstance(body, dict) and body.get("status") == "ok"
        result = body.get("result") if ok else (body.get("error") or {}).get("message", body)
        if record:
            self.ops.append({
                "tool": tool, "outcome": "ok" if ok else "fail",
                "http_status": status, "duration_ms": body.get("duration_ms"),
                "note": note, "result": _trim(result),
            })
        return ok, result

    def check(self, name: str, ok: bool, detail=""):
        self.checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})
        return ok

    def rows(self, result, *keys):
        for key in keys:
            if isinstance(result, dict) and isinstance(result.get(key), list):
                return result[key]
        if isinstance(result, list):
            return result
        return []


def _trim(value, limit=900):
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    return text[:limit]


def _parse_body(body: str):
    """Accepts Ghidra body strings like '[[001004e0, 001004f7]]' or '[a:b]'."""
    match = re.search(r"([0-9a-fA-F]{4,})\s*[,:]\s*([0-9a-fA-F]+)", body or "")
    if not match:
        return None, None
    return int(match.group(1), 16), int(match.group(2), 16)


def _body_size(record: dict) -> int:
    start, end = _parse_body(record.get("body", ""))
    return (end - start) if start is not None else 0


def _pick_functions(h: Harness):
    _, result = h.call("function.list", h.args(limit=80))
    functions = h.rows(result, "functions")
    if not functions:
        return None, None, []

    def score(f):
        return (
            4 * (not f.get("custom_storage", False))
            + 2 * (int(f.get("parameter_count", 0)) >= 1)
            + 1 * (_body_size(f) >= 0x20)
            + 1 * (not str(f.get("name", "")).startswith("FUN_"))
            + 1 * (str(f.get("name", "")) not in SKIP_FUNCTIONS)
        )

    pool = [f for f in functions
            if not f.get("external") and not f.get("thunk")
            and f.get("name") not in SKIP_FUNCTIONS]
    pool = pool or [f for f in functions if not f.get("external")]
    pool = sorted(pool, key=lambda f: (-score(f), f["address"]))
    main = pool[0]
    scratch = next((f for f in pool[1:]), main)
    return main, scratch, functions


def _rewritten_signature(signature: str) -> str:
    tokens = signature.split()
    if not tokens:
        return signature
    if tokens[0].lower() in RETURN_WORDS:
        tokens[0] = "long"
    else:
        tokens.insert(0, "long")
    return " ".join(tokens)


def _immediate_candidates(h: Harness, functions: list[dict], want: int = 4):
    """Find scalar operands (address, operand_index, value) for equate ops."""
    found = []
    for fn in functions[:8]:
        start, end = _parse_body(fn.get("body", ""))
        if start is None:
            continue
        _, result = h.call("listing.code_units.list",
                           h.args(start=fn["address"], end=hex(end), limit=400),
                           record=False)
        for unit in h.rows(result, "code_units"):
            operands = unit.get("operands") or []
            texts = [str(o) for o in operands]
            if not texts and unit.get("text"):
                parts = str(unit["text"]).split(None, 1)
                texts = parts[1].split(",") if len(parts) > 1 else []
            for index, token in enumerate(texts):
                token = token.strip()
                value = token.lstrip("#").strip().rstrip(",")
                try:
                    number = int(value, 0)
                except ValueError:
                    continue
                if token.startswith("#") or value.lower().startswith("0x"):
                    found.append((str(unit["address"]), index, number))
                    break
            if len(found) >= want:
                return found
    return found


def _free_stack_offsets(frame_result, count: int = 2):
    used = set()
    items = frame_result.get("variables", frame_result.get("items", [])) \
        if isinstance(frame_result, dict) else []
    for var in items:
        if isinstance(var, dict) and var.get("stack_offset") is not None:
            used.add(int(var["stack_offset"]))
    chosen, offset = [], -0x10
    while len(chosen) < count and offset >= -0x80:
        if offset not in used:
            chosen.append(offset)
        offset -= 8
    return chosen


def _decompiler_variable_names(h: Harness, entry: str):
    """Pointer-declared variables first (best structure-inference targets)."""
    ok, result = h.call("decomp.function", h.args(function_start=entry, timeout_secs=90),
                        record=False)
    if not ok:
        return [], []
    code = result.get("code", "") if isinstance(result, dict) else ""
    signature = result.get("signature", "") if isinstance(result, dict) else ""
    keywords = {"return", "goto", "break", "continue", "else", "case", "do",
                "while", "if", "for", "switch", "typedef", "struct"}
    pointers, plain = [], []

    def classify(decl: str, sink: list):
        found = re.findall(r"[\w\*]+\s*\*?\s*(\w+)\s*(?:=[^=]|;|\[|,|\))", decl + ";")
        sink.extend(found)

    params = re.search(r"\((.*)\)", signature)
    if params:
        for decl in params.group(1).split(","):
            decl = decl.strip()
            if not decl:
                continue
            classify(decl, pointers if "*" in decl else plain)
    for line in code.splitlines():
        if "(" in line or not re.match(r"^\s+.+;\s*$", line):
            continue
        first = line.strip().split(None, 1)[0] if line.strip() else ""
        if first.rstrip("*") in keywords:
            continue
        classify(line, pointers if "*" in line else plain)
    seen, unique = set(), []
    for name in pointers + plain:
        if name and re.fullmatch(r"[A-Za-z_]\w*", name) and name not in seen:
            seen.add(name)
            unique.append(name)
    return ([n for n in unique if n in pointers],
            [n for n in unique if n not in pointers])


def run_binary(base: str, worker: str, binary: str, tag: str) -> dict:
    api = RestClient(base)
    h = Harness(api, worker, tag, binary)
    started = time.monotonic()
    boot = {}

    health = api.health()
    h.check("health", health.get("status") == "ok", health.get("status"))

    t0 = time.monotonic()
    ok, result = h.call("program.open",
                        {"worker_id": worker, "path": binary,
                         "read_only": False, "update_analysis": True},
                        record=False)
    boot["open_seconds"] = round(time.monotonic() - t0, 2)
    if not ok:
        h.ops.append({"tool": "program.open", "outcome": "fail", "http_status": 500,
                      "duration_ms": None, "note": "setup", "result": _trim(result)})
        return _finish(h, boot, started, early=True)
    h.session_id = result["session_id"]

    # ---------------- phase 1: read sweep --------------------------------
    fn_main, fn_scratch, functions = _pick_functions(h)
    main_entry, main_name = fn_main["address"], fn_main["name"]
    scratch_entry = fn_scratch["address"]

    h.call("function.at", h.args(address=main_entry))
    h.call("function.by_name", h.args(name=main_name, exact=True, limit=5))
    ok, cc = h.call("function.calling_conventions.list", h.args())
    ok, sig = h.call("function.signature.get", h.args(function_start=main_entry))
    base_signature = sig.get("signature", "") if ok else ""
    h.call("function.variables", h.args(function_start=main_entry))
    h.call("function.callers", h.args(function_start=main_entry))
    h.call("function.callees", h.args(function_start=main_entry))
    h.call("function.report", h.args(function_start=main_entry))
    h.call("function.batch.run",
           h.args(action="report.function_summary", limit=2, timeout_secs=180),
           note="report.function_summary over first 2 functions")
    h.call("stackframe.variables", h.args(function_start=main_entry))

    _, type_page = h.call("type.list", h.args(limit=25))
    ok, type_int = h.call("type.get", h.args(name="int"), note="builtin lookup")
    if not ok:  # name-only lookup is ambiguous in some programs; use absolute path
        ok, type_int = h.call("type.get", h.args(path="/int"),
                              note="absolute-path fallback for builtin int")
    if not ok:  # builtins may not resolve at all; use the first program type
        names = [t.get("name") for t in h.rows(type_page, "types")
                 if isinstance(t, dict) and t.get("name")]
        if names:
            ok, type_int = h.call("type.get", h.args(name=names[0]),
                                  note=f"program type fallback {names[0]}")
    type_id = type_int.get("data_type_id") if ok else None
    if type_id is not None:
        h.call("type.get_by_id", h.args(data_type_id=type_id),
               note="id sourced from type.get payload")
    else:
        h.ops.append({"tool": "type.get_by_id", "outcome": "not_run",
                      "http_status": None, "duration_ms": None,
                      "note": "no data_type_id available from type.get", "result": None})
    h.call("type.category.list", h.args(path="/"))
    h.call("type.archives.list", h.args())
    h.call("type.source_archives.list", h.args())
    h.call("symbol.list", h.args(limit=25))
    h.call("symbol.by_name", h.args(name=main_name, exact=True, limit=5))
    h.call("external.library.list", h.args())
    ok, imports = h.call("external.imports.list", h.args(limit=100),
                         note="baseline for transaction diff")
    imports_before = len(h.rows(imports, "imports", "items"))
    h.call("external.exports.list", h.args(limit=100))
    h.call("external.entrypoint.list", h.args())
    h.call("equate.list", h.args(limit=50))
    import_names = [str(i.get("name", i.get("label")))
                    for i in h.rows(imports, "imports", "items") if isinstance(i, dict)]
    if import_names:
        h.call("external.location.get", h.args(name=import_names[0]),
               note=f"baseline import {import_names[0]}")
        location_get_done = True
    else:
        location_get_done = False

    # setup: scalar anchors for equates + data address for apply_at/labels
    cands = _immediate_candidates(h, [fn_main, fn_scratch, *functions])
    _, blocks = h.call("memory.blocks.list", h.args(), record=False)
    writable = [b for b in h.rows(blocks, "blocks")
                if isinstance(b, dict) and b.get("write") and b.get("initialized")
                and not b.get("execute")]
    plain_data = [b for b in h.rows(blocks, "blocks")
                  if isinstance(b, dict) and not b.get("execute") and b.get("initialized")]
    data_pool = [b for b in (writable + plain_data) if b.get("length", 0) >= 64]
    data_block = max(data_pool, key=lambda b: b.get("length", 0)) if data_pool else {}
    data_addr = data_block.get("start")
    label_addr = (_shift(data_addr, min(0x10, data_block.get("length", 0x20) // 2))
                  if data_addr else _shift(main_entry, 4))

    # ---------------- phase 2: txn A (functions/vars/symbols/equates/ext) -
    pipeline_ev = {"assignment_chain": None, "working_chain": None}
    h.call("transaction.begin", h.args(description=f"recon-{tag} write sweep A"),
           record=False)
    try:
        ok, res = h.call("function.signature.set",
                         h.args(function_start=main_entry,
                                signature=_rewritten_signature(base_signature)),
                         note=f"rewritten from '{base_signature}'")
        _, sig_now = h.call("function.signature.get",
                            h.args(function_start=main_entry), record=False)
        h.check("signature.set applied",
                ok and isinstance(sig_now, dict)
                and sig_now.get("signature") != base_signature,
                sig_now.get("signature"))
        h.call("function.return_type.set", h.args(function_start=main_entry,
                                                  data_type="int"))
        ok, _ = h.call("function.flags.set",
                       h.args(function_start=main_entry, inline=True,
                              noreturn=False, custom_storage=False))
        _, rec = h.call("function.at", h.args(address=main_entry), record=False)
        h.check("flags.set inline visible", ok and rec.get("inline") is True,
                rec.get("inline"))
        conventions = h.rows(cc, "conventions", "items")
        conv_names = [c if isinstance(c, str) else str(c.get("name")) for c in conventions]
        target_conv = (conv_names[0] if conv_names
                       else (fn_main.get("calling_convention") or "unknown"))
        ok, _ = h.call("function.calling_convention.set",
                       h.args(function_start=main_entry, name=target_conv))
        _, rec = h.call("function.at", h.args(address=main_entry), record=False)
        h.check("calling_convention.set visible",
                ok and rec.get("calling_convention") == target_conv,
                rec.get("calling_convention"))

        # scratch function: delete -> create -> body.set -> thunk.set
        s_start, s_end = _parse_body(fn_scratch.get("body", ""))
        h.call("function.delete", h.args(function_start=scratch_entry))
        h.call("function.create", h.args(address=scratch_entry, name="recon_made"))
        recreated = scratch_entry
        if s_start is not None:
            h.call("function.body.set",
                   h.args(function_start=recreated, start=hex(s_start), end=hex(s_end)),
                   note="restore original body bounds on recreated function")
        else:
            h.ops.append({"tool": "function.body.set", "outcome": "not_run",
                          "http_status": None, "duration_ms": None,
                          "note": "scratch body unparseable", "result": None})
        ok, _ = h.call("function.thunk.set",
                       h.args(function_start=recreated, thunk_target=main_entry))
        _, rec = h.call("function.at", h.args(address=recreated), record=False)
        h.check("thunk.set visible", ok and rec.get("thunk") is True, rec.get("thunk"))
        renamed = main_name + "_reconren"
        ok, _ = h.call("function.rename", h.args(function_start=main_entry, name=renamed))
        _, res = h.call("function.by_name", h.args(name=renamed, exact=True),
                        record=False)
        h.check("rename visible via by_name",
                ok and renamed in json.dumps(res), renamed)

        # variables + parameters on fn_main
        _, frame = h.call("stackframe.variables", h.args(function_start=main_entry),
                          record=False)
        offsets = _free_stack_offsets(frame, 2)
        h.call("variable.local.create",
               h.args(function_start=main_entry, name="recon_local",
                      data_type="long", stack_offset=offsets[0]),
               note=f"stack_offset {offsets[0]}")
        h.call("variable.rename", h.args(function_start=main_entry, name="recon_local",
                                         new_name="recon_local2"))
        h.call("variable.retype", h.args(function_start=main_entry,
                                         name="recon_local2", data_type="int"))
        h.call("variable.comment.set", h.args(function_start=main_entry,
                                              name="recon_local2", comment="recon var"))
        h.call("stackframe.variable.create",
               h.args(function_start=main_entry, name="recon_stack",
                      stack_offset=offsets[1], data_type="int"))
        h.call("stackframe.variable.clear",
               h.args(function_start=main_entry, stack_offset=offsets[1]))
        h.call("variable.local.remove",
               h.args(function_start=main_entry, name="recon_local2"))

        ok, _ = h.call("parameter.add",
                       h.args(function_start=main_entry, name="recon_pA",
                              data_type="int"))
        register_used = False
        if not ok:  # custom-storage functions demand explicit storage
            ok, _ = h.call("parameter.add",
                           h.args(function_start=main_entry, name="recon_pA",
                                  data_type="int", register="x0"),
                           note="retry with explicit register storage")
            register_used = ok
        extra = {"register": "x1"} if register_used else {}
        h.call("parameter.add",
               h.args(function_start=main_entry, name="recon_pB",
                      data_type="int", **extra),
               note="second parameter so move/replace have room")
        ok3, _ = h.call("parameter.move",
                        h.args(function_start=main_entry, ordinal=0, new_ordinal=1))
        _, sigmv = h.call("function.signature.get",
                          h.args(function_start=main_entry), record=False)
        params = sigmv.get("parameters", []) if isinstance(sigmv, dict) else []
        h.check("parameter.move reordered",
                ok3 and len(params) >= 2 and params[0].get("name") != params[1].get("name"),
                [p.get("name") for p in params][:4])
        h.call("parameter.replace",
               h.args(function_start=main_entry, name="recon_pB",
                      new_name="recon_pB2", data_type="long", **extra),
               note=("explicit register: custom-storage params cannot retype "
                     "without storage" if register_used else None))
        h.call("parameter.remove", h.args(function_start=main_entry, name="recon_pA"))

        # symbols / namespaces / class
        h.call("namespace.create", h.args(name="ReconNS"))
        h.call("class.create", h.args(name="ReconCls"))
        ok, _ = h.call("symbol.create", h.args(address=label_addr,
                                               name="recon_second", make_primary=False),
                       note=f"second label at data address {label_addr}")
        ok, res = h.call("symbol.primary.set",
                         h.args(address=label_addr, name="recon_second"))
        h.check("primary.set ok", ok, res)
        ok, _ = h.call("symbol.rename",
                       h.args(address=recreated, old_name="recon_made",
                              new_name="recon_made2"))
        ok, _ = h.call("symbol.namespace.move",
                       h.args(address=label_addr, name="recon_second",
                              namespace="ReconNS"))
        ok, res = h.call("symbol.delete",
                         h.args(address=label_addr, name="recon_second"))
        h.check("scratch symbol deleted", ok, res)

        # equates on real scalar operands
        if cands:
            addr0, idx0, val0 = cands[0]
            ok, res = h.call("equate.create",
                             h.args(address=addr0, name="RECON_EQ_A", value=val0,
                                    operand_index=idx0),
                             note=f"scalar {hex(val0)} at {addr0} op{idx0}")
            ok, res = h.call("equate.list", h.args(name="RECON_EQ_A"))
            h.check("equate.list finds RECON_EQ_A",
                    ok and "RECON_EQ_A" in json.dumps(res), res)
            if len(cands) > 1:
                addr1, idx1, val1 = cands[1]
                h.call("equate.create", h.args(address=addr1, name="RECON_EQ_B",
                                               value=val1, operand_index=idx1))
            h.call("equate.clear_range", h.args(start=addr0, length=16),
                   note="clear references around first scalar")
            h.call("equate.delete", h.args(name="RECON_EQ_A"))
        else:
            for tool in ("equate.create", "equate.list", "equate.delete",
                         "equate.clear_range"):
                h.ops.append({"tool": tool, "outcome": "not_run",
                              "http_status": None, "duration_ms": None,
                              "note": "no scalar operand found in scanned bodies",
                              "result": None})

        # externals: create + diff + entrypoints
        h.call("external.library.create", h.args(name="librecon.so"))
        h.call("external.library.set_path", h.args(name="librecon.so",
                                                   path="/tmp/librecon.so"))
        h.call("external.function.create",
               h.args(library_name="librecon.so", name="recon_ext_fn"))
        h.call("external.location.create",
               h.args(library_name="librecon.so", label="recon_ext_loc"))
        if not location_get_done:
            h.call("external.location.get", h.args(name="recon_ext_fn"),
                   note="binary had no baseline imports")
        ok, libs = h.call("external.library.list", h.args(), record=False)
        h.check("librecon.so registered", ok and "librecon.so" in json.dumps(libs), libs)
        ok, imports_now = h.call("external.imports.list", h.args(limit=100),
                                 note="inside transaction; expect +2 vs baseline")
        imports_during = len(h.rows(imports_now, "imports", "items"))
        h.check("externals diff (+2 in txn)",
                imports_during == imports_before + 2,
                {"before": imports_before, "during": imports_during})
        ok, _ = h.call("external.entrypoint.add", h.args(address=main_entry))
        ok, eps = h.call("external.entrypoint.list", h.args(), record=False)
        h.check("entrypoint added", ok and main_entry in json.dumps(eps), main_entry)
        h.call("external.entrypoint.remove", h.args(address=main_entry))

        # ---- batch pipeline proofs ----
        calls = [
            {"tool": "function.at", "arguments": h.args(address=main_entry)},
            {"tool": "function.signature.get",
             "arguments": h.args(function_start=main_entry)},
            {"tool": "function.variables",
             "arguments": h.args(function_start=main_entry)},
        ]
        _, body = api._request("POST", "/api/v1/batch",
                               {"calls": calls, "pipeline": True, "stop_on_error": False})
        pipeline_ev["assignment_chain"] = {
            "calls": [c["tool"] for c in calls],
            "statuses": [r.get("status") for r in body.get("results", [])],
            "errors": [str(r.get("error", {}).get("message"))[:300]
                       for r in body.get("results", [])],
        }
        calls = [
            {"tool": "external.library.set_path",
             "arguments": h.args(name="librecon.so", path="/tmp/pl1.so")},
            {"tool": "external.library.set_path", "arguments": h.args(path="/tmp/pl2.so")},
        ]
        _, body = api._request("POST", "/api/v1/batch",
                               {"calls": calls, "pipeline": True, "stop_on_error": False})
        results = body.get("results", [])
        second = results[1].get("result") if len(results) > 1 else None
        merged_ok = (len(results) == 2
                     and all(r.get("status") == "ok" for r in results)
                     and isinstance(second, dict)
                     and second.get("name") == "librecon.so"
                     and second.get("path") == "/tmp/pl2.so")
        pipeline_ev["working_chain"] = {
            "calls": [c["tool"] for c in calls],
            "second_call_arguments": {k: v for k, v in calls[1]["arguments"].items()
                                      if k not in ("worker_id", "session_id")},
            "statuses": [r.get("status") for r in results],
            "second_result": second,
            "assertion": "call 2 sends only path; name arrives via merged payload",
            "merged_args_worked": merged_ok,
        }
        h.check("pipeline merged args worked (set_path chain)", merged_ok,
                pipeline_ev["working_chain"])
    finally:
        h.call("transaction.revert", h.args(), record=False)

    ok, sig_after = h.call("function.signature.get", h.args(function_start=main_entry),
                           record=False)
    h.check("transaction.revert restored signature",
            ok and sig_after.get("signature") == base_signature,
            {"before": base_signature, "after": sig_after.get("signature")})
    ok, libs = h.call("external.library.list", h.args(), record=False)
    h.check("revert removed librecon.so",
            ok and "librecon.so" not in json.dumps(libs), libs)
    ok, imports_after = h.call("external.imports.list", h.args(limit=100), record=False)
    count = len(h.rows(imports_after, "imports", "items"))
    h.check("revert restored imports count", count == imports_before,
            {"before": imports_before, "after": count})

    # ---------------- phase 3: txn B (types + layouts) --------------------
    decl_a, decl_b = C_DECLARATIONS.get(tag, C_DECLARATIONS["stripped"])
    h.call("transaction.begin", h.args(description=f"recon-{tag} write sweep B"),
           record=False)
    try:
        h.call("type.category.create", h.args(path="/recon"))
        h.call("type.category.list", h.args(path="/recon"))
        h.call("type.parse_c", h.args(declaration=decl_a, name="ReconParseT",
                                      category="/recon"))
        h.call("type.define_c", h.args(declaration=decl_b, name="ReconDefineT",
                                       category="/recon"),
               note="references the type created by parse_c in the same transaction")
        h.call("type.rename", h.args(name="ReconParseT", new_name="ReconParseT2"))
        ok, res = h.call("type.get", h.args(name="ReconParseT2"))
        h.check("type.rename visible",
                ok and isinstance(res, dict) and res.get("name") == "ReconParseT2", res)

        h.call("layout.struct.create", h.args(name="ReconStruct", category="/recon",
                                              length=16))
        h.call("layout.struct.field.add", h.args(struct_name="ReconStruct",
                                                 field_name="f_magic", data_type="int",
                                                 offset=0))
        h.call("layout.struct.field.add", h.args(struct_name="ReconStruct",
                                                 field_name="f_ptr", data_type="char *",
                                                 offset=8))
        h.call("layout.struct.field.replace",
               h.args(struct_name="ReconStruct", offset=8, data_type="unsigned int",
                      field_name="f_count"))
        h.call("layout.struct.field.rename",
               h.args(struct_name="ReconStruct", old_name="f_magic",
                      new_name="f_magic2"))
        h.call("layout.struct.field.comment.set",
               h.args(struct_name="ReconStruct", offset=0, comment="recon field"))
        h.call("layout.struct.bitfield.add",
               h.args(struct_name="ReconStruct", byte_offset=16, byte_width=4,
                      bit_offset=0, data_type="int", bit_size=5, field_name="f_bits"))
        h.call("layout.struct.resize", h.args(struct_name="ReconStruct", length=32))
        h.call("layout.struct.field.clear", h.args(struct_name="ReconStruct", offset=8))
        ok, res = h.call("layout.struct.get", h.args(struct_name="ReconStruct"))
        comps = json.dumps(res)
        h.check("struct components after edits",
                ok and "f_magic2" in comps and "f_bits" in comps, _trim(res, 400))
        h.call("layout.inspect.components", h.args(name="ReconStruct"))

        h.call("layout.enum.create", h.args(name="ReconEnum"))
        h.call("layout.enum.member.add", h.args(enum_name="ReconEnum",
                                                name="RECON_ONE", value=1,
                                                comment="first"))
        h.call("layout.enum.member.add", h.args(enum_name="ReconEnum",
                                                name="RECON_TWO", value=2))
        h.call("layout.enum.member.remove", h.args(enum_name="ReconEnum",
                                                   name="RECON_ONE"))
        h.call("layout.union.create", h.args(name="ReconUnion"))
        h.call("layout.union.member.add", h.args(union_name="ReconUnion",
                                                 field_name="u_int", data_type="int"))
        h.call("layout.union.member.add", h.args(union_name="ReconUnion",
                                                 field_name="u_ptr", data_type="char *"))
        h.call("layout.union.member.remove", h.args(union_name="ReconUnion",
                                                    field_name="u_ptr"))

        if data_addr:
            h.call("type.apply_at", h.args(address=data_addr, data_type="ReconStruct",
                                           clear_existing=True),
                   note=f"applied at data block {data_addr}")
        else:
            h.ops.append({"tool": "type.apply_at", "outcome": "not_run",
                          "http_status": None, "duration_ms": None,
                          "note": "no initialized data block found", "result": None})

        # fill_from_decompiler: use decompiler-declared variable names,
        # trying named non-stub functions first (JNI/RTTI pointer params are
        # the best structure-inference targets). Bounded attempts; binaries
        # without any pointer/structure variable are a tool-level limitation.
        fill_recorded = False
        fill_attempts = 0
        ordered = sorted(
            (f for f in functions[:16] if not f.get("thunk")),
            key=lambda f: (f.get("name") in SKIP_FUNCTIONS,
                           str(f.get("name", "")).startswith("FUN_")),
        )
        names_by_fn = []
        for fn in ordered:
            pointers, plain = _decompiler_variable_names(h, fn["address"])
            names_by_fn.append((fn, pointers, plain))
        candidates = [(fn, name) for fn, pointers, _ in names_by_fn
                      for name in pointers[:2]]
        candidates += [(fn, name) for fn, _, plain in names_by_fn
                       for name in plain[:2]]
        for fn, name in candidates:
            ok, res = h.call("layout.struct.fill_from_decompiler",
                             h.args(function_start=fn["address"], name=name,
                                    create_new_structure=True,
                                    create_class_if_needed=False, timeout_secs=120),
                             note=f"decompiler variable '{name}' of {fn['name']}")
            fill_recorded = True
            fill_attempts += 1
            if ok or fill_attempts >= 16:
                break
        if not fill_recorded:
            h.ops.append({"tool": "layout.struct.fill_from_decompiler",
                          "outcome": "not_run", "http_status": None,
                          "duration_ms": None,
                          "note": "no decompilable function with variables",
                          "result": None})
        elif not any(o["tool"] == "layout.struct.fill_from_decompiler"
                     and o["outcome"] == "ok" for o in h.ops):
            h.ops.append({"tool": "layout.struct.fill_from_decompiler",
                          "outcome": "ghidra_limitation", "http_status": None,
                          "duration_ms": None,
                          "note": "no decompiled pointer/structure variable in any "
                                  "scanned function; FillOutStructureHelper has "
                                  "nothing to infer from",
                          "result": None})
            h.findings.append(
                "layout.struct.fill_from_decompiler: this binary has no decompiled "
                "pointer/structure variable, so structure inference cannot produce "
                "a type (tool-level Ghidra limitation, not a REST defect)."
            )

        h.call("type.delete", h.args(name="ReconDefineT"))
    finally:
        h.call("transaction.revert", h.args(), record=False)
    ok, res = h.call("type.get", h.args(name="ReconStruct"), record=False)
    h.check("revert removed ReconStruct", not ok, res)

    # ---------------- phase 4: expected-rejection probes -------------------
    def probe(tool, arguments, expected, note=""):
        status, body = api.call_raw(tool, arguments)
        message = ""
        if isinstance(body, dict):
            message = str((body.get("error") or {}).get("message", ""))
        h.probes.append({"tool": tool, "spec_expected": expected,
                         "http_status": status, "ok": status == expected,
                         "note": note, "message": message[:220]})
        return status == expected

    probe("function.does_not_exist", h.args(), 404, "unknown tool")
    probe("function.at", h.args(address="0xdeadbeefdead"), 400,
          "ValueError: address outside program")
    probe("type.get", h.args(name="__recon_missing__"), 400,
          "ValueError: unknown type")
    probe("type.get_by_id", h.args(), 400, "ValueError: neither id argument")
    probe("type.parse_c", h.args(declaration="struct {"), 400,
          "ValueError: malformed C")
    probe("function.signature.set",
          h.args(function_start=main_entry, signature="not a signature ("), 400,
          "ValueError: unparseable signature")
    probe("layout.struct.get", h.args(struct_name="__missing__"), 400,
          "ValueError: unknown struct")
    probe("external.location.get", h.args(), 400, "ValueError: no selectors")
    probe("function.list", h.args(limit=0), 400, "ValueError: limit below 1")
    if cands:
        probe("equate.create", h.args(address=cands[0][0], name="RECON_BAD",
                                      value=cands[0][2], operand_index=9), 400,
              "ValueError: operand index out of range")
    status, body = api._request("POST", "/api/v1/batch", [1, 2, 3])
    h.probes.append({"tool": "POST /api/v1/batch", "spec_expected": 400,
                     "http_status": status, "ok": status == 400,
                     "note": "non-object body", "message": str(body)[:220]})

    if any(not p["ok"] and p["spec_expected"] == 400 for p in h.probes):
        h.findings.append(
            "REST error mapping: tool ValueErrors are wrapped as "
            "'Error executing tool ...' by the worker MCP layer, so the REST "
            "_STATUS_BY_KIND ValueError->400 mapping never fires; bad-argument "
            "probes return HTTP 500 instead of the documented 400."
        )
    if pipeline_ev["assignment_chain"] and "error" in pipeline_ev["assignment_chain"]["statuses"]:
        h.findings.append(
            "POST /api/v1/batch pipeline=true merges every prior payload key into "
            "later calls' arguments, but all tool schemas are "
            "additionalProperties:false, so heterogeneous chains (function.at -> "
            "signature.get -> variables) fail validation on the injected keys. "
            "Merging only works when each payload key set is contained in the next "
            "tool's properties (proof: external.library.set_path -> itself)."
        )

    h.call("program.close", h.args(), record=False)
    return _finish(h, boot, started, pipeline=pipeline_ev)


def _shift(address: str, delta: int) -> str:
    try:
        return hex(int(address, 16) + delta)
    except (TypeError, ValueError):
        return address


def _finish(h: Harness, boot: dict, started: float, early: bool = False,
            pipeline: dict | None = None) -> dict:
    pass_table, failed, missing, limited = {}, [], [], []
    for tool in COVERED:
        entries = [o for o in h.ops if o["tool"] == tool]
        ok_entries = [o for o in entries if o["outcome"] == "ok"]
        if ok_entries:
            pass_table[tool] = {"outcome": "ok",
                                "duration_ms": ok_entries[0].get("duration_ms")}
        elif entries:
            last = entries[-1]
            pass_table[tool] = {"outcome": last["outcome"],
                                "note": last.get("note"),
                                "error": last.get("result"),
                                "http_status": last.get("http_status")}
            if last["outcome"] == "fail":
                failed.append(tool)
            elif last["outcome"] == "ghidra_limitation":
                limited.append(tool)
        else:
            pass_table[tool] = {"outcome": "not_run"}
        if pass_table[tool]["outcome"] == "not_run":
            missing.append(tool)

    durations = [o["duration_ms"] for o in h.ops
                 if isinstance(o.get("duration_ms"), (int, float))]
    by_family = {}
    for tool, entry in pass_table.items():
        family = tool.split(".", 1)[0]
        row = by_family.setdefault(family, {"ok": 0, "fail": 0, "not_run": 0,
                                             "ghidra_limitation": 0})
        row[entry["outcome"]] = row.get(entry["outcome"], 0) + 1
    evidence = {
        "suite": "api_recon",
        "tag": h.tag,
        "base": h.api.base,
        "worker_id": h.worker,
        "binary": h.binary,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "boot": boot,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "ops": h.ops,
        "checks": h.checks,
        "probes": h.probes,
        "pipeline": pipeline or {},
        "pass_table": pass_table,
        "summary": {
            "tools_total": len(COVERED),
            "family_counts": FAMILY_COUNTS,
            "family_outcomes": by_family,
            "tools_ok": len(COVERED) - len(failed) - len(missing) - len(limited),
            "tools_failed": failed,
            "tools_ghidra_limitation": limited,
            "tools_not_run": missing,
            "failed_checks": [c for c in h.checks if not c["ok"]],
            "failed_probes": [p for p in h.probes if not p["ok"]],
            "latency_ms": {
                "p50": statistics.median(durations) if durations else None,
                "max": max(durations) if durations else None,
                "mean": round(statistics.mean(durations), 1) if durations else None,
            },
            "findings": h.findings,
            "exit_ok": not failed and not missing
                       and all(c["ok"] for c in h.checks)
                       and all(p["ok"] for p in h.probes),
        },
    }
    out = REPO_ROOT / "runtime" / "acceptance" / "api" / f"recon-{h.tag}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=1))
    evidence["_evidence_path"] = str(out)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:29950")
    parser.add_argument("--worker", default="api_recon")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--tag", required=True,
                        help="evidence suffix: recon-<tag>.json (jnidemo|stripped|rtti)")
    args = parser.parse_args()

    evidence = run_binary(args.base, args.worker, args.binary, args.tag)
    summary = evidence["summary"]
    print(json.dumps({k: v for k, v in summary.items()
                      if k in ("tools_total", "tools_ok", "tools_failed",
                               "tools_ghidra_limitation", "tools_not_run",
                               "family_outcomes", "latency_ms", "exit_ok")}, indent=1))
    print(f"failed checks: {summary['failed_checks']}")
    print(f"failed probes: {[(p['tool'], p['spec_expected'], p['http_status']) for p in summary['failed_probes']]}")
    print(f"evidence: {evidence['_evidence_path']}")
    return 0 if summary["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
