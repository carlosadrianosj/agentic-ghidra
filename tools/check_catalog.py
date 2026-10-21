#!/usr/bin/env python3
"""Check pinned interface facts against real, independently implemented handlers.

No reference implementation is imported or executed. Offline runs use the checked
factual inventory; CI additionally fetches the immutable interface source and
extracts its public names with AST literals. Runtime proof is a separate artifact.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def extract_names(source: bytes) -> list[str]:
    names = []
    found = set()
    for node in ast.parse(source).body:
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        if node.target.id == "_SERVER_TOOL_SPECS":
            names.extend(spec["name"] for spec in ast.literal_eval(node.value))
            found.add(node.target.id)
        elif node.target.id == "_BACKEND_TOOL_NAME_MAP":
            names.extend(ast.literal_eval(node.value).values())
            found.add(node.target.id)
    if len(found) != 2 or len(names) != len(set(names)):
        raise ValueError("Pinned interface has missing or duplicate public name declarations")
    return sorted(names)


def expected_classification(name: str) -> set[str]:
    if name in {"ghidra.call", "ghidra.eval", "ghidra.script"}:
        return {"script"}
    # These change caches, analysis, program/project state, tasks or transaction
    # ownership without necessarily changing a Program database immediately.
    lifecycle_mutations = {
        "analysis.clear_cache",
        "analysis.update",
        "analysis.update_and_wait",
        "analysis.analyzers.set",
        "analysis.options.set",
        "program.open",
        "program.open_bytes",
        "program.close",
        "program.export_binary",
        "program.save",
        "program.save_as",
        "program.image_base.set",
        "program.mode.set",
        "project.export",
        "project.program.open",
        "project.program.open_existing",
        "task.analysis_update",
        "task.cancel",
        "transaction.begin",
        "transaction.commit",
        "transaction.revert",
        "transaction.undo",
        "transaction.redo",
    }
    if name in lifecycle_mutations:
        return {"project", "write"}
    mutation_verbs = {
        "add",
        "remove",
        "clear",
        "create",
        "delete",
        "rename",
        "retype",
        "set",
        "move",
        "replace",
        "resize",
        "apply_at",
        "define_c",
        "store",
        "set_path",
        "clear_range",
        "clear_from",
        "clear_to",
        "fill_from_decompiler",
        "assemble",
        "branch_invert",
        "nop",
    }
    if (
        name.rsplit(".", 1)[-1] in mutation_verbs
        or ".create." in name
        or name in {
            "listing.disassemble.seed",
            "type.parse_c",
            "decomp.writeback.locals",
            "decomp.writeback.params",
            "memory.write",
        }
    ):
        return {"write"}
    return {"read"}


def _parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fetch-reference",
        action="store_true",
        help="Fetch and validate the immutable pinned source (used by standalone CI)",
    )
    parser.add_argument(
        "--reference", type=Path, help="Inspect this local pinned server.py instead"
    )
    parser.add_argument("--matrix", type=Path, help="Write factual capability matrix JSON")
    parser.add_argument(
        "--runtime-evidence",
        type=Path,
        help="Real-Ghidra runner artifact with tools keyed by public name",
    )
    return parser.parse_args()


def _load_inventory() -> dict:
    facts = json.loads((ROOT / "tools/reference_names.json").read_text())
    names = facts["names"]
    if len(names) != 212 or len(set(names)) != 212:
        raise ValueError("The pinned inventory must contain exactly 212 distinct names")
    return facts


def _reference_source(args, facts: dict) -> bytes | None:
    if args.reference is not None:
        return args.reference.read_bytes()
    if args.fetch_reference:
        with urllib.request.urlopen(facts["source_url"], timeout=30) as response:
            source = response.read(2 * 1024 * 1024 + 1)
        if len(source) > 2 * 1024 * 1024:
            raise ValueError("Pinned interface source exceeds the expected size bound")
        return source
    sibling = ROOT.parent / "benchmark/ghidra-headless-mcp" / facts["source_path"]
    return sibling.read_bytes() if sibling.is_file() else None


def _validate_reference(source: bytes | None, facts: dict) -> None:
    if source is None:
        return
    if hashlib.sha256(source).hexdigest() != facts["source_sha256"]:
        raise ValueError("Reference source digest differs from the pinned factual inventory")
    if extract_names(source) != facts["names"]:
        raise ValueError("Pinned source names differ from the factual inventory")


def _validated_catalog(facts: dict):
    from pyghidra_mcp.advanced.registry import build_operations, reference_catalog

    catalog = reference_catalog()
    if catalog["source_revision"] != facts["source_revision"]:
        raise ValueError("Schema snapshot and factual inventory revisions differ")
    specs = {spec["name"]: spec for spec in catalog["tools"]}
    if sorted(specs) != facts["names"]:
        raise ValueError("Schema snapshot names differ from the pinned interface")
    operations = build_operations()
    if sorted(operations) != facts["names"]:
        raise ValueError("Handler coverage differs from pinned interface")
    return specs, operations


def _registered_tools(names: list[str], legacy_capabilities: dict) -> dict:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.server import Settings

    from pyghidra_mcp.advanced.legacy import register_legacy_tools
    from pyghidra_mcp.advanced.registry import register_advanced_tools

    Settings.model_rebuild()
    server = FastMCP("catalog-check")
    register_legacy_tools(server)
    register_advanced_tools(server)
    registered = {tool.name: tool for tool in server._tool_manager.list_tools()}
    expected = set(names) | set(legacy_capabilities)
    if set(registered) != expected or len(registered) != 232:
        raise ValueError(
            f"Actual registration differs: missing={sorted(expected - set(registered))}, "
            f"extra={sorted(set(registered) - expected)}"
        )
    return registered


def _validate_advanced_tools(operations: dict, specs: dict, registered: dict) -> None:
    from jsonschema import Draft202012Validator

    from pyghidra_mcp.advanced.registry import input_schema

    for name, definition in operations.items():
        if definition.kind not in expected_classification(name):
            raise ValueError(f"Misclassified operation {name}: {definition.kind}")
        tool = registered[name]
        if tool.name != name or tool.parameters != input_schema(specs[name]):
            raise ValueError(f"Registration lost the public name or source schema: {name}")
        Draft202012Validator.check_schema(tool.parameters)
        Draft202012Validator.check_schema(tool.output_schema)
        if tool.meta.get("api_version") != definition.version:
            raise ValueError(f"Registration lost the API version: {name}")


def _validate_legacy_tools(operations: dict, registered: dict) -> list:
    from pyghidra_mcp.advanced.legacy import LEGACY_CAPABILITIES

    legacy = [registered[name] for name in LEGACY_CAPABILITIES]
    if len(legacy) != 20 or {tool.name for tool in legacy} != set(LEGACY_CAPABILITIES):
        raise ValueError("The original 20 public tools were not preserved")
    if set(LEGACY_CAPABILITIES) & set(operations):
        raise ValueError("Legacy names must not count as advanced coverage aliases")
    for name, capability in LEGACY_CAPABILITIES.items():
        if not capability["capability"] or set(capability["advanced"]) - set(operations):
            raise ValueError(f"Invalid legacy capability relationship: {name}")
    return legacy


def _write_matrix(path: Path | None, facts: dict, evidence_path: Path | None) -> None:
    from pyghidra_mcp.advanced.legacy import LEGACY_CAPABILITIES
    from pyghidra_mcp.advanced.registry import equivalence_matrix

    matrix = equivalence_matrix(evidence_path=evidence_path)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "source_revision": facts["source_revision"],
                "existing_capabilities": LEGACY_CAPABILITIES,
                "tools": matrix,
            },
            indent=2,
        )
        + "\n"
    )


def main() -> int:
    args = _parse_arguments()
    facts = _load_inventory()
    _validate_reference(_reference_source(args, facts), facts)
    specs, operations = _validated_catalog(facts)

    from pyghidra_mcp.advanced.legacy import LEGACY_CAPABILITIES

    registered = _registered_tools(facts["names"], LEGACY_CAPABILITIES)
    _validate_advanced_tools(operations, specs, registered)
    legacy = _validate_legacy_tools(operations, registered)
    _write_matrix(args.matrix, facts, args.runtime_evidence)
    print(
        json.dumps(
            {
                "source_revision": facts["source_revision"],
                "advanced": len(operations),
                "legacy": len(legacy),
                "missing": [],
                "extra": [],
                "runtime_evidence_supplied": args.runtime_evidence is not None,
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, ImportError) as error:
        print(f"Catalog check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
