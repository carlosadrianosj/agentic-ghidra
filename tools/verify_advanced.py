#!/usr/bin/env python3
"""Exercise the advanced catalog against disposable, real Ghidra projects."""

from __future__ import annotations

import argparse
import importlib.util
import json
import secrets
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

SMOKES = (
    ("symbols", "advanced_symbols_smoke"),
    ("listing", "advanced_listing_smoke"),
    ("functions", "advanced_functions_smoke"),
    ("types", "advanced_types_smoke"),
    ("decompiler", "advanced_decompiler_smoke"),
    ("annotations", "advanced_annotations_smoke"),
    ("trusted", "advanced_trusted_smoke"),
    ("lifecycle", "advanced_lifecycle_smoke"),
)


def symbol_address(program, name):
    values = list(program.getSymbolTable().getSymbols(name))
    if len(values) != 1:
        raise AssertionError(f"Fixture requires one symbol {name}, found {len(values)}")
    return str(values[0].getAddress())


def scratch_for(runtime, owner, session_id, directory):
    session = runtime.registry.resolve(session_id, owner)
    program = session.info.program
    return {
        "directory": str(directory),
        "address": symbol_address(program, "advanced_scratch"),
        "function_start": symbol_address(program, "advanced_add"),
        "secondary_function_start": symbol_address(program, "advanced_secondary"),
        "fill_function": symbol_address(program, "advanced_type_fill"),
        "fill_variable": "p",
        "create_address": symbol_address(program, "advanced_disposable"),
    }


def smoke_module(name):
    path = ROOT / "tests/integration" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load acceptance cases: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_fixture(fixture, directory, evidence, selected=None):
    from pyghidra_mcp.advanced.core import Call, address
    from pyghidra_mcp.advanced.registry import build_operations, get_runtime
    from pyghidra_mcp.context import PyGhidraContext

    context = PyGhidraContext(
        project_name="acceptance",
        project_path=directory / "project",
        no_symbols=True,
        threaded=True,
        max_workers=1,
        wait_for_analysis=True,
    )
    runtime = get_runtime(context)
    operations = build_operations()
    owner = "acceptance-" + secrets.token_hex(12)
    original_invoke = runtime.invoke
    successful = {}
    results = {}

    def recorded(definition, arguments, client):
        started = time.monotonic()
        result = original_invoke(definition, arguments, client)
        if definition.name in operations:
            observation = {
                "fixture": str(fixture),
                "seconds": time.monotonic() - started,
                "outcome": "completed",
                "arguments": arguments,
                "result": result,
            }
            successful.setdefault(definition.name, []).append(observation)
            evidence["tools"].setdefault(definition.name, {"runs": []})["runs"].append(observation)
        return result

    runtime.invoke = recorded
    session_id = None
    try:
        opened = runtime.invoke(
            operations["program.open"],
            {
                "path": str(fixture),
                "read_only": False,
                "update_analysis": True,
            },
            owner,
        )
        session_id = opened["session_id"]
        session = runtime.registry.resolve(session_id, owner)
        program = session.info.program
        original_base = str(program.getImageBase())
        shifted_base = str(program.getImageBase().addNoWrap(0x10000))
        runtime.invoke(
            operations["program.image_base.set"],
            {
                "session_id": session_id,
                "image_base": shifted_base,
                "commit": True,
            },
            owner,
        )
        assert str(program.getImageBase()) == shifted_base
        runtime.invoke(
            operations["program.image_base.set"],
            {
                "session_id": session_id,
                "image_base": original_base,
                "commit": True,
            },
            owner,
        )
        assert str(program.getImageBase()) == original_base
        scratch = scratch_for(runtime, owner, session_id, directory / "artifacts")
        language = str(program.getLanguageID())
        print(f"FIXTURE {fixture.name} {language} {session_id}", flush=True)
        for name, module_name in SMOKES:
            if selected and name not in selected:
                continue
            module = smoke_module(module_name)
            values = dict(scratch)
            if name == "listing":
                values["address"] = None
            if name == "functions":
                existing = program.getFunctionManager().getFunctionAt(
                    address(
                        Call(runtime, session.context, owner, session, runtime.monitor()),
                        scratch["create_address"],
                    )
                )
                if existing is not None:
                    runtime.invoke(
                        operations["function.delete"],
                        {
                            "session_id": session_id,
                            "function_start": scratch["create_address"],
                        },
                        owner,
                    )
            print(f"START {fixture.name} {name}", flush=True)
            result = getattr(module, f"smoke_{name}")(runtime, owner, session_id, values)
            if isinstance(result, dict) and result.get("fixture_requirements"):
                raise AssertionError(
                    f"Unmet real-runtime requirements: {result['fixture_requirements']}"
                )
            results[name] = result
            print(f"PASS {fixture.name} {name}", flush=True)
        runtime.invoke(operations["program.save"], {"session_id": session_id}, owner)
        program_path = str(program.getDomainFile().getPathname())
        project_path = str(session.context.project_path)
        project_name = str(session.context.project_name)
        runtime.invoke(operations["program.close"], {"session_id": session_id}, owner)
        reopened = runtime.invoke(
            operations["project.program.open_existing"],
            {
                "project_location": project_path,
                "project_name": project_name,
                "program_path": program_path,
                "read_only": True,
            },
            owner,
        )
        session_id = reopened["session_id"]
        if "annotations" in results:
            module = smoke_module("advanced_annotations_smoke")
            results["annotation_persistence"] = module.smoke_annotations_reopen(
                runtime,
                owner,
                session_id,
                results["annotations"]["persistence_probe"],
            )
        runtime.invoke(operations["program.close"], {"session_id": session_id}, owner)
        session_id = None
        return {
            "fixture": str(fixture),
            "language": language,
            "families": results,
            "exercised_operations": sorted(successful),
            "status": "passed",
        }
    finally:
        runtime.close()
        context.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", action="append", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("runtime/acceptance/evidence.json"))
    parser.add_argument("--only", action="append", choices=[name for name, _ in SMOKES])
    args = parser.parse_args()
    import pyghidra

    pyghidra.start(False)
    from ghidra.framework import Application

    from pyghidra_mcp.advanced.registry import reference_catalog
    from pyghidra_mcp.telemetry import METRICS

    base = ROOT / "runtime/acceptance" / ("run-" + secrets.token_hex(6))
    evidence = {
        "ghidra_version": str(Application.getApplicationVersion()),
        "worker_model": "local-python-processes",
        "tools": {},
        "fixtures": [],
        "started_at": time.time(),
        "status": "running",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        for index, value in enumerate(args.fixture):
            fixture = value.expanduser().resolve(strict=True)
            result = run_fixture(fixture, base / f"fixture-{index}", evidence, args.only)
            evidence["fixtures"].append(result)
            args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")
        expected = {row["name"] for row in reference_catalog()["tools"]}
        missing = sorted(expected - set(evidence["tools"]))
        evidence["missing"] = missing
        if missing and not args.only:
            raise AssertionError(f"Unexercised catalog operations ({len(missing)}): {missing}")
        evidence["status"] = "passed"
    except BaseException as error:
        evidence["status"] = "failed"
        evidence["error"] = f"{type(error).__name__}: {error}"
        evidence["traceback"] = traceback.format_exc()
        raise
    finally:
        evidence["completed_at"] = time.time()
        evidence["metrics"] = METRICS.snapshot()
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")
        print(f"EVIDENCE {args.output} {evidence['status']}", flush=True)


if __name__ == "__main__":
    main()
