"""Real Ghidra lifecycle smoke; called by the parent integration driver."""

from __future__ import annotations

import base64
import secrets
import time
import zipfile
from pathlib import Path

from agenticghidra_mcp.advanced import lifecycle


def _analysis_transactions(invoke, sid):
    options = invoke("analysis.options.list", sid)["options"]
    assert options
    analyzers = invoke("analysis.analyzers.list", sid)["analyzers"]
    assert analyzers
    choice = analyzers[0]
    before = invoke("analysis.options.get", sid, name=choice["name"])["value"]
    invoke("transaction.begin", sid, description="lifecycle revert proof")
    assert invoke("transaction.status", sid)["pending"]
    invoke("analysis.options.set", sid, name=choice["name"], value=not before)
    assert invoke("analysis.options.get", sid, name=choice["name"])["value"] is not before
    try:
        invoke("analysis.options.set", sid, name=choice["name"], value="not-a-boolean")
    except ValueError:
        pass
    else:
        raise AssertionError("Boolean analyzer option accepted a string")
    assert invoke("transaction.status", sid)["pending"]
    invoke("transaction.revert", sid)
    assert invoke("analysis.options.get", sid, name=choice["name"])["value"] == before
    invoke("transaction.begin", sid, description="lifecycle undo proof")
    invoke("analysis.analyzers.set", sid, name=choice["name"], enabled=not before)
    invoke("transaction.commit", sid)
    assert invoke("analysis.options.get", sid, name=choice["name"])["value"] == (not before)
    invoke("transaction.undo", sid)
    assert invoke("analysis.options.get", sid, name=choice["name"])["value"] == before
    invoke("transaction.redo", sid)
    assert invoke("analysis.options.get", sid, name=choice["name"])["value"] == (not before)
    invoke("analysis.analyzers.set", sid, name=choice["name"], enabled=before)


def _saves_tasks_exports(invoke, wait, runtime, sid, summary, directory, imported):
    invoke("program.image_base.set", sid, image_base=summary["image_base"], commit=True)
    invoke("analysis.clear_cache", sid)
    invoke("analysis.update_and_wait", sid)
    assert wait(invoke("analysis.update", sid)["task_id"])["status"] == "succeeded"
    task = invoke("task.analysis_update", sid)
    cancelled = invoke("task.cancel", task_id=task["task_id"])
    assert cancelled["status"] in {"cancelling", "cancelled", "succeeded"}
    wait(task["task_id"])
    invoke("program.save", sid)
    name = "lifecycle-saved-" + secrets.token_hex(5)
    saved = invoke("program.save_as", sid, program_name=name)
    assert saved["path"].endswith("/" + name)
    assert invoke("project.file.info", sid, path=saved["path"])["name"] == name
    assert invoke("project.files.list", sid, query=name)["files"]
    assert invoke("project.search.programs", sid, query=name)["files"]
    invoke("project.folders.list", sid)
    alternate = invoke("project.program.open", sid, path=saved["path"], read_only=True)
    assert alternate["read_only"]
    invoke("program.close", alternate["session_id"])
    existing = invoke(
        "project.program.open_existing",
        project_location=str(runtime.context.project_path),
        project_name=str(runtime.context.project_name),
        program_path=saved["path"],
    )
    assert existing["project_id"] == imported["project_id"]
    invoke("program.close", existing["session_id"])
    reopened = invoke("program.open", path=saved["path"], update_analysis=False)
    assert reopened["read_only"]
    invoke("program.close", reopened["session_id"])
    return name, saved


def _program_exports(invoke, sid, directory, name):
    for format in ("gzf", "raw"):
        destination = directory / (name + "." + format)
        assert (
            invoke("program.export_binary", sid, path=str(destination), format=format)["size"] > 0
        )
    archive = directory / (name + ".gar")
    invoke("project.export", sid, destination=str(archive))
    with zipfile.ZipFile(archive) as contents:
        assert "JAR_FORMAT" in contents.namelist()
        assert any(value.startswith("idata/") for value in contents.namelist()), (
            contents.namelist()
        )




def smoke_lifecycle(runtime, owner, session_id, scratch):
    operations = {
        value.__operation__.name: value.__operation__
        for value in vars(lifecycle).values()
        if hasattr(value, "__operation__")
    }
    exercised = set()

    def invoke(operation_name, sid=session_id, **arguments):
        definition = operations[operation_name]
        if definition.program:
            arguments["session_id"] = sid
        result = runtime.invoke(definition, arguments, owner)
        exercised.add(operation_name)
        return result

    def wait(task_id):
        deadline = time.monotonic() + 300
        while True:
            status = invoke("task.status", task_id=task_id)
            if status["status"] in {"succeeded", "failed", "cancelled"}:
                result = invoke("task.result", task_id=task_id)
                assert result["status"] != "failed", result
                return result
            if time.monotonic() >= deadline:
                invoke("task.cancel", task_id=task_id)
                raise AssertionError(
                    "Analysis did not stop within the smoke deadline; runtime must still drain it"
                )
            time.sleep(0.02)

    directory = (
        Path(scratch["directory"])
        if isinstance(scratch, dict) and "directory" in scratch
        else Path(runtime.context.project_path) / "advanced-lifecycle-smoke"
    )
    directory.mkdir(parents=True, exist_ok=True)
    assert invoke("health.ping")["status"] == "ok"
    assert invoke("mcp.response_format")["format"] == "json"
    forced_project = "forced-import-" + secrets.token_hex(5)
    forced = invoke(
        "program.open_bytes",
        data_base64=base64.b64encode(b"\xc3\x90\x90\x90").decode(),
        filename="forced.bin",
        project_location=str(directory),
        project_name=forced_project,
        program_name="forced",
        language="x86:LE:64:default",
        compiler="gcc",
        loader="BinaryLoader",
        read_only=False,
        update_analysis=False,
    )
    forced_id = forced["session_id"]
    try:
        forced_summary = invoke("program.summary", forced_id)
        assert forced_summary["language"] == "x86:LE:64:default"
        assert forced_summary["compiler"] == "gcc"
        assert "Raw" in forced_summary["executable_format"]
        assert forced_summary["executable_path"].endswith("forced.bin")
        assert not Path(forced_summary["executable_path"]).exists()
        invoke("program.save", forced_id)
        same_project = invoke(
            "project.program.open_existing",
            project_location=str(directory),
            project_name=forced_project,
            program_path=forced["binary_name"],
        )
        assert same_project["project_id"] == forced["project_id"]
        invoke("program.close", same_project["session_id"])
    finally:
        invoke("program.close", forced_id)
    original = directory / "original.bin"
    assert invoke("program.export_binary", path=str(original))["size"] > 0
    imported = invoke(
        "program.open_bytes",
        data_base64=base64.b64encode(original.read_bytes()).decode(),
        filename="lifecycle.bin",
        program_name="lifecycle-" + secrets.token_hex(6),
        read_only=False,
        update_analysis=True,
    )
    sid = imported["session_id"]
    try:
        assert imported["read_only"] is False
        assert any(item["session_id"] == sid for item in invoke("program.list_open")["programs"])
        assert invoke("program.mode.get", sid)["read_only"] is False
        assert invoke("program.mode.set", sid, deterministic=True)["deterministic"] is True
        summary = invoke("program.summary", sid)
        assert summary["memory_size"] > 0
        assert invoke("program.report", sid)["memory_blocks"]
        assert invoke("analysis.status", sid)["analysis_complete"]
        _analysis_transactions(invoke, sid)
        name, _ = _saves_tasks_exports(
            invoke, wait, runtime, sid, summary, directory, imported
        )
        _program_exports(invoke, sid, directory, name)
    finally:
        pending = runtime._transactions.get(id(runtime.registry.resolve(sid, owner).info.program))
        if pending:
            invoke("transaction.revert", sid)
        invoke("program.close", sid)
    assert exercised == set(operations), sorted(set(operations) - exercised)
    return {"operations": sorted(exercised), "count": len(exercised), "artifacts": str(directory)}
