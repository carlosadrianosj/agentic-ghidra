#!/usr/bin/env python3
"""Prove team isolation, saved changes and manifest reload over real MCP endpoints.

Only the two workers created by this run are stopped. Existing workers must be
stopped explicitly by their owner if the supervisor has no available capacity.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
from collections import Counter
from contextlib import asynccontextmanager, nullcontext
from pathlib import Path

import anyio
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from agenticghidra_mcp.supervisor import create_http_app, create_server
from agenticghidra_mcp.supervisor_runtime import SupervisorConfig, SupervisorRuntime, reserve_port


class EvidenceClient:
    def __init__(self, client):
        self.client = client
        self.calls = Counter()

    async def __call__(self, operation_name, **arguments):
        self.calls[operation_name] += 1
        result = await self.client.call_tool(operation_name, arguments)
        if result.isError:
            raise AssertionError(f"{operation_name}: {result.model_dump()}")
        if result.structuredContent is not None:
            return result.structuredContent
        return json.loads(result.content[0].text)


@asynccontextmanager
async def _client(url):
    async with streamable_http_client(url) as (reader, writer, _):
        async with ClientSession(reader, writer) as client:
            await client.initialize()
            yield EvidenceClient(client)


def _indexed(group):
    return all(
        team["programs"]
        and all(
            program["analysis_complete"]
            and program["code_indexed"]
            and program["strings_indexed"]
            for program in team["programs"]
        )
        for team in group["teams"]
    )


async def _wait_indexed(call, identity):
    deadline = time.monotonic() + 180
    while True:
        group = await call("investigation.status", investigation_id=identity)
        if _indexed(group):
            return group
        if time.monotonic() > deadline:
            raise AssertionError(f"Team analysis/indexing deadline: {group}")
        await asyncio.sleep(0.25)


async def _open_teams(call, group, original_hash, sessions):
    teams = {team["team"]: team for team in group["teams"]}
    for key in ("project_identity", "artifact_directory", "port", "pid"):
        assert teams["tls"][key] != teams["raw"][key], (key, teams)
    reports = {}
    for name, team in teams.items():
        opened = await call(
            "program.open", worker_id=team["worker_id"], path=group["snapshot"],
            read_only=False, update_analysis=False,
        )
        sessions[name] = opened["session_id"]
        reports[name] = await call(
            "program.report", worker_id=team["worker_id"], session_id=sessions[name]
        )
        assert original_hash in json.dumps(reports[name]["metadata"]).lower(), reports[name]
    return reports


async def _rename_and_patch(call, teams, sessions):
    tls = {"worker_id": teams["tls"]["worker_id"], "session_id": sessions["tls"]}
    raw = {"worker_id": teams["raw"]["worker_id"], "session_id": sessions["raw"]}
    # Substring lookup discovers the loader's real spelling, including Mach-O ABI prefixes.
    first = await call("function.by_name", **tls, name="advanced_add", exact=False)
    functions = [row for row in first["functions"] if row["name"].lstrip("_") == "advanced_add"]
    assert len(functions) == 1, first
    original_name = functions[0]["name"]
    location = functions[0]["address"]
    await call("function.rename", **tls, function_start=location, name="tls_only_hypothesis")
    data = await call("symbol.by_name", **tls, name="advanced_scratch", exact=False)
    symbols = [row for row in data["symbols"] if row["name"].lstrip("_") == "advanced_scratch"]
    assert len(symbols) == 1, data
    address = symbols[0]["address"]
    before = await call("memory.read", **raw, address=address, length=4)
    await call("memory.write", **tls, address=address, data_hex="10203040")
    patched = await call("memory.read", **tls, address=address, length=4)
    unchanged = await call("memory.read", **raw, address=address, length=4)
    assert unchanged == before and patched != before, (before, patched, unchanged)
    other = await call("function.by_name", **raw, name=original_name, exact=True)
    assert other["functions"][0]["name"] == original_name, other
    absent = await call("function.by_name", **raw, name="tls_only_hypothesis", exact=True)
    assert absent["functions"] == [], absent
    renamed = await call("function.by_name", **tls, name="tls_only_hypothesis", exact=True)
    assert renamed["functions"][0]["name"] == "tls_only_hypothesis", renamed
    return {
        "function_address": location, "patch_address": address,
        "raw_before": before, "raw_after": unchanged, "tls_after": patched,
        "raw_function": other, "raw_tls_name_lookup": absent, "tls_function": renamed,
    }


async def _save_and_restart(call, group, teams, sessions, changes):
    tls = {"worker_id": teams["tls"]["worker_id"], "session_id": sessions["tls"]}
    raw = {"worker_id": teams["raw"]["worker_id"], "session_id": sessions["raw"]}
    await call("program.save", **tls)
    await call("program.close", **tls)
    sessions.pop("tls")
    await _wait_indexed(call, group["investigation_id"])
    restarted = await call("worker_restart", worker_id=tls["worker_id"], force=False)
    assert restarted["pid"] != teams["tls"]["pid"], restarted
    reopened = await call(
        "program.open", worker_id=tls["worker_id"], path=group["snapshot"],
        read_only=True, update_analysis=False,
    )
    sessions["tls"] = reopened["session_id"]
    persisted = await call(
        "function.by_name", worker_id=tls["worker_id"], session_id=sessions["tls"],
        name="tls_only_hypothesis", exact=True,
    )
    assert persisted["functions"][0]["name"] == "tls_only_hypothesis", persisted
    memory = await call(
        "memory.read", worker_id=tls["worker_id"], session_id=sessions["tls"],
        address=changes["patch_address"], length=4,
    )
    assert memory == changes["tls_after"], memory
    running = await call("worker_status", worker_id=raw["worker_id"])
    assert running["pid"] == teams["raw"]["pid"] and running["state"] == "ready", running
    # A successful call using the original handle proves capability survival, not just a live PID.
    summary = await call("program.summary", **raw)
    unchanged = await call("memory.read", **raw, address=changes["patch_address"], length=4)
    assert unchanged == changes["raw_before"], unchanged
    return {
        "tls_pid_before": teams["tls"]["pid"], "tls_pid_after": restarted["pid"],
        "raw_pid_before": teams["raw"]["pid"], "raw_pid_after": running["pid"],
        "raw_session_id": sessions["raw"], "raw_session_summary": summary,
        "persisted_function": persisted, "persisted_patch": memory,
    }


async def _close_and_stop(call, teams, sessions):
    for name, session in list(sessions.items()):
        await call("program.close", worker_id=teams[name]["worker_id"], session_id=session)
        sessions.pop(name)
    stopped = []
    for team in teams.values():
        status = await call("worker_stop", worker_id=team["worker_id"], force=False)
        assert status["state"] == "stopped", status
        stopped.append(status)
    return stopped


@asynccontextmanager
async def _reload_supervisor(group, output):
    """Load persisted definitions in a separate owner without restarting the caller's server."""
    runtime = SupervisorRuntime(SupervisorConfig(
        workers=(), log_directory=output.parent / "investigation-reload-logs",
        investigation_directory=Path(group["directory"]).parent,
    ))
    listener = reserve_port("127.0.0.1", 0)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        create_http_app(create_server(runtime), "127.0.0.1", port),
        host="127.0.0.1", port=port, log_level="warning",
    ))
    server.capture_signals = nullcontext
    serving = None
    try:
        await runtime.start()
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        with anyio.fail_after(15):
            while not server.started:
                if serving.done():
                    await serving
                    raise RuntimeError("Reload supervisor exited before readiness")
                await asyncio.sleep(0.02)
        yield f"http://127.0.0.1:{port}/mcp", port
    finally:
        server.should_exit = True
        if serving is not None:
            await serving
        listener.close()
        await runtime.close()
        with reserve_port("127.0.0.1", port):
            pass


async def _verify_manifest_reload(group, output):
    manifest_path = Path(group["directory"]) / "investigation.json"
    manifest = json.loads(manifest_path.read_text())
    async with _reload_supervisor(group, output) as (url, port):
        async with _client(url) as call:
            listing = await call("investigation.list")
            assert group["investigation_id"] in {
                row["investigation_id"] for row in listing["investigations"]
            }, listing
            restored = await call(
                "investigation.status", investigation_id=group["investigation_id"]
            )
            assert restored["sha256"] == group["sha256"], restored
            for before, after in zip(group["teams"], restored["teams"], strict=True):
                for key in ("worker_id", "project_identity", "artifact_directory", "port"):
                    assert before[key] == after[key], (key, before, after)
                assert after["state"] == "stopped" and after["pid"] is None, after
            return {
                "manifest_path": str(manifest_path), "manifest": manifest,
                "fresh_supervisor_port": port, "restored": restored,
                "calls": dict(call.calls), "fresh_supervisor_stopped": True,
            }


async def verify(url, fixture, output):
    original_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    async with _client(url) as call:
        group = await call(
            "investigation.create", binary_path=str(fixture), teams=["tls", "raw"],
            name="Acceptance: same binary, independent teams",
        )
        teams = {team["team"]: team for team in group["teams"]}
        sessions = {}
        try:
            assert group["sha256"] == original_hash, group
            snapshot_hash = hashlib.sha256(Path(group["snapshot"]).read_bytes()).hexdigest()
            assert snapshot_hash == original_hash, group
            group = await _wait_indexed(call, group["investigation_id"])
            reports = await _open_teams(call, group, original_hash, sessions)
            changes = await _rename_and_patch(call, teams, sessions)
            restart = await _save_and_restart(call, group, teams, sessions, changes)
        finally:
            stopped = await _close_and_stop(call, teams, sessions)
        assert hashlib.sha256(fixture.read_bytes()).hexdigest() == original_hash
        assert hashlib.sha256(Path(group["snapshot"]).read_bytes()).hexdigest() == original_hash
        reload_evidence = await _verify_manifest_reload(group, output)
        result = {
            "status": "passed", "url": url, "investigation_id": group["investigation_id"],
            "sha256": original_hash, "snapshot_sha256": snapshot_hash,
            "analysis_and_indexes": group, "program_reports": reports,
            "changes": changes, "restart": restart,
            "manifest_reload": reload_evidence, "stopped_workers": stopped,
            "calls": dict(call.calls), "independent_function_names": True,
            "independent_memory_patches": True, "source_unchanged": True,
            "save_reopen": True, "other_team_survived_restart": True,
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:29840/mcp")
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument(
        "--output", default=Path("runtime/acceptance/investigations-evidence.json"), type=Path
    )
    args = parser.parse_args()
    asyncio.run(verify(args.url, args.fixture.resolve(strict=True), args.output.resolve()))


if __name__ == "__main__":
    main()
