import hashlib
from pathlib import Path

import pytest

from agenticghidra_mcp.advanced.investigations import InvestigationManager


class _StoppedWorker:
    def __init__(self, config):
        self.config = config

    def status(self):
        return {
            "worker_id": self.config.worker_id,
            "state": "stopped",
            "port": self.config.port,
            "project_identity": str(self.config.project.gpr_path),
            "artifact_directory": str(self.config.project.agenticghidra_mcp_dir),
        }


class _Runtime:
    def __init__(self):
        self.workers = {}

    async def add_workers(self, configs, start=False):
        for config in configs:
            if config.worker_id in self.workers:
                raise ValueError("Duplicate worker identity")
        self.workers.update({config.worker_id: _StoppedWorker(config) for config in configs})


@pytest.mark.asyncio
async def test_same_binary_teams_have_immutable_snapshot_and_independent_project_state(tmp_path):
    source = tmp_path / "library.so"
    contents = bytes(range(256)) * 17
    source.write_bytes(contents)
    runtime = _Runtime()
    manager = InvestigationManager(runtime, tmp_path / "investigations")
    group = await manager.create(str(source), ["tls", "raw"], name="same binary", start=False)
    snapshot = Path(group["snapshot"])
    assert group["sha256"] == hashlib.sha256(contents).hexdigest()
    assert snapshot.read_bytes() == contents
    assert snapshot != source and snapshot.stat().st_mode & 0o222 == 0
    source.write_bytes(b"the source changed after collection")
    assert snapshot.read_bytes() == contents
    teams = group["teams"]
    assert {team["team"] for team in teams} == {"tls", "raw"}
    assert len({team["worker_id"] for team in teams}) == 2
    assert len({team["project_identity"] for team in teams}) == 2
    assert len({team["artifact_directory"] for team in teams}) == 2
    assert len({team["port"] for team in teams}) == 2


@pytest.mark.asyncio
async def test_investigation_definition_survives_supervisor_restart_without_starting_workers(
    tmp_path,
):
    source = tmp_path / "binary"
    source.write_bytes(b"one captured binary")
    directory = tmp_path / "investigations"
    first = InvestigationManager(_Runtime(), directory)
    created = await first.create(str(source), ["flow", "native"], start=False)
    reloaded = InvestigationManager(_Runtime(), directory)
    await reloaded.load()
    restored = await reloaded.status(created["investigation_id"])
    assert restored["sha256"] == created["sha256"]
    assert {team["project_identity"] for team in restored["teams"]} == {
        team["project_identity"] for team in created["teams"]
    }
    assert all(team["state"] == "stopped" for team in restored["teams"])
    assert restored["snapshot"] == created["snapshot"]
    assert {team["worker_id"] for team in restored["teams"]} == set(reloaded.runtime.workers)
    for worker in reloaded.runtime.workers.values():
        assert worker.config.input_paths == (Path(created["snapshot"]),)
    await reloaded.load()
    assert len(reloaded.list()["investigations"]) == 1
    assert len(reloaded.runtime.workers) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("teams", [["tls"], ["TLS", "tls"], ["tls", "../raw"], ["", "raw"]])
async def test_invalid_team_layout_is_rejected_before_creating_projects(tmp_path, teams):
    source = tmp_path / "binary"
    source.write_bytes(b"source")
    directory = tmp_path / "investigations"
    manager = InvestigationManager(_Runtime(), directory)
    with pytest.raises(ValueError, match=r"[Tt]eam"):
        await manager.create(str(source), teams, start=False)
    assert not directory.exists()


@pytest.mark.asyncio
async def test_persisted_project_path_cannot_escape_its_investigation(tmp_path):
    import json

    source = tmp_path / "binary"
    source.write_bytes(b"source")
    directory = tmp_path / "investigations"
    manager = InvestigationManager(_Runtime(), directory)
    group = await manager.create(str(source), ["tls", "raw"], start=False)
    manifest_path = directory / group["investigation_id"] / "investigation.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["teams"][0]["project_path"] = "../../unrelated-project"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="escapes"):
        await InvestigationManager(_Runtime(), directory).load()


@pytest.mark.asyncio
async def test_port_count_mismatch_cannot_persist_truncated_team_manifest(tmp_path, monkeypatch):
    source = tmp_path / "binary"
    source.write_bytes(b"source")
    directory = tmp_path / "investigations"
    runtime = _Runtime()
    manager = InvestigationManager(runtime, directory)
    monkeypatch.setattr(manager, "_ports", lambda count: [31000])
    with pytest.raises(ValueError, match="zip"):
        await manager.create(str(source), ["tls", "raw"], start=False)
    assert runtime.workers == {}
    assert manager.list() == {"investigations": []}
    assert not list(directory.glob("*/investigation.json"))
