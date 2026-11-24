"""One immutable binary snapshot, independently owned local projects for each team."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

from agenticghidra_mcp.project_spec import ProjectSpec
from agenticghidra_mcp.supervisor_runtime import WorkerConfig, reserve_port

TEAM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
INVESTIGATION_ID = re.compile(r"[a-f0-9]{24}\Z")


class InvestigationManager:
    def __init__(self, runtime, directory: Path):
        self.runtime = runtime
        self.directory = Path(directory).expanduser().resolve()
        if any(part.startswith(".") for part in self.directory.parts):
            raise ValueError("Investigation projects require a non-hidden directory")
        self._groups: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _teams(teams):
        if not isinstance(teams, list) or not 2 <= len(teams) <= 16:
            raise ValueError("teams must contain between 2 and 16 distinct team names")
        if any(not isinstance(team, str) or not TEAM_NAME.fullmatch(team) for team in teams):
            raise ValueError("Team names must contain 1-32 letters, numbers, underscores or dashes")
        if len({team.casefold() for team in teams}) != len(teams):
            raise ValueError("Team names must be distinct, including case-insensitive filesystems")
        return teams

    def _ports(self, count):
        used = {worker.config.port for worker in self.runtime.workers.values()}
        reservations = []
        try:
            # Stay outside the OS ephemeral range and existing project defaults.
            for port in range(31000, 40000):
                if port in used:
                    continue
                try:
                    reservation = reserve_port("127.0.0.1", port)
                except ValueError:
                    continue
                reservations.append(reservation)
                if len(reservations) == count:
                    return [value.getsockname()[1] for value in reservations]
            raise RuntimeError("No free investigation ports in 31000-39999")
        finally:
            for reservation in reservations:
                reservation.close()

    @staticmethod
    def _copy_snapshot(source: Path, destination: Path):
        digest = hashlib.sha256()
        length = 0
        with source.open("rb") as reader, destination.open("xb") as writer:
            before = os.fstat(reader.fileno())
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(chunk)
                writer.write(chunk)
                length += len(chunk)
            after = os.fstat(reader.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError("The source binary changed while its snapshot was being created")
            writer.flush()
            os.fsync(writer.fileno())
        destination.chmod(0o400)
        return digest.hexdigest(), length

    @staticmethod
    def _save(directory: Path, manifest: dict):
        temporary = directory / "investigation.json.tmp"
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "investigation.json")

    @staticmethod
    def _contained(directory: Path, relative):
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise ValueError("Investigation manifest paths must be relative")
        resolved = (directory / relative).resolve()
        if directory not in resolved.parents:
            raise ValueError("Investigation manifest escapes its own directory")
        return resolved

    def _worker_configs(self, directory, manifest):
        self._teams([team["team"] for team in manifest["teams"]])
        snapshot = self._contained(directory, manifest["snapshot"])
        if not snapshot.is_file():
            raise FileNotFoundError(f"Investigation snapshot is missing: {snapshot}")
        result = []
        for team in manifest["teams"]:
            project_path = self._contained(directory, team["project_path"])
            project = ProjectSpec.from_cli(project_path, team["team"])
            result.append(
                WorkerConfig(
                    worker_id=team["worker_id"],
                    port=team["port"],
                    project=project,
                    max_workers=team.get("max_workers", 2),
                    input_paths=(snapshot,),
                )
            )
        return tuple(result)

    async def load(self):
        """Restore definitions, not processes, so restart does not reload every JVM."""
        async with self._lock:
            if not self.directory.exists():
                return
            for directory in sorted(self.directory.iterdir()):
                path = directory / "investigation.json"
                if not path.is_file():
                    continue
                manifest = json.loads(path.read_text(encoding="utf-8"))
                identity = manifest.get("investigation_id")
                if not isinstance(identity, str) or not INVESTIGATION_ID.fullmatch(identity):
                    raise ValueError(f"Invalid investigation identity in {path}")
                if directory.name != identity or manifest.get("version") != 1:
                    raise ValueError(f"Invalid investigation manifest layout: {path}")
                if identity in self._groups:
                    continue
                await self.runtime.add_workers(
                    self._worker_configs(directory, manifest), start=False
                )
                self._groups[identity] = manifest

    async def create(self, binary_path, teams, name=None, start=True):
        teams = self._teams(teams)
        if name is not None and (not isinstance(name, str) or not 1 <= len(name) <= 128):
            raise ValueError("name must contain 1-128 characters")
        if not isinstance(start, bool):
            raise ValueError("start must be a boolean")
        source = Path(binary_path).expanduser().resolve(strict=True)
        if not source.is_file():
            raise ValueError("binary_path must identify one regular file, not a directory")
        async with self._lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            identity = secrets.token_hex(12)
            directory = self.directory / identity
            directory.mkdir()
            source_directory = directory / "source"
            source_directory.mkdir()
            snapshot = source_directory / source.name
            digest, length = await asyncio.to_thread(self._copy_snapshot, source, snapshot)
            ports = self._ports(len(teams))
            manifest = {
                "version": 1,
                "investigation_id": identity,
                "name": name or source.name,
                "original_source": str(source),
                "snapshot": str(snapshot.relative_to(directory)),
                "sha256": digest,
                "size": length,
                "created_at": time.time(),
                "teams": [
                    {
                        "team": team,
                        "worker_id": f"inv_{identity}_{team}",
                        "port": port,
                        "project_path": f"teams/{team}/project",
                        "max_workers": 2,
                    }
                    for team, port in zip(teams, ports, strict=True)
                ],
            }
            self._save(directory, manifest)
            configs = self._worker_configs(directory, manifest)
            await self.runtime.add_workers(configs, start=False)
            self._groups[identity] = manifest
        if start:
            try:
                await asyncio.gather(
                    *(self.runtime.start_worker(config.worker_id) for config in configs)
                )
            except Exception as error:
                raise RuntimeError(
                    f"Investigation {identity} was preserved, but not every worker "
                    f"started: {error}; inspect investigation.status before retrying"
                ) from error
        return await self.status(identity)

    async def status(self, investigation_id):
        if investigation_id not in self._groups:
            raise ValueError(f"Unknown investigation_id: {investigation_id!r}")
        manifest = self._groups[investigation_id]
        result = {key: value for key, value in manifest.items() if key != "teams"}
        result["directory"] = str(self.directory / investigation_id)
        result["snapshot"] = str(self.directory / investigation_id / manifest["snapshot"])
        result["teams"] = []
        for team in manifest["teams"]:
            worker = self.runtime.workers[team["worker_id"]]
            row = {**team, **worker.status(), "programs": None}
            if row["state"] == "ready":
                try:
                    response = await worker.call("list_project_binaries", {})
                    if response.isError:
                        row["status_error"] = str(response.content)
                    else:
                        payload = response.structuredContent
                        if payload is None:
                            payload = json.loads(response.content[0].text)
                        row["programs"] = payload["programs"]
                except Exception as error:
                    row["status_error"] = f"{type(error).__name__}: {error}"
            result["teams"].append(row)
        return result

    def list(self):
        return {
            "investigations": [
                {
                    "investigation_id": identity,
                    "name": group["name"],
                    "sha256": group["sha256"],
                    "teams": [
                        {"team": value["team"], "worker_id": value["worker_id"]}
                        for value in group["teams"]
                    ],
                }
                for identity, group in self._groups.items()
            ]
        }
