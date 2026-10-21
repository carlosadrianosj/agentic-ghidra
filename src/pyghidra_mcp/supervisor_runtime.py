"""Owned subprocesses and task-local MCP sessions for the supervisor."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import secrets
import signal
import socket
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from pyghidra_mcp.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec

logger = logging.getLogger(__name__)
WORKER_HOST = "127.0.0.1"
MANAGEMENT_TOOLS = frozenset({"worker_status", "worker_restart"})


@dataclass(frozen=True)
class WorkerConfig:
    worker_id: str
    port: int
    project: ProjectSpec
    max_workers: int
    input_paths: tuple[Path, ...]

    def command(self) -> list[str]:
        return [
            sys.executable,
            "-m",
            "pyghidra_mcp",
            "--transport",
            "streamable-http",
            "--host",
            WORKER_HOST,
            "--port",
            str(self.port),
            "--project-path",
            str(self.project.project_directory),
            "--project-name",
            self.project.project_name,
            "--max-workers",
            str(self.max_workers),
            "--no-wait-for-analysis",
            "--",
            *(str(path) for path in self.input_paths),
        ]


@dataclass(frozen=True)
class SupervisorConfig:
    workers: tuple[WorkerConfig, ...]
    log_directory: Path
    startup_timeout: float = 180.0
    shutdown_timeout: float = 60.0


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a positive number")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)


def _port(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{name} must be an integer between 1 and 65535")
    return value


def _path(value: Any, base: Path, name: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty path string")
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _worker_project(entry: dict[str, Any], base: Path, worker_id: str) -> ProjectSpec:
    name = entry.get("project_name", DEFAULT_PROJECT_NAME)
    if (
        not isinstance(name, str)
        or not name.strip()
        or name in {".", ".."}
        or any(char in name for char in "/\\\x00")
    ):
        raise ValueError(f"Invalid project_name for {worker_id}")
    project = ProjectSpec.from_cli(_path(entry.get("project_path"), base, "project_path"), name)
    project = ProjectSpec(
        project_directory=project.project_directory.resolve(),
        project_name=project.project_name,
        gpr_path=project.gpr_path.resolve(),
        pyghidra_mcp_dir=project.pyghidra_mcp_dir.resolve(),
        was_gpr_path=project.was_gpr_path,
    )
    if project.project_name.startswith(".") or any(
        part.startswith(".") for part in project.project_directory.parts
    ):
        raise ValueError(
            f"Ghidra project paths must not contain hidden path components: "
            f"{project.gpr_path}; use a non-hidden project directory and name"
        )
    return project


def _worker_config(entry: Any, base: Path) -> WorkerConfig:
    if not isinstance(entry, dict):
        raise ValueError("Each worker must be an object")
    allowed = {"worker_id", "port", "project_path", "project_name", "max_workers", "input_paths"}
    if set(entry) - allowed:
        raise ValueError(f"Unknown worker settings: {sorted(set(entry) - allowed)}")
    worker_id = entry.get("worker_id")
    if not isinstance(worker_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", worker_id):
        raise ValueError(
            "worker_id must contain only letters, numbers, dots, underscores or dashes"
        )
    port = _port(entry.get("port"), f"{worker_id} port")
    project = _worker_project(entry, base, worker_id)
    max_workers = entry.get("max_workers", 1)
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
        raise ValueError(f"{worker_id} max_workers must be a positive integer")
    inputs = entry.get("input_paths", [])
    if not isinstance(inputs, list):
        raise ValueError(f"{worker_id} input_paths must be an array")
    input_paths = tuple(_path(value, base, "input_paths") for value in inputs)
    for input_path in input_paths:
        if not input_path.exists():
            raise ValueError(f"Input path does not exist: {input_path}")
    return WorkerConfig(worker_id, port, project, max_workers, input_paths)


def _validate_storage_isolation(worker: WorkerConfig, previous: WorkerConfig) -> None:
    storage = (
        worker.project.project_directory,
        worker.project.gpr_path,
        worker.project.pyghidra_mcp_dir,
    )
    previous_storage = (
        previous.project.project_directory,
        previous.project.gpr_path,
        previous.project.pyghidra_mcp_dir,
    )
    if any(_overlap(left, right) for left in storage for right in previous_storage):
        raise ValueError(
            f"Workers {previous.worker_id} and {worker.worker_id} share project paths "
            "or artifact directories; use separate, non-nested project directories"
        )


def load_config(path: Path, supervisor_port: int = 29840) -> SupervisorConfig:
    """Resolve paths against the config, rejecting overlapping project storage."""
    path = path.expanduser().resolve()
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("Supervisor config must be a JSON object")
    allowed = {"workers", "log_directory", "startup_timeout", "shutdown_timeout"}
    if set(data) - allowed:
        raise ValueError(f"Unknown supervisor settings: {sorted(set(data) - allowed)}")
    entries = data.get("workers")
    if not isinstance(entries, list) or not entries:
        raise ValueError("workers must be a nonempty array")
    ports = {_port(supervisor_port, "supervisor port")}
    worker_ids: set[str] = set()
    workers: list[WorkerConfig] = []
    for entry in entries:
        worker = _worker_config(entry, path.parent)
        if worker.worker_id in worker_ids:
            raise ValueError(f"Duplicate worker_id: {worker.worker_id}")
        if worker.port in ports:
            raise ValueError(f"Duplicate port or supervisor port collision: {worker.port}")
        for previous in workers:
            _validate_storage_isolation(worker, previous)
        worker_ids.add(worker.worker_id)
        ports.add(worker.port)
        workers.append(worker)
    return SupervisorConfig(
        workers=tuple(workers),
        log_directory=_path(
            data.get("log_directory", ".runtime/logs"), path.parent, "log_directory"
        ),
        startup_timeout=_positive_number(data.get("startup_timeout", 180), "startup_timeout"),
        shutdown_timeout=_positive_number(data.get("shutdown_timeout", 60), "shutdown_timeout"),
    )


def reserve_port(host: str, port: int) -> socket.socket:
    """Keep a port reserved until its owned server is about to bind it."""
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    last_error: OSError | None = None
    for family, socktype, protocol, _, address in addresses:
        sock = socket.socket(family, socktype, protocol)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(address)
            sock.listen()
            sock.setblocking(False)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise ValueError(f"Cannot reserve {host}:{port}: {last_error}; refusing to attach")


def tool_contract(tools: list[types.Tool]) -> dict[str, tuple[dict[str, Any], Any]]:
    result: dict[str, tuple[dict[str, Any], Any]] = {}
    for tool in tools:
        if tool.name in result or tool.name in MANAGEMENT_TOOLS:
            raise ValueError(f"Duplicate or reserved worker tool: {tool.name}")
        if tool.inputSchema.get("type") != "object":
            raise ValueError(f"Worker tool {tool.name} must accept an object")
        if "worker_id" in tool.inputSchema.get("properties", {}):
            raise ValueError(f"Worker tool {tool.name} already declares worker_id")
        result[tool.name] = (tool.inputSchema, tool.outputSchema)
    if not result:
        raise ValueError("Worker did not expose any tools")
    return result


class WorkerOwnershipError(RuntimeError):
    """An endpoint does not belong to the process just spawned."""


class WorkerRuntime:
    def __init__(self, config: WorkerConfig, settings: SupervisorConfig, log_directory: Path):
        self.config = config
        self.settings = settings
        self.log_directory = log_directory
        self.state = "stopped"
        self.recent_failure: str | None = None
        self.log_path: Path | None = None
        self.process: asyncio.subprocess.Process | None = None
        self.tools: list[types.Tool] = []
        self.expected_contract: dict[str, tuple[dict[str, Any], Any]] | None = None
        self._session: ClientSession | None = None
        self._task: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[None] | None = None
        self._stop = asyncio.Event()
        self._lifecycle_lock = asyncio.Lock()
        self._calls = asyncio.Semaphore(config.max_workers)

    def status(self) -> dict[str, Any]:
        process = self.process
        return {
            "worker_id": self.config.worker_id,
            "state": self.state,
            "pid": process.pid if process else None,
            "port": self.config.port,
            "project_path": str(self.config.project.project_directory),
            "project_name": self.config.project.project_name,
            "project_identity": str(self.config.project.gpr_path),
            "artifact_directory": str(self.config.project.pyghidra_mcp_dir),
            "max_workers": self.config.max_workers,
            "returncode": process.returncode if process else None,
            "log_path": str(self.log_path) if self.log_path else None,
            "recent_failure": self.recent_failure,
        }

    async def start(self, reservation: socket.socket | None = None) -> None:
        async with self._lifecycle_lock:
            await self._start_locked(reservation)

    async def _start_locked(self, reservation: socket.socket | None = None) -> None:
        if self._task is not None and not self._task.done():
            raise RuntimeError(f"Worker {self.config.worker_id} is already running")
        if self.process is not None and self.process.returncode is None:
            raise RuntimeError(
                f"Worker {self.config.worker_id} still owns a live process; restart refused"
            )
        reservation = reservation or reserve_port(WORKER_HOST, self.config.port)
        self._stop = asyncio.Event()
        self._ready = asyncio.get_running_loop().create_future()
        self.state = "starting"
        self._task = asyncio.create_task(
            self._run(reservation), name=f"worker-{self.config.worker_id}"
        )
        try:
            await asyncio.shield(self._ready)
        except BaseException:
            await self._stop_locked()
            # Retrieve startup exceptions even when the caller was cancelled.
            if self._ready.done() and not self._ready.cancelled():
                self._ready.exception()
            raise

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            await self._stop_locked()

    async def _stop_locked(self) -> None:
        if self.state in {"starting", "ready"}:
            self.state = "stopping"
        self._stop.set()
        if self._task is not None:
            await asyncio.shield(self._task)

    async def restart(self) -> None:
        async with self._lifecycle_lock:
            await self._stop_locked()
            await self._start_locked()

    async def call(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        session = self._session
        if session is None or self.state != "ready":
            raise RuntimeError(f"Worker {self.config.worker_id} is unavailable ({self.state})")
        async with self._calls:
            # A queued write must never move to the replacement session after a restart.
            if self._session is not session or self.state != "ready":
                raise RuntimeError(
                    f"Worker {self.config.worker_id} changed session; request not sent"
                )
            try:
                return await session.call_tool(name, arguments)
            except Exception as exc:
                self.recent_failure = f"{name}: {exc}"
                raise RuntimeError(
                    f"Worker {self.config.worker_id} call failed: {exc}. "
                    "The operation may have completed; it was not retried."
                ) from exc

    async def _run(self, reservation: socket.socket) -> None:
        token = secrets.token_urlsafe(32)
        try:
            descriptor, filename = tempfile.mkstemp(
                prefix=f"{self.config.worker_id}-", suffix=".log", dir=self.log_directory
            )
            self.log_path = Path(filename)
            environment = dict(os.environ, PYGHIDRA_MCP_WORKER_TOKEN=token)
            # Start a new session: terminal Ctrl+C goes to the supervisor, not every JVM.
            with os.fdopen(descriptor, "ab", buffering=0) as log:
                reservation.close()
                self.process = await asyncio.create_subprocess_exec(
                    *self.config.command(),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log,
                    stderr=asyncio.subprocess.STDOUT,
                    env=environment,
                    start_new_session=os.name != "nt",
                )
            await self._connect_and_wait(token)
        except BaseException as exc:
            if not self._stop.is_set():
                self.state = "failed"
                self.recent_failure = f"{type(exc).__name__}: {exc}"
                logger.error(
                    "Worker %s failed: %s (log: %s)", self.config.worker_id, exc, self.log_path
                )
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(
                    RuntimeError(
                        f"Worker {self.config.worker_id} startup failed: {exc}; "
                        f"log: {self.log_path}"
                    )
                )
        finally:
            reservation.close()
            self._session = None
            # Transport cancellation must not cancel project save-and-close.
            with anyio.CancelScope(shield=True):
                await self._stop_process()
            if self.state != "failed":
                self.state = "stopped"
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(
                    RuntimeError(f"Worker {self.config.worker_id} stopped during startup")
                )

    async def _connect_and_wait(self, token: str) -> None:
        deadline = asyncio.get_running_loop().time() + self.settings.startup_timeout
        last_error: Exception | None = None
        while not self._stop.is_set():
            process = self.process
            if process is None or process.returncode is not None:
                raise RuntimeError(
                    f"Process exited before readiness (exit {getattr(process, 'returncode', None)})"
                )
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Startup deadline exceeded: {last_error}")
            try:
                # All transport and session contexts belong to this one owner task.
                # Callers may use the session but never enter or close these contexts.
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(10.0, read=None), trust_env=False
                ) as client:
                    async with streamable_http_client(
                        f"http://{WORKER_HOST}:{self.config.port}/mcp",
                        http_client=client,
                        terminate_on_close=False,
                    ) as (read_stream, write_stream, _):
                        async with ClientSession(read_stream, write_stream) as session:
                            await self._serve_session(session, token, remaining, deadline, process)
                            return
            except Exception as exc:
                if self._stop.is_set():
                    return
                # Context managers may wrap the ownership failure in an ExceptionGroup.
                if self._ready is not None and self._ready.done():
                    raise
                if _contains_ownership_error(exc):
                    raise
                last_error = exc
                await asyncio.sleep(
                    min(0.25, max(0.0, deadline - asyncio.get_running_loop().time()))
                )
            finally:
                self._session = None

    async def _serve_session(
        self,
        session: ClientSession,
        token: str,
        remaining: float,
        deadline: float,
        process: asyncio.subprocess.Process,
    ) -> None:
        initialized = await asyncio.wait_for(session.initialize(), min(remaining, 5.0))
        if initialized.serverInfo.name != f"pyghidra-mcp:{token}":
            raise WorkerOwnershipError("Endpoint ownership token mismatch; refusing to attach")
        tools = await self._discover_tools(session, deadline)
        contract = tool_contract(tools)
        if self.expected_contract is not None and contract != self.expected_contract:
            raise WorkerOwnershipError("Restarted worker tool schemas are incompatible")
        if process.returncode is not None:
            raise RuntimeError(f"Worker exited during initialization: {process.returncode}")
        if self._stop.is_set():
            return
        self.tools = tools
        self._session = session
        self.state = "ready"
        assert self._ready is not None
        self._ready.set_result(None)
        await self._wait_until_stopped(process)

    async def _discover_tools(self, session: ClientSession, deadline: float) -> list[types.Tool]:
        tools: list[types.Tool] = []
        cursor: str | None = None
        seen: set[str] = set()
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Startup deadline exceeded during tool discovery")
            result = await asyncio.wait_for(session.list_tools(cursor=cursor), remaining)
            tools.extend(result.tools)
            cursor = result.nextCursor
            if cursor is None:
                return tools
            if cursor in seen:
                raise ValueError("Worker returned a repeated tools/list cursor")
            seen.add(cursor)

    async def _wait_until_stopped(self, process: asyncio.subprocess.Process) -> None:
        exited = asyncio.create_task(process.wait())
        stopped = asyncio.create_task(self._stop.wait())
        try:
            await asyncio.wait({exited, stopped}, return_when=asyncio.FIRST_COMPLETED)
            if not self._stop.is_set():
                raise RuntimeError(
                    f"Worker process exited unexpectedly (exit {process.returncode})"
                )
            self.state = "stopping"
            self._session = None
            with anyio.CancelScope(shield=True):
                await self._stop_process()
        finally:
            exited.cancel()
            stopped.cancel()
            await asyncio.gather(exited, stopped, return_exceptions=True)

    async def _stop_process(self) -> None:
        process = self.process
        if process is None or process.returncode is not None:
            return
        logger.info(
            "Stopping worker %s (pid %s); saving and closing project",
            self.config.worker_id,
            process.pid,
        )
        try:
            process.send_signal(signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), self.settings.shutdown_timeout)
            return
        except asyncio.TimeoutError:
            self.recent_failure = (
                "Graceful shutdown deadline exceeded; "
                "forced termination risks unsaved project changes"
            )
            logger.error("Worker %s: %s", self.config.worker_id, self.recent_failure)
        for action in (process.terminate, process.kill):
            try:
                action()
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(process.wait(), 5.0)
                return
            except asyncio.TimeoutError:
                continue
        self.state = "failed"
        self.recent_failure = (
            "Worker could not be reaped after kill; project ownership is uncertain"
        )
        logger.critical("Worker %s: %s", self.config.worker_id, self.recent_failure)


def _contains_ownership_error(error: BaseException) -> bool:
    if isinstance(error, WorkerOwnershipError):
        return True
    return any(_contains_ownership_error(child) for child in getattr(error, "exceptions", ()))


class SupervisorRuntime:
    def __init__(self, config: SupervisorConfig):
        self.config = config
        self.workers: dict[str, WorkerRuntime] = {}
        self.tools: list[types.Tool] = []
        self._closing = False

    async def start(self) -> None:
        reservations: dict[str, socket.socket] = {}
        try:
            # Preflight every port before starting any JVM.
            for config in self.config.workers:
                reservations[config.worker_id] = reserve_port(WORKER_HOST, config.port)
            self.config.log_directory.mkdir(parents=True, exist_ok=True)
            log_directory = Path(
                tempfile.mkdtemp(prefix="supervisor-", dir=self.config.log_directory)
            )
            self.workers = {
                config.worker_id: WorkerRuntime(config, self.config, log_directory)
                for config in self.config.workers
            }
            logger.info("Worker logs: %s", log_directory)
            starts = [
                asyncio.create_task(worker.start(reservations[worker_id]))
                for worker_id, worker in self.workers.items()
            ]
            results = await asyncio.gather(*starts, return_exceptions=True)
            failures = [str(result) for result in results if isinstance(result, BaseException)]
            if failures:
                raise RuntimeError("; ".join(failures))
            first = next(iter(self.workers.values()))
            contract = tool_contract(first.tools)
            for worker in self.workers.values():
                if tool_contract(worker.tools) != contract:
                    raise ValueError(
                        f"Worker {worker.config.worker_id} exposes incompatible tool schemas"
                    )
                worker.expected_contract = contract
            self.tools = first.tools
        except BaseException:
            with anyio.CancelScope(shield=True):
                await self.close()
            raise
        finally:
            for reservation in reservations.values():
                reservation.close()

    def worker(self, worker_id: Any) -> WorkerRuntime:
        if not isinstance(worker_id, str) or worker_id not in self.workers:
            raise ValueError(f"Unknown worker_id: {worker_id!r}")
        return self.workers[worker_id]

    async def call(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        if self._closing:
            raise RuntimeError("Supervisor is shutting down; no request was sent")
        worker = self.worker(arguments.get("worker_id"))
        forwarded = {key: value for key, value in arguments.items() if key != "worker_id"}
        return await worker.call(name, forwarded)

    async def restart(self, worker_id: Any) -> dict[str, Any]:
        if self._closing:
            raise RuntimeError("Supervisor is shutting down; restart refused")
        worker = self.worker(worker_id)
        await worker.restart()
        return worker.status()

    async def close(self) -> None:
        self._closing = True
        await asyncio.gather(*(worker.stop() for worker in self.workers.values()))
