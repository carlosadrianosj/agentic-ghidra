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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from agenticghidra_mcp.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec
from agenticghidra_mcp.telemetry import METRICS, measure

logger = logging.getLogger(__name__)
WORKER_HOST = "127.0.0.1"
MANAGEMENT_TOOLS = frozenset(
    {
        "worker_status",
        "worker_start",
        "worker_stop",
        "worker_restart",
        "investigation.create",
        "investigation.list",
        "investigation.status",
    }
)


@dataclass(frozen=True)
class WorkerConfig:
    worker_id: str
    port: int
    project: ProjectSpec
    max_workers: int
    input_paths: tuple[Path, ...]
    decompiler_pool_size: int = 2
    max_queued_calls: int = 32

    def command(self) -> list[str]:
        return [
            sys.executable,
            "-m",
            "agenticghidra_mcp",
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
    max_active_workers: int = 2
    investigation_directory: Path | None = None


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
        agenticghidra_mcp_dir=project.agenticghidra_mcp_dir.resolve(),
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
    allowed = {
        "worker_id",
        "port",
        "project_path",
        "project_name",
        "max_workers",
        "input_paths",
        "decompiler_pool_size",
        "max_queued_calls",
    }
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
    pool_size = entry.get("decompiler_pool_size", 2)
    if isinstance(pool_size, bool) or not isinstance(pool_size, int) or not 1 <= pool_size <= 32:
        raise ValueError(f"{worker_id} decompiler_pool_size must be between 1 and 32")
    queue_limit = entry.get("max_queued_calls", 32)
    if isinstance(queue_limit, bool) or not isinstance(queue_limit, int) or queue_limit < 1:
        raise ValueError(f"{worker_id} max_queued_calls must be a positive integer")
    return WorkerConfig(worker_id, port, project, max_workers, input_paths, pool_size, queue_limit)


def _validate_storage_isolation(worker: WorkerConfig, previous: WorkerConfig) -> None:
    storage = (
        worker.project.project_directory,
        worker.project.gpr_path,
        worker.project.agenticghidra_mcp_dir,
    )
    previous_storage = (
        previous.project.project_directory,
        previous.project.gpr_path,
        previous.project.agenticghidra_mcp_dir,
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
    allowed = {
        "workers",
        "log_directory",
        "startup_timeout",
        "shutdown_timeout",
        "max_active_workers",
        "investigation_directory",
    }
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
    cap = data.get("max_active_workers", 2)
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        raise ValueError("max_active_workers must be a positive integer")
    investigation_directory = _path(
        data.get("investigation_directory", "runtime/investigations"),
        path.parent,
        "investigation_directory",
    )
    if any(part.startswith(".") for part in investigation_directory.parts):
        raise ValueError("investigation_directory must not contain hidden path components")
    return SupervisorConfig(
        workers=tuple(workers),
        log_directory=_path(
            data.get("log_directory", ".runtime/logs"), path.parent, "log_directory"
        ),
        startup_timeout=_positive_number(data.get("startup_timeout", 180), "startup_timeout"),
        shutdown_timeout=_positive_number(data.get("shutdown_timeout", 60), "shutdown_timeout"),
        max_active_workers=cap,
        investigation_directory=investigation_directory,
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


class WorkerClient:
    """One task owns one upstream MCP session for a downstream transport owner."""

    def __init__(self, worker: WorkerRuntime):
        self.worker = worker
        self.generation = worker.generation
        self.session: ClientSession | None = None
        self.ready = asyncio.get_running_loop().create_future()
        self.stop = asyncio.Event()
        self.failure: str | None = None
        self.task = asyncio.create_task(
            self._run(), name=f"worker-client-{worker.config.worker_id}"
        )

    async def _run(self) -> None:
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, read=None), trust_env=False
            ) as client:
                async with streamable_http_client(
                    f"http://{WORKER_HOST}:{self.worker.config.port}/mcp",
                    http_client=client,
                    terminate_on_close=True,
                ) as (reader, writer, _):
                    async with ClientSession(reader, writer) as session:
                        initialized = await asyncio.wait_for(session.initialize(), 10.0)
                        if (
                            initialized.serverInfo.name
                            != f"agenticghidra-mcp:{self.worker._ownership_token}"
                        ):
                            raise WorkerOwnershipError("Client endpoint ownership token mismatch")
                        if (
                            self.worker.generation != self.generation
                            or self.worker.state != "ready"
                        ):
                            raise RuntimeError(
                                "Worker changed during client initialization; request not sent"
                            )
                        self.session = session
                        self.ready.set_result(session)
                        await self.stop.wait()
        except BaseException as exc:
            self.failure = f"{type(exc).__name__}: {exc}"
            if not self.ready.done():
                self.ready.set_exception(
                    RuntimeError(f"Worker client initialization failed: {exc}")
                )
        finally:
            self.session = None
            if not self.ready.done():
                self.ready.set_exception(RuntimeError("Worker client closed before initialization"))

    async def close(self) -> None:
        self.stop.set()
        await asyncio.shield(self.task)
        if self.ready.done() and not self.ready.cancelled():
            self.ready.exception()


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
        self.queued_calls = 0
        self.active_calls = 0
        self.completed_calls = 0
        self.failed_calls = 0
        self.last_latency_seconds: float | None = None
        self.started_at: float | None = None
        self.generation = secrets.token_hex(8)
        self._ownership_token: str | None = None
        self._clients: dict[object, WorkerClient] = {}
        self._clients_lock = asyncio.Lock()
        self.max_client_sessions = 128

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
            "artifact_directory": str(self.config.project.agenticghidra_mcp_dir),
            "max_workers": self.config.max_workers,
            "returncode": process.returncode if process else None,
            "log_path": str(self.log_path) if self.log_path else None,
            "recent_failure": self.recent_failure,
            "queued_calls": self.queued_calls,
            "active_calls": self.active_calls,
            "completed_calls": self.completed_calls,
            "failed_calls": self.failed_calls,
            "last_latency_seconds": self.last_latency_seconds,
            "started_at": self.started_at,
            "generation": self.generation,
            "client_sessions": len(self._clients),
            "max_client_sessions": self.max_client_sessions,
            "max_queued_calls": self.config.max_queued_calls,
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
        self.generation = secrets.token_hex(8)
        self.started_at = time.time()
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

    async def client(self, owner: object) -> WorkerClient:
        async with self._clients_lock:
            if self.state != "ready":
                raise RuntimeError("Worker is not ready; request not sent")
            connection = self._clients.get(owner)
            if connection is not None and connection.task.done():
                del self._clients[owner]
                connection = None
            if connection is None:
                if len(self._clients) >= self.max_client_sessions:
                    raise RuntimeError("Worker client-session limit reached; request not sent")
                connection = WorkerClient(self)
                self._clients[owner] = connection
        await asyncio.shield(connection.ready)
        return connection

    async def release_owner(self, owner: object) -> None:
        async with self._clients_lock:
            connection = self._clients.pop(owner, None)
        if connection is not None:
            await connection.close()

    async def _close_clients(self) -> None:
        async with self._clients_lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            client.stop.set()
        await asyncio.gather(*(client.close() for client in clients))

    async def call(
        self, name: str, arguments: dict[str, Any], *, owner: object | None = None
    ) -> types.CallToolResult:
        connection = await self.client(owner) if owner is not None else None
        session = connection.session if connection is not None else self._session
        generation = self.generation
        if session is None or self.state != "ready":
            raise RuntimeError(f"Worker {self.config.worker_id} is unavailable ({self.state})")
        if self.queued_calls >= self.config.max_queued_calls:
            raise RuntimeError("Worker request queue is full; request not sent")
        stage = f"worker.{self.config.worker_id}"
        self.queued_calls += 1
        METRICS.queue(stage, 1)
        acquired = False
        try:
            with measure("worker_queue_wait"):
                await self._calls.acquire()
            acquired = True
        finally:
            self.queued_calls -= 1
            METRICS.queue(stage, -1)
        started = time.perf_counter()
        failed = True
        try:
            # Never send queued work to a replacement process/session.
            current = self._session if connection is None else connection.session
            if (
                current is not session
                or self.state != "ready"
                or self.generation != generation
                or (connection is not None
                and self._clients.get(owner) is not connection)
            ):
                raise RuntimeError(
                    f"Worker {self.config.worker_id} changed session; request not sent"
                )
            self.active_calls += 1
            METRICS.active(stage, 1)
            try:
                with measure("worker_request"):
                    result = await self._call_session(session, name, arguments)
                failed = bool(result.isError)
                if result.isError:
                    METRICS.error("worker_request")
                    self.failed_calls += 1
                self.completed_calls += 1
                return result
            except BaseException as exc:
                failed = True
                self.failed_calls += 1
                self.recent_failure = f"{name}: {exc}"
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise RuntimeError(
                    f"Worker {self.config.worker_id} call failed: {exc}. "
                    "The operation may have completed; it was not retried."
                ) from exc
            finally:
                self.active_calls -= 1
                METRICS.active(stage, -1)
        finally:
            self.last_latency_seconds = time.perf_counter() - started
            METRICS.observe(stage, self.last_latency_seconds, error=failed)
            if acquired:
                self._calls.release()

    async def _call_session(self, session, name, arguments) -> types.CallToolResult:
        """Settle sent calls when their owned worker dies, without replaying them."""
        lifecycle = self._task
        if lifecycle is None:
            raise RuntimeError("Worker has no owning lifecycle task")
        request = asyncio.create_task(session.call_tool(name, arguments))
        try:
            settled, _ = await asyncio.wait(
                (request, lifecycle), return_when=asyncio.FIRST_COMPLETED
            )
            if request in settled:
                return request.result()
            # MCP's HTTP transport may reconnect its GET stream indefinitely.
            # The owned process lifecycle is authoritative: no replacement can
            # supply a result for a request already sent to the old process.
            raise RuntimeError(
                "Owned worker stopped before returning a response; outcome is unknown"
            )
        finally:
            if not request.done():
                request.cancel()
            await asyncio.gather(request, return_exceptions=True)

    async def _run(self, reservation: socket.socket) -> None:
        token = secrets.token_urlsafe(32)
        self._ownership_token = token
        try:
            descriptor, filename = tempfile.mkstemp(
                prefix=f"{self.config.worker_id}-", suffix=".log", dir=self.log_directory
            )
            self.log_path = Path(filename)
            environment = dict(
                os.environ,
                AGENTICGHIDRA_MCP_WORKER_TOKEN=token,
                AGENTICGHIDRA_MCP_DECOMPILER_POOL_SIZE=str(self.config.decompiler_pool_size),
            )
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
                await self._close_clients()
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
        if initialized.serverInfo.name != f"agenticghidra-mcp:{token}":
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
                await self._close_clients()
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


def _normalized_worker_config(item: WorkerConfig) -> WorkerConfig:
    """Apply the same validation to dynamic workers as to file-backed settings."""
    return _worker_config(
        {
            "worker_id": item.worker_id,
            "port": item.port,
            "project_path": str(item.project.project_directory),
            "project_name": item.project.project_name,
            "max_workers": item.max_workers,
            "input_paths": [str(path) for path in item.input_paths],
            "decompiler_pool_size": item.decompiler_pool_size,
            "max_queued_calls": item.max_queued_calls,
        },
        Path.cwd(),
    )


class SupervisorRuntime:
    def __init__(self, config: SupervisorConfig):
        self.config = config
        self.workers: dict[str, WorkerRuntime] = {}
        self.tools: list[types.Tool] = []
        self._closing = False
        self._lifecycle_lock = asyncio.Lock()
        self._worker_log_directory: Path | None = None
        self._investigations = None

    @property
    def investigations(self):
        if self._investigations is None:
            from agenticghidra_mcp.advanced.investigations import InvestigationManager

            directory = (
                self.config.investigation_directory
                or self.config.log_directory.parent / "investigations"
            )
            self._investigations = InvestigationManager(self, directory)
        return self._investigations

    async def start(self) -> None:
        """Discover Python schemas without starting any JVM."""
        from agenticghidra_mcp.advanced.registry import static_tool_catalog

        self.config.log_directory.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="supervisor-", dir=self.config.log_directory))
        self._worker_log_directory = directory
        self.workers = {
            item.worker_id: WorkerRuntime(item, self.config, directory)
            for item in self.config.workers
        }
        self.tools = static_tool_catalog()
        contract = tool_contract(self.tools)
        for worker in self.workers.values():
            worker.expected_contract = contract
        await self.investigations.load()

    async def add_workers(
        self, configs: tuple[WorkerConfig, ...], start: bool = False
    ) -> list[dict[str, Any]]:
        """Insert an isolated group atomically; optionally start only that new group."""
        if not isinstance(start, bool):
            raise ValueError("start must be a boolean")
        if not configs:
            raise ValueError("At least one worker configuration is required")
        reservations: dict[str, socket.socket] = {}
        created: dict[str, WorkerRuntime] = {}
        async with self._lifecycle_lock:
            if self._closing or self._worker_log_directory is None:
                raise RuntimeError("Supervisor is not accepting worker additions")
            try:
                checked = self._prepare_additions(configs, reservations, start=start)
                contract = tool_contract(self.tools)
                created = {
                    config.worker_id: WorkerRuntime(
                        config, self.config, self._worker_log_directory
                    )
                    for config in checked
                }
                for worker in created.values():
                    worker.expected_contract = contract
                self.workers.update(created)
                if start:
                    await self._start_additions(created, reservations)
                return [worker.status() for worker in created.values()]
            except BaseException:
                await self._rollback_additions(created)
                raise
            finally:
                for reservation in reservations.values():
                    reservation.close()

    async def _start_additions(self, created, reservations) -> None:
        for worker_id, worker in created.items():
            if self._closing:
                raise RuntimeError("Supervisor is shutting down; worker group startup cancelled")
            await worker.start(reservations[worker_id])

    async def _rollback_additions(self, created) -> None:
        # Roll back only this invocation's new processes and registrations.
        with anyio.CancelScope(shield=True):
            await asyncio.gather(*(worker.stop() for worker in created.values()))
        for worker_id, worker in created.items():
            if worker.process is None or worker.process.returncode is not None:
                self.workers.pop(worker_id, None)

    def _prepare_additions(
        self,
        configs: tuple[WorkerConfig, ...],
        reservations: dict[str, socket.socket],
        *,
        start: bool,
    ) -> list[WorkerConfig]:
        existing = [worker.config for worker in self.workers.values()]
        checked: list[WorkerConfig] = []
        identifiers = set(self.workers)
        ports = {worker.port for worker in existing}
        for item in configs:
            config = _normalized_worker_config(item)
            if config.worker_id in identifiers:
                raise ValueError(f"Duplicate worker_id: {config.worker_id}")
            if config.port in ports:
                raise ValueError(f"Duplicate worker port: {config.port}")
            for previous in existing + checked:
                _validate_storage_isolation(config, previous)
            reservations[config.worker_id] = reserve_port(WORKER_HOST, config.port)
            identifiers.add(config.worker_id)
            ports.add(config.port)
            checked.append(config)
        if start and self._active_count() + len(checked) > self.config.max_active_workers:
            raise RuntimeError(
                f"Worker group exceeds max_active_workers={self.config.max_active_workers}; "
                "no workers added"
            )
        return checked

    def _active_count(self, *, exclude: WorkerRuntime | None = None) -> int:
        return sum(
            (worker.process is not None
            and worker.process.returncode is None)
            or worker.state in {"starting", "stopping"}
            for worker in self.workers.values()
            if worker is not exclude
        )

    async def remove_workers(self, worker_ids: tuple[str, ...]) -> None:
        """Remove only stopped registrations; never deletes a project's storage."""
        async with self._lifecycle_lock:
            workers = [self.worker(worker_id) for worker_id in worker_ids]
            if any(
                (worker.process is not None
                and worker.process.returncode is None)
                or (worker._task is not None
                and not worker._task.done())
                for worker in workers
            ):
                raise RuntimeError("Cannot remove a running worker; explicitly stop it first")
            for worker in workers:
                self.workers.pop(worker.config.worker_id)

    def worker(self, worker_id: Any) -> WorkerRuntime:
        if not isinstance(worker_id, str) or worker_id not in self.workers:
            raise ValueError(f"Unknown worker_id: {worker_id!r}")
        return self.workers[worker_id]

    async def start_worker(self, worker_id: Any) -> dict[str, Any]:
        worker = self.worker(worker_id)
        async with self._lifecycle_lock:
            if self._closing:
                raise RuntimeError("Supervisor is shutting down; no request was sent")
            if (
                worker.state == "ready"
                and worker.process is not None
                and worker.process.returncode is None
            ):
                return worker.status()
            # Never evict a live project to satisfy another worker's demand.
            if self._active_count(exclude=worker) >= self.config.max_active_workers:
                raise RuntimeError(
                    f"max_active_workers={self.config.max_active_workers} reached; "
                    "explicitly worker_stop an idle worker before starting this one"
                )
            # A stale transport must be fully reaped before a replacement owns the project.
            if worker._task is not None and not worker._task.done():
                await worker.stop()
            await worker.start()
            return worker.status()

    def _scoped(self, value: Any, worker: WorkerRuntime, *, incoming: bool) -> Any:
        prefix = f"{worker.config.worker_id}:{worker.generation}:"
        if isinstance(value, list):
            return [self._scoped(item, worker, incoming=incoming) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key in {"task_id", "session_id", "transaction_id"} and isinstance(item, str):
                if incoming:
                    if not item.startswith(prefix):
                        raise ValueError(f"{key} belongs to another worker or process generation")
                    item = item[len(prefix) :]
                else:
                    item = prefix + item
                result[key] = item
            else:
                result[key] = self._scoped(item, worker, incoming=incoming)
        return result

    async def call(
        self, name: str, arguments: dict[str, Any], *, owner: object | None = None
    ) -> types.CallToolResult:
        if self._closing:
            raise RuntimeError("Supervisor is shutting down; no request was sent")
        worker = self.worker(arguments.get("worker_id"))
        forwarded = {key: value for key, value in arguments.items() if key != "worker_id"}
        # Validate existing opaque handles before demand-start changes the generation.
        forwarded = self._scoped(forwarded, worker, incoming=True)
        generation = worker.generation
        await self.start_worker(worker.config.worker_id)
        if generation != worker.generation and forwarded != {
            key: value for key, value in arguments.items() if key != "worker_id"
        }:
            raise ValueError(
                "Worker restarted; existing session/task handles are invalid; no request was sent"
            )
        dispatch_generation = worker.generation
        result = await worker.call(name, forwarded, owner=owner)
        if worker.generation != dispatch_generation:
            raise RuntimeError(
                "Worker restarted during request; outcome may be unknown and was not retried"
            )
        updates: dict[str, Any] = {}
        if result.structuredContent is not None:
            updates["structuredContent"] = self._scoped(
                result.structuredContent, worker, incoming=False
            )
        content = []
        for item in result.content:
            if isinstance(item, types.TextContent):
                try:
                    parsed = json.loads(item.text)
                except (ValueError, TypeError):
                    pass
                else:
                    item = item.model_copy(
                        update={"text": json.dumps(self._scoped(parsed, worker, incoming=False))}
                    )
            content.append(item)
        updates["content"] = content
        return result.model_copy(update=updates)

    async def stop_worker(self, worker_id: Any, *, force: bool = False) -> dict[str, Any]:
        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")
        worker = self.worker(worker_id)
        async with self._lifecycle_lock:
            busy = {"active_calls": worker.active_calls, "queued_calls": worker.queued_calls}
            if not force and not any(busy.values()) and worker.state == "ready":
                if any(tool.name == "health.ping" for tool in worker.tools):
                    response = await worker.call("health.ping", {})
                    if response.isError:
                        raise RuntimeError(
                            "Cannot establish worker quiescence; stop/restart refused"
                        )
                    health = response.structuredContent
                    if health is None:
                        health = json.loads(
                            next(
                                item.text
                                for item in response.content
                                if isinstance(item, types.TextContent)
                            )
                        )
                    for field in (
                        "active_tasks",
                        "pending_transactions",
                        "pending_imports",
                        "analysis_pending",
                        "indexing_pending",
                    ):
                        busy[field] = int(health.get(field, 0))
                    # Client-session initialization may finish while health is awaited.
                    busy.update(active_calls=worker.active_calls, queued_calls=worker.queued_calls)
            if any(busy.values()) and not force:
                raise RuntimeError(
                    f"Worker has active or queued work {busy}; stop/restart refused. "
                    "Wait for peers or explicitly force=true with unknown-outcome risk."
                )
            if force:
                worker.recent_failure = (
                    f"Explicit forced stop requested ({busy}); outcomes may be unknown; "
                    "no requests replayed"
                )
                logger.warning("Worker %s: %s", worker.config.worker_id, worker.recent_failure)
            await worker.stop()
            return worker.status()

    async def restart(self, worker_id: Any, *, force: bool = False) -> dict[str, Any]:
        await self.stop_worker(worker_id, force=force)
        return await self.start_worker(worker_id)

    async def release_owner(self, owner: object) -> None:
        await asyncio.gather(*(worker.release_owner(owner) for worker in self.workers.values()))

    async def close(self) -> None:
        # Set this before waiting for an in-progress startup to prevent queued restarts.
        self._closing = True
        for worker in self.workers.values():
            worker._stop.set()
        async with self._lifecycle_lock:
            await asyncio.gather(*(worker.stop() for worker in self.workers.values()))
