"""Owner-bound sessions and serialized access to live Ghidra databases.

Program locks precede context/index scheduling locks. Index workers acquire
the program lock before reading or publishing caches; never wait for their
futures under that lock. Java work is always drained before shutdown.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import secrets
import threading
from concurrent.futures import CancelledError, ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agenticghidra_mcp.telemetry import measure

from .core import Call


def _drain_background(future, label):
    """A failed background job must not strand project ownership at shutdown."""
    try:
        future.result()
    except CancelledError:
        pass
    except Exception:
        logging.getLogger(__name__).exception("%s failed while draining background work", label)


@dataclass
class Session:
    session_id: str
    owner: str
    project_id: str
    context: Any
    info: Any
    read_only: bool = True
    deterministic: bool = False

    def describe(self):
        return {
            "session_id": self.session_id,
            "project_id": self.project_id,
            "binary_name": str(self.info.program.getDomainFile().getPathname()),
            "name": str(self.info.program.getName()),
            "read_only": self.read_only,
            "deterministic": self.deterministic,
        }


@dataclass
class PendingTransaction:
    transaction_id: int
    session_id: str
    owner: str
    description: str


@dataclass
class Task:
    task_id: str
    owner: str
    session: Session
    monitor: Any
    status: str = "queued"
    result: Any = None
    error: str | None = None
    future: Any = None


class ProgramRegistry:
    """One project context per physical project, many capability sessions."""

    def __init__(self, context):
        self.context = context
        self.sessions: dict[str, Session] = {}
        self.contexts: dict[tuple[str, str], Any] = {}
        self.managed: list[Any] = []
        self.lock = threading.RLock()
        self.contexts[self.project_key(context)] = context

    @staticmethod
    def project_key(context):
        return (str(Path(context.project_path).expanduser().resolve()), str(context.project_name))

    @classmethod
    def project_id(cls, context):
        import hashlib

        return hashlib.sha256("\0".join(cls.project_key(context)).encode()).hexdigest()[:24]

    def add(self, context, info, owner, read_only=True, deterministic=False):
        with self.lock:
            session = Session(
                secrets.token_urlsafe(32),
                owner,
                self.project_id(context),
                context,
                info,
                bool(read_only),
                bool(deterministic),
            )
            self.sessions[session.session_id] = session
            return session

    def resolve(self, session_id, owner):
        with self.lock:
            session = self.sessions.get(session_id)
            if session is None or session.owner != owner:
                raise ValueError("Unknown session or session belongs to another MCP client")
            return session

    def project_context(self, location=None, name=None, *, existing=False):
        location = str(Path(location or self.context.project_path).expanduser().resolve())
        name = str(name or self.context.project_name)
        key = (location, name)
        with self.lock:
            if key in self.contexts:
                return self.contexts[key]
            if existing and not (Path(location) / (name + ".gpr")).exists():
                raise FileNotFoundError(f"Ghidra project not found: {location}/{name}.gpr")
            from agenticghidra_mcp.context import PyGhidraContext

            try:
                context = PyGhidraContext(
                    name,
                    location,
                    agenticghidra_mcp_dir=Path(location) / (name + ".advanced-mcp"),
                    threaded=True,
                    max_workers=1,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Cannot open Ghidra project {location}/{name}; "
                    f"it may already be locked by another worker: {exc}"
                ) from exc
            self.contexts[key] = context
            self.managed.append(context)
            return context


class AdvancedRuntime:
    def __init__(self, context):
        self.context = context
        self.registry = ProgramRegistry(context)
        self._state_lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._locks: dict[int, threading.RLock] = {}
        self._project_lock = threading.RLock()
        self._consumers: dict[int, tuple[Any, Any, Any]] = {}
        self._transactions: dict[int, PendingTransaction] = {}
        self._tasks: dict[str, Task] = {}
        self._max_pending_tasks = int(os.environ.get("AGENTICGHIDRA_MCP_MAX_PENDING_TASKS", "32"))
        if self._max_pending_tasks < 1:
            raise ValueError("AGENTICGHIDRA_MCP_MAX_PENDING_TASKS must be positive")
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="advanced-task")
        self._closing = False
        self._closed = False
        self._active = 0
        self._owner_active: dict[str, int] = {}
        self._closed_owners: set[str] = set()
        self._idle = threading.Condition(self._state_lock)
        self._attached: set[int] = set()
        self._attach_indexing(context)

    @staticmethod
    def monitor():
        from ghidra.util.task import TaskMonitorAdapter

        return TaskMonitorAdapter(True)

    def program_lock(self, program):
        with self._state_lock:
            return self._locks.setdefault(id(program), threading.RLock())

    def own_program(self, context, program, consumer):
        self._consumers[id(program)] = (context, program, consumer)

    def adopt_program(self, context, program):
        """Remove GhidraProject's implicit batch transaction, retaining the DB."""
        project = getattr(context, "project", None)
        if id(program) in self._consumers or not hasattr(project, "openProgram"):
            return
        from java.lang import Object

        consumer = Object()
        if not program.addConsumer(consumer):
            raise RuntimeError("Cannot acquire a closed program")
        try:
            project.close(program)
        except BaseException:
            program.release(consumer)
            raise
        self.own_program(context, program, consumer)

    def return_program(self, program):
        owned = self._consumers.get(id(program))
        if owned is None:
            return
        context, program, consumer = owned
        if hasattr(context.project, "openProgram"):
            domain = program.getDomainFile()
            context.project.openProgram(
                str(domain.getParent().getPathname()), str(domain.getName()), False
            )
        program.release(consumer)
        del self._consumers[id(program)]

    def _attach_index_worker(self, context):
        original = getattr(context, "_index_program", None)
        if original is None:
            return

        def locked_index(info, **kwargs):
            with self.program_lock(info.program):
                if hasattr(info.program, "isClosed") and info.program.isClosed():
                    return
                if id(info.program) in self._transactions:
                    return
                return original(info, **kwargs)

        context._index_program = locked_index

    def _legacy_analysis_info(self, context, domain):
        path = str(domain.getPathname())
        with self._project_lock:
            info = context._lookup_program_info(path)
            if info is None:
                program = context.project.openProgram(
                    str(domain.getParent().getPathname()), str(domain.getName()), False
                )
                info = context._init_program_info(program)
                context.programs[path] = info
            return info

    def _legacy_analysis(self, context, original, value, *args, **kwargs):
        domain = value.getDomainFile() if hasattr(value, "getDomainFile") else value
        info = self._legacy_analysis_info(context, domain)
        session = Session(
            "legacy-analysis",
            "legacy-analysis",
            self.registry.project_id(context),
            context,
            info,
            False,
        )
        with self.program_lock(info.program):
            self.guard(session, session.owner, no_pending=True)
            self.adopt_program(context, info.program)
            # The existing context analyzer saves through GhidraProject, which
            # requires its own consumer and implicit transaction while it runs.
            context.project.openProgram(
                str(domain.getParent().getPathname()), str(domain.getName()), False
            )
            try:
                return original(value, *args, **kwargs)
            finally:
                context.project.close(info.program)
                self.invalidate(session)

    def _attach_legacy_analysis(self, context):
        original = getattr(context, "analyze_program", None)
        if original is None:
            return

        def locked_analysis(value, *args, **kwargs):
            return self._legacy_analysis(context, original, value, *args, **kwargs)

        context.analyze_program = locked_analysis

    def _attach_indexing(self, context):
        if id(context) in self._attached:
            return
        # Jobs submitted before runtime installation do not yet share our lock.
        startup = getattr(context, "_analysis_future", None)
        if startup is not None:
            _drain_background(startup, "Startup analysis")
        work_lock = getattr(context, "_work_lock", threading.RLock())
        with work_lock:
            futures = list(getattr(context, "_index_futures", {}).values())
            self._attach_index_worker(context)
            self._attach_legacy_analysis(context)
            self._attached.add(id(context))
        for future in futures:
            _drain_background(future, "Pre-runtime indexing")
        for info in list(context.programs.values()):
            with self.program_lock(info.program):
                self.adopt_program(context, info.program)

    def ensure_open(self):
        if self._closing:
            raise RuntimeError("Advanced runtime is closing")

    def busy_status(self):
        with self._state_lock:
            active_tasks = sum(
                task.future is None or not task.future.done() for task in self._tasks.values()
            )
            pending_transactions = len(self._transactions)
        pending_imports = analysis_pending = indexing_pending = 0
        for context in list(self.registry.contexts.values()):
            pending_imports += int(getattr(context, "_pending_imports", 0))
            futures = set(getattr(context, "_analysis_futures", ()))
            coordinator = getattr(context, "_analysis_future", None)
            if coordinator is not None:
                futures.add(coordinator)
            analysis_pending += sum(not future.done() for future in futures)
            indexing_pending += sum(
                not future.done()
                for future in list(getattr(context, "_index_futures", {}).values())
            )
        return {
            "active_tasks": active_tasks,
            "pending_transactions": pending_transactions,
            "pending_imports": pending_imports,
            "analysis_pending": analysis_pending,
            "indexing_pending": indexing_pending,
        }

    def guard(self, session, owner, *, write=False, no_pending=False):
        pending = self._transactions.get(id(session.info.program))
        if pending and (pending.owner != owner or pending.session_id != session.session_id):
            raise RuntimeError("Program has an explicit transaction owned by another session")
        if no_pending and pending:
            raise RuntimeError("Commit or revert the pending transaction first")
        if write and session.read_only:
            raise PermissionError("Program session is read-only; use program.mode.set first")

    def invalidate(self, session, *, rebuild=True):
        """Called with the program lock, excluding all attached index writers."""
        info, context = session.info, session.context
        pool = getattr(info, "decompiler_pool", None)
        if pool is not None:
            pool.invalidate_all()
        collection = getattr(info, "code_collection", None)
        info.code_collection = None
        info.strings = None
        if hasattr(info.program, "getMetadata"):
            info.metadata = dict(info.program.getMetadata())
        client = getattr(context, "chroma_client", None)
        if client is not None:
            name = (
                str(collection.name)
                if collection is not None
                else context._normalize_collection_name(info.name)
            )
            # Collection lookup distinguishes absence from a real storage failure.
            names = {str(getattr(item, "name", item)) for item in client.list_collections()}
            if name in names:
                client.delete_collection(name=name)
        if rebuild and id(info.program) not in self._transactions:
            context.schedule_indexing(str(info.program.getDomainFile().getPathname()))

    def _rollback_mutation(self, session, pending, transaction, modification):
        program = session.info.program
        if transaction is not None:
            program.endTransaction(transaction, False)
            self.invalidate(session)
            return False
        if pending is not None and program.getModificationNumber() != modification:
            # Ghidra nested transactions cannot independently roll back one edit.
            program.endTransaction(pending.transaction_id, False)
            self._transactions.pop(id(program), None)
            self.invalidate(session)
            return True
        return False

    @contextmanager
    def mutation(self, session, owner, description):
        self.guard(session, owner, write=True)
        program = session.info.program
        pending = self._transactions.get(id(program))
        analysis_complete = session.info.ghidra_analysis_complete
        modification = program.getModificationNumber() if pending is not None else None
        transaction = None if pending else program.startTransaction(description)
        try:
            yield
            self.invalidate(session, rebuild=False)
        except BaseException as exc:
            session.info.ghidra_analysis_complete = analysis_complete
            reverted = self._rollback_mutation(session, pending, transaction, modification)
            if reverted:
                raise RuntimeError(
                    f"{description} failed; the explicit transaction was reverted: {exc}"
                ) from exc
            raise
        else:
            if transaction is not None:
                program.endTransaction(transaction, True)
                session.context.schedule_indexing(str(program.getDomainFile().getPathname()))

    def invoke(self, definition, arguments, owner):
        with self._state_lock:
            self.ensure_open()
            if owner in self._closed_owners:
                raise RuntimeError("MCP client connection is closed")
            self._owner_active[owner] = self._owner_active.get(owner, 0) + 1
            self._active += 1
        try:
            with measure("mcp_request"):
                return self._invoke(definition, arguments, owner)
        finally:
            with self._idle:
                self._active -= 1
                self._owner_active[owner] -= 1
                self._idle.notify_all()

    def _invoke(self, definition, arguments, owner):
        arguments = dict(arguments)
        if definition.name == "program.open" and "binary_name" in arguments:
            binary_name = arguments.pop("binary_name")
            if "path" in arguments and arguments["path"] != binary_name:
                raise ValueError("Specify path or binary_name, not conflicting values")
            arguments.setdefault("path", binary_name)
        session_id = arguments.pop("session_id", None)
        session = self.registry.resolve(session_id, owner) if definition.program else None
        context = session.context if session else self.context
        call = Call(self, context, owner, session, self.monitor())
        bound = inspect.signature(definition.handler).bind(call, **arguments)
        bound.apply_defaults()
        if session is None:
            if definition.name in {
                "program.open",
                "program.open_bytes",
                "project.program.open_existing",
            }:
                with self._project_lock:
                    return definition.handler(*bound.args, **bound.kwargs)
            return definition.handler(*bound.args, **bound.kwargs)
        if definition.name == "analysis.status":
            self.guard(session, owner)
            return definition.handler(*bound.args, **bound.kwargs)
        if definition.name in {"project.export", "project.program.open"}:
            with self.program_lock(session.info.program):
                self.guard(session, owner)
            return definition.handler(*bound.args, **bound.kwargs)
        with self.locked(session.info.program):
            self.ensure_open()
            self.registry.resolve(session.session_id, owner)
            self.adopt_program(context, session.info.program)
            self.guard(session, owner)
            if definition.analysis and not session.info.analysis_complete:
                raise RuntimeError("Program analysis is incomplete")
            write = definition.kind == "write" or (
                definition.kind == "script" and bool(arguments.get("write", False))
            )
            if write:
                if definition.name == "analysis.update_and_wait":
                    self.guard(session, owner, write=True, no_pending=True)
                with self.mutation(session, owner, definition.name):
                    return definition.handler(*bound.args, **bound.kwargs)
            return definition.handler(*bound.args, **bound.kwargs)

    @contextmanager
    def locked(self, program):
        lock = self.program_lock(program)
        with measure("program_lock_wait"):
            lock.acquire()
        try:
            yield
        finally:
            lock.release()

    def begin(self, session, owner, description):
        self.guard(session, owner, write=True, no_pending=True)
        tx = session.info.program.startTransaction(description)
        self._transactions[id(session.info.program)] = PendingTransaction(
            tx, session.session_id, owner, description
        )
        return self.transaction_status(session)

    def finish(self, session, owner, commit):
        self.guard(session, owner, write=True)
        pending = self._transactions.get(id(session.info.program))
        if pending is None:
            raise ValueError("No explicit transaction is pending")
        session.info.program.endTransaction(pending.transaction_id, commit)
        del self._transactions[id(session.info.program)]
        self.invalidate(session)
        return {"committed": commit, "reverted": not commit, **self.transaction_status(session)}

    def transaction_status(self, session):
        program = session.info.program
        pending = self._transactions.get(id(program))
        return {
            "pending": pending is not None,
            "description": pending.description if pending else None,
            "can_undo": bool(program.canUndo()),
            "can_redo": bool(program.canRedo()),
        }

    def submit_analysis(self, session, owner):
        self.guard(session, owner, write=True, no_pending=True)
        with self._state_lock:
            self.ensure_open()
            if owner in self._closed_owners:
                raise RuntimeError("MCP client connection is closed")
            if (
                sum(task.future is None or not task.future.done() for task in self._tasks.values())
                >= self._max_pending_tasks
            ):
                raise RuntimeError(
                    f"Advanced task queue is full ({self._max_pending_tasks} pending tasks)"
                )
            task = Task(secrets.token_urlsafe(32), owner, session, self.monitor())
            self._tasks[task.task_id] = task

            def run():
                with self.program_lock(session.info.program):
                    with self._state_lock:
                        if task.monitor.isCancelled():
                            task.status = "cancelled"
                            return
                        task.status = "running"
                    try:
                        self.guard(session, owner, write=True, no_pending=True)
                        with self.mutation(session, owner, "MCP analysis update"):
                            result = self.analyze(session, task.monitor)
                        with self._state_lock:
                            task.result = result
                            task.status = "succeeded"
                    except BaseException as exc:
                        with self._state_lock:
                            task.error = str(exc)
                            task.status = "cancelled" if task.monitor.isCancelled() else "failed"

            task.future = self._executor.submit(run)
            return self.task_status(task.task_id, owner)

    def analyze(self, session, monitor):
        lock = getattr(session.context, "_analysis_bundle_host_lock", _ANALYSIS_LOCK)
        from ghidra.app.script import GhidraScriptUtil

        with lock, measure("analyze"):
            GhidraScriptUtil.acquireBundleHostReference()
            try:
                return self._analyze(session, monitor)
            finally:
                GhidraScriptUtil.releaseBundleHostReference()

    def _analyze(self, session, monitor):
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities

        manager = AutoAnalysisManager.getAnalysisManager(session.info.program)
        if manager.isAnalyzing():
            raise RuntimeError("Program is already being analyzed outside this runtime")
        manager.initializeOptions()
        session.info.ghidra_analysis_complete = False
        manager.reAnalyzeAll(None)
        manager.startAnalysis(monitor)
        monitor.checkCancelled()
        GhidraProgramUtilities.markProgramAnalyzed(session.info.program)
        session.info.ghidra_analysis_complete = True
        return {"analysis_complete": True}

    def _task(self, task_id, owner):
        task = self._tasks.get(task_id)
        if task is None or task.owner != owner:
            raise ValueError("Unknown task or task belongs to another MCP client")
        return task

    @staticmethod
    def _task_state(task):
        # Terminal state is observable only after the Python/Java worker returns.
        if (
            task.future is not None
            and not task.future.done()
            and task.status in {"succeeded", "failed", "cancelled"}
        ):
            return "cancelling" if task.monitor.isCancelled() else "running"
        return task.status

    def task_status(self, task_id, owner):
        with self._state_lock:
            task = self._task(task_id, owner)
            return {
                "task_id": task_id,
                "status": self._task_state(task),
                "session_id": task.session.session_id,
                "error": task.error,
                "progress": int(task.monitor.getProgress()),
                "maximum": int(task.monitor.getMaximum()),
                "message": str(task.monitor.getMessage() or ""),
            }

    def task_result(self, task_id, owner):
        with self._state_lock:
            task = self._task(task_id, owner)
            state = self._task_state(task)
            if state not in {"succeeded", "failed", "cancelled"}:
                raise RuntimeError(f"Task is {state}; result is not ready")
            return {**self.task_status(task_id, owner), "result": task.result}

    def cancel_task(self, task_id, owner):
        with self._state_lock:
            task = self._task(task_id, owner)
            if task.status not in {"succeeded", "failed", "cancelled"}:
                task.monitor.cancel()
                if task.future.cancel():
                    task.status = "cancelled"
                else:
                    task.status = "cancelling"
            return self.task_status(task_id, owner)

    def legacy_call(self, function, arguments, owner):
        with self._state_lock:
            self.ensure_open()
            if owner in self._closed_owners:
                raise RuntimeError("MCP client connection is closed")
            self._owner_active[owner] = self._owner_active.get(owner, 0) + 1
            self._active += 1
        try:
            return self._legacy_call(function, arguments, owner)
        finally:
            with self._idle:
                self._active -= 1
                self._owner_active[owner] -= 1
                self._idle.notify_all()

    def _legacy_call(self, function, arguments, owner):
        arguments = dict(arguments)
        name = function.__name__
        binary_name = arguments.get("binary_name")
        writes = {
            "rename_function",
            "rename_variable",
            "set_variable_type",
            "set_function_prototype",
            "set_comment",
            "apply_data_type",
            "create_label",
            "rename_symbol",
            "patch_bytes",
        }

        def execute():
            result = function(**arguments)
            return asyncio.run(result) if inspect.isawaitable(result) else result

        if binary_name is None:
            # Project-wide save and mutations must not bypass pending batches.
            sessions = [
                Session(
                    "legacy:" + owner,
                    owner,
                    self.registry.project_id(self.context),
                    self.context,
                    info,
                    False,
                )
                for info in list(self.context.programs.values())
            ]
            from contextlib import ExitStack

            with ExitStack() as stack:
                for session in sorted(sessions, key=lambda s: id(s.info.program)):
                    stack.enter_context(self.program_lock(session.info.program))
                    self.guard(session, owner, no_pending=True)
                return execute()
        info = self.context._lookup_program_info(binary_name)
        if info is None:
            raise ValueError(f"Unknown binary: {binary_name}")
        session = Session(
            "legacy:" + owner,
            owner,
            self.registry.project_id(self.context),
            self.context,
            info,
            False,
        )
        with self.program_lock(info.program):
            self.guard(session, owner)
            self.adopt_program(self.context, info.program)
            if name == "delete_project_binary":
                self.guard(session, owner, no_pending=True)
                self.invalidate(session, rebuild=False)
                self.return_program(info.program)
                result = execute()
                for key, registered in list(self.registry.sessions.items()):
                    if registered.info.program is info.program:
                        self.registry.sessions.pop(key, None)
                return result
            if name in writes:
                with self.mutation(session, owner, "Legacy " + name):
                    return execute()
            return execute()

    def close_owner(self, owner):
        """Drain one disconnected MCP connection without closing shared programs."""
        with self._close_lock:
            if self._closed:
                return
            with self._idle:
                self._closed_owners.add(owner)
                tasks = [task for task in self._tasks.values() if task.owner == owner]
            for task in tasks:
                self.cancel_task(task.task_id, owner)
            with self._idle:
                while self._owner_active.get(owner, 0):
                    self._idle.wait()
            for task in tasks:
                if not task.future.cancelled():
                    task.future.result()
            sessions = [
                session
                for session in list(self.registry.sessions.values())
                if session.owner == owner
            ]
            for session in sessions:
                with self.program_lock(session.info.program):
                    pending = self._transactions.get(id(session.info.program))
                    if pending is not None and pending.owner == owner:
                        session.info.program.endTransaction(pending.transaction_id, False)
                        del self._transactions[id(session.info.program)]
                        self.invalidate(session)
                    self.registry.sessions.pop(session.session_id, None)
            with self._state_lock:
                self._owner_active.pop(owner, None)
                for task in tasks:
                    self._tasks.pop(task.task_id, None)

    def close(self):
        with self._close_lock:
            return self._close()

    def _stop_context_work(self):
        for context in list(self.registry.contexts.values()):
            shutdown = getattr(context, "shutdown_executor", None)
            if shutdown is not None:
                for name in ("import_executor", "analysis_coordinator", "executor"):
                    shutdown(name, getattr(context, name, None))

    def _revert_transactions(self):
        for session in list(self.registry.sessions.values()):
            with self.program_lock(session.info.program):
                pending = self._transactions.pop(id(session.info.program), None)
                if pending:
                    session.info.program.endTransaction(pending.transaction_id, False)
                    self.invalidate(session, rebuild=False)

    def _drain_indexing(self):
        # Submitters are stopped and transactions reverted. Drain index workers
        # outside all program locks before transferring program ownership.
        for context in list(self.registry.contexts.values()):
            shutdown = getattr(context, "shutdown_executor", None)
            if shutdown is not None:
                shutdown("indexing", getattr(context, "index_executor", None))
            for future in list(getattr(context, "_index_futures", {}).values()):
                _drain_background(future, "Indexing")

    def _close(self):
        with self._state_lock:
            if self._closed:
                return
            self._closing = True
            for task in self._tasks.values():
                if task.status in {"queued", "running", "cancelling"}:
                    task.monitor.cancel()
            while self._active:
                self._idle.wait()
        self._executor.shutdown(wait=True, cancel_futures=True)
        for task in self._tasks.values():
            if task.future.cancelled():
                task.status = "cancelled"
        self._stop_context_work()
        self._revert_transactions()
        self._drain_indexing()
        for _, program, _ in list(self._consumers.values()):
            self.return_program(program)
        for context in reversed(self.registry.managed):
            context.close()
        self.registry.sessions.clear()
        with self._state_lock:
            self._closed = True


_RUNTIME_LOCK = threading.RLock()
_ANALYSIS_LOCK = threading.RLock()


def get_runtime(context):
    with _RUNTIME_LOCK:
        runtime = getattr(context, "_advanced_runtime", None)
        if runtime is None:
            runtime = AdvancedRuntime(context)
            context._advanced_runtime = runtime
        return runtime
