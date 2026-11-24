"""Consumer-visible ownership, rollback, cancellation, and shutdown boundaries."""

import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from agenticghidra_mcp.advanced.core import operation
from agenticghidra_mcp.advanced.runtime import AdvancedRuntime


class Monitor:
    def __init__(self):
        self.cancelled = threading.Event()

    def cancel(self):
        self.cancelled.set()

    def isCancelled(self):
        return self.cancelled.is_set()

    def checkCancelled(self):
        if self.isCancelled():
            raise RuntimeError("Cancelled")

    def getProgress(self):
        return 0

    def getMaximum(self):
        return 0

    def getMessage(self):
        return ""


class Database:
    """Small transactional state model, independent of Java/tool handler output."""

    def __init__(self):
        self.values = {}
        self.pending = {}
        self.history = []
        self.redo_history = []
        self.next_id = 0
        self._observed = {}
        self._modification_number = 0

    def getModificationNumber(self):
        if self.values != self._observed:
            self._modification_number += 1
            self._observed = deepcopy(self.values)
        return self._modification_number

    def startTransaction(self, description):
        self.next_id += 1
        self.pending[self.next_id] = deepcopy(self.values)
        return self.next_id

    def endTransaction(self, transaction, commit):
        before = self.pending.pop(transaction)
        if commit:
            self.history.append(before)
            self.redo_history.clear()
        else:
            self.values = before

    def canUndo(self):
        return bool(self.history)

    def canRedo(self):
        return bool(self.redo_history)

    def getDomainFile(self):
        return SimpleNamespace(getPathname=lambda: "/fixture")

    def getName(self):
        return "fixture"


class Runtime(AdvancedRuntime):
    @staticmethod
    def monitor():
        return Monitor()


@pytest.fixture
def context(tmp_path):
    database = Database()
    info = SimpleNamespace(
        program=database,
        name="fixture",
        flat_api=None,
        decompiler_pool=None,
        code_collection=None,
        strings=None,
        ghidra_analysis_complete=True,
        analysis_complete=True,
    )
    return SimpleNamespace(
        project_path=Path(tmp_path),
        project_name="project",
        programs={"/fixture": info},
        schedule_indexing=lambda name: None,
        _lookup_program_info=lambda name: info if name == "/fixture" else None,
    )


@pytest.fixture
def runtime(context):
    instance = Runtime(context)
    yield instance
    instance.close()


@operation("test.write", kind="write", api="test state model")
def write(call, value=9, fail=False):
    call.program.values["value"] = value
    if fail:
        raise ValueError("Failure after mutation")
    return value


@operation("test.read", api="test state model")
def read(call):
    return dict(call.program.values)


def session(runtime, owner="alice", read_only=False):
    return runtime.registry.add(
        runtime.context, runtime.context.programs["/fixture"], owner, read_only
    )


def invoke(runtime, handler, registered, owner="alice", **kwargs):
    return runtime.invoke(
        handler.__operation__, {"session_id": registered.session_id, **kwargs}, owner
    )


def test_session_capability_is_owner_bound_and_random(runtime):
    first, second = session(runtime), session(runtime)
    assert first.session_id != second.session_id
    assert len(first.session_id) >= 32
    assert first.project_id == second.project_id
    with pytest.raises(ValueError, match="another MCP client"):
        invoke(runtime, read, first, "bob")
    with pytest.raises(ValueError, match="Unknown session"):
        runtime.invoke(read.__operation__, {"session_id": "missing"}, "alice")


def test_read_only_rejects_mutation_before_database_transaction(runtime):
    registered = session(runtime, read_only=True)
    with pytest.raises(PermissionError, match="read-only"):
        invoke(runtime, write, registered)
    assert registered.info.program.values == {}
    assert registered.info.program.next_id == 0


def test_automatic_failure_rolls_back_and_defaults_are_applied(runtime):
    registered = session(runtime)
    assert invoke(runtime, write, registered) == 9
    with pytest.raises(ValueError, match="after mutation"):
        invoke(runtime, write, registered, value=12, fail=True)
    assert invoke(runtime, read, registered) == {"value": 9}
    assert not registered.info.program.pending


def test_explicit_transaction_locks_program_not_only_session(runtime):
    first, second = session(runtime), session(runtime)
    third = session(runtime, "bob")
    with runtime.program_lock(first.info.program):
        runtime.begin(first, "alice", "batch")
    invoke(runtime, write, first, value=7)
    for other, owner in ((second, "alice"), (third, "bob")):
        with pytest.raises(RuntimeError, match="another session"):
            invoke(runtime, read, other, owner)
    with pytest.raises(RuntimeError, match="Commit or revert"):
        runtime.guard(first, "alice", no_pending=True)
    runtime.finish(first, "alice", False)
    assert invoke(runtime, read, second) == {}


def test_failed_mutation_reverts_explicit_batch(runtime):
    registered = session(runtime)
    runtime.begin(registered, "alice", "batch")
    invoke(runtime, write, registered, value=1)
    with pytest.raises(RuntimeError, match="explicit transaction was reverted"):
        invoke(runtime, write, registered, value=2, fail=True)
    assert registered.info.program.values == {}
    assert not runtime.transaction_status(registered)["pending"]


def test_validation_failure_preserves_existing_explicit_batch(runtime):
    registered = session(runtime)
    runtime.begin(registered, "alice", "batch")
    invoke(runtime, write, registered, value=1)

    @operation("test.validate", kind="write", api="test state model")
    def validate(call):
        raise ValueError("Invalid edit before touching the program")

    with pytest.raises(ValueError, match="Invalid edit"):
        invoke(runtime, validate, registered)
    assert runtime.transaction_status(registered)["pending"]
    assert invoke(runtime, read, registered) == {"value": 1}
    runtime.finish(registered, "alice", True)
    assert invoke(runtime, read, registered) == {"value": 1}


def test_cancel_is_cooperative_and_result_private_until_worker_stops(runtime):
    registered = session(runtime)
    entered, release = threading.Event(), threading.Event()

    def analyze(current, monitor):
        current.info.program.values["partial"] = True
        entered.set()
        release.wait(5)
        monitor.checkCancelled()
        return {"finished": True}

    runtime.analyze = analyze
    task = runtime.submit_analysis(registered, "alice")
    assert entered.wait(2)
    with pytest.raises(ValueError, match="another MCP client"):
        runtime.task_status(task["task_id"], "bob")
    assert runtime.cancel_task(task["task_id"], "alice")["status"] == "cancelling"
    with pytest.raises(RuntimeError, match="not ready"):
        runtime.task_result(task["task_id"], "alice")
    release.set()
    runtime._tasks[task["task_id"]].future.result(timeout=2)
    result = runtime.task_result(task["task_id"], "alice")
    assert result["status"] == "cancelled"
    assert result["result"] is None
    assert registered.info.program.values == {}


def test_async_legacy_call_remains_inside_database_lock(runtime):
    registered = session(runtime)

    async def set_variable_type(binary_name):
        registered.info.program.values["legacy"] = True
        raise ValueError("legacy failure")

    with pytest.raises(ValueError, match="legacy failure"):
        runtime.legacy_call(set_variable_type, {"binary_name": "/fixture"}, "alice")
    assert registered.info.program.values == {}


def test_close_waits_for_running_java_equivalent_and_reverts_batches(runtime):
    registered = session(runtime)
    runtime.begin(registered, "alice", "pending")
    invoke(runtime, write, registered, value=3)
    runtime.close()
    assert registered.info.program.values == {}
    with pytest.raises(RuntimeError, match="closing"):
        invoke(runtime, read, registered)
    runtime.close()


def test_program_operations_serialize_without_blocking_other_programs(runtime):
    registered = session(runtime)
    other_info = SimpleNamespace(**{**vars(registered.info), "program": Database()})
    other = runtime.registry.add(runtime.context, other_info, "alice", False)
    entered, release, observed = threading.Event(), threading.Event(), threading.Event()

    @operation("test.block", api="test synchronization")
    def block(call):
        entered.set()
        release.wait(5)

    @operation("test.observe", api="test synchronization")
    def observe(call):
        observed.set()

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(invoke, runtime, block, registered)
        assert entered.wait(2)
        assert invoke(runtime, read, other) == {}
        second = workers.submit(invoke, runtime, observe, registered)
        assert not observed.wait(0.05)
        release.set()
        first.result(timeout=2)
        second.result(timeout=2)
    assert observed.is_set()


@pytest.mark.parametrize(
    "name, arguments",
    [
        ("program.save", {}),
        ("program.close", {}),
        ("program.mode.set", {"read_only": True}),
        ("transaction.undo", {}),
        ("transaction.redo", {}),
        ("analysis.update_and_wait", {}),
    ],
)
def test_pending_transaction_rejects_lifecycle_changes_without_losing_batch(
    runtime, name, arguments
):
    from agenticghidra_mcp.advanced import lifecycle

    registered = session(runtime)
    runtime.begin(registered, "alice", "pending")
    invoke(runtime, write, registered, value=4)
    definitions = {
        item.__operation__.name: item.__operation__
        for item in vars(lifecycle).values()
        if hasattr(item, "__operation__")
    }
    with pytest.raises(RuntimeError, match="Commit or revert"):
        runtime.invoke(
            definitions[name], {"session_id": registered.session_id, **arguments}, "alice"
        )
    assert runtime.transaction_status(registered)["pending"]
    assert registered.info.program.values == {"value": 4}
    runtime.finish(registered, "alice", False)


def test_writes_remove_persisted_semantic_collection_and_flush_decompiler(runtime):
    registered = session(runtime)
    storage = {"fixture": ["old semantic document"]}
    flushed = []
    registered.info.decompiler_pool = SimpleNamespace(invalidate_all=lambda: flushed.append(True))
    registered.info.code_collection = SimpleNamespace(name="fixture")
    registered.info.strings = ["old string"]
    runtime.context.chroma_client = SimpleNamespace(
        list_collections=lambda: list(storage), delete_collection=lambda name: storage.pop(name)
    )
    runtime.context._normalize_collection_name = lambda name: name
    invoke(runtime, write, registered, value=5)
    assert flushed == [True]
    assert storage == {}
    assert registered.info.code_collection is None
    assert registered.info.strings is None


def test_shutdown_waits_for_inflight_request(runtime):
    registered = session(runtime)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()

    @operation("test.active", api="test synchronization")
    def active(call):
        entered.set()
        release.wait(5)
        return "completed"

    def close():
        runtime.close()
        closed.set()

    with ThreadPoolExecutor(max_workers=2) as workers:
        request = workers.submit(invoke, runtime, active, registered)
        assert entered.wait(2)
        shutdown = workers.submit(close)
        assert not closed.wait(0.05)
        release.set()
        assert request.result(timeout=2) == "completed"
        shutdown.result(timeout=2)
    assert closed.is_set()


def test_disconnect_rolls_back_only_owners_transaction_and_revokes_capability(runtime):
    alice = session(runtime)
    bob = session(runtime, "bob")
    runtime.begin(alice, "alice", "disconnect")
    invoke(runtime, write, alice, value=17)
    assert runtime.busy_status()["pending_transactions"] == 1
    runtime.close_owner("alice")
    assert invoke(runtime, read, bob, "bob") == {}
    assert runtime.busy_status()["pending_transactions"] == 0
    with pytest.raises(RuntimeError, match="connection is closed"):
        invoke(runtime, read, alice)
    with pytest.raises(ValueError, match="Unknown session"):
        runtime.registry.resolve(alice.session_id, "alice")


def test_task_failure_exposes_actual_error_without_committing_partial_state(runtime):
    registered = session(runtime)

    def analyze(current, monitor):
        current.info.program.values["partial"] = 1
        raise ValueError("Analyzer failure detail")

    runtime.analyze = analyze
    task = runtime.submit_analysis(registered, "alice")
    runtime._tasks[task["task_id"]].future.result(timeout=2)
    result = runtime.task_result(task["task_id"], "alice")
    assert result["status"] == "failed"
    assert "Analyzer failure detail" in result["error"]
    assert result["result"] is None
    assert registered.info.program.values == {}
    with pytest.raises(ValueError, match="another MCP client"):
        runtime.task_result(task["task_id"], "bob")


def test_analysis_backpressure_rejects_before_allocating_another_task(runtime):
    registered = session(runtime)
    runtime._max_pending_tasks = 1
    entered, release = threading.Event(), threading.Event()

    def analyze(current, monitor):
        entered.set()
        release.wait(5)
        current.info.program.values["finished"] = True
        return {"analysis_complete": True}

    runtime.analyze = analyze
    first = runtime.submit_analysis(registered, "alice")
    assert entered.wait(2)
    try:
        with pytest.raises(RuntimeError, match="queue is full"):
            runtime.submit_analysis(registered, "alice")
        assert len(runtime._tasks) == 1
    finally:
        release.set()
    runtime._tasks[first["task_id"]].future.result(timeout=2)
    assert registered.info.program.values == {"finished": True}


def test_queued_cancellation_never_runs_the_database_worker(runtime):
    registered = session(runtime)
    runtime._executor.shutdown()
    runtime._executor = ThreadPoolExecutor(max_workers=1)
    entered, release = threading.Event(), threading.Event()

    def analyze(current, monitor):
        entered.set()
        release.wait(5)
        current.info.program.values["executions"] = (
            current.info.program.values.get("executions", 0) + 1
        )
        return {"analysis_complete": True}

    runtime.analyze = analyze
    first = runtime.submit_analysis(registered, "alice")
    assert entered.wait(2)
    second = runtime.submit_analysis(registered, "alice")
    try:
        assert second["status"] == "queued"
        assert runtime.cancel_task(second["task_id"], "alice")["status"] == "cancelled"
        assert runtime.task_result(second["task_id"], "alice")["result"] is None
    finally:
        release.set()
    runtime._tasks[first["task_id"]].future.result(timeout=2)
    assert registered.info.program.values == {"executions": 1}


def test_failed_index_job_does_not_strand_managed_project_shutdown(runtime, caplog):
    from concurrent.futures import Future

    failed = Future()
    failed.set_exception(ValueError("index storage failure"))
    runtime.context._index_futures = {"/fixture": failed}
    closed = []
    runtime.registry.managed.append(SimpleNamespace(close=lambda: closed.append(True)))
    runtime.close()
    assert closed == [True]
    assert "index storage failure" in caplog.text


def test_shutdown_drains_index_worker_before_releasing_program(context):
    entered, release, handed_back = threading.Event(), threading.Event(), threading.Event()
    info = context.programs["/fixture"]
    info.program.release = lambda consumer: handed_back.set()
    context.project = SimpleNamespace()
    context._index_program = lambda current: (entered.set(), release.wait(5))
    context.index_executor = ThreadPoolExecutor(max_workers=1)
    context.shutdown_executor = lambda label, executor: (
        executor.shutdown(wait=True, cancel_futures=True) if executor is not None else None
    )
    runtime = Runtime(context)
    runtime.own_program(context, info.program, object())
    future = context.index_executor.submit(context._index_program, info)
    context._index_futures = {"/fixture": future}
    assert entered.wait(2)
    try:
        with ThreadPoolExecutor(max_workers=1) as workers:
            shutdown = workers.submit(runtime.close)
            assert not handed_back.wait(0.05)
            release.set()
            shutdown.result(timeout=2)
        assert handed_back.is_set()
        future.result(timeout=2)
        with pytest.raises(RuntimeError, match="cannot schedule new futures"):
            context.index_executor.submit(lambda: None)
    finally:
        release.set()
        runtime.close()


def test_eager_analysis_releases_project_batch_before_public_edits(context, monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "java.lang", SimpleNamespace(Object=object))
    program = context.programs["/fixture"].program
    domain = SimpleNamespace(
        getPathname=lambda: "/fixture",
        getParent=lambda: SimpleNamespace(getPathname=lambda: "/"),
        getName=lambda: "fixture",
    )
    program.getDomainFile = lambda: domain
    consumers = set()
    program.addConsumer = lambda consumer: not consumers.add(consumer)
    program.release = consumers.remove

    class Project:
        batch = None

        def openProgram(self, folder, name, read_only):
            if self.batch is None:
                self.batch = program.startTransaction("project batch")
            return program

        def close(self, current):
            program.endTransaction(self.batch, True)
            self.batch = None

    context.project = Project()
    context.project.openProgram("/", "fixture", False)

    def analyze(value):
        assert context.project.batch is not None
        program.values["analyzed"] = True

    context.analyze_program = analyze
    runtime = Runtime(context)
    registered = session(runtime)
    try:
        assert context.project.batch is None
        context.analyze_program(domain)
        assert context.project.batch is None
        assert invoke(runtime, read, registered) == {"analyzed": True}
        with pytest.raises(ValueError, match="after mutation"):
            invoke(runtime, write, registered, fail=True)
        assert invoke(runtime, read, registered) == {"analyzed": True}
        runtime.close()
        assert context.project.batch is not None
        assert not consumers
        context.project.close(program)
        assert program.values == {"analyzed": True}
    finally:
        runtime.close()


def test_failed_project_handback_retains_consumer_for_retry(runtime):
    registered = session(runtime)
    program = registered.info.program
    domain = SimpleNamespace(
        getPathname=lambda: "/fixture",
        getParent=lambda: SimpleNamespace(getPathname=lambda: "/"),
        getName=lambda: "fixture",
    )
    program.getDomainFile = lambda: domain
    released = []
    program.release = released.append
    consumer = object()

    def fail_open(*arguments):
        raise RuntimeError("Project reopen failed")

    runtime.context.project = SimpleNamespace(openProgram=fail_open)
    runtime.own_program(runtime.context, program, consumer)
    with pytest.raises(RuntimeError, match="Project reopen failed"):
        runtime.return_program(program)
    assert released == []
    runtime.context.project.openProgram = lambda *arguments: program
    runtime.return_program(program)
    assert released == [consumer]
