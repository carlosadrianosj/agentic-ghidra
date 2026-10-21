import concurrent.futures
import logging
import sys
import threading
import types
from unittest.mock import Mock, call

import pytest

import pyghidra_mcp.context as context_module
from pyghidra_mcp.context import PyGhidraContext

_TIMEOUT = 5


@pytest.fixture
def context_factory(monkeypatch, tmp_path):
    ghidra_module = types.ModuleType("ghidra")
    base_module = types.ModuleType("ghidra.base")
    project_module = types.ModuleType("ghidra.base.project")
    project_module.GhidraProject = object
    monkeypatch.setitem(sys.modules, "ghidra", ghidra_module)
    monkeypatch.setitem(sys.modules, "ghidra.base", base_module)
    monkeypatch.setitem(sys.modules, "ghidra.base.project", project_module)
    monkeypatch.setattr(PyGhidraContext, "_get_or_create_project", lambda self: Mock())
    monkeypatch.setattr(PyGhidraContext, "_init_project_programs", lambda self: None)

    def init_indexing_state(self, path, *, threaded):
        self.index_executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1) if threaded else None
        )
        self._index_futures = {}
        self._index_lock = threading.Lock()

    monkeypatch.setattr(PyGhidraContext, "_init_indexing_state", init_indexing_state)
    contexts = []

    def create(*, threaded=True, wait_for_analysis=False):
        context = PyGhidraContext(
            "concurrency",
            tmp_path,
            threaded=threaded,
            max_workers=1,
            wait_for_analysis=wait_for_analysis,
        )
        context._dispose_decompiler = Mock()
        context._index_program = Mock()
        contexts.append(context)
        return context

    yield create

    for context in contexts:
        context.close(save=False)


def _domain_file(name):
    domain_file = Mock()
    domain_file.getName.return_value = name
    return domain_file


def _ready_program(name):
    return types.SimpleNamespace(
        name=name,
        program=Mock(),
        analysis_complete=True,
        code_collection=None,
        strings=None,
    )


def test_one_worker_project_analysis_completes(context_factory):
    context = context_factory()
    assert context.analysis_coordinator is not context.executor
    domain_files = [_domain_file("one"), _domain_file("two")]
    context.list_binary_domain_files = Mock(return_value=domain_files)
    context.analyze_program = Mock(side_effect=lambda domain_file, *args: domain_file)
    indexing_scheduled = threading.Event()
    context.schedule_startup_indexing = Mock(side_effect=lambda **kwargs: indexing_scheduled.set())

    future = context.analyze_project()

    assert future.result(timeout=_TIMEOUT) is None
    assert indexing_scheduled.wait(_TIMEOUT)
    assert context.analyze_program.call_args_list == [
        call(domain_file, True, False, False) for domain_file in domain_files
    ]
    context.schedule_startup_indexing.assert_called_once_with(max_binaries=1)


def test_overlapping_project_analysis_reuses_current_sweep(context_factory):
    context = context_factory()
    domain_file = _domain_file("one")
    context.list_binary_domain_files = Mock(return_value=[domain_file])
    running = threading.Event()
    release = threading.Event()

    def analyze(*args):
        running.set()
        assert release.wait(_TIMEOUT)
        return domain_file

    context.analyze_program = Mock(side_effect=analyze)
    try:
        first = context.analyze_project()
        assert running.wait(_TIMEOUT)
        second = context.analyze_project()
        assert first is second
    finally:
        release.set()

    first.result(timeout=_TIMEOUT)
    context.list_binary_domain_files.assert_called_once_with()
    context.analyze_program.assert_called_once_with(domain_file, True, False, False)


@pytest.mark.parametrize("mode", ["background", "waiting", "synchronous"])
def test_analysis_exceptions_reach_the_caller(context_factory, mode, caplog):
    caplog.set_level(logging.INFO)
    context = context_factory(threaded=mode != "synchronous", wait_for_analysis=mode == "waiting")
    context.list_binary_domain_files = Mock(return_value=[_domain_file("broken")])
    failure = RuntimeError("analyzer failed")
    context.analyze_program = Mock(side_effect=failure)
    context.schedule_startup_indexing = Mock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as caller:
        try:
            future = caller.submit(context.analyze_project)
            if mode == "background":
                future = future.result(timeout=_TIMEOUT)
            with pytest.raises(RuntimeError, match="analyzer failed") as raised:
                future.result(timeout=_TIMEOUT)
        finally:
            context.close(save=False)

    assert raised.value is failure
    context.schedule_startup_indexing.assert_not_called()
    assert "Analysis complete." not in caplog.messages


def test_synchronous_project_analysis_still_indexes(context_factory):
    context = context_factory(threaded=False)
    domain_files = [_domain_file("one"), _domain_file("two")]
    context.list_binary_domain_files = Mock(return_value=domain_files)
    context.analyze_program = Mock(side_effect=lambda domain_file, *args: domain_file)
    context.schedule_startup_indexing = Mock()

    assert context.analyze_project(force_analysis=True) is None

    assert context.analyze_program.call_args_list == [
        call(domain_file, True, True, False) for domain_file in domain_files
    ]
    context.schedule_startup_indexing.assert_called_once_with(max_binaries=1)


def test_close_drains_submitters_and_cancels_queued_children(
    context_factory, monkeypatch, tmp_path
):
    context = context_factory()
    program_info = _ready_program("/sample")
    context.programs = {program_info.name: program_info}
    domain_files = [_domain_file("one"), _domain_file("two")]
    context.list_binary_domain_files = Mock(return_value=domain_files)
    context.analyze_program = Mock(side_effect=lambda domain_file, *args: domain_file)
    worker_running = threading.Event()
    release_worker = threading.Event()
    import_running = threading.Event()
    release_import = threading.Event()
    children_submitted = threading.Event()
    import_shutdown = threading.Event()
    coordinator_stopped = threading.Event()
    analysis_shutdown = threading.Event()
    second_close_started = threading.Event()
    shutdown_order = []
    late_indexing = []
    late_analysis_errors = []

    def occupy_worker():
        worker_running.set()
        assert release_worker.wait(_TIMEOUT)

    blocker = context.executor.submit(occupy_worker)
    assert worker_running.wait(_TIMEOUT)
    submit = context.executor.submit
    child_futures = []

    def submit_child(*args, **kwargs):
        future = submit(*args, **kwargs)
        child_futures.append(future)
        if len(child_futures) == len(domain_files):
            children_submitted.set()
        return future

    monkeypatch.setattr(context.executor, "submit", submit_child)
    shutdown_executor = context.shutdown_executor

    def shutdown(label, executor):
        shutdown_order.append(label)
        event = {"import": import_shutdown, "analysis": analysis_shutdown}.get(label)
        if event is not None:
            event.set()
        shutdown_executor(label, executor)
        if label == "analysis coordinator":
            coordinator_stopped.set()

    monkeypatch.setattr(context, "shutdown_executor", shutdown)

    def import_candidates(candidates, *, analyze):
        assert analyze is True
        import_running.set()
        assert release_import.wait(_TIMEOUT)
        late_indexing.append(context.schedule_indexing(program_info.name))
        try:
            context.analyze_project()
        except RuntimeError as error:
            late_analysis_errors.append(str(error))
        return [program_info.name]

    context._import_candidates = Mock(side_effect=import_candidates)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    import_plan = types.SimpleNamespace(
        candidates=[types.SimpleNamespace(path=binary, relative_path=None)], skipped=[]
    )
    monkeypatch.setattr(context_module, "build_import_plan", Mock(return_value=import_plan))

    def close_again():
        second_close_started.set()
        context.close(save=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as closers:
        try:
            context.import_binary_backgrounded(binary)
            assert import_running.wait(_TIMEOUT)
            analysis = context.analyze_project()
            assert children_submitted.wait(_TIMEOUT)
            first_close = closers.submit(context.close, save=False)
            assert import_shutdown.wait(_TIMEOUT)
            second_close = closers.submit(close_again)
            assert second_close_started.wait(_TIMEOUT)

            assert context.schedule_indexing(program_info.name) is False
            with pytest.raises(RuntimeError, match="closing"):
                context.analyze_project()
            with pytest.raises(RuntimeError, match="closing"):
                context.import_binary_backgrounded(binary)
            # Imports still own project state, so their consumers must remain alive.
            assert context.index_executor.submit(lambda: True).result(timeout=_TIMEOUT)
            assert not coordinator_stopped.is_set()
            context.project.close.assert_not_called()

            release_import.set()
            assert analysis_shutdown.wait(_TIMEOUT)
            assert coordinator_stopped.is_set()
            assert all(future.cancelled() for future in child_futures)
            assert not first_close.done()
            assert not second_close.done()

            release_worker.set()
            first_close.result(timeout=_TIMEOUT)
            second_close.result(timeout=_TIMEOUT)
            analysis.result(timeout=_TIMEOUT)
            blocker.result(timeout=_TIMEOUT)
        finally:
            release_import.set()
            release_worker.set()

    assert late_indexing == [False]
    assert late_analysis_errors == ["Project context is closing."]
    assert shutdown_order == ["import", "analysis coordinator", "analysis", "indexing"]
    context.analyze_program.assert_not_called()
    context._index_program.assert_not_called()
    assert context.project.close.call_args_list == [call(program_info.program), call()]

    completed = concurrent.futures.Future()
    completed.set_result(None)
    context._analysis_done_callback(completed)
    assert context.schedule_indexing(program_info.name) is False
    context._index_program.assert_not_called()


def test_close_cancels_queued_indexing_and_awaits_running_index(context_factory):
    context = context_factory()
    programs = [_ready_program("/one"), _ready_program("/two")]
    context.programs = {program.name: program for program in programs}
    indexing_running = threading.Event()
    release_indexing = threading.Event()
    indexing_cancelled = threading.Event()
    indexed = []

    def index_program(program_info, **kwargs):
        indexed.append(program_info.name)
        indexing_running.set()
        assert release_indexing.wait(_TIMEOUT)

    context._index_program = Mock(side_effect=index_program)

    def record_cancellation(future):
        if future.cancelled():
            indexing_cancelled.set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as closer:
        try:
            assert context.schedule_indexing("/one")
            assert indexing_running.wait(_TIMEOUT)
            assert context.schedule_indexing("/two")
            queued = context._index_futures["/two"]
            queued.add_done_callback(record_cancellation)
            closing = closer.submit(context.close, save=False)
            assert indexing_cancelled.wait(_TIMEOUT)
            assert not closing.done()
            context.project.close.assert_not_called()
            assert context.schedule_indexing("/two") is False
            release_indexing.set()
            closing.result(timeout=_TIMEOUT)
        finally:
            release_indexing.set()

    assert indexed == ["/one"]
    assert queued.cancelled()
    assert context.project.close.call_args_list == [
        call(programs[0].program),
        call(programs[1].program),
        call(),
    ]
