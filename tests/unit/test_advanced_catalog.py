"""Consumer-visible input, connection identity and response safety boundaries."""

import asyncio
import threading
from types import SimpleNamespace

import anyio
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from agenticghidra_mcp.advanced.registry import (
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    build_operations,
    install_owner_cleanup,
    make_tool,
    normalize_result,
    owner_from_context,
    owner_from_session,
    reference_catalog,
    settled_thread_call,
    track_owner,
)


@pytest.fixture(scope="module")
def public_tools():
    specs = {item["name"]: item for item in reference_catalog()["tools"]}
    return {
        name: make_tool(definition, specs[name]) for name, definition in build_operations().items()
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "arguments", "message"),
    [
        ("memory.read", {"session_id": "s", "address": "1000"}, "length"),
        ("memory.read", {"session_id": "s", "address": "1000", "length": True}, "integer"),
        ("memory.read", {"session_id": "s", "address": "1000", "length": "16"}, "integer"),
        ("memory.read", {"session_id": "s", "address": [], "length": 16}, "schema"),
        ("function.rename", {"session_id": "s", "function_start": 4096, "name": None}, "string"),
        ("symbol.by_name", {"session_id": "s", "name": "main", "exact": 1}, "boolean"),
        (
            "symbol.by_name",
            {"session_id": "s", "name": "main", "owner": "another-client"},
            "Additional properties",
        ),
        ("program.open", {"path": "/tmp/example", "read_only": "false"}, "boolean"),
        ("health.ping", {"session_id": "caller-chosen-owner"}, "Additional properties"),
    ],
)
async def test_invalid_public_arguments_are_rejected(public_tools, name, arguments, message):
    with pytest.raises(ToolError, match=message):
        await public_tools[name].run(arguments)


@pytest.mark.asyncio
async def test_valid_arguments_still_require_a_real_mcp_connection(public_tools):
    with pytest.raises(ToolError, match="active MCP request context"):
        await public_tools["health.ping"].run({})


def test_register_arguments_preserve_public_aliases_and_defaults(public_tools):
    arguments = {"session_id": "s", "register": "rax", "address": 4096}
    parsed = public_tools["context.get"].fn_metadata.arg_model.model_validate(arguments)
    assert parsed.model_dump_one_level() == {**arguments, "signed": False}


@pytest.mark.asyncio
async def test_internal_argument_names_are_not_public_inputs(public_tools):
    with pytest.raises(ToolError, match="Additional properties"):
        await public_tools["context.get"].run(
            {"session_id": "s", "register": "rax", "address": 4096, "argument_signed": True}
        )


@pytest.mark.asyncio
async def test_oversized_request_is_rejected_before_dispatch(public_tools):
    with pytest.raises(ToolError, match="request limit"):
        await public_tools["program.open"].run({"path": "x" * MAX_INPUT_BYTES})


class _TransportSession:
    pass


def _context(session):
    return SimpleNamespace(request_context=SimpleNamespace(session=session))


def test_owner_follows_connection_not_request_or_client_session_id():
    first = _TransportSession()
    second = _TransportSession()
    request = _context(first)
    request.session_id = "forged-session-owner"
    owner = owner_from_context(request)
    assert owner == owner_from_context(_context(first))
    assert owner != owner_from_context(_context(second))
    assert owner != request.session_id
    assert owner == owner_from_session(first)


@pytest.mark.parametrize("context", [None, SimpleNamespace(), _context(None)])
def test_owner_cannot_be_invented_without_transport(context):
    with pytest.raises(ValueError, match="MCP"):
        owner_from_context(context)


def test_non_object_results_have_an_honest_structured_wrapper():
    assert normalize_result([1, "two"]) == {"result": [1, "two"]}
    assert normalize_result(None) == {"result": None}
    assert normalize_result({"items": [1]}) == {"items": [1]}


def test_oversized_response_is_an_explicit_error_not_silent_truncation():
    with pytest.raises(ValueError, match="response limit"):
        normalize_result({"payload": "x" * MAX_OUTPUT_BYTES})


@pytest.mark.asyncio
async def test_cancellation_waits_for_the_protected_operation_to_settle():
    started = threading.Event()
    release = threading.Event()
    completed = threading.Event()

    def mutation():
        started.set()
        release.wait()
        completed.set()

    request = asyncio.create_task(settled_thread_call(mutation))
    await asyncio.to_thread(started.wait)
    try:
        request.cancel()
        await asyncio.sleep(0)
        assert not request.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await request
    assert completed.is_set()


class _ClosingRuntime:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.closed = []

    def close_owner(self, owner):
        self.started.set()
        self.release.wait()
        self.closed.append(owner)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancellation", ["asyncio", "anyio"])
async def test_transport_cleanup_drains_under_cancellation_and_isolates_owners(cancellation):
    runtime = _ClosingRuntime()
    connected = {owner: asyncio.Event() for owner in ("first", "second")}
    disconnected = {owner: asyncio.Event() for owner in connected}
    scopes = {}

    async def original_run(owner):
        track_owner(runtime, owner)
        connected[owner].set()
        await disconnected[owner].wait()

    backend = SimpleNamespace(run=original_run)
    install_owner_cleanup(SimpleNamespace(_mcp_server=backend))

    async def connection(owner):
        with anyio.CancelScope() as scope:
            scopes[owner] = scope
            await backend.run(owner)

    first = asyncio.create_task(connection("first"))
    second = asyncio.create_task(connection("second"))
    await connected["first"].wait()
    await connected["second"].wait()
    try:
        if cancellation == "asyncio":
            first.cancel()
        else:
            scopes["first"].cancel()
        assert await asyncio.to_thread(runtime.started.wait, 5)
        assert not first.done()
        assert not second.done()
        assert runtime.closed == []
        if cancellation == "asyncio":
            first.cancel()
            await asyncio.sleep(0)
            assert not first.done()
    finally:
        runtime.release.set()
        disconnected["second"].set()
        results = await asyncio.gather(first, second, return_exceptions=True)
    if cancellation == "asyncio":
        assert isinstance(results[0], asyncio.CancelledError)
    else:
        assert results[0] is None
    assert results[1] is None
    assert sorted(runtime.closed) == ["first", "second"]
