import asyncio
import threading
from types import SimpleNamespace

import pytest

from pyghidra_mcp import mcp_tools
from pyghidra_mcp.models import DecompiledFunction


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_request", [False, True])
async def test_request_does_not_release_live_decompiler_after_timeout_or_cancellation(
    monkeypatch, cancel_request
):
    loop = asyncio.get_running_loop()
    entered = asyncio.Event()
    release = threading.Event()
    exited = threading.Event()

    class NativeTools:
        def __init__(self, info):
            pass

        def decompile_function_by_name_or_addr(self, target, timeout):
            loop.call_soon_threadsafe(entered.set)
            try:
                assert release.wait(5), "Test did not release its native worker"
                return DecompiledFunction(name=target, code="int recovered(void) { return 42; }")
            finally:
                exited.set()

    context = SimpleNamespace(get_program_info=lambda name: object())
    request_context = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))
    monkeypatch.setattr(mcp_tools, "GhidraTools", NativeTools)
    monkeypatch.setattr(mcp_tools, "DECOMPILE_TIMEOUT_GRACE_SECONDS", 0)
    request = asyncio.create_task(
        mcp_tools.decompile_function("program", "entry", request_context, timeout_sec=0.01)
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        if cancel_request:
            request.cancel()
            await asyncio.sleep(0)
        else:
            deadline_observed = asyncio.Event()
            loop.call_later(0.03, deadline_observed.set)
            await deadline_observed.wait()
        assert not request.done(), "The response abandoned a live native operation"
        assert not exited.is_set()
        release.set()
        if cancel_request:
            with pytest.raises(asyncio.CancelledError):
                await request
        else:
            response = await request
            assert "timed out" in response[0].error
        assert exited.is_set()
    finally:
        release.set()
        if not request.done():
            request.cancel()
            try:
                await request
            except asyncio.CancelledError:
                pass
