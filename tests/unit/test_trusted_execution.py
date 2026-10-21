import sys
from types import SimpleNamespace

import pytest

from pyghidra_mcp.advanced.core import Call
from pyghidra_mcp.advanced.trusted import MAX_OUTPUT_CHARS, evaluate


@pytest.fixture
def call():
    program = SimpleNamespace(getMinAddress=lambda: "1000")
    info = SimpleNamespace(program=program, flat_api=None)
    session = SimpleNamespace(session_id="owned", read_only=False, info=info)
    return Call(runtime=None, context=None, owner="client", session=session)


def test_execution_requires_explicit_trust_and_owned_session(call, monkeypatch):
    monkeypatch.delenv("GHIDRA_ADVANCED_TRUSTED_CODE", raising=False)
    with pytest.raises(PermissionError, match="disabled"):
        evaluate(call, "raise AssertionError('must not execute')")
    monkeypatch.setenv("GHIDRA_ADVANCED_TRUSTED_CODE", "1")
    call.session = None
    with pytest.raises(ValueError, match="owned program session"):
        evaluate(call, "raise AssertionError('must not execute')")


def test_read_only_session_rejects_declared_write_before_execution(call, monkeypatch):
    monkeypatch.setenv("GHIDRA_ADVANCED_TRUSTED_CODE", "1")
    call.session.read_only = True
    with pytest.raises(PermissionError, match="read-only"):
        evaluate(call, "raise AssertionError('must not execute')", write=True)


def test_python_deadline_interrupts_unbounded_code_and_restores_trace(call, monkeypatch):
    monkeypatch.setenv("GHIDRA_ADVANCED_TRUSTED_CODE", "1")
    monkeypatch.setenv("GHIDRA_ADVANCED_CODE_TIMEOUT", "0.01")
    original = sys.gettrace()
    with pytest.raises(TimeoutError, match="deadline"):
        evaluate(call, "while True:\n    pass")
    assert sys.gettrace() is original


def test_excessive_python_output_is_rejected(call, monkeypatch):
    monkeypatch.setenv("GHIDRA_ADVANCED_TRUSTED_CODE", "1")
    with pytest.raises(ValueError, match="output exceeds"):
        evaluate(call, f"print('x' * {MAX_OUTPUT_CHARS + 1})")
