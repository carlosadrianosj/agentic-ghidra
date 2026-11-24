"""REST surface contract tests using a stub supervisor runtime (no JVM)."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from mcp import types
from starlette.applications import Starlette
from starlette.testclient import TestClient

from agenticghidra_mcp.rest_api import create_api_routes
from agenticghidra_mcp.supervisor import _dispatch, _management_tools, _result as wrap_result

SECRET_DIGEST = hashlib.sha256(b"rest-secret").hexdigest()


class _Worker:
    def status(self):
        return {"worker_id": "w1", "state": "ready"}


class _Investigations:
    async def create(self, binary_path, teams, name=None, start=True):
        return {"investigation_id": "inv1", "binary_path": binary_path, "teams": teams}

    def list(self):
        return {"investigations": [{"investigation_id": "inv1"}]}

    async def status(self, investigation_id):
        return {"investigation_id": investigation_id, "sha256": "ab" * 32}


class _Runtime:
    def __init__(self):
        self.tools = [
            types.Tool(
                name="health.ping",
                description="ping",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="decomp.function",
                description="decompile",
                inputSchema={
                    "type": "object",
                    "properties": {"session_id": {"type": "string"}},
                    "required": ["session_id"],
                },
            ),
            types.Tool(
                name="decomp.boom",
                description="always fails",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="decomp.missing",
                description="missing target",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]
        self.workers = {"w1": _Worker()}
        self.config = SimpleNamespace(max_active_workers=2)
        self.investigations = _Investigations()
        self.calls = []

    async def start_worker(self, worker_id):
        return {"worker_id": worker_id, "started": True}

    async def stop_worker(self, worker_id, force=False):
        return {"worker_id": worker_id, "stopped": True, "force": force}

    async def restart(self, worker_id, force=False):
        return {"worker_id": worker_id, "restarted": True}

    async def call(self, name, arguments, owner):
        self.calls.append((name, arguments, owner))
        if name == "decomp.boom":
            raise ValueError("bad decompile input")
        if name == "decomp.missing":
            raise FileNotFoundError("function not found")
        return wrap_result({"session_id": "s1", "ok": True, "code": "return 42;"})


def _client(api_key=None):
    runtime = _Runtime()
    app = Starlette(
        routes=create_api_routes(runtime, _dispatch, _management_tools(), api_key=api_key)
    )
    return TestClient(app), runtime


def test_health_reports_workers():
    client, _ = _client()
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["workers"]["workers"] == [{"worker_id": "w1", "state": "ready"}]
    assert body["auth"] == "dev"


def test_tools_listing_and_filters():
    client, _ = _client()
    body = client.get("/api/v1/tools").json()
    names = {item["name"] for item in body["tools"]}
    assert {"health.ping", "decomp.function", "worker_status"} <= names
    assert body["total"] == 4 + len(_management_tools())
    family = client.get("/api/v1/tools", params={"family": "decomp"}).json()
    assert {item["name"] for item in family["tools"]} == {
        "decomp.function",
        "decomp.boom",
        "decomp.missing",
    }
    query = client.get("/api/v1/tools", params={"q": "ping"}).json()
    assert "health.ping" in {item["name"] for item in query["tools"]}


def test_tool_schema_known_and_unknown():
    client, _ = _client()
    schema = client.get("/api/v1/tools/decomp.function").json()
    assert schema["input_schema"]["required"] == ["session_id"]
    missing = client.get("/api/v1/tools/decomp.nope")
    assert missing.status_code == 404


def test_invoke_envelope_and_error_mapping():
    client, runtime = _client()
    ok = client.post("/api/v1/tools/decomp.function", json={"session_id": "s1"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["status"] == "ok" and body["session_id"] == "s1"
    assert body["result"]["code"] == "return 42;"
    assert isinstance(runtime.calls[0][2], str)
    boom = client.post("/api/v1/tools/decomp.boom", json={})
    assert boom.status_code == 400
    assert boom.json()["error"]["message"] == "bad decompile input"
    missing = client.post("/api/v1/tools/decomp.missing", json={})
    assert missing.status_code == 404
    unknown = client.post("/api/v1/tools/not.a.tool", json={})
    assert unknown.status_code == 404
    broken = client.post(
        "/api/v1/tools/decomp.function",
        data="not-json",
        headers={"content-type": "application/json"},
    )
    assert broken.status_code == 400


def test_batch_sequential_stop_on_error_and_pipeline():
    client, _ = _client()
    body = client.post(
        "/api/v1/batch",
        json={
            "calls": [
                {"tool": "decomp.function", "arguments": {"session_id": "s1"}},
                {"tool": "decomp.boom", "arguments": {}},
                {"tool": "health.ping", "arguments": {}},
            ]
        },
    ).json()
    assert body["status"] == "error" and body["count"] == 2
    assert body["results"][1]["error"]["code"] == 400
    continued = client.post(
        "/api/v1/batch",
        json={"calls": [{"tool": "decomp.boom"}, {"tool": "health.ping"}], "stop_on_error": False},
    ).json()
    assert continued["count"] == 2 and continued["results"][1]["status"] == "ok"
    piped = client.post(
        "/api/v1/batch",
        json={"calls": [{"tool": "decomp.function"}, {"tool": "health.ping"}], "pipeline": True},
    ).json()
    assert piped["status"] == "ok"

def test_pipeline_filters_unknown_keys_and_applies_map():
    client, runtime = _client()
    body = client.post(
        "/api/v1/batch",
        json={
            "calls": [
                {"tool": "decomp.function", "arguments": {"session_id": "s1"}},
                {"tool": "health.ping", "arguments": {}, "map": {"text": "code"}},
            ],
            "pipeline": True,
        },
    ).json()
    assert body["status"] == "ok"
    # health.ping accepts no properties, so only the explicit map binding lands.
    assert runtime.calls[1][1] == {"text": "return 42;"}
    with_map = client.post(
        "/api/v1/batch",
        json={
            "calls": [
                {"tool": "decomp.function", "arguments": {"session_id": "s1"}},
                {
                    "tool": "decomp.function",
                    "arguments": {},
                    "map": {"session_id": "code"},
                },
            ],
            "pipeline": True,
        },
    ).json()
    assert with_map["status"] == "ok"
    assert runtime.calls[3][1]["session_id"] == "return 42;"

def test_message_classification_vocabulary():
    from agenticghidra_mcp.rest_api import _classify

    assert _classify("limit must be between 1 and 1000") == 400
    assert _classify("Address or unique symbol not found: zzz") == 400
    assert _classify("field 'functions' is unexpected") == 400
    assert _classify("Trusted execution is disabled; enable it") == 403
    assert _classify("Program session is read-only; use program.mode.set") == 403
    assert _classify("project may already be locked by another worker") == 409
    assert _classify("Program analysis is incomplete") == 503
    assert _classify("request timed out after 30s") == 504
    assert _classify("Unknown tool: nope") == 404
    assert _classify("Function or symbol '001234' not found.") == 404
    assert _classify("something exploded in the JVM") == 500

def test_worker_and_investigation_routes():
    client, _ = _client()
    workers = client.get("/api/v1/workers").json()
    assert workers["result"]["workers"] == [{"worker_id": "w1", "state": "ready"}]
    started = client.post("/api/v1/workers/w1/start").json()
    assert started["result"]["worker_id"] == "w1"
    stopped = client.post("/api/v1/workers/w1/stop", json={"force": True}).json()
    assert stopped["status"] == "ok"
    created = client.post(
        "/api/v1/investigations",
        json={"binary_path": "/bin/true", "teams": ["tls", "raw"]},
    ).json()
    assert created["result"]["investigation_id"] == "inv1"
    listed = client.get("/api/v1/investigations").json()
    assert listed["result"]["investigations"][0]["investigation_id"] == "inv1"
    status = client.get("/api/v1/investigations/inv1").json()
    assert status["result"]["sha256"] == "ab" * 32
    bad = client.post("/api/v1/workers/w1/detonate")
    assert bad.status_code == 404


def test_api_key_authentication():
    client, _ = _client(api_key=SECRET_DIGEST)
    denied = client.get("/api/v1/tools")
    assert denied.status_code == 401
    wrong = client.get(
        "/api/v1/tools", headers={"Authorization": "Bearer nope"}
    )
    assert wrong.status_code == 401
    allowed = client.get(
        "/api/v1/tools", headers={"X-API-Key": "rest-secret"}
    )
    assert allowed.status_code == 200
    health = client.get("/health")
    assert health.status_code == 200


def test_openapi_document():
    client, _ = _client()
    body = client.get("/api/v1/openapi.json").json()
    assert "/api/v1/tools/{name}" in body["paths"]
    assert {"get", "post"} <= set(body["paths"]["/api/v1/tools/{name}"])
