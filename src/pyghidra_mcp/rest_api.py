"""REST surface served beside the MCP endpoint: one registry, two protocols.

The supervisor already dispatches every tool call through a single code path.
These routes expose the same registry over plain JSON/HTTP so throwaway scripts
can chain calls (open, analyze, decompile, report) without an MCP client, and
so curl-style debugging stays possible during incident analysis.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

from mcp import types
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# await dispatch(runtime, name, arguments, owner) -> types.CallToolResult
Dispatch = Callable[[Any, str, dict[str, Any], Any], Awaitable[types.CallToolResult]]

_DEV_OWNER = "rest-local"


# Message vocabulary mirrors the reference project's error-class mapping: worker
# tool failures cross the MCP boundary as text only, so curated phrases carry
# the class. Specific phrases must be tested before the generic "not found".
_MESSAGE_CLASS = (
    (403, ("trusted execution is disabled", "read-only", "permission", "denied")),
    (409, ("locked by another worker", "in use", "already open", "already exists")),
    (503, ("analysis is incomplete", "busy", "active tasks", "pending transaction")),
    (504, ("timeout", "timed out", "deadline")),
    (
        400,
        (
            "must be",
            "must not",
            "invalid",
            "required",
            "unexpected",
            "ambiguous",
            "between",
            "specify",
            "cannot be empty",
            "at least",
            "at most",
            "not a boolean",
            "address or unique symbol not found",
            "no load spec found",
        ),
    ),
    (404, ("unknown tool", "not found", "no such file", "no function", "no instruction")),
)


def _classify(message: str) -> int:
    lowered = message.lower()
    for status, phrases in _MESSAGE_CLASS:
        if any(phrase in lowered for phrase in phrases):
            return status
    return 500


_STATUS_BY_KIND = {
    "ValueError": 400,
    "FileNotFoundError": 404,
    "PermissionError": 403,
    "TimeoutError": 504,
}

def _payload(result: types.CallToolResult) -> Any:
    if result.structuredContent is not None:
        return result.structuredContent
    if result.content and result.content[0].text:
        try:
            return json.loads(result.content[0].text)
        except ValueError:
            return result.content[0].text
    return None



def _failure(result: types.CallToolResult) -> tuple[int, str]:
    """Map a dispatch error to HTTP, preferring the preserved exception kind."""
    message = _error_message(result)
    payload = _payload(result)
    if isinstance(payload, dict) and payload.get("kind"):
        status = _STATUS_BY_KIND.get(payload["kind"])
        if status is not None:
            return status, message
    return _classify(message), message




def _error_message(result: types.CallToolResult) -> str:
    if result.content and result.content[0].text:
        return result.content[0].text
    return "tool call failed"


def _tool_descriptor(tool: types.Tool) -> dict[str, Any]:
    name = tool.name
    return {
        "name": name,
        "family": name.split(".")[0],
        "description": tool.description or "",
        "input_schema": tool.inputSchema,
        "read_only": bool(
            tool.annotations and getattr(tool.annotations, "readOnlyHint", False)
        ),
    }


class RestApi:
    """Route handlers sharing the supervisor dispatch path and its ownership rules."""

    def __init__(
        self,
        runtime: Any,
        dispatch: Dispatch,
        management_tools: list[types.Tool],
        api_key: str | None = None,
    ) -> None:
        self.runtime = runtime
        self.dispatch = dispatch
        self.management_tools = management_tools
        self.api_key = api_key
        self.started_at = time.monotonic()
        self._properties: dict[str, frozenset[str]] = {}

    # -- identity -----------------------------------------------------------

    def _argument_properties(self, name: str) -> frozenset[str]:
        """Argument names a tool accepts; empty set means unknown (merge nothing)."""
        cached = self._properties.get(name)
        if cached is not None:
            return cached
        schema = next(
            (
                tool.inputSchema
                for tool in (*self.runtime.tools, *self.management_tools)
                if tool.name == name
            ),
            None,
        )
        if schema is None:
            return frozenset()
        properties = frozenset(schema.get("properties", {}))
        self._properties[name] = properties
        return properties

    def _authenticate(self, request: Request) -> tuple[Any, JSONResponse | None]:
        if self.api_key is None:
            return _DEV_OWNER, None
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        token = token or request.headers.get("x-api-key", "").strip()
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if token and digest == self.api_key:
            return f"rest-{digest[:16]}", None
        return None, JSONResponse(
            {"status": "error", "error": {"code": 401, "message": "invalid or missing API key"}},
            status_code=401,
        )

    # -- envelopes ----------------------------------------------------------

    async def _call(self, name: str, arguments: dict[str, Any], owner: Any) -> JSONResponse:
        started = time.monotonic()
        result = await self.dispatch(self.runtime, name, arguments, owner)
        elapsed = int((time.monotonic() - started) * 1000)
        payload = _payload(result)
        if result.isError:
            status, message = _failure(result)
            return JSONResponse(
                {
                    "status": "error",
                    "tool": name,
                    "error": {"code": status, "message": message},
                },
                status_code=status,
            )
        body: dict[str, Any] = {
            "status": "ok",
            "tool": name,
            "duration_ms": elapsed,
            "result": payload,
        }
        if isinstance(payload, dict) and "session_id" in payload:
            body["session_id"] = payload["session_id"]
        return JSONResponse(body)

    # -- handlers -----------------------------------------------------------

    async def health(self, request: Request) -> JSONResponse:
        result = await self.dispatch(self.runtime, "worker_status", {}, _DEV_OWNER)
        payload = _payload(result)
        return JSONResponse(
            {
                "status": "ok",
                "uptime_seconds": round(time.monotonic() - self.started_at, 3),
                "auth": "api-key" if self.api_key else "dev",
                "workers": payload,
            }
        )

    async def tools(self, request: Request) -> JSONResponse:
        _, failure = self._authenticate(request)
        if failure is not None:
            return failure
        family = request.query_params.get("family")
        query = (request.query_params.get("q") or "").lower()
        read_only = request.query_params.get("read_only")
        descriptors = [
            _tool_descriptor(tool)
            for tool in (*self.runtime.tools, *self.management_tools)
        ]
        selected = [
            item
            for item in descriptors
            if (family is None or item["family"] == family)
            and (not query or query in item["name"].lower())
            and (
                read_only is None
                or item["read_only"] is (read_only.lower() in {"1", "true", "yes"})
            )
        ]
        return JSONResponse(
            {
                "tools": selected,
                "count": len(selected),
                "total": len(descriptors),
                "filters": {"family": family, "q": query or None, "read_only": read_only},
            }
        )

    async def tool_schema(self, request: Request) -> JSONResponse:
        _, failure = self._authenticate(request)
        if failure is not None:
            return failure
        name = request.path_params["name"]
        for tool in (*self.runtime.tools, *self.management_tools):
            if tool.name == name:
                return JSONResponse(_tool_descriptor(tool))
        return JSONResponse(
            {"status": "error", "error": {"code": 404, "message": f"Unknown tool: {name}"}},
            status_code=404,
        )

    async def invoke(self, request: Request) -> JSONResponse:
        owner, failure = self._authenticate(request)
        if failure is not None:
            return failure
        name = request.path_params["name"]
        try:
            arguments = await request.json()
        except ValueError:
            return JSONResponse(
                {"status": "error", "error": {"code": 400, "message": "body must be JSON"}},
                status_code=400,
            )
        if not isinstance(arguments, dict):
            return JSONResponse(
                {
                    "status": "error",
                    "error": {"code": 400, "message": "body must be a JSON object of arguments"},
                },
                status_code=400,
            )
        return await self._call(name, arguments, owner)

    def _pipeline_arguments(self, call: dict, merged: dict[str, Any], pipeline: bool):
        """Prepare one batch call's arguments: explicit args, then per-call
        result renames, then schema-filtered pipeline merge. Raises ValueError
        on a malformed call or map."""
        if not isinstance(call, dict) or not isinstance(call.get("tool"), str):
            raise ValueError("each call needs tool and arguments")
        raw_arguments = dict(call.get("arguments", {}))
        mapping = call.get("map") or {}
        if not isinstance(mapping, dict):
            raise ValueError("map must map destination names to result keys")
        for destination, source in mapping.items():
            if source in merged:
                raw_arguments[destination] = merged[source]
        if pipeline:
            # Heterogeneous tools reject unknown keys and use different
            # argument names: only schema-known keys flow forward, plus the
            # explicit renames above.
            allowed = self._argument_properties(call["tool"])
            for key, value in merged.items():
                if key in allowed and key not in raw_arguments:
                    raw_arguments[key] = value
        return call["tool"], raw_arguments


    async def batch(self, request: Request) -> JSONResponse:
        owner, failure = self._authenticate(request)
        if failure is not None:
            return failure
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict) or not isinstance(body.get("calls"), list):
            return JSONResponse(
                {
                    "status": "error",
                    "error": {"code": 400, "message": "body must be {calls: [{tool, arguments}]}"},
                },
                status_code=400,
            )
        stop_on_error = bool(body.get("stop_on_error", True))
        pipeline = bool(body.get("pipeline", False))
        merged: dict[str, Any] = {}
        results = []
        for call in body["calls"]:
            try:
                tool, arguments = self._pipeline_arguments(call, merged, pipeline)
            except ValueError as exc:
                return JSONResponse(
                    {"status": "error", "error": {"code": 400, "message": str(exc)}},
                    status_code=400,
                )
            started = time.monotonic()
            result = await self.dispatch(self.runtime, tool, arguments, owner)
            payload = _payload(result)
            envelope: dict[str, Any] = {
                "tool": call["tool"],
                "status": "error" if result.isError else "ok",
                "duration_ms": int((time.monotonic() - started) * 1000),
                "result": payload,
            }
            if result.isError:
                status, message = _failure(result)
                envelope["error"] = {"code": status, "message": message}
                results.append(envelope)
                if stop_on_error:
                    break
                continue
            if pipeline and isinstance(payload, dict):
                merged.update({k: v for k, v in payload.items() if k not in ("error",)})
            results.append(envelope)
        failures = [item for item in results if item["status"] == "error"]
        return JSONResponse(
            {"status": "error" if failures else "ok", "count": len(results), "results": results},
            status_code=200,
        )

    async def workers(self, request: Request) -> JSONResponse:
        owner, failure = self._authenticate(request)
        if failure is not None:
            return failure
        return await self._call("worker_status", {}, owner)

    async def worker_action(self, request: Request) -> JSONResponse:
        owner, failure = self._authenticate(request)
        if failure is not None:
            return failure
        action = request.path_params["action"]
        name = {"start": "worker_start", "stop": "worker_stop", "restart": "worker_restart"}.get(
            action
        )
        if name is None:
            return JSONResponse(
                {"status": "error", "error": {"code": 404, "message": "unknown worker action"}},
                status_code=404,
            )
        try:
            body = await request.json()
        except ValueError:
            body = {}
        arguments = {"worker_id": request.path_params["worker_id"]}
        if action != "start" and isinstance(body, dict) and body.get("force") is not None:
            arguments["force"] = bool(body["force"])
        return await self._call(name, arguments, owner)

    async def investigations(self, request: Request) -> JSONResponse:
        owner, failure = self._authenticate(request)
        if failure is not None:
            return failure
        if request.method == "POST":
            try:
                body = await request.json()
            except ValueError:
                body = None
            if not isinstance(body, dict) or "binary_path" not in body or "teams" not in body:
                return JSONResponse(
                    {
                        "status": "error",
                        "error": {"code": 400, "message": "binary_path and teams are required"},
                    },
                    status_code=400,
                )
            return await self._call("investigation.create", body, owner)
        return await self._call("investigation.list", {}, owner)

    async def investigation(self, request: Request) -> JSONResponse:
        owner, failure = self._authenticate(request)
        if failure is not None:
            return failure
        return await self._call(
            "investigation.status",
            {"investigation_id": request.path_params["investigation_id"]},
            owner,
        )

    async def openapi(self, request: Request) -> JSONResponse:
        def operation(summary, statuses):
            return {"summary": summary, "responses": {str(code): {} for code in statuses}}

        return JSONResponse(
            {
                "openapi": "3.1.0",
                "info": {
                    "title": "ghidra-advanced-mcp REST",
                    "version": "1",
                    "description": (
                        "Same registry as the MCP server on /mcp. Invoke any tool by "
                        "name; the body is the tool input schema as a JSON object."
                    ),
                },
                "paths": {
                    "/health": {"get": operation("Liveness plus worker snapshot", [200])},
                    "/api/v1/tools": {
                        "get": operation(
                            "List tools; filters family, q, read_only", [200]
                        )
                    },
                    "/api/v1/tools/{name}": {
                        "get": operation("One tool descriptor and schema", [200, 404]),
                        "post": operation("Invoke a tool with JSON arguments", [200, 400, 404]),
                    },
                    "/api/v1/batch": {
                        "post": operation(
                            "Sequential calls; pipeline merges results forward", [200, 400]
                        )
                    },
                    "/api/v1/workers": {"get": operation("Worker status snapshot", [200])},
                    "/api/v1/workers/{worker_id}/{action}": {
                        "post": operation("start, stop or restart one worker", [200, 404])
                    },
                    "/api/v1/investigations": {
                        "get": operation("List investigations", [200]),
                        "post": operation(
                            "Create same-binary team investigation", [200, 400]
                        ),
                    },
                    "/api/v1/investigations/{investigation_id}": {
                        "get": operation("One investigation status", [200, 404])
                    },
                },
            }
        )


def create_api_routes(
    runtime: Any,
    dispatch: Dispatch,
    management_tools: list[types.Tool],
    api_key: str | None = None,
) -> list[Route]:
    """Build the /health and /api/v1 routes for the supervisor Starlette app."""
    api = RestApi(runtime, dispatch, management_tools, api_key)
    return [
        Route("/health", api.health, methods=["GET"]),
        Route("/api/v1/tools", api.tools, methods=["GET"]),
        Route("/api/v1/tools/{name}", api.tool_schema, methods=["GET"]),
        Route("/api/v1/tools/{name}", api.invoke, methods=["POST"]),
        Route("/api/v1/batch", api.batch, methods=["POST"]),
        Route("/api/v1/workers", api.workers, methods=["GET"]),
        Route("/api/v1/workers/{worker_id}/{action}", api.worker_action, methods=["POST"]),
        Route("/api/v1/investigations", api.investigations, methods=["GET", "POST"]),
        Route(
            "/api/v1/investigations/{investigation_id}", api.investigation, methods=["GET"]
        ),
        Route("/api/v1/openapi.json", api.openapi, methods=["GET"]),
    ]
