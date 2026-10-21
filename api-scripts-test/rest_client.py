"""Shared REST client for the api-scripts-test suite.

Every script in this folder imports from here so the suite has exactly one
HTTP code path. Usage:

    from rest_client import RestClient

    api = RestClient("http://127.0.0.1:29950")
    opened = api.call("program.open", {"worker_id": "w", "path": binary})
"""

from __future__ import annotations

import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


class RestError(RuntimeError):
    """REST call that returned a non-OK envelope or transport failure."""

    def __init__(self, tool: str, status: int, body) -> None:
        self.tool = tool
        self.status = status
        self.body = body
        message = body.get("error", {}).get("message") if isinstance(body, dict) else str(body)
        super().__init__(f"{tool} -> HTTP {status}: {message}")


class RestClient:
    def __init__(self, base: str, api_key: str | None = None, timeout: float = 600.0) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.headers = {"content-type": "application/json"}
        if api_key:
            self.headers["authorization"] = f"Bearer {api_key}"

    def _request(self, method: str, path: str, payload=None) -> tuple[int, object]:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=self.headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                body = json.loads(raw) if raw else None
                return response.status, body
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else None
            except ValueError:
                return exc.code, raw.decode(errors="replace")

    def get(self, path: str):
        status, body = self._request("GET", path)
        return status, body

    def call(self, tool: str, arguments: dict | None = None):
        status, body = self._request("POST", f"/api/v1/tools/{tool}", arguments or {})
        if status != 200 or not isinstance(body, dict) or body.get("status") != "ok":
            raise RestError(tool, status, body)
        return body["result"]

    def call_raw(self, tool: str, arguments: dict | None = None):
        return self._request("POST", f"/api/v1/tools/{tool}", arguments or {})

    def batch(self, calls: list[dict], pipeline: bool = False, stop_on_error: bool = True):
        """Run a batch; returns per-call envelopes even when some calls failed.

        Raises only for transport failures or a malformed batch body; callers
        inspect each envelope's "status" for per-call outcomes.
        """
        status, body = self._request(
            "POST",
            "/api/v1/batch",
            {"calls": calls, "pipeline": pipeline, "stop_on_error": stop_on_error},
        )
        if status != 200 or not isinstance(body, dict) or "results" not in body:
            raise RestError("batch", status, body)
        return body["results"]

    def health(self):
        status, body = self.get("/health")
        if status != 200:
            raise RestError("health", status, body)
        return body


def soak(
    api: RestClient,
    workload,
    threads: int,
    duration_seconds: float,
) -> dict:
    """Run `workload(api)` on a thread pool until the deadline; report latencies.

    Returns {count, errors, p50_ms, p95_ms, max_ms, threads, duration_seconds}.
    Each worker thread stops at the deadline; workload failures are counted,
    never raised, so the soak always reports.
    """
    deadline = time.monotonic() + duration_seconds
    latencies: list[float] = []
    errors: list[str] = []
    lock_pool = ThreadPoolExecutor(max_workers=threads)

    def runner():
        while time.monotonic() < deadline:
            started = time.perf_counter()
            try:
                workload(api)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
            latencies.append((time.perf_counter() - started) * 1000.0)

    list(lock_pool.map(lambda _: runner(), range(threads)))
    lock_pool.shutdown()
    latencies.sort()
    return {
        "count": len(latencies),
        "errors": len(errors),
        "error_samples": errors[:5],
        "p50_ms": round(statistics.median(latencies), 2) if latencies else None,
        "p95_ms": round(latencies[int(len(latencies) * 0.95) - 1], 2) if latencies else None,
        "max_ms": round(latencies[-1], 2) if latencies else None,
        "threads": threads,
        "duration_seconds": duration_seconds,
    }
