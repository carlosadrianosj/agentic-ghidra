"""Bounded, process-local timings; snapshots never start a JVM."""

from __future__ import annotations

import math
import os
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager


class Metrics:
    def __init__(self, capacity: int = 512):
        self.capacity = capacity
        self._lock = threading.Lock()
        self._stages: dict[str, dict] = {}

    def _stage(self, stage: str) -> dict:
        return self._stages.setdefault(
            stage,
            {
                "samples": deque(maxlen=self.capacity),
                "count": 0,
                "errors": 0,
                "total_seconds": 0.0,
                "queued": 0,
                "queue_peak": 0,
                "active": 0,
            },
        )

    def observe(self, stage: str, seconds: float, *, error: bool = False) -> None:
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Duration must be finite and nonnegative")
        with self._lock:
            row = self._stage(stage)
            row["samples"].append(seconds)
            row["count"] += 1
            row["errors"] += int(error)
            row["total_seconds"] += seconds

    def error(self, stage: str) -> None:
        """Count protocol-level errors that are returned rather than raised."""
        with self._lock:
            self._stage(stage)["errors"] += 1

    def queue(self, stage: str, delta: int) -> None:
        with self._lock:
            row = self._stage(stage)
            row["queued"] = max(0, row["queued"] + delta)
            row["queue_peak"] = max(row["queue_peak"], row["queued"])

    def active(self, stage: str, delta: int) -> None:
        with self._lock:
            row = self._stage(stage)
            row["active"] = max(0, row["active"] + delta)

    def snapshot(self) -> dict:
        with self._lock:
            stages = {}
            for name, row in self._stages.items():
                samples = sorted(row["samples"])
                stages[name] = {key: value for key, value in row.items() if key != "samples"}
                stages[name].update(
                    {
                        "sample_count": len(samples),
                        "p50_seconds": samples[math.ceil(len(samples) * 0.50) - 1]
                        if samples
                        else None,
                        "p95_seconds": samples[math.ceil(len(samples) * 0.95) - 1]
                        if samples
                        else None,
                    }
                )
        memory = {
            "pid": os.getpid(),
            "rss_bytes": None,
            "peak_rss_bytes": None,
            "jvm_heap_used_bytes": None,
            "jvm_heap_committed_bytes": None,
            "jvm_heap_max_bytes": None,
        }
        try:
            import resource

            memory["peak_rss_bytes"] = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * (
                1 if sys.platform == "darwin" else 1024
            )
            import psutil

            memory["rss_bytes"] = psutil.Process().memory_info().rss
        except (ImportError, OSError):
            pass
        try:
            import jpype

            if jpype.isJVMStarted():
                runtime = jpype.JClass("java.lang.Runtime").getRuntime()
                memory.update(
                    jvm_heap_used_bytes=int(runtime.totalMemory() - runtime.freeMemory()),
                    jvm_heap_committed_bytes=int(runtime.totalMemory()),
                    jvm_heap_max_bytes=int(runtime.maxMemory()),
                )
        except Exception:
            pass
        if memory["rss_bytes"] is None:
            try:
                usage = subprocess.run(
                    ["ps", "-o", "rss=", "-p", str(os.getpid())],
                    capture_output=True,
                    text=True,
                    timeout=1,
                    check=True,
                )
                memory["rss_bytes"] = int(usage.stdout.strip()) * 1024
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        return {"stages": stages, "memory": memory, "sample_capacity": self.capacity}


METRICS = Metrics()


@contextmanager
def measure(stage: str):
    started = time.perf_counter()
    failed = False
    METRICS.active(stage, 1)
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        METRICS.active(stage, -1)
        METRICS.observe(stage, time.perf_counter() - started, error=failed)


def snapshot() -> dict:
    return METRICS.snapshot()
