# Ghidra-advanced-MCP

Fork of [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) (v0.2.7) extended with a
212-operation headless catalog, isolated local workers, team investigations, and a scriptable
REST API — validated against real Ghidra 12.1.4 on AArch64, ARM32, x86-64, and native Mach-O
ARM64.

## What is included

- **Advanced catalog**: 212 operations across 34 families (`analysis`, `decomp`, `function`,
  `listing`, `memory`, `pcode`, `patch`, `symbol`, `reference`, `type`, `transaction`, …) plus the
  20 legacy headless tools. Source names are preserved as aliases; an alias is never counted as a
  new capability. The pinned equivalence matrix lives in
  `src/pyghidra_mcp/advanced/reference_catalog.json`; run `python tools/check_catalog.py`
  locally to fail when `source_names - implemented_or_mapped != ∅`.
- **Sessions and transactions**: every operation is session-bound with explicit read/write modes,
  per-program locks, undo/redo, revert, and decompiler/index cache invalidation after mutations.
- **Local worker supervisor** (`ghidra-advanced-mcp` CLI): on-demand JVM workers with isolated
  projects, ports, and Chroma indexes; task queue with safe cancellation and restart.
- **Investigations** (`investigation.create`): two or more teams analyzing the same binary
  (common SHA-256) with fully isolated projects, indexes, ports, and mutations.
- **REST API beside MCP**: the supervisor serves `/mcp` and `/api/v1/*` on the same port. One
  registry, two protocols — chain calls from plain Python/curl for custom RE pipelines.
- **Trusted code policy**: `ghidra.call`, `ghidra.eval`, and `ghidra.script` require
  `--advanced-trusted-code` (default off). They are session-bound, time-limited, and logged with
  owner/session/write flags. They execute arbitrary code: enable only for trusted local clients.
  The transports have no authentication; do not expose them to untrusted networks.

## Running

```bash
uv sync
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  .venv/bin/ghidra-advanced-mcp --project-path runtime/projects --port 8766
```

Workers are started on demand and routed by `worker_id`; see `--help` for the supervisor options
(max active workers, per-worker ports, decompiler pool size).

## REST API

Same process and port as MCP. Every tool (212 advanced + 20 legacy + 7 management) is callable
by name with a JSON object of its input schema:

```bash
curl -s localhost:29950/health | jq .status
curl -s localhost:29950/api/v1/tools?family=decomp | jq '.count'
curl -s -XPOST localhost:29950/api/v1/tools/decomp.function \
  -H 'content-type: application/json' \
  -d '{"worker_id":"rest_smoke","session_id":"...","function_start":"00100438"}' | jq .result.code
```

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | liveness plus worker snapshot |
| `GET /api/v1/tools` | catalog with input schemas; filters `family`, `q`, `read_only` |
| `GET/POST /api/v1/tools/{name}` | schema / invoke any tool |
| `POST /api/v1/batch` | sequential calls; `pipeline: true` merges each result into the next arguments |
| `GET /api/v1/workers`, `POST /api/v1/workers/{id}/{start,stop,restart}` | worker lifecycle |
| `GET/POST /api/v1/investigations`, `GET /api/v1/investigations/{id}` | team investigations |
| `GET /api/v1/openapi.json` | machine-readable route list |

Success envelope: `{"status":"ok","tool":...,"duration_ms":...,"session_id":...,"result":...}`.
Errors map to HTTP by exception kind: `ValueError`→400, `FileNotFoundError`→404,
`PermissionError`→403, `TimeoutError`→504, unknown tool→404.

**Auth**: dev mode (default, loopback) shares one `rest-local` owner. Pass
`--rest-api-key <sha256-hex>` (or `GHIDRA_ADVANCED_REST_API_KEY`) to require
`Authorization: Bearer <token>` / `X-API-Key` on `/api/v1/*`; each key is its own owner for
session isolation.

**Custom pipelines**: `examples/rest_pipeline.py` chains health → worker start → open →
function list → decompile → constant search → close → stop using only `urllib`:

```bash
python examples/rest_pipeline.py http://127.0.0.1:29950 rest_smoke /path/to/binary
```

## Verification

All acceptance evidence below was produced with real Ghidra 12.1.4 (headless, no mocks) and lives
under `runtime/acceptance/` when generated locally.

| Scope | Result |
| --- | --- |
| 212 advanced + 20 legacy operations, native Mach-O ARM64 | all pass (`native-all-evidence.json`) |
| 212 operations, ELF aarch64 / arm / x86_64 | all pass (`elf-all-evidence.json`) |
| Annotations incl. branch inversion + reopen persistence, 4 architectures | 32/32 each (`annotations-*.json`) |
| Supervisor, 3 concurrent MCP clients, isolation, semantic index rebuild | pass (`mcp-evidence.json`, 239 tools) |
| Same-binary teams (tls/raw), isolated mutations, restart survival | pass (`investigations-evidence.json`) |
| REST pipeline over real worker (open→decompile→close) | pass (`rest-smoke.json`) |
| Unit suite (incl. REST contract tests) | 262 passed, 1 skipped |

Regenerate with:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/verify_advanced.py \
  --fixture runtime/acceptance/fixtures/native --output runtime/acceptance/native-all-evidence.json
GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/benchmark_workers.py \
  --binary runtime/acceptance/fixtures/native --counts 1 2 4 --iterations 12
```

## Parallel-worker benchmark (same binary, 12 iterations)

| Workers | Concurrent decompile throughput | p95 latency | Boot (s, serialized) | Cold/warm import (s) | RSS per JVM |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 63.5/s | 31 ms | 2.6 | 0.90 / 0.44 | 1006 MiB |
| 2 | 83.1/s | 35 ms | 2.6, 5.2 | 3.6→0.9 / ~0.5 | 874–1039 MiB |
| 4 | 128.1/s | 49 ms | 2.6…10.3 | 9.0→1.1 / ~0.6 | 745–912 MiB |

All runs: analysis overlap observed, `save`/reopen integrity true on every worker. Per-stage
telemetry (`mcp_request`, `import`, `analyze`, `decompile`(+pool wait), `indexing`(+queue wait),
`program_lock_wait`) and JVM memory counters are recorded in `measurements.json`. Cold imports
degrade while workers boot concurrently (shared disk/CPU); warm imports stay ~0.5 s.
