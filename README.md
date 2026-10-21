# Ghidra-advanced-MCP

Fork of [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) (v0.2.7) extended with a
212-operation headless catalog, isolated local workers, and team investigations — validated against
real Ghidra 12.1.4 on AArch64, ARM32, x86-64, and native Mach-O ARM64.

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
| Unit suite | 254 passed, 1 skipped |

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
