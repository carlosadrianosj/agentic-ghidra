<p align="center">
  <a href="#english"><img src="https://img.shields.io/badge/lang-English-2ea44f" alt="English"></a>
  <a href="#zh"><img src="https://img.shields.io/badge/%E8%AF%AD%E8%A8%80-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-blue" alt="简体中文"></a>
</p>

<p align="center">
  <img src="icon/agentic-ghidra-logo.png" alt="Agentic-Ghidra" width="400"/>
</p>

<h1 align="center">Agentic-Ghidra</h1>

<p align="center"><em>Many agents, one Ghidra: agentic binary reverse engineering over a catalog of 212 headless operations.</em></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/Python-100%25-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?logo=linux&logoColor=white" alt="Platform: macOS | Linux">
  <img src="https://img.shields.io/badge/Ghidra-12.1.4-orange" alt="Ghidra 12.1.4">
  <img src="https://img.shields.io/badge/arch-AArch64%20%7C%20ARM32%20%7C%20x86--64-success" alt="Arch: AArch64 | ARM32 | x86-64">
  <img src="https://img.shields.io/badge/tools-239%20exposed-blueviolet" alt="Tools: 239 exposed">
  <img src="https://img.shields.io/badge/REST-%2Fapi%2Fv1-teal" alt="REST API">
  <img src="https://img.shields.io/badge/MCP-AI%20assisted-brightgreen" alt="MCP">
</p>

<a id="english"></a>

## English

Agentic-Ghidra started as a fork of [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)
(v0.2.7), which ships twenty headless tools for pointing an MCP client at Ghidra. It has since
grown into a full agentic reverse engineering platform: a catalog of 212 operations (decompilation,
type reconstruction, patching, pcode, transactions), a supervisor that boots isolated JVM workers
on demand, team investigations where multiple agents analyze the same binary without stepping on
each other, and a scriptable REST API beside MCP with one registry serving both protocols.
Everything is validated against real Ghidra 12.1.4 on AArch64, ARM32, x86-64, and native Mach-O
ARM64.

### How to use it (one picture)

<p align="center">
  <img src="icon/agentic-ghidra-flow.svg" alt="MCP and REST clients drive the supervisor, which routes each call by worker_id to an isolated worker JVM" width="760"/>
</p>

Start the supervisor once, then drive it from either side:

```bash
uv sync
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  .venv/bin/ghidra-advanced-mcp --project-path runtime/projects --port 8766
```

### Via MCP

Point any MCP client at the supervisor and drive Ghidra by conversation: list binaries, decompile,
rename, rebuild structs, patch bytes, export. Workers start on demand and are routed by
`worker_id`; see `--help` for supervisor options (max active workers, per worker ports,
decompiler pool size).

```json
{
  "mcpServers": {
    "ghidra": { "url": "http://127.0.0.1:8766/mcp" }
  }
}
```

### Via REST

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
| `GET /api/v1/openapi.json` | machine readable route list |

Success envelope: `{"status":"ok","tool":...,"duration_ms":...,"session_id":...,"result":...}`.
Errors map to HTTP by exception kind: `ValueError`→400, `FileNotFoundError`→404,
`PermissionError`→403, `TimeoutError`→504, unknown tool→404.

**Auth**: dev mode (default, loopback) shares one `rest-local` owner. Pass
`--rest-api-key <sha256-hex>` (or `GHIDRA_ADVANCED_REST_API_KEY`) to require
`Authorization: Bearer <token>` / `X-API-Key` on `/api/v1/*`; each key is its own owner for
session isolation.

### What is included

- **Advanced catalog**: 212 operations across 34 families (`analysis`, `decomp`, `function`,
  `listing`, `memory`, `pcode`, `patch`, `symbol`, `reference`, `type`, `transaction`, …) plus the
  20 legacy headless tools. Source names are preserved as aliases; an alias is never counted as a
  new capability. The pinned equivalence matrix lives in
  `src/pyghidra_mcp/advanced/reference_catalog.json`; run `python tools/check_catalog.py`
  locally to fail when `source_names - implemented_or_mapped != ∅`.
- **Sessions and transactions**: every operation is session bound with explicit read/write modes,
  locks per program, undo/redo, revert, and decompiler/index cache invalidation after mutations.
- **Local worker supervisor** (`ghidra-advanced-mcp` CLI): JVM workers on demand with isolated
  projects, ports, and Chroma indexes; task queue with safe cancellation and restart.
- **Investigations** (`investigation.create`): two or more teams analyzing the same binary
  (common SHA-256) with fully isolated projects, indexes, ports, and mutations.
- **REST API beside MCP**: the supervisor serves `/mcp` and `/api/v1/*` on the same port. One
  registry, two protocols; chain calls from plain Python or curl for custom RE pipelines.
- **Trusted code policy**: `ghidra.call`, `ghidra.eval`, and `ghidra.script` require
  `--advanced-trusted-code` (default off). They are session bound, time limited, and logged with
  owner/session/write flags. They execute arbitrary code: enable only for trusted local clients.
  The transports have no authentication; do not expose them to untrusted networks.

### Verification

All acceptance evidence below was produced with real Ghidra 12.1.4 (headless, no mocks) and lives
under `runtime/acceptance/` when generated locally.

| Scope | Result |
| --- | --- |
| 212 advanced + 20 legacy operations, native Mach-O ARM64 | all pass (`native-all-evidence.json`) |
| 212 operations, ELF aarch64 / arm / x86_64 | all pass (`elf-all-evidence.json`) |
| Annotations incl. branch inversion + reopen persistence, 4 architectures | 32/32 each (`annotations-*.json`) |
| Supervisor, 3 concurrent MCP clients, isolation, semantic index rebuild | pass (`mcp-evidence.json`, 239 tools) |
| Same binary teams (tls/raw), isolated mutations, restart survival | pass (`investigations-evidence.json`) |
| REST pipeline over real worker (open, decompile, close) | pass (`rest-smoke.json`) |
| Unit suite (incl. REST contract tests) | 262 passed, 1 skipped |

Regenerate with:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/verify_advanced.py \
  --fixture runtime/acceptance/fixtures/native --output runtime/acceptance/native-all-evidence.json
GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/benchmark_workers.py \
  --binary runtime/acceptance/fixtures/native --counts 1 2 4 --iterations 12
```

### Parallel worker benchmark (same binary, 12 iterations)

| Workers | Concurrent decompile throughput | p95 latency | Boot (s, serialized) | Cold/warm import (s) | RSS per JVM |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 63.5/s | 31 ms | 2.6 | 0.90 / 0.44 | 1006 MiB |
| 2 | 83.1/s | 35 ms | 2.6, 5.2 | 3.6→0.9 / ~0.5 | 874–1039 MiB |
| 4 | 128.1/s | 49 ms | 2.6…10.3 | 9.0→1.1 / ~0.6 | 745–912 MiB |

All runs: analysis overlap observed, `save`/reopen integrity true on every worker. Per stage
telemetry (`mcp_request`, `import`, `analyze`, `decompile`(+pool wait), `indexing`(+queue wait),
`program_lock_wait`) and JVM memory counters are recorded in `measurements.json`. Cold imports
degrade while workers boot concurrently (shared disk/CPU); warm imports stay ~0.5 s.

---

<a id="zh"></a>

## 简体中文

Agentic-Ghidra 起源于 [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)（v0.2.7）的
fork，原项目提供二十个无头工具，用于让 MCP 客户端接入 Ghidra。此后它成长为完整的智能体
逆向分析平台：212 项操作目录（反编译、类型重建、打补丁、pcode、事务）、按需启动隔离 JVM
工作进程的 supervisor、多团队互不干扰地分析同一二进制的 investigation 机制，以及与 MCP
并列的可脚本化 REST API，同一份注册表服务两种协议。所有能力均在真实 Ghidra 12.1.4 上
验证，覆盖 AArch64、ARM32、x86-64 以及原生 Mach-O ARM64。

### 一图看懂怎么用

<p align="center">
  <img src="icon/agentic-ghidra-flow.svg" alt="MCP 与 REST 客户端驱动 supervisor，后者按 worker_id 把每次调用路由到隔离的 JVM 工作进程" width="760"/>
</p>

先启动一次 supervisor，然后从任意一侧驱动它：

```bash
uv sync
GHIDRA_INSTALL_DIR=/path/to/ghidra \
  .venv/bin/ghidra-advanced-mcp --project-path runtime/projects --port 8766
```

### 通过 MCP 使用

把任意 MCP 客户端指向 supervisor，用对话驱动 Ghidra：列出二进制、反编译、重命名、重建
结构体、打补丁、导出。工作进程按需启动，并按 `worker_id` 路由；supervisor 选项（最大
活跃工作进程数、每进程端口、反编译池大小）见 `--help`。

```json
{
  "mcpServers": {
    "ghidra": { "url": "http://127.0.0.1:8766/mcp" }
  }
}
```

### 通过 REST 使用

与 MCP 同进程同端口。每个工具（212 项高级 + 20 项遗留 + 7 项管理）都可按名称调用，
传入符合其输入 schema 的 JSON 对象：

```bash
curl -s localhost:29950/health | jq .status
curl -s localhost:29950/api/v1/tools?family=decomp | jq '.count'
curl -s -XPOST localhost:29950/api/v1/tools/decomp.function \
  -H 'content-type: application/json' \
  -d '{"worker_id":"rest_smoke","session_id":"...","function_start":"00100438"}' | jq .result.code
```

| 端点 | 用途 |
| --- | --- |
| `GET /health` | 存活状态与工作进程快照 |
| `GET /api/v1/tools` | 带输入 schema 的工具目录；支持 `family`、`q`、`read_only` 过滤 |
| `GET/POST /api/v1/tools/{name}` | 查看 schema / 调用任意工具 |
| `POST /api/v1/batch` | 顺序调用；`pipeline: true` 会把每次结果合并进下一次调用参数 |
| `GET /api/v1/workers`，`POST /api/v1/workers/{id}/{start,stop,restart}` | 工作进程生命周期 |
| `GET/POST /api/v1/investigations`，`GET /api/v1/investigations/{id}` | 多团队调查 |
| `GET /api/v1/openapi.json` | 机器可读的路由列表 |

成功响应统一封装为 `{"status":"ok","tool":...,"duration_ms":...,"session_id":...,"result":...}`。
错误按异常类型映射为 HTTP 状态：`ValueError`→400、`FileNotFoundError`→404、
`PermissionError`→403、`TimeoutError`→504、未知工具→404。

**鉴权**：开发模式（默认，回环地址）共用一个 `rest-local` 所有者。传入
`--rest-api-key <sha256-hex>`（或环境变量 `GHIDRA_ADVANCED_REST_API_KEY`）后，
`/api/v1/*` 要求 `Authorization: Bearer <token>` 或 `X-API-Key`；每个 key 都是其独立的
所有者，用于会话隔离。

### 包含内容

- **高级操作目录**：34 个族共 212 项操作（`analysis`、`decomp`、`function`、`listing`、
  `memory`、`pcode`、`patch`、`symbol`、`reference`、`type`、`transaction` 等），外加 20 个
  遗留无头工具。源名称保留为别名；别名不会被计入新能力。固定的等价矩阵位于
  `src/pyghidra_mcp/advanced/reference_catalog.json`；本地运行 `python tools/check_catalog.py`，
  当 `source_names - implemented_or_mapped != ∅` 时直接失败。
- **会话与事务**：每个操作都绑定会话，带显式读写模式、按程序加锁、undo/redo、revert，
  以及变更后对反编译器和索引缓存的失效处理。
- **本地工作进程 supervisor**（`ghidra-advanced-mcp` CLI）：按需启动 JVM 工作进程，
  项目、端口与 Chroma 索引彼此隔离；任务队列支持安全取消与重启。
- **多团队调查**（`investigation.create`）：两个或更多团队分析同一个二进制（相同
  SHA-256），项目、索引、端口与变更完全隔离。
- **与 MCP 并列的 REST API**：supervisor 在同一端口提供 `/mcp` 与 `/api/v1/*`。一份注册表，
  两种协议；用纯 Python 或 curl 串联调用，构建自定义逆向流水线。
- **可信代码策略**：`ghidra.call`、`ghidra.eval` 与 `ghidra.script` 需要
  `--advanced-trusted-code`（默认关闭）。它们绑定会话、限时执行，并以 owner、session、
  write 标志记录日志。它们会执行任意代码：仅对可信的本地客户端开启。传输层没有鉴权，
  不要暴露给不受信任的网络。

### 验证

下表所有验收证据均由真实 Ghidra 12.1.4（无头、无 mock）产出，本地生成时位于
`runtime/acceptance/`。

| 范围 | 结果 |
| --- | --- |
| 212 项高级 + 20 项遗留操作，原生 Mach-O ARM64 | 全部通过（`native-all-evidence.json`） |
| 212 项操作，ELF aarch64 / arm / x86_64 | 全部通过（`elf-all-evidence.json`） |
| 注解（含分支反转与重开持久化），4 种架构 | 每架构 32/32（`annotations-*.json`） |
| supervisor、3 个并发 MCP 客户端、隔离、语义索引重建 | 通过（`mcp-evidence.json`，239 个工具） |
| 同一二进制多团队（tls/raw）、变更隔离、重启存活 | 通过（`investigations-evidence.json`） |
| 真实工作进程上的 REST 流水线（打开、反编译、关闭） | 通过（`rest-smoke.json`） |
| 单元套件（含 REST 契约测试） | 262 通过，1 跳过 |

重新生成：

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/verify_advanced.py \
  --fixture runtime/acceptance/fixtures/native --output runtime/acceptance/native-all-evidence.json
GHIDRA_INSTALL_DIR=/path/to/ghidra .venv/bin/python tools/benchmark_workers.py \
  --binary runtime/acceptance/fixtures/native --counts 1 2 4 --iterations 12
```

### 并行工作进程基准（同一二进制，12 轮）

| 工作进程 | 并发反编译吞吐 | p95 延迟 | 启动（秒，串行） | 冷/热导入（秒） | 每 JVM RSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 63.5/s | 31 ms | 2.6 | 0.90 / 0.44 | 1006 MiB |
| 2 | 83.1/s | 35 ms | 2.6, 5.2 | 3.6→0.9 / ~0.5 | 874–1039 MiB |
| 4 | 128.1/s | 49 ms | 2.6…10.3 | 9.0→1.1 / ~0.6 | 745–912 MiB |

所有轮次：观察到分析重叠，每个工作进程的 `save` 与重开完整性均为真。分阶段遥测
（`mcp_request`、`import`、`analyze`、`decompile`（含池等待）、`indexing`（含队列等待）、
`program_lock_wait`）与 JVM 内存计数记录在 `measurements.json`。多个工作进程并发启动时
冷导入会退化（磁盘与 CPU 共享）；热导入稳定在约 0.5 秒。
