#!/usr/bin/env python3
"""Generate docs/llm.txt and docs/llm-zh.txt from a live tool catalog dump.

Usage:
    # start the supervisor, then dump the catalog once
    curl -s localhost:29840/api/v1/tools > /tmp/tools.json
    python tools/gen_llms_doc.py --catalog /tmp/tools.json

The catalog file is the JSON served by GET /api/v1/tools. Tool names, families
and input schemas are rendered from it; the worked examples embed real outputs
captured against Ghidra 12.1.4.
"""

from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

MANAGEMENT_FAMILIES = {"worker_status", "worker_start", "worker_stop", "worker_restart", "investigation"}

FAMILY_BLURB_EN = {
    "analysis": "Run and configure Ghidra analysis, inspect analyzer and option state.",
    "bookmark": "Create, list and remove address bookmarks.",
    "class": "Create Ghidra classes.",
    "comment": "Read and write plate, pre, post, eol and repeatable comments.",
    "context": "Inspect and set processor context register ranges.",
    "decomp": "Decompile functions, trace types, rename and retype globals, write results back.",
    "equate": "Manage equates, mapping scalar values to names.",
    "external": "Manage external libraries, locations, entry points, imports and exports.",
    "function": "Create, delete, rename and inspect functions, signatures and calling conventions.",
    "ghidra": "Trusted execution: eval, script and call into the live Ghidra JVM. Gated behind --advanced-trusted-code.",
    "graph": "Control flow and call path graphs.",
    "health": "Liveness probes.",
    "layout": "Build structs, unions and enums, including fill from decompiler inference.",
    "listing": "Code units, data, disassembly seeds and ranges.",
    "mcp": "Transport level metadata such as the response format.",
    "memory": "Read and write memory, manage memory blocks.",
    "metadata": "Store and query arbitrary program metadata.",
    "namespace": "Create namespaces.",
    "parameter": "Add, move, remove and replace function parameters.",
    "patch": "Patch instructions: nop, assemble, invert branches.",
    "pcode": "Pcode operations, blocks and varnode uses.",
    "program": "Open, close, save, export and inspect programs.",
    "project": "Inspect Ghidra projects, files and folders.",
    "reference": "Create, list, clear and delete references of every kind.",
    "relocation": "List and add relocations.",
    "search": "Search bytes, instructions, text, constants, defined strings and pcode.",
    "source": "Map source files and line ranges to addresses.",
    "stackframe": "Inspect and create stack frame variables.",
    "symbol": "Create, rename, move and delete symbols, set primary symbols.",
    "tag": "Function tags with statistics.",
    "task": "Async analysis tasks: status, result, cancel.",
    "transaction": "Explicit transactions with commit, revert, undo and redo.",
    "type": "Parse C, define, list, rename and delete data types and categories.",
    "variable": "Create, rename, retype and comment local variables.",
    "worker_status": "Management: inspect one worker.",
    "worker_start": "Management: start one worker.",
    "worker_stop": "Management: stop one worker.",
    "worker_restart": "Management: restart one worker.",
    "investigation": "Management: create and inspect multi team investigations.",
}

FAMILY_BLURB_ZH = {
    "analysis": "运行与配置 Ghidra 分析，查看分析器与选项状态。",
    "bookmark": "创建、列出与删除地址书签。",
    "class": "创建 Ghidra class。",
    "comment": "读写 plate、pre、post、eol 与 repeatable 注释。",
    "context": "查看与设置处理器上下文寄存器区间。",
    "decomp": "反编译函数、追踪类型、重命名与重定型全局、回写结果。",
    "equate": "管理 equate，把标量映射为名字。",
    "external": "管理外部库、外部位置、入口点、导入与导出。",
    "function": "创建、删除、重命名与检查函数、签名与调用约定。",
    "ghidra": "可信执行：eval、script 与直接调用 Ghidra JVM。需 --advanced-trusted-code 门禁。",
    "graph": "控制流图与调用路径图。",
    "health": "存活探测。",
    "layout": "构建 struct、union 与 enum，包括从反编译推断自动填充。",
    "listing": "code unit、数据、反汇编种子与区间。",
    "mcp": "传输层元信息，例如响应格式。",
    "memory": "读写内存，管理内存块。",
    "metadata": "存储与查询任意程序元数据。",
    "namespace": "创建命名空间。",
    "parameter": "新增、移动、删除与替换函数参数。",
    "patch": "打指令补丁：nop、汇编、反转分支。",
    "pcode": "pcode 操作、块与 varnode 使用。",
    "program": "打开、关闭、保存、导出与检查程序。",
    "project": "检查 Ghidra 项目、文件与目录。",
    "reference": "创建、列出、清除与删除各类引用。",
    "relocation": "列出与新增重定位。",
    "search": "搜索字节、指令、文本、常量、已定义字符串与 pcode。",
    "source": "把源码文件与行区间映射到地址。",
    "stackframe": "检查与创建栈帧变量。",
    "symbol": "创建、重命名、移动与删除符号，设置 primary 符号。",
    "tag": "函数标签与统计。",
    "task": "异步分析任务：状态、结果、取消。",
    "transaction": "显式事务，支持 commit、revert、undo 与 redo。",
    "type": "解析 C、定义、列出、重命名与删除数据类型和分类。",
    "variable": "创建、重命名、重定型与注释局部变量。",
    "worker_status": "管理：查看单个工作进程。",
    "worker_start": "管理：启动单个工作进程。",
    "worker_stop": "管理：停止单个工作进程。",
    "worker_restart": "管理：重启单个工作进程。",
    "investigation": "管理：创建与检查多团队调查。",
}

LEGACY_BLURB_EN = (
    "The 20 original pyghidra-mcp headless tools. They are preserved as aliases with "
    "their source names; the advanced catalog covers the same ground."
)
LEGACY_BLURB_ZH = (
    "原 pyghidra-mcp 的 20 个无头工具。以源名称保留为别名；高级目录覆盖同样的能力。"
)


def fmt_type(prop: dict) -> str:
    if "oneOf" in prop:
        return "|".join(fmt_type(p) for p in prop["oneOf"])
    t = prop.get("type", "any")
    if t == "array":
        items = prop.get("items", {})
        return f"array<{fmt_type(items)}>"
    if "enum" in prop:
        return "|".join(str(v) for v in prop["enum"])
    return str(t)


def render_tool(tool: dict) -> list[str]:
    schema = tool.get("input_schema", {})
    props: dict = schema.get("properties", {})
    required = set(schema.get("required", []))
    lines = [f"#### {tool['name']}", ""]
    desc = (tool.get("description") or "").strip()
    if desc:
        lines += [desc, ""]
    mode = "read only" if tool.get("read_only") else "write (needs a writable session)"
    lines += [f"Mode: {mode}."]
    if props:
        lines += ["Input:"]
        for name, prop in props.items():
            t = fmt_type(prop)
            bits = []
            if name in required:
                bits.append("required")
            if "default" in prop and prop["default"] is not None:
                bits.append(f"default {json.dumps(prop['default'])}")
            if prop.get("minLength"):
                bits.append(f"min length {prop['minLength']}")
            suffix = f" ({', '.join(bits)})" if bits else ""
            lines.append(f"- `{name}`: {t}{suffix}")
        lines.append("")
    return lines


def group_tools(tools: list[dict]) -> OrderedDict[str, list[dict]]:
    fams: OrderedDict[str, list[dict]] = OrderedDict()
    for t in sorted(tools, key=lambda x: x["name"]):
        fam = t["family"]
        if fam in MANAGEMENT_FAMILIES or fam.startswith("worker_"):
            fams.setdefault("__management__", []).append(t)
        elif fam == t["name"]:
            fams.setdefault("__legacy__", []).append(t)
        else:
            fams.setdefault(fam, []).append(t)
    return fams


def render_reference(tools: list[dict], zh: bool) -> list[str]:
    fams = group_tools(tools)
    blurbs = FAMILY_BLURB_ZH if zh else FAMILY_BLURB_EN
    out: list[str] = []
    for fam, items in fams.items():
        if fam == "__management__":
            title = "Management tools" if not zh else "管理工具"
        elif fam == "__legacy__":
            title = "Legacy tools" if not zh else "遗留工具"
        else:
            title = fam
        out += [f"## {title} ({len(items)})", ""]
        if fam == "__legacy__":
            out += [LEGACY_BLURB_ZH if zh else LEGACY_BLURB_EN, ""]
        elif fam in blurbs:
            out += [blurbs[fam], ""]
        for t in items:
            out += render_tool(t)
    return out


EN_HEAD = """# Agentic-Ghidra

> Agentic binary reverse engineering over one headless Ghidra catalog: 239 tools
> through MCP and REST, isolated JVM workers, transactions, no GUI.

Repo: https://github.com/carlosadrianosj/agentic-ghidra (Apache-2.0). This file is a
complete usage reference for LLM clients: how to connect, the response envelope,
routing, sessions, transactions, a worked example with real outputs, and every
tool with its input schema.

## Quickstart

Requirements: macOS or Linux, JDK 21, Ghidra 12.1.4, uv.

```bash
./run.sh          # detects Ghidra, uv sync, default worker config, port 29840
```

- MCP endpoint: http://127.0.0.1:29840/mcp (any MCP client)
- REST base: http://127.0.0.1:29840 (health at /health, tools at /api/v1)

## Using via MCP

Point any MCP client at the supervisor:

```json
{
  "mcpServers": {
    "ghidra": { "url": "http://127.0.0.1:29840/mcp" }
  }
}
```

Every exposed tool schema carries an extra `worker_id` string property: the
explicit target worker from `worker_status`. Workers are never auto rerouted; a
call names its worker or fails. Workers boot on first routed call, each with an
isolated project, port and index.

## Using via REST

Same process and port. Call any tool by name with a JSON body holding its input
schema plus the transport level `worker_id`:

```bash
curl -s localhost:29840/health | jq .status
curl -s "localhost:29840/api/v1/tools?family=decomp" | jq .count
curl -s -XPOST localhost:29840/api/v1/tools/decomp.function \\
  -H 'content-type: application/json' \\
  -d '{"worker_id":"main","session_id":"...","function_start":"_main"}'
```

| Endpoint | Purpose |
| --- | --- |
| GET /health | Liveness plus worker snapshot |
| GET /api/v1/tools | Tool catalog with input schemas; filters `family`, `q`, `read_only` |
| GET /api/v1/tools/{name} | Input schema of one tool |
| POST /api/v1/tools/{name} | Invoke any tool by name |
| POST /api/v1/batch | Sequential calls; `pipeline: true` feeds each result into the next call |
| GET /api/v1/workers | Worker snapshot |
| POST /api/v1/workers/{worker_id}/{start,stop,restart} | Worker lifecycle |
| GET/POST /api/v1/investigations | List or create team investigations |
| GET /api/v1/investigations/{investigation_id} | One investigation |
| GET /api/v1/openapi.json | Machine readable route list |

## Response envelope, errors, auth

Every success returns the same envelope:

```json
{"status":"ok","tool":"decomp.function","duration_ms":11,"session_id":"main:...","result":{...}}
```

Errors map to HTTP by exception kind: ValueError 400, FileNotFoundError 404,
PermissionError 403, TimeoutError 504, unknown tool 404.

Dev mode (default, loopback) shares one `rest-local` owner. Pass
`--rest-api-key <sha256-hex>` (or GHIDRA_ADVANCED_REST_API_KEY) to require
`Authorization: Bearer <token>` or `X-API-Key` on /api/v1/*; each key is its own
owner for session isolation.

## Sessions, transactions, routing

- `session_id` binds a program open in one worker. Opening a program returns it;
  every later tool call repeats it plus `worker_id`.
- Sessions have explicit read/write modes. Write tools refuse read only sessions.
- Mutations can run inside `transaction.begin` ... `transaction.commit` (or
  `transaction.revert`), with undo and redo available.
- After any mutation the decompiler and index caches invalidate; the next read
  sees current program state.
- `ghidra.call`, `ghidra.eval` and `ghidra.script` require the supervisor flag
  `--advanced-trusted-code` (default off). They execute arbitrary code in the
  worker JVM: only enable for trusted local clients. Transports have no auth
  beyond the optional REST key; never expose them to untrusted networks.

## Worked example (real outputs, Ghidra 12.1.4, Mach-O ARM64)

Open bytes on worker `main` (read only). The worker boots on this first routed
call; `duration_ms` drops to single digits afterwards:

```json
POST /api/v1/tools/program.open_bytes
{"worker_id":"main","data_base64":"<base64 of the binary>","filename":"llms_demo.bin","read_only":true}

{"status":"ok","tool":"program.open_bytes","duration_ms":6421,
 "result":{"session_id":"main:648f83d8988be9f4:XtV64t9l...","project_id":"cc88cd392f6fed6e97fcf3f5",
           "binary_name":"/llms_demo.bin-3bcc5a","name":"llms_demo.bin","read_only":true,"deterministic":false},
 "session_id":"main:648f83d8988be9f4:XtV64t9l..."}
```

List functions with the returned session:

```json
POST /api/v1/tools/function.list
{"worker_id":"main","session_id":"main:648f83d8988be9f4:XtV64t9l...","limit":3}

{"status":"ok","tool":"function.list","duration_ms":598,
 "result":{"functions":[
   {"name":"_advanced_type_fill","address":"1000004f8","signature":"undefined _advanced_type_fill(void)",
    "external":false,"thunk":false,"body":"[[1000004f8, 100000527]]","parameter_count":0,
    "calling_convention":"unknown","return_type":"undefined","varargs":false,"inline":false,
    "noreturn":false,"custom_storage":false},
   ...
 ]}}
```

Decompile one function by name or address:

```json
POST /api/v1/tools/decomp.function
{"worker_id":"main","session_id":"main:648f83d8988be9f4:XtV64t9l...","function_start":"_advanced_add"}

{"status":"ok","tool":"decomp.function","duration_ms":11,
 "result":{"function":"100000528","signature":"int _advanced_add(int param_1,int param_2);",
           "code":"\\nint _advanced_add(int param_1,int param_2)\\n\\n{\\n  ...\\n}\\n"}}
```

Close the session:

```json
POST /api/v1/tools/program.close
{"worker_id":"main","session_id":"main:648f83d8988be9f4:XtV64t9l..."}

{"status":"ok","tool":"program.close","duration_ms":2,"result":{"closed":true,"session_id":"main:..."}}
```

## Tool reference

All 239 tools follow the same rules: names are dotted `family.operation`, every
call carries `worker_id` plus the tool input schema, every response uses the
envelope above. Mode marks read only tools; anything else needs a writable
session.
"""

ZH_HEAD = """# Agentic-Ghidra

> 基于同一份 Ghidra 无头目录的智能体二进制逆向分析：239 个工具，MCP 与 REST 双通道，
> 隔离 JVM 工作进程，事务支持，无需 GUI。

仓库：https://github.com/carlosadrianosj/agentic-ghidra（Apache-2.0）。本文件是面向
LLM 客户端的完整使用参考：如何接入、响应封装、路由、会话、事务、带真实输出的完整
示例，以及全部工具及其输入 schema。工具名与工具描述保持英文原文。

## 快速开始

环境要求：macOS 或 Linux、JDK 21、Ghidra 12.1.4、uv。

```bash
./run.sh          # 自动检测 Ghidra、uv sync、默认 worker 配置、端口 29840
```

- MCP 端点：http://127.0.0.1:29840/mcp（任意 MCP 客户端）
- REST 基址：http://127.0.0.1:29840（/health 与 /api/v1）

## 通过 MCP 使用

把任意 MCP 客户端指向 supervisor：

```json
{
  "mcpServers": {
    "ghidra": { "url": "http://127.0.0.1:29840/mcp" }
  }
}
```

每个暴露的工具 schema 都带一个额外的 `worker_id` 字符串属性：即 `worker_status`
里显式选择的目标工作进程。工作进程从不自动改路由；调用必须指名 worker，否则失败。
工作进程在首次被路由调用时启动，各自拥有隔离的项目、端口与索引。

## 通过 REST 使用

同进程同端口。按名称调用任意工具，JSON body 为其输入 schema 加上传输层的
`worker_id`：

```bash
curl -s localhost:29840/health | jq .status
curl -s "localhost:29840/api/v1/tools?family=decomp" | jq .count
curl -s -XPOST localhost:29840/api/v1/tools/decomp.function \\
  -H 'content-type: application/json' \\
  -d '{"worker_id":"main","session_id":"...","function_start":"_main"}'
```

| 端点 | 用途 |
| --- | --- |
| GET /health | 存活状态与工作进程快照 |
| GET /api/v1/tools | 带输入 schema 的工具目录；支持 `family`、`q`、`read_only` 过滤 |
| GET /api/v1/tools/{name} | 单个工具的输入 schema |
| POST /api/v1/tools/{name} | 按名称调用任意工具 |
| POST /api/v1/batch | 顺序调用；`pipeline: true` 会把每次结果喂给下一次调用 |
| GET /api/v1/workers | 工作进程快照 |
| POST /api/v1/workers/{worker_id}/{start,stop,restart} | 工作进程生命周期 |
| GET/POST /api/v1/investigations | 列出或创建多团队调查 |
| GET /api/v1/investigations/{investigation_id} | 单个调查 |
| GET /api/v1/openapi.json | 机器可读的路由列表 |

## 响应封装、错误与鉴权

每次成功都返回同样的封装：

```json
{"status":"ok","tool":"decomp.function","duration_ms":11,"session_id":"main:...","result":{...}}
```

错误按异常类型映射为 HTTP 状态：ValueError 400、FileNotFoundError 404、
PermissionError 403、TimeoutError 504、未知工具 404。

开发模式（默认，回环地址）共用一个 `rest-local` 所有者。传入
`--rest-api-key <sha256-hex>`（或环境变量 GHIDRA_ADVANCED_REST_API_KEY）后，
/api/v1/* 要求 `Authorization: Bearer <token>` 或 `X-API-Key`；每个 key 都是独立
所有者，用于会话隔离。

## 会话、事务与路由

- `session_id` 绑定某个工作进程中打开的程序。打开程序时会返回它；之后的每次调用
  都带上它和 `worker_id`。
- 会话有显式读写模式。写工具会拒绝只读会话。
- 变更可以包在 `transaction.begin` ... `transaction.commit`（或 `transaction.revert`）
  之间执行，另提供 undo 与 redo。
- 任何变更后，反编译器与索引缓存都会失效；下一次读取总能看到最新程序状态。
- `ghidra.call`、`ghidra.eval`、`ghidra.script` 需要 supervisor 标志
  `--advanced-trusted-code`（默认关闭）。它们会在工作进程 JVM 内执行任意代码：仅对
  可信的本地客户端开启。除可选的 REST key 外传输层没有鉴权，绝不要暴露给不受信任
  的网络。

## 完整示例（真实输出，Ghidra 12.1.4，Mach-O ARM64）

在 worker `main` 上打开字节（只读）。首次被路由的调用会启动该工作进程；之后
`duration_ms` 会降到个位数毫秒：

```json
POST /api/v1/tools/program.open_bytes
{"worker_id":"main","data_base64":"<二进制文件的 base64>","filename":"llms_demo.bin","read_only":true}

{"status":"ok","tool":"program.open_bytes","duration_ms":6421,
 "result":{"session_id":"main:648f83d8988be9f4:XtV64t9l...","project_id":"cc88cd392f6fed6e97fcf3f5",
           "binary_name":"/llms_demo.bin-3bcc5a","name":"llms_demo.bin","read_only":true,"deterministic":false},
 "session_id":"main:648f83d8988be9f4:XtV64t9l..."}
```

用返回的会话列出函数：

```json
POST /api/v1/tools/function.list
{"worker_id":"main","session_id":"main:648f83d8988be9f4:XtV64t9l...","limit":3}

{"status":"ok","tool":"function.list","duration_ms":598,
 "result":{"functions":[
   {"name":"_advanced_type_fill","address":"1000004f8","signature":"undefined _advanced_type_fill(void)",
    "external":false,"thunk":false,"body":"[[1000004f8, 100000527]]","parameter_count":0,
    "calling_convention":"unknown","return_type":"undefined","varargs":false,"inline":false,
    "noreturn":false,"custom_storage":false},
   ...
 ]}}
```

按名称或地址反编译函数：

```json
POST /api/v1/tools/decomp.function
{"worker_id":"main","session_id":"main:648f83d8988be9f4:XtV64t9l...","function_start":"_advanced_add"}

{"status":"ok","tool":"decomp.function","duration_ms":11,
 "result":{"function":"100000528","signature":"int _advanced_add(int param_1,int param_2);",
           "code":"\\nint _advanced_add(int param_1,int param_2)\\n\\n{\\n  ...\\n}\\n"}}
```

关闭会话：

```json
POST /api/v1/tools/program.close
{"worker_id":"main","session_id":"main:648f83d8988be9f4:XtV64t9l..."}

{"status":"ok","tool":"program.close","duration_ms":2,"result":{"closed":true,"session_id":"main:..."}}
```

## 工具参考

全部 239 个工具遵循同样的规则：名称为点分式 `family.operation`，每次调用带
`worker_id` 加工具输入 schema，响应使用上述封装。Mode 标注只读工具；其余工具需要
可写会话。
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", required=True, help="JSON from GET /api/v1/tools")
    args = ap.parse_args()

    tools = json.loads(Path(args.catalog).read_text())["tools"]
    docs = REPO / "docs"
    docs.mkdir(exist_ok=True)

    (docs / "llm.txt").write_text(EN_HEAD.rstrip() + "\n\n" + "\n".join(render_reference(tools, zh=False)))
    (docs / "llm-zh.txt").write_text(ZH_HEAD.rstrip() + "\n\n" + "\n".join(render_reference(tools, zh=True)))
    print(f"wrote docs/llm.txt and docs/llm-zh.txt for {len(tools)} tools")


if __name__ == "__main__":
    main()
