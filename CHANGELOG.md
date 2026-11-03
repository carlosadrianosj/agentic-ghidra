# Changelog

All notable changes to Agentic-Ghidra, newest first. The project started as a fork of
pyghidra-mcp v0.2.7; every entry below is relative to that baseline. 中文版本在下方。

## 1.0.0 (2026-11-03)

First standalone release.

### Added

- Headless catalog of 212 operations across 34 families: decompilation, type and layout
  reconstruction, patching, pcode, memory, listing, references and transactions, plus the
  20 legacy tools (239 tools exposed)
- Session bound operations with explicit read/write modes, locks per program, undo/redo and
  revert
- Local worker supervisor, the `agentic-ghidra` CLI: isolated JVM workers on demand with a
  task queue that supports safe cancellation and restart
- Team investigations: two or more teams analyzing the same binary with isolated projects,
  indexes, ports and mutations
- REST API beside MCP on the same port: tool catalog and invocation under `/api/v1`, batch
  pipelines, worker lifecycle, investigations and an OpenAPI document
- Trusted code policy: `ghidra.call`, `ghidra.eval` and `ghidra.script` require
  `--advanced-trusted-code`
- Acceptance suites under `tests/acceptance` with evidence under `runtime/acceptance`
- Bilingual documentation in English and Simplified Chinese with an animated usage diagram

### Changed

- Project renamed to Agentic-Ghidra: repository, CLI, MCP server name and documentation
- The automated pytest run covers `tests/unit` and `tests/integration` only

### Removed

- PyPI release workflows, keeping the project internal
- Devcontainer, editor and CI configuration not used by the internal workflow
- Pre-commit hooks and their dependencies; lint runs through ruff and the macOS smoke
  workflow

## 中文版

所有重要变更，最新在前。项目起源于 pyghidra-mcp v0.2.7 的 fork，以下所有条目均相对该基线。

### 1.0.0（2026-11-03）

首个独立版本。

#### 新增

- 34 个族共 212 项无头操作目录：反编译、类型与结构体重建、打补丁、pcode、内存、
  listing、引用与事务，外加 20 个遗留工具（共暴露 239 个工具）
- 操作绑定会话，带显式读写模式、按程序加锁、undo/redo 与 revert
- 本地工作进程 supervisor，即 `agentic-ghidra` CLI：按需启动隔离 JVM 工作进程，任务队列
  支持安全取消与重启
- 多团队调查：两个或更多团队分析同一二进制，项目、索引、端口与变更完全隔离
- 与 MCP 同端口并列的 REST API：`/api/v1` 下的工具目录与调用、批量流水线、工作进程
  生命周期、多团队调查与 OpenAPI 文档
- 可信代码策略：`ghidra.call`、`ghidra.eval`、`ghidra.script` 需要
  `--advanced-trusted-code`
- `tests/acceptance` 下的验收套件与 `runtime/acceptance` 下的证据
- 英文与简体中文双语文档，附动画用法示意图

#### 变更

- 项目更名为 Agentic-Ghidra：仓库、CLI、MCP 服务名与文档
- 自动化 pytest 只覆盖 `tests/unit` 与 `tests/integration`

#### 移除

- PyPI 发布工作流，项目保持内部使用
- 内部流程不用的 devcontainer、编辑器与 CI 配置
- pre-commit 钩子及其依赖；代码检查走 ruff 与 macOS 冒烟工作流
