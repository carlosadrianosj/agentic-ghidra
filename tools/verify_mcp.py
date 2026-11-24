#!/usr/bin/env python3
"""Verify the public MCP surface, legacy behavior, and two-client ownership."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def verify(url, worker, fixture, output):
    exercised = set()
    evidence = {"endpoint": url, "worker_id": worker, "fixture": str(fixture), "status": "running"}
    async with streamable_http_client(url) as (reader_a, writer_a, _):
        async with ClientSession(reader_a, writer_a) as client_a:
            await client_a.initialize()
            async with streamable_http_client(url) as (reader_b, writer_b, _):
                async with ClientSession(reader_b, writer_b) as client_b:
                    await client_b.initialize()

                    async def call(operation_name, client=client_a, **arguments):
                        request = {"worker_id": worker, **arguments}
                        result = await client.call_tool(operation_name, request)
                        if result.isError:
                            raise AssertionError(f"{operation_name}: {result.model_dump()}")
                        exercised.add(operation_name)
                        payload = result.structuredContent
                        if payload is None:
                            payload = json.loads(result.content[0].text)
                        return payload

                    tools = {item.name for item in (await client_a.list_tools()).tools}
                    reference = json.loads(
                        (
                            Path(__file__).resolve().parents[1]
                            / "src/agenticghidra_mcp/advanced/reference_catalog.json"
                        ).read_text()
                    )
                    assert {item["name"] for item in reference["tools"]} <= tools
                    evidence["tool_count"] = len(tools)
                    imported = await call("import_binary", binary_path=str(fixture))
                    assert imported["queued_count"] == 1, imported

                    async def ready():
                        deadline = time.monotonic() + 180
                        while time.monotonic() < deadline:
                            project = await call("list_project_binaries")
                            matches = [
                                p for p in project["programs"] if p["file_path"] == str(fixture)
                            ]
                            if (
                                matches
                                and matches[0]["analysis_complete"]
                                and matches[0]["code_indexed"]
                            ):
                                return matches[0]["name"]
                            await asyncio.sleep(0.25)
                        raise AssertionError("Legacy analysis/indexing did not become ready")

                    binary = await ready()
                    metadata = await call("list_project_binary_metadata", binary_name=binary)
                    assert metadata, metadata
                    symbols = await call(
                        "search_symbols_by_name", binary_name=binary, query="^advanced_add$"
                    )
                    assert len(symbols["symbols"]) == 1, symbols
                    entry = symbols["symbols"][0]["address"]
                    data = await call(
                        "search_symbols_by_name", binary_name=binary, query="^advanced_scratch$"
                    )
                    data_address = data["symbols"][0]["address"]
                    raw = await call("read_bytes", binary_name=binary, address=data_address, size=4)
                    assert raw["data"].lower().replace(" ", "") == "01020304", raw
                    decompiled = await call(
                        "decompile_function", binary_name=binary, name_or_address="advanced_add"
                    )
                    assert decompiled["result"][0]["error"] is None, decompiled
                    assert "advanced_global" in decompiled["result"][0]["code"], decompiled
                    listing = await call(
                        "disassemble",
                        binary_name=binary,
                        address=entry,
                        count=4,
                        include_bytes=True,
                    )
                    assert entry in listing["listing"] and listing["count"] == 4, listing
                    imports = await call("list_imports", binary_name=binary)
                    assert any("puts" in row["name"] for row in imports["imports"]), imports
                    await call("list_exports", binary_name=binary)
                    references = await call(
                        "list_xrefs", binary_name=binary, name_or_address="advanced_secondary"
                    )
                    assert references, references
                    strings = await call(
                        "search_strings", binary_name=binary, query="Advanced catalog", limit=10
                    )
                    assert any(
                        "Advanced catalog fixture" in row["value"] for row in strings["strings"]
                    ), strings
                    semantic = await call(
                        "search_code",
                        binary_name=binary,
                        query="add integers and compare a global",
                        limit=10,
                    )
                    assert any(
                        "advanced_add" in row["function_name"] for row in semantic["results"]
                    ), semantic
                    graph = await call(
                        "gen_callgraph",
                        binary_name=binary,
                        function_name="main",
                        direction="called",
                    )
                    assert "advanced_secondary" in graph["graph"], graph
                    async with streamable_http_client(url) as (reader_c, writer_c, _):
                        async with ClientSession(reader_c, writer_c) as client_c:
                            await client_c.initialize()
                            trio = await asyncio.gather(
                                call(
                                    "decompile_function",
                                    binary_name=binary,
                                    name_or_address="advanced_add",
                                ),
                                call(
                                    "decompile_function",
                                    client=client_b,
                                    binary_name=binary,
                                    name_or_address="advanced_add",
                                ),
                                call(
                                    "decompile_function",
                                    client=client_c,
                                    binary_name=binary,
                                    name_or_address="advanced_add",
                                ),
                            )
                            codes = [value["result"][0]["code"] for value in trio]
                            assert (
                                all(code == codes[0] for code in codes)
                                and "advanced_global" in codes[0]
                            )
                            evidence["three_clients_shared_program"] = True

                    owned = await call(
                        "program.open", path=str(fixture), read_only=False, update_analysis=False
                    )
                    session_id = owned["session_id"]
                    denied = await client_b.call_tool(
                        "program.summary", {"worker_id": worker, "session_id": session_id}
                    )
                    assert denied.isError, "A second MCP client accessed the first client's session"
                    other_sessions = await call("program.list_open", client=client_b)
                    assert session_id not in json.dumps(other_sessions), other_sessions
                    await call(
                        "transaction.begin",
                        session_id=session_id,
                        description="transport ownership proof",
                    )
                    try:
                        denied = await client_b.call_tool(
                            "rename_function",
                            {
                                "worker_id": worker,
                                "binary_name": binary,
                                "name_or_address": "advanced_add",
                                "new_name": "must_not_be_written",
                            },
                        )
                        assert denied.isError, (
                            "Legacy write crossed another client's explicit transaction"
                        )
                    finally:
                        await call("transaction.revert", session_id=session_id)
                    evidence["two_client_isolation"] = True

                    renamed = await call(
                        "rename_function",
                        binary_name=binary,
                        name_or_address="advanced_add",
                        new_name="legacy_added",
                    )
                    assert (
                        renamed["old_name"] == "advanced_add"
                        and renamed["new_name"] == "legacy_added"
                    )
                    prototype = await call(
                        "set_function_prototype",
                        binary_name=binary,
                        function_name_or_address="legacy_added",
                        prototype="int legacy_added(int left, int right)",
                    )
                    assert "left" in json.dumps(prototype) and "right" in json.dumps(prototype)
                    variable = await call(
                        "rename_variable",
                        binary_name=binary,
                        function_name_or_address="legacy_added",
                        variable_name="left",
                        new_name="left_legacy",
                    )
                    assert variable["new_name"] == "left_legacy", variable
                    typed = await call(
                        "set_variable_type",
                        binary_name=binary,
                        function_name_or_address="legacy_added",
                        variable_name="left_legacy",
                        type_name="unsigned int",
                    )
                    assert "uint" in json.dumps(typed) or "unsigned" in json.dumps(typed), typed
                    comment = await call(
                        "set_comment",
                        binary_name=binary,
                        target="legacy_added",
                        comment="Verified through legacy MCP",
                        comment_type="decompiler",
                    )
                    assert comment["comment"] == "Verified through legacy MCP", comment
                    await call("save")
                    await ready()
                    rebuilt = await call(
                        "search_code",
                        binary_name=binary,
                        query="legacy_added",
                        search_mode="literal",
                        limit=10,
                    )
                    assert any(
                        "legacy_added" in row["function_name"] for row in rebuilt["results"]
                    ), rebuilt
                    assert all(
                        not row["function_name"].startswith("advanced_add-")
                        for row in rebuilt["results"]
                    ), rebuilt
                    evidence["semantic_index_invalidated_and_rebuilt"] = True
                    await call("program.close", session_id=session_id)
                    await call("delete_project_binary", binary_name=binary)
                    project = await call("list_project_binaries")
                    assert binary not in {item["name"] for item in project["programs"]}, project
                    legacy = {
                        "decompile_function",
                        "search_symbols_by_name",
                        "search_code",
                        "list_project_binaries",
                        "list_project_binary_metadata",
                        "rename_function",
                        "rename_variable",
                        "save",
                        "set_variable_type",
                        "set_function_prototype",
                        "set_comment",
                        "delete_project_binary",
                        "list_exports",
                        "list_imports",
                        "list_xrefs",
                        "search_strings",
                        "read_bytes",
                        "disassemble",
                        "gen_callgraph",
                        "import_binary",
                    }
                    assert legacy <= exercised, sorted(legacy - exercised)
                    evidence["legacy_tools"] = sorted(legacy)
                    evidence["status"] = "passed"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:29840/mcp")
    parser.add_argument("--worker", default="analysis_a")
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output", default=Path("runtime/acceptance/mcp-evidence.json"), type=Path)
    args = parser.parse_args()
    asyncio.run(verify(args.url, args.worker, args.fixture.resolve(strict=True), args.output))


if __name__ == "__main__":
    main()
