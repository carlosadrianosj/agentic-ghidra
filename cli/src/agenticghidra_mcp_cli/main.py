"""CLI entry point for agenticghidra-mcp client.

This CLI connects to a running agenticghidra-mcp server and provides a user-friendly
interface for binary analysis.

Usage examples:
    # Connect to HTTP server running on default port
    agenticghidra-mcp-cli list binaries

    # Connect to server on custom port
    agenticghidra-mcp-cli --port 8080 list binaries

Prerequisites:
    The agenticghidra-mcp server must be running. Start it with:

    # Option 1: Open existing project
    agenticghidra-mcp --transport streamable-http --project-path /path/to/project.gpr

    # Option 2: Import and analyze a binary
    agenticghidra-mcp --transport streamable-http --wait-for-analysis /bin/ls

    # Option 3: Import multiple binaries
    agenticghidra-mcp --transport streamable-http --wait-for-analysis /path/to/binary1 /path/to/binary2
"""

import click

from . import __version__
from .commands import (
    callgraph,
    decompile,
    delete,
    goto,
    import_cmd,
    metadata,
    open_cmd,
    read,
    rename,
    save,
    search,
    set_cmd,
    xref,
)
from .commands import list as list_mod

SERVER_NOT_RUNNING_ERROR = """Error: Cannot connect to agenticghidra-mcp server.

The CLI requires a running agenticghidra-mcp server. Please start it first:

Examples:

1. Open existing Ghidra project:
   agenticghidra-mcp --transport streamable-http --project-path /path/to/project.gpr

2. Import and analyze a binary:
   agenticghidra-mcp --transport streamable-http --wait-for-analysis /bin/ls

3. Import multiple binaries:
   agenticghidra-mcp --transport streamable-http --wait-for-analysis ./binary1 ./binary2

After starting the server, run this CLI again:
   agenticghidra-mcp-cli list binaries
"""


@click.group()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Server host address.",
)
@click.option(
    "--port",
    type=click.IntRange(1, 65535),
    default=29841,
    envvar="GHIDRA_ADVANCED_MCP_PORT",
    show_default=True,
    help="Server port.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enable verbose output.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "table", "text"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.version_option(version=__version__, prog_name="agenticghidra-mcp-cli")
@click.pass_context
def cli(
    ctx: click.Context,
    host: str,
    port: int,
    verbose: bool,
    output_format: str,
) -> None:
    """AgenticGhidra MCP Command-Line Client

    Connect to a running agenticghidra-mcp HTTP server for binary analysis.

    Start the server separately before using this CLI.

    \b
    Common commands:
        agenticghidra-mcp-cli list binaries
        agenticghidra-mcp-cli decompile --binary myapp main
        agenticghidra-mcp-cli search symbols --binary myapp malloc -l 20
        agenticghidra-mcp-cli rename variable --binary myapp main old_name new_name
        agenticghidra-mcp-cli set comment --binary myapp main "reviewed"
        agenticghidra-mcp-cli open program --binary myapp
        agenticghidra-mcp-cli goto --binary myapp main --type function
    """
    ctx.ensure_object(dict)
    ctx.obj["HOST"] = host
    ctx.obj["PORT"] = port
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["OUTPUT_FORMAT"] = output_format


# Register commands
cli.add_command(decompile.decompile)
cli.add_command(search.search)
cli.add_command(list_mod.list_cmd)
cli.add_command(rename.rename)
cli.add_command(set_cmd.set_cmd)
cli.add_command(open_cmd.open_cmd)
cli.add_command(goto.goto)
cli.add_command(xref.xref)
cli.add_command(read.read)
cli.add_command(callgraph.callgraph)
cli.add_command(import_cmd.import_cmd)
cli.add_command(save.save)
cli.add_command(delete.delete)
cli.add_command(metadata.metadata)


if __name__ == "__main__":
    cli()
