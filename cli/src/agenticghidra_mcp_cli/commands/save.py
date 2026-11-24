"""Save command for agenticghidra-mcp CLI."""

import asyncio

import click

from ..client import AgenticGhidraMcpClient
from ..utils import format_output, handle_command_error


@click.command()
@click.pass_context
def save(ctx: click.Context) -> None:
    """Save all ghidra programs."""

    client = AgenticGhidraMcpClient(
        host=ctx.obj["HOST"],
        port=ctx.obj["PORT"],
    )

    async def run():
        async with client:
            result = await client.save()
            format_output(result, ctx.obj["OUTPUT_FORMAT"], ctx.obj["VERBOSE"])

    try:
        from ..utils import run_async

        run_async(run())
    except (asyncio.exceptions.CancelledError, Exception) as e:
        handle_command_error(e, ctx)
