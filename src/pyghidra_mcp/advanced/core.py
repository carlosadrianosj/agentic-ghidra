"""Shared operation contracts and Ghidra value conversion for the advanced catalog."""

from __future__ import annotations

import base64
import itertools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MAX_RESULTS = 1000
MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Operation:
    name: str
    handler: Callable[..., Any]
    kind: str
    api: str
    program: bool = True
    analysis: bool = False
    timeout: float = 60.0
    version: str = "1"


def operation(
    name: str,
    *,
    kind: str = "read",
    api: str,
    program: bool = True,
    analysis: bool = False,
    timeout: float = 60.0,
    version: str = "1",
):
    """Attach registration metadata without wrapping or changing a handler signature."""

    def decorate(handler):
        handler.__operation__ = Operation(
            name, handler, kind, api, program, analysis, timeout, version
        )
        return handler

    return decorate


@dataclass
class Call:
    runtime: Any
    context: Any
    owner: str
    session: Any = None
    monitor: Any = None

    @property
    def info(self):
        if self.session is None:
            raise ValueError("This operation requires a program session")
        return self.session.info

    @property
    def program(self):
        return self.info.program

    @property
    def flat(self):
        return self.info.flat_api


def address(call: Call, value: Any):
    if value is None:
        raise ValueError("An address is required")
    if hasattr(value, "getAddressSpace"):
        return value
    text = hex(value) if isinstance(value, int) else str(value).strip()
    resolved = call.program.getAddressFactory().getAddress(text)
    if resolved is None:
        symbols = list(call.program.getSymbolTable().getSymbols(text))
        if len(symbols) != 1:
            raise ValueError(f"Address or unique symbol not found: {value}")
        return symbols[0].getAddress()
    return resolved


def address_range(call: Call, start: Any, end: Any = None, length: int | None = None):
    from ghidra.program.model.address import AddressSet

    first = address(call, start)
    if end is not None and length is not None:
        raise ValueError("Specify end or length, not both")
    if length is not None:
        if length < 1:
            raise ValueError("length must be positive")
        last = first.addNoWrap(length - 1)
    else:
        last = first if end is None else address(call, end)
    if first.getAddressSpace() != last.getAddressSpace() or first.compareTo(last) > 0:
        raise ValueError("Invalid address range")
    return AddressSet(first, last)


def function(call: Call, value: Any):
    from pyghidra_mcp.tools import GhidraTools

    return GhidraTools(call.info).find_function(
        hex(value) if isinstance(value, int) else str(value)
    )


def datatype(call: Call, value: str):
    from pyghidra_mcp.tools import GhidraTools

    return GhidraTools(call.info)._parse_data_type(value)


def source_type(name: str = "USER_DEFINED"):
    from ghidra.program.model.symbol import SourceType

    try:
        return getattr(SourceType, name.upper())
    except AttributeError as exc:
        raise ValueError(f"Unknown source type: {name}") from exc


def reference_type(name: str = "DATA"):
    from ghidra.program.model.symbol import RefType

    try:
        return getattr(RefType, name.upper())
    except AttributeError as exc:
        raise ValueError(f"Unknown reference type: {name}") from exc


def page(items, offset: int = 0, limit: int = 100, *, key: str = "items") -> dict:
    if offset < 0 or not 1 <= limit <= MAX_RESULTS:
        raise ValueError(
            f"offset must be nonnegative and limit must be between 1 and {MAX_RESULTS}"
        )
    rows = list(itertools.islice(iter(items), offset, offset + limit + 1))
    more = len(rows) > limit
    return {
        key: rows[:limit],
        "offset": offset,
        "limit": limit,
        "has_more": more,
        "next_offset": offset + limit if more else None,
    }


def decode_bytes(*, data_hex: str | None = None, data_base64: str | None = None) -> bytes:
    if (data_hex is None) == (data_base64 is None):
        raise ValueError("Specify exactly one hexadecimal or base64 payload")
    try:
        result = (
            bytes.fromhex(data_hex)
            if data_hex is not None
            else base64.b64decode(data_base64, validate=True)
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid byte encoding") from exc
    if len(result) > MAX_BYTES:
        raise ValueError(f"Payload exceeds {MAX_BYTES} bytes")
    return result


def read_bytes(call: Call, location: Any, length: int) -> bytes:
    import jpype

    if not 0 <= length <= MAX_BYTES:
        raise ValueError(f"length must be between 0 and {MAX_BYTES}")
    result = jpype.JArray(jpype.JByte)(int(length))
    count = call.program.getMemory().getBytes(address(call, location), result)
    if count != length:
        raise ValueError(f"Only {count} of {length} bytes could be read")
    return bytes((int(value) & 255) for value in result)


def java_iter(iterator):
    """Bridge Ghidra iterator interfaces which do not extend java.util.Iterator."""
    if hasattr(iterator, "hasNext") and hasattr(iterator, "next"):
        while iterator.hasNext():
            yield iterator.next()
    else:
        yield from iterator


def function_dict(item) -> dict:
    return {
        "name": str(item.getName()),
        "address": str(item.getEntryPoint()),
        "signature": str(item.getSignature()),
        "external": bool(item.isExternal()),
        "thunk": bool(item.isThunk()),
        "body": str(item.getBody()),
        "parameter_count": int(item.getParameterCount()),
    }


def symbol_dict(item) -> dict:
    return {
        "id": int(item.getID()),
        "name": str(item.getName()),
        "address": str(item.getAddress()),
        "namespace": str(item.getParentNamespace()),
        "type": str(item.getSymbolType()),
        "source": str(item.getSource()),
        "primary": bool(item.isPrimary()),
        "external": bool(item.isExternal()),
    }


def variable_dict(item) -> dict:
    return {
        "name": str(item.getName()),
        "data_type": str(item.getDataType()),
        "storage": str(item.getVariableStorage()),
        "comment": str(item.getComment() or ""),
        "first_use_offset": int(item.getFirstUseOffset()),
        "ordinal": int(item.getOrdinal()) if hasattr(item, "getOrdinal") else None,
    }


def json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {"hex": value.hex(), "base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_value(item) for item in value]
    if hasattr(value, "model_dump"):
        return json_value(value.model_dump())
    return str(value)
