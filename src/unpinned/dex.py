"""Just enough of the DEX format for triage: every string, and each class with its superclass and interfaces (to find
the app's own TrustManagers and HostnameVerifiers). Reads the tables directly; nothing is decompiled."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

NO_INDEX = 0xFFFFFFFF


class DexError(ValueError):
    pass


@dataclass
class Dex:
    strings: list[str] = field(default_factory=list)
    classes: list[tuple[str, str, list[str]]] = field(default_factory=list)  # (class, superclass, interfaces)


def _uleb128(data: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if off >= len(data) or shift > 28:
            raise DexError("bad uleb128")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def _u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise DexError("read past the end")
    return struct.unpack_from("<I", data, off)[0]


def parse(data: bytes, max_strings: int = 2_000_000) -> Dex:
    """Raises DexError, and only DexError, for anything malformed."""
    try:
        return _parse(data, max_strings)
    except (struct.error, IndexError, OverflowError) as e:
        raise DexError(f"malformed dex: {type(e).__name__}") from e


def _parse(data: bytes, max_strings: int) -> Dex:
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        raise DexError("not a dex file")
    string_ids_size, string_ids_off = _u32(data, 0x38), _u32(data, 0x3C)
    type_ids_size, type_ids_off = _u32(data, 0x40), _u32(data, 0x44)
    class_defs_size, class_defs_off = _u32(data, 0x60), _u32(data, 0x64)
    if string_ids_size > max_strings or type_ids_size > 65536 or class_defs_size > 65536:
        raise DexError("implausible table sizes")

    strings = []
    for i in range(string_ids_size):
        off = _u32(data, string_ids_off + 4 * i)
        _, start = _uleb128(data, off)  # utf16 length, unused
        end = data.find(b"\0", start)
        if end < 0:
            raise DexError("unterminated string")
        strings.append(data[start:end].decode("utf-8", "replace"))  # MUTF-8; close enough for matching

    def type_name(idx: int) -> str:
        if idx == NO_INDEX or idx >= type_ids_size:
            return ""
        s = _u32(data, type_ids_off + 4 * idx)
        return strings[s] if s < len(strings) else ""

    classes = []
    for i in range(class_defs_size):
        base = class_defs_off + 32 * i
        cls, sup, ifaces_off = _u32(data, base), _u32(data, base + 8), _u32(data, base + 12)
        ifaces = []
        if ifaces_off:
            n = _u32(data, ifaces_off)
            if n > 256:
                raise DexError("implausible interface list")
            ifaces = [type_name(struct.unpack_from("<H", data, ifaces_off + 4 + 2 * j)[0]) for j in range(n)]
        classes.append((type_name(cls), type_name(sup), ifaces))
    return Dex(strings, classes)
