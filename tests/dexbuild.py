"""A minimal DEX writer for tests and fuzz seeds: just the string, type and class tables dex.parse reads."""

import struct


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build(strings: list[str], classes: list[tuple[str, str, list[str]]]) -> bytes:
    """classes: (class descriptor, superclass descriptor, interface descriptors); every descriptor must be in
    strings."""
    strings = sorted(set(strings))
    index = {s: i for i, s in enumerate(strings)}
    types = sorted({t for c, sup, ifs in classes for t in (c, sup, *ifs)})
    tindex = {t: i for i, t in enumerate(types)}
    header = 0x70
    string_ids_off = header
    type_ids_off = string_ids_off + 4 * len(strings)
    class_defs_off = type_ids_off + 4 * len(types)
    data_off = class_defs_off + 32 * len(classes)

    data = bytearray()
    string_offsets = []
    for s in strings:
        string_offsets.append(data_off + len(data))
        raw = s.encode()
        data += _uleb(len(s)) + raw + b"\0"
    if len(data) % 4:
        data += b"\0" * (4 - len(data) % 4)
    iface_offsets = []
    for _, _, ifs in classes:
        if ifs:
            iface_offsets.append(data_off + len(data))
            data += struct.pack("<I", len(ifs)) + b"".join(struct.pack("<H", tindex[i]) for i in ifs)
            if len(data) % 4:
                data += b"\0" * (4 - len(data) % 4)
        else:
            iface_offsets.append(0)

    out = bytearray(b"dex\n035\0" + b"\0" * (header - 8))
    struct.pack_into("<II", out, 0x38, len(strings), string_ids_off)
    struct.pack_into("<II", out, 0x40, len(types), type_ids_off)
    struct.pack_into("<II", out, 0x60, len(classes), class_defs_off)
    out += b"".join(struct.pack("<I", o) for o in string_offsets)
    out += b"".join(struct.pack("<I", index[t]) for t in types)
    for (c, sup, _), ioff in zip(classes, iface_offsets, strict=True):
        out += struct.pack("<IIIIIIII", tindex[c], 1, tindex[sup], ioff, 0xFFFFFFFF, 0, 0, 0)
    return bytes(out + data)
