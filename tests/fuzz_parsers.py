"""Atheris fuzzing for everything that reads app- or user-supplied bytes: the DEX tables, APK bundles, certificates,
proxy addresses, aapt2 badging, and the network security config / smali rewrites. Only the documented error types
may escape; anything else is a bug.

    python tests/fuzz_parsers.py tests/fuzz-corpus/parsers -max_total_time=180
"""

import io
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

try:
    import atheris
except ImportError:  # local runs without Atheris: tests/test_fuzz_harness.py drives TestOneInput directly
    atheris = None

if atheris:
    with atheris.instrument_imports():
        from unpinned import apk, certs, dex, patch
else:
    from unpinned import apk, certs, dex, patch

TMP = Path(tempfile.mkdtemp(prefix="fuzz-"))
warnings.filterwarnings("ignore", "Duplicate name", UserWarning)  # bundles with repeated names are a case


def _zip_case(data: bytes) -> None:
    """A bundle whose members come from the input: names and contents."""
    buf, pos = io.BytesIO(), 1
    with zipfile.ZipFile(buf, "w") as z:
        for _ in range(data[0] % 7 if data else 0):  # [count] then per member: [name len] name [body len] body
            n = data[pos] % 41 if pos < len(data) else 0
            name = data[pos + 1 : pos + 1 + n].decode("utf-8", "replace") or "x"
            pos += 1 + n
            m = data[pos] if pos < len(data) else 0
            body = data[pos + 1 : pos + 1 + m]
            pos += 1 + m
            z.writestr(name, body)
    path = TMP / "in.apks"
    path.write_bytes(buf.getvalue())
    work = Path(tempfile.mkdtemp(dir=TMP))
    try:
        out = apk.load(path, work)
    except apk.ApkError:
        return
    for p in out:
        assert p.resolve().parent in (work.resolve(), path.resolve().parent), p  # nothing lands outside workdir
    names = [n for p in out if zipfile.is_zipfile(p) for n in zipfile.ZipFile(p).namelist()]
    apk.classify(names)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    kind, body = data[0] % 6, data[1:]
    if kind == 0:
        try:
            d = dex.parse(body)
        except dex.DexError:
            return
        assert all(isinstance(s, str) for s in d.strings)
    elif kind == 1:
        _zip_case(body)
    elif kind == 2:
        p = TMP / "cert.bin"
        p.write_bytes(body)
        try:
            certs.read_der(p)
        except certs.CertError:
            pass
    elif kind == 3:
        text = body.decode("utf-8", "replace")
        try:
            host, port = certs.parse_proxy(text)
        except certs.CertError:
            return
        assert 0 < port < 65536 and ("\n" not in host and ";" not in host)
    elif kind == 4:
        text = body.decode("utf-8", "replace")
        apk.parse_badging(text)
        patch.relax_network_security_config(text)
    else:
        text = body.decode("utf-8", "replace")
        patch.inject_load(text)
        patch.set_extract_native_libs(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
