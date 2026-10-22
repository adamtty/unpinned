"""Your own proxy's CA (Burp, HTTP Toolkit, Charles, …): read as PEM or DER, checked to be a certificate, fingerprinted
(SHA-256 of the DER), and kept in certs/ under that fingerprint, so adding the same one again changes nothing."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----")
MAX_CERT_BYTES = 64 * 1024


class CertError(ValueError):
    pass


@dataclass
class StoredCert:
    path: Path
    fingerprint: str
    subject: str
    is_ca: bool


def certs_dir() -> Path:
    """certs/ in the project (git-ignored), or $UNPINNED_CERTS."""
    d = Path(os.environ.get("UNPINNED_CERTS") or Path(__file__).resolve().parents[2] / "certs")
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_der(path: Path) -> bytes:
    """The first certificate in a PEM or DER file, as DER."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise CertError(f"no such file: {p}")
    data = p.read_bytes()
    if len(data) > MAX_CERT_BYTES:
        raise CertError(f"{p.name} is too large to be a certificate")
    m = PEM_RE.search(data)
    if m:
        try:
            return base64.b64decode(re.sub(rb"\s+", b"", m.group(1)), validate=True)
        except ValueError as e:
            raise CertError(f"{p.name}: the PEM block isn't valid base64") from e
    if data[:1] != b"\x30":  # a DER certificate is an ASN.1 SEQUENCE
        raise CertError(f"{p.name} isn't a PEM or DER certificate")
    return data


def to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
        + ("\n-----END CERTIFICATE-----\n")
    )


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def describe(pem_path: Path) -> tuple[str, bool]:
    """(subject, is it a CA) via openssl, which also proves the bytes parse as an X.509 certificate."""
    r = subprocess.run(
        ["openssl", "x509", "-in", str(pem_path), "-noout", "-subject", "-text"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if r.returncode != 0:
        raise CertError("openssl couldn't read it as an X.509 certificate")
    subject = next((ln.split("=", 1)[1].strip() for ln in r.stdout.splitlines() if ln.startswith("subject")), "?")
    return subject, "CA:TRUE" in r.stdout


def stored() -> list[StoredCert]:
    out = []
    for p in sorted(certs_dir().glob("*.pem")):
        try:
            der = read_der(p)
            subject, is_ca = describe(p)
        except CertError:
            continue
        out.append(StoredCert(p, fingerprint(der), subject, is_ca))
    return out


def add(path: Path) -> tuple[StoredCert, bool]:
    """Store the certificate at path (PEM or DER). → (the stored cert, whether it was already there)."""
    der = read_der(path)
    fp = fingerprint(der)
    for c in stored():
        if c.fingerprint == fp:
            return c, True
    dest = certs_dir() / f"{fp[:16]}.pem"
    tmp = dest.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    tmp.write_text(to_pem(der))
    try:
        subject, is_ca = describe(tmp)
    except CertError:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, dest)
    return StoredCert(dest, fp, subject, is_ca), False


def parse_proxy(text: str) -> tuple[str, int]:
    """'host:port' (an IPv4 address, 'localhost', or [IPv6]:port) → (host, port)."""
    t = text.strip()
    m = re.fullmatch(r"\[([0-9a-fA-F:]+)\]:(\d+)|([^:\s]+):(\d+)", t)
    if not m:
        raise CertError(f"expected host:port, got {text!r}")
    host, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    if host != "localhost":
        try:
            ipaddress.ip_address(host)
        except ValueError as e:
            raise CertError(f"{host!r} isn't an IP address (or localhost)") from e
    port_n = int(port)
    if not 0 < port_n < 65536:
        raise CertError(f"port {port} is out of range")
    return ("127.0.0.1" if host == "localhost" else host), port_n


def is_loopback(host: str) -> bool:
    return host == "localhost" or ipaddress.ip_address(host).is_loopback
