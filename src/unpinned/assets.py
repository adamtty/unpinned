"""Downloads, each verified before use: frida-server for the device (matching the pinned frida exactly, checked
against the SHA-256 digest GitHub publishes for the release asset), and HTTP Toolkit's interception and unpinning
scripts at a pinned commit, checked against the hashes below. The scripts are AGPL-3.0, so they're fetched, not
copied into this repo."""

from __future__ import annotations

import hashlib
import json
import lzma
import os
import re
import urllib.request
from pathlib import Path

import frida

from unpinned import env, trust

SCRIPTS_REPO = "httptoolkit/frida-interception-and-unpinning"
SCRIPTS_COMMIT = "560dd29d410fe785f9f390e3c7f86ca8359c8d67"
# load order matters: config first, then the hooks (the order HTTP Toolkit's README gives, plus the Flutter hooks)
SCRIPTS = {
    "config.js": "0721fd3dc61daa56e883f7b612464fce9543cf97cc3a537db2c2cab92c04c6d2",
    "native-connect-hook.js": "f7ade57d2b1499e767ea0baa65823c27816d4f3f62a9b93d9ba72747b228f3e9",
    "native-tls-hook.js": "6a9f38ec80e5803742e651d6058184484611d0d14611ba12d23500b1f715f4ba",
    "android/android-proxy-override.js": "d0d97c6d65ed819ba85fad3870b4c139c6d526b24dcd700e28e2ae42e4cc14fd",
    "android/android-system-certificate-injection.js": "099300efbffd26e1b23695f7a28d2c01e6e5fa2dc9ead6bda861930ac83367ca",
    "android/android-certificate-unpinning.js": "82b48cc2fa904a99c7ead2ac3fe43ad559db249d350f4d805e3848eee80b84ac",
    "android/android-certificate-unpinning-fallback.js": "5190e449ae590e896f362a5751267199c2bef5417f69635715705def00462cd7",
    "android/android-disable-flutter-certificate-pinning.js": "fbf60f2d3c4878fe4829e460c553636c52e71c8bed86cad74348def8d220198d",
    "android/android-disable-root-detection.js": "69888dc57c8ac988d7326c507f91d1bb8532cbbaf12a9bbbe0a444655de7fc10",
}
MAX_DOWNLOAD = 200 * 1024 * 1024


class AssetError(RuntimeError):
    pass


def _get(url: str, limit: int = MAX_DOWNLOAD, accept: str | None = None) -> bytes:
    if not url.startswith("https://"):
        raise AssetError(f"refusing a non-https download: {url}")
    req = urllib.request.Request(  # noqa: S310 - https only, checked above
        url, headers={"User-Agent": "unpinned", **({"Accept": accept} if accept else {})}
    )
    with urllib.request.urlopen(req, timeout=120, context=trust.context()) as r:  # noqa: S310 - https only, checked above
        data = r.read(limit + 1)
    if len(data) > limit:
        raise AssetError(f"{url} is larger than {limit // (1024 * 1024)} MB")
    return data


def _write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scripts_dir() -> Path:
    return env.home() / "scripts" / SCRIPTS_COMMIT[:12]


def ensure_scripts() -> Path:
    """The pinned scripts, downloading any that are missing or don't match their hash."""
    d = scripts_dir()
    for rel, want in SCRIPTS.items():
        p = d / rel
        if p.is_file() and _sha256(p.read_bytes()) == want:
            continue
        data = _get(f"https://raw.githubusercontent.com/{SCRIPTS_REPO}/{SCRIPTS_COMMIT}/{rel}", limit=5 * 1024 * 1024)
        if _sha256(data) != want:
            raise AssetError(f"{rel}: SHA-256 doesn't match the pinned hash; not using it")
        _write(p, data)
    return d


def frida_server_path(version: str | None = None) -> Path:
    return env.home() / f"frida-server-{version or frida.__version__}-android-arm64"


def ensure_frida_server(version: str | None = None) -> Path:
    """frida-server for arm64 Android, the same version as the frida this runs with (a mismatch won't connect)."""
    version = version or frida.__version__
    out = frida_server_path(version)
    if out.is_file():
        return out
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise AssetError(f"unexpected frida version {version!r}")
    rel = json.loads(
        _get(
            f"https://api.github.com/repos/frida/frida/releases/tags/{version}",
            10 * 1024 * 1024,
            accept="application/vnd.github+json",
        )
    )
    name = f"frida-server-{version}-android-arm64.xz"
    asset = next((a for a in rel.get("assets", []) if a.get("name") == name), None)
    digest = (asset or {}).get("digest") or ""
    if not asset or not digest.startswith("sha256:"):
        raise AssetError(f"frida {version}: no {name} with a published SHA-256 digest")
    url = asset.get("browser_download_url", "")
    if not url.startswith(f"https://github.com/frida/frida/releases/download/{version}/"):
        raise AssetError(f"unexpected download URL for {name}: {url}")
    data = _get(url)
    if _sha256(data) != digest.removeprefix("sha256:"):
        raise AssetError(f"{name}: SHA-256 doesn't match the digest GitHub publishes; not using it")
    _write(out, lzma.decompress(data), mode=0o700)
    return out


def render_config(template: str, ca_pem: str, host: str, port: int) -> str:
    """config.js with our CA and proxy filled in. Fails loudly if the template's shape changed, rather than
    running hooks that point at the wrong place."""
    pem = ca_pem.strip()
    if not (pem.startswith("-----BEGIN CERTIFICATE-----") and pem.endswith("-----END CERTIFICATE-----")):
        raise AssetError("the CA isn't a single PEM certificate")
    if "`" in pem or "${" in pem:
        raise AssetError("the CA PEM contains template characters")
    out, n1 = re.subn(
        r"const CERT_PEM = `-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`;",
        lambda _: f"const CERT_PEM = `{pem}`;",
        template,
        count=1,
        flags=re.S,
    )
    out, n2 = re.subn(r"const PROXY_HOST = '[^']*';", lambda _: f"const PROXY_HOST = '{host}';", out, count=1)
    out, n3 = re.subn(r"const PROXY_PORT = \d+;", lambda _: f"const PROXY_PORT = {int(port)};", out, count=1)
    if (n1, n2, n3) != (1, 1, 1):
        raise AssetError("config.js doesn't have the expected CERT_PEM / PROXY_HOST / PROXY_PORT lines")
    return out


def frida_server_fallback() -> Path:
    """frida-server 17.5.2, for devices that current builds crash on; downloaded and verified when first needed."""
    return ensure_frida_server("17.5.2")
