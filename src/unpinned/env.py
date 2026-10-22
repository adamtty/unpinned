"""Where things live: the Android SDK, unpinned's own cache, and the defaults every command shares."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

DEFAULT_API = "36.1"  # Android 16, Google APIs (rootable). 37.0's Google APIs image 404s on Google's side for now.
SNAPSHOT = "unpinned-clean"
PROXY_PORT = 8080
WEB_PORT = 8081


def sdk() -> Path:
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(var):
            return Path(os.environ[var])
    return Path.home() / "Library/Android/sdk"


def avd_home() -> Path:
    return Path(os.environ.get("ANDROID_AVD_HOME") or Path.home() / ".android/avd")


def home() -> Path:
    """unpinned's cache: downloaded frida-server and scripts, logs, per-run config, process state."""
    p = Path(os.environ.get("UNPINNED_HOME") or Path.home() / ".cache/unpinned")
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def tool(name: str) -> str | None:
    """An SDK tool by name (the SDK copy first, so the emulator and adb match), else PATH."""
    candidates = {
        "adb": sdk() / "platform-tools/adb",
        "emulator": sdk() / "emulator/emulator",
    }
    p = candidates.get(name)
    if p and p.is_file() and os.access(p, os.X_OK):
        return str(p)
    if name == "aapt2":
        found = sorted(
            (sdk() / "build-tools").glob("*/aapt2"),
            key=lambda q: [int(x) for x in q.parent.name.split(".") if x.isdigit()],
        )
        if found:
            return str(found[-1])
    return shutil.which(name)


def frida_bin(name: str = "frida") -> str:
    """The frida CLI from this environment, which matches the pinned frida (not some other frida on PATH)."""
    import sys

    p = Path(sys.executable).parent / name
    return str(p) if p.exists() else (shutil.which(name) or name)


def avd_name(api: str) -> str:
    return "unpinned-api" + api.replace(".", "_")
