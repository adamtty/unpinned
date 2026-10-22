"""After launch: did the app come up, or did it refuse? It refused if its process died within the watch window (Android
records why: crash, exit, killed by a signal) or its own window shows text about root, tampering, Frida, an emulator,
integrity or a debugger."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from unpinned import device

REFUSAL_RE = re.compile(
    r"\b(root(ed)?\b|jail\s?broken|jailbreak|superuser|magisk|\bsu\b binary|tamper\w*|emulat\w+|integrity|"
    r"insecure device|unsafe device|security (risk|threat|issue)|frida|hook\w*|debugg\w+|modified|"
    r"not (supported|allowed) on this device|compromised)",
    re.I,
)


@dataclass
class Outcome:
    alive: bool
    reason: str = ""  # why it died, or what it showed
    refused: bool = False

    @property
    def ok(self) -> bool:
        return self.alive and not self.refused


def screen_text(serial: str, package: str) -> list[str]:
    """Visible text in the app's own windows (dialogs included)."""
    device.shell(serial, "uiautomator dump /data/local/tmp/unpinned-ui.xml", check=False, timeout=30)
    xml = device.shell(serial, "cat /data/local/tmp/unpinned-ui.xml", check=False, timeout=30)
    out = []
    for m in re.finditer(r'<node [^>]*?text="([^"]+)"[^>]*?package="([^"]+)"', xml):
        if m.group(2) == package:
            out.append(m.group(1).replace("&quot;", '"').replace("&amp;", "&").replace("&#10;", " "))
    return out


def exit_reason(serial: str, package: str) -> str:
    """Android's last recorded exit for the package (ApplicationExitInfo), plus a crash message if there is one."""
    info = device.shell(serial, f"dumpsys activity exit-info {package}", check=False, timeout=30)
    reason = re.search(r"reason=\d+ \(([^)]+)\)", info)
    desc = re.search(r"description=(.+)", info)
    parts = [reason.group(1).lower() if reason else "exited"]
    if desc and desc.group(1).strip() not in ("null", ""):
        parts.append(desc.group(1).strip()[:160])
    crash = device.shell(serial, "logcat -d -b crash -t 200", check=False, timeout=30)
    blocks = [b for b in crash.split("FATAL EXCEPTION") if f"Process: {package}" in b]
    if blocks:
        m = re.search(r"\n[^\n]*?([\w.$]+(?:Exception|Error)[^\n]*)", blocks[-1])
        if m:
            parts.append(m.group(1).strip()[:200])
    return ": ".join(parts)


def watch(serial: str, package: str, seconds: float = 20, look_at: float = 8) -> Outcome:
    start = time.monotonic()
    seen, looked = False, False
    while time.monotonic() - start < seconds:
        alive = bool(device.shell(serial, f"pidof {package}", check=False, timeout=10).strip())
        seen |= alive
        if not alive and (seen or time.monotonic() - start > 12):
            return Outcome(False, exit_reason(serial, package) if seen else "it never started", refused=True)
        if alive and not looked and time.monotonic() - start >= look_at:
            looked = True
            hits = [t for t in screen_text(serial, package) if REFUSAL_RE.search(t)]
            if hits:
                return Outcome(True, " / ".join(hits)[:300], refused=True)
        time.sleep(1)
    return Outcome(True)
