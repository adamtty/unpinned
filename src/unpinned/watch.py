"""After launch: did the app come up, or did it refuse? It refused if its process died within the watch window (Android
records why: crash, exit, killed by a signal) or its own window shows text about root, tampering, Frida, an emulator,
integrity or a debugger, or Google Play's licence-check dialogs."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from unpinned import device

REFUSAL_RE = re.compile(
    r"\b(root(ed)?\b|jail\s?broken|jailbreak|superuser|magisk|\bsu\b binary|tamper\w*|emulat\w+|integrity|"
    r"insecure device|unsafe device|security (risk|threat|issue)|frida|hook\w*|debugg\w+|modified|"
    r"not (supported|allowed) on this device|compromised|"
    # Google Play's automatic protection: no Play Store to ask, or not installed from Play
    r"check that google play is enabled|get this app from (google )?play)",
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
        cause = crash_cause(blocks[-1])
        if cause:
            parts.append(cause)
    return ": ".join(parts)


def crash_cause(block: str) -> str:
    """The exception that ended the app: the last "Caused by:" if there is one, else the thrown exception (the first
    exception line after "Process:"), not whatever exception text appears first in the block."""
    lines = [re.sub(r"^.*?\b(?:AndroidRuntime|DEBUG)\s*:\s?", "", ln).strip() for ln in block.splitlines()]
    caused = [ln.removeprefix("Caused by: ") for ln in lines if ln.startswith("Caused by:")]
    if caused:
        return caused[-1][:200]
    after = False
    for ln in lines:
        if ln.startswith("Process:"):
            after = True
            continue
        if after and re.match(r"^[\w.$]+(?:Exception|Error)\b", ln):
            return ln[:200]
    return ""


def in_front(serial: str, package: str) -> bool:
    """Is one of the app's activities the resumed (foreground) one?"""
    out = device.shell(serial, "dumpsys activity activities", check=False, timeout=30)
    m = re.search(r"(?:topResumedActivity|ResumedActivity)[:=]\s*ActivityRecord\{\S+ \S+ ([\w.]+)/", out)
    return bool(m) and m.group(1) == package


def log_reason(serial: str, pid: str) -> str:
    """The app's own last log line that sounds like a refusal ("FRIDA Server DETECTED", "Root detected!", …)."""
    if not pid:
        return ""
    out = device.shell(serial, f"logcat -d --pid={pid} -v brief", check=False, timeout=30)
    hits = [ln.split(": ", 1)[-1].strip() for ln in out.splitlines() if REFUSAL_RE.search(ln.split(": ", 1)[-1])]
    hits = [h for h in hits if "NOT" not in h.upper().split()]  # "FRIDA Server NOT RUNNING" is the app saying it's fine
    return hits[-1][:200] if hits else ""


def watch(serial: str, package: str, seconds: float = 20, look_at: float = 8) -> Outcome:
    start = time.monotonic()
    seen, looked, pid = False, False, ""
    while time.monotonic() - start < seconds:
        pids = device.shell(serial, f"pidof {package}", check=False, timeout=10).split()
        alive = bool(pids)
        pid = pids[0] if pids else pid
        seen |= alive
        if not alive and (seen or time.monotonic() - start > 12):
            why = f"it exited ({exit_reason(serial, package)})" if seen else "it never started"
            said = log_reason(serial, pid)
            return Outcome(False, f"{why}; the app logged: {said}" if said else why, refused=True)
        if alive and not looked and time.monotonic() - start >= look_at:
            looked = True
            hits = [t for t in screen_text(serial, package) if REFUSAL_RE.search(t)]
            if hits:
                return Outcome(True, "it's showing: " + " / ".join(hits)[:300], refused=True)
            if not in_front(serial, package):  # closed its own window but kept the process (DVBA's Frida check)
                said = log_reason(serial, pid)
                return Outcome(
                    True, "it closed its window" + (f"; the app logged: {said}" if said else ""), refused=True
                )
        time.sleep(1)
    return Outcome(True)
