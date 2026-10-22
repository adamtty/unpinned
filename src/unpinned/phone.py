"""A real phone over adb: find it, check its root, search its apps, and pull an installed app (every split) into one
`.apks` bundle, which the emulator flow, the patcher and a later restore all take as is."""

from __future__ import annotations

import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from unpinned import device, env

APK_PATH_RE = re.compile(r"^/(data/app|system|product|vendor|system_ext)/[\w./~=+-]+\.apk$")


class PhoneError(RuntimeError):
    pass


def find(serial: str | None = None) -> str:
    """The phone's serial: the one given, else the only connected device that isn't an emulator."""
    out = device.adb("devices", check=False)
    rows = [ln.split() for ln in out.splitlines()[1:] if ln.strip()]
    if serial:
        state = next((r[1] for r in rows if r[0] == serial), None)
        if state != "device":
            raise PhoneError(f"{serial} isn't connected ({state or 'not listed'}): check USB debugging and the prompt")
        return serial
    phones = [r[0] for r in rows if len(r) > 1 and r[1] == "device" and not r[0].startswith("emulator-")]
    pending = [r[0] for r in rows if len(r) > 1 and r[1] == "unauthorized"]
    if pending and not phones:
        raise PhoneError("the phone is waiting for you to allow USB debugging (check its screen)")
    if not phones:
        raise PhoneError("no phone connected over adb (USB debugging on, cable in)")
    if len(phones) > 1:
        raise PhoneError(f"more than one phone connected ({', '.join(phones)}): pick one with --device")
    return phones[0]


def describe(serial: str) -> str:
    props = device.shell(
        serial,
        "echo $(getprop ro.product.manufacturer) $(getprop ro.product.model), Android "
        "$(getprop ro.build.version.release)",
        check=False,
    )
    return " ".join(props.split())


def check_root(serial: str) -> str:
    """Mark the phone as a `su` device and return its root tool's version; raise if root isn't granted."""
    device.mark_su(serial)
    device.root(serial)
    out = device.shell(serial, "su -v", check=False).strip().splitlines()
    return out[0] if out else "su"


def packages(serial: str, query: str = "", third_party: bool = True) -> list[str]:
    out = device.shell(serial, "pm list packages" + (" -3" if third_party else ""), check=False)
    names = sorted(ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.startswith("package:"))
    q = query.lower()
    return [n for n in names if device.is_package(n) and (not q or q in n.lower())]


def pull(serial: str, package: str, dest_dir: Path | None = None) -> Path:
    """Every APK of an installed app (base and splits) → one `<package>-<time>.apks` bundle."""
    if not device.is_package(package):
        raise PhoneError(f"not a package name: {package!r}")
    paths = [
        ln.split(":", 1)[1].strip()
        for ln in device.shell(serial, f"pm path {package}", check=False).splitlines()
        if ln.startswith("package:")
    ]
    if not paths:
        raise PhoneError(f"{package} isn't installed on the phone")
    bad = [p for p in paths if not APK_PATH_RE.match(p)]
    if bad:
        raise PhoneError(f"unexpected APK path on the phone: {bad[0][:120]!r}")
    dest_dir = Path(dest_dir or env.home() / "pulled")
    dest_dir.mkdir(parents=True, exist_ok=True)
    work = dest_dir / f".{package}-{int(time.time())}"
    work.mkdir()
    names = []
    for i, src in enumerate(paths):
        name = Path(src).name if Path(src).name not in names else f"{i}-{Path(src).name}"
        out = device.adb("pull", src, str(work / name), serial=serial, timeout=600, check=False)
        if not (work / name).is_file():
            # some builds keep APKs unreadable to the shell user: copy them out as root first
            tmp = f"/data/local/tmp/unpinned-pull-{i}.apk"
            device.rootsh(serial, f"cp {src} {tmp} && chmod 644 {tmp}")
            device.adb("pull", tmp, str(work / name), serial=serial, timeout=600)
            device.rootsh(serial, f"rm -f {tmp}", check=False)
        if not (work / name).is_file():
            raise PhoneError(f"couldn't pull {src}: {out.strip()[-200:]}")
        names.append(name)
    bundle = dest_dir / f"{package}-{time.strftime('%Y%m%d-%H%M%S')}.apks"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_STORED) as z:
        for name in names:
            z.write(work / name, name)
    for name in names:
        (work / name).unlink()
    work.rmdir()
    return bundle


# --- hiding root from the app under test --------------------------------------------------------------------------
@dataclass
class Magisk:
    version: str
    denylist_enforced: bool


def magisk(serial: str) -> Magisk | None:
    """Magisk's version and whether its DenyList is enforced (it needs Zygisk), or None without Magisk."""
    version = device.rootsh(serial, "magisk -v 2>/dev/null", check=False).strip()
    if not version or "MAGISK" not in version.upper():
        return None
    status = device.rootsh(serial, "magisk --denylist status 2>&1", check=False)
    return Magisk(version, "is enforced" in status and "not enforced" not in status)


def denylisted(serial: str, package: str) -> bool:
    out = device.rootsh(serial, "magisk --denylist ls 2>&1", check=False)
    return any(ln.split("|", 1)[0].strip() == package for ln in out.splitlines())


def hide_root(serial: str, package: str) -> str:
    """Put the app on Magisk's DenyList, so Magisk hides itself and undoes its changes inside that app. → what was
    done, for the user. Remembers additions so cleanup only removes what unpinned added."""
    from unpinned import intercept

    m = magisk(serial)
    if m is None:
        return "no Magisk on this phone: root isn't hidden (KernelSU and others have their own per-app settings)"
    if not m.denylist_enforced:
        return (
            "Magisk's DenyList isn't enforced, so root isn't hidden. To turn it on: Magisk app → Settings → "
            "Zygisk on, Enforce DenyList on, then reboot"
        )
    if denylisted(serial, package):
        return f"{package} is already on Magisk's DenyList"
    device.rootsh(serial, f"magisk --denylist add {package}")
    added = intercept.state().get("denylist_added", {})
    added.setdefault(serial, [])
    if package not in added[serial]:
        added[serial].append(package)
    intercept.save_state(denylist_added=added)
    return f"added {package} to Magisk's DenyList: Magisk hides itself from it"


def unhide_root(serial: str) -> list[str]:
    """Take off the DenyList what unpinned put there (and nothing else)."""
    from unpinned import intercept

    added = intercept.state().get("denylist_added", {})
    removed = []
    for package in added.pop(serial, []):
        if device.is_package(package):
            device.rootsh(serial, f"magisk --denylist rm {package}", check=False)
            removed.append(package)
    intercept.save_state(denylist_added=added)
    return removed
