"""The emulator: unpinned's own AVD (never the user's), cold-booted once and saved as a clean snapshot that every run
starts from, rooted adbd, frida-server, and app installs."""

from __future__ import annotations

import re
import shlex
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from unpinned import env

BOOT_TIMEOUT = 300
DEVICE_SERVER = "/data/local/tmp/unpinned-frida-server"  # its own name: never overwrite a frida-server you keep there


class DeviceError(RuntimeError):
    pass


def _adb() -> str:
    adb = env.tool("adb")
    if not adb:
        raise DeviceError("adb not found (install the Android SDK platform-tools)")
    return adb


def adb(*args: str, serial: str | None = None, timeout: float = 60, check: bool = True) -> str:
    cmd = [_adb(), *(["-s", serial] if serial else []), *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        raise DeviceError(f"adb {' '.join(args)} timed out after {timeout:.0f}s") from e
    if check and r.returncode != 0:
        raise DeviceError(f"adb {' '.join(args)} failed: {(r.stderr or r.stdout).strip()[:400]}")
    return r.stdout


def shell(serial: str, command: str, timeout: float = 60, check: bool = True) -> str:
    return adb("shell", command, serial=serial, timeout=timeout, check=check)


# --- the AVD ----------------------------------------------------------------------------------------------------
def image_dir(api: str) -> Path:
    return env.sdk() / "system-images" / f"android-{api}" / "google_apis" / "arm64-v8a"


def avd_dir(api: str) -> Path:
    return env.avd_home() / f"{env.avd_name(api)}.avd"


def avd_config(api: str) -> str:
    """A plain phone: Google APIs image (rootable, no Play Store), 4 cores, 4 GB, no skin."""
    return "\n".join(
        [
            f"AvdId={env.avd_name(api)}",
            f"avd.ini.displayname=unpinned (Android {api})",
            "abi.type=arm64-v8a",
            "hw.cpu.arch=arm64",
            "hw.cpu.ncore=4",
            "hw.ramSize=4096",
            "disk.dataPartition.size=8G",
            "hw.lcd.width=1080",
            "hw.lcd.height=2400",
            "hw.lcd.density=420",
            "hw.keyboard=yes",
            "hw.gpu.enabled=yes",
            "hw.gpu.mode=auto",
            "hw.audioInput=no",
            "PlayStore.enabled=false",
            f"image.sysdir.1=system-images/android-{api}/google_apis/arm64-v8a/",
            "tag.id=google_apis",
            "tag.display=Google APIs",
            "showDeviceFrame=no",
            "fastboot.forceColdBoot=no",
            "",
        ]
    )


def create_avd(api: str) -> Path:
    if not image_dir(api).is_dir():
        raise DeviceError(
            f"the Android {api} Google APIs arm64 image isn't installed. Install it with:\n"
            f'  sdkmanager "system-images;android-{api};google_apis;arm64-v8a"'
        )
    d = avd_dir(api)
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.ini").write_text(avd_config(api))
    (env.avd_home() / f"{env.avd_name(api)}.ini").write_text(
        f"avd.ini.encoding=UTF-8\npath={d}\npath.rel=avd/{d.name}\ntarget=android-{api}\n"
    )
    return d


def has_snapshot(api: str) -> bool:
    return (avd_dir(api) / "snapshots" / env.SNAPSHOT).is_dir()


# --- running emulators ------------------------------------------------------------------------------------------
def serials() -> list[str]:
    out = adb("devices", check=False)
    return [
        ln.split()[0] for ln in out.splitlines()[1:] if ln.strip().endswith("device") and ln.startswith("emulator-")
    ]


def running(api: str) -> str | None:
    """The serial of the emulator running this AVD, if any."""
    for s in serials():
        name = adb("emu", "avd", "name", serial=s, check=False).splitlines()
        if name and name[0].strip() == env.avd_name(api):
            return s
    return None


def boot(api: str, cold: bool = False, window: bool = True) -> str:
    """Start the AVD (from the clean snapshot, discarding changes on exit; or cold for setup) and wait for boot."""
    emulator = env.tool("emulator")
    if not emulator:
        raise DeviceError('the Android emulator isn\'t installed (sdkmanager "emulator")')
    before = set(serials())
    args = [emulator, "-avd", env.avd_name(api), "-no-boot-anim", "-netdelay", "none", "-netspeed", "full", "-no-audio"]
    args += ["-no-snapshot-load"] if cold else ["-snapshot", env.SNAPSHOT, "-no-snapshot-save"]
    if not window:
        args.append("-no-window")
    log = open(env.home() / "emulator.log", "ab")
    subprocess.Popen(args, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + BOOT_TIMEOUT
    serial = None
    while time.monotonic() < deadline:
        if serial is None:
            new = [s for s in serials() if s not in before]
            serial = new[0] if new else running(api)
        if serial and shell(serial, "getprop sys.boot_completed", check=False).strip() == "1":
            return serial
        time.sleep(2)
    raise DeviceError(f"the emulator didn't finish booting within {BOOT_TIMEOUT}s (see {env.home() / 'emulator.log'})")


def wait_booted(serial: str, timeout: float = BOOT_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if shell(serial, "getprop sys.boot_completed", check=False, timeout=10).strip() == "1":
            return
        time.sleep(1)
    raise DeviceError(f"{serial} didn't finish booting within {timeout:.0f}s")


def settle(serial: str, timeout: float = 120) -> None:
    """After boot_completed: wait for the boot animation to stop and the package manager to answer, so a snapshot
    taken now isn't of a system still starting up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        anim = shell(serial, "getprop init.svc.bootanim", check=False, timeout=10).strip()
        pm = shell(serial, "pm path android", check=False, timeout=20).strip()
        if anim in ("stopped", "") and pm.startswith("package:"):
            return
        time.sleep(2)


_SU: set[str] = set()  # real devices rooted with Magisk / KernelSU: root commands go through `su`


def mark_su(serial: str) -> None:
    _SU.add(serial)


def rootsh(serial: str, command: str, timeout: float = 60, check: bool = True) -> str:
    """Run a shell command as root: through `su -mm` (Magisk's global mount namespace, so mounts reach apps) on a
    rooted phone, or with adbd already root on the emulator."""
    if serial in _SU:
        return shell(serial, "su -mm -c " + shlex.quote(command), timeout=timeout, check=check)
    root(serial)
    return shell(serial, command, timeout=timeout, check=check)


def root(serial: str) -> None:
    if serial in _SU:
        if shell(serial, "su -c 'id -u'", check=False, timeout=30).strip() != "0":
            raise DeviceError("`su` didn't give root: grant the shell root in Magisk / KernelSU and try again")
        return
    if shell(serial, "id -u", check=False).strip() == "0":
        return
    adb("root", serial=serial, check=False)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        time.sleep(1)
        if shell(serial, "id -u", check=False, timeout=10).strip() == "0":
            return
    raise DeviceError("adb root didn't take (is this a Google APIs image, not a Play Store one?)")


def prepare(serial: str, frida_server: Path) -> None:
    """One-time setup on a fresh device, before the clean snapshot is saved."""
    root(serial)
    adb("push", str(frida_server), DEVICE_SERVER, serial=serial, timeout=180)
    shell(serial, f"chmod 755 {DEVICE_SERVER}")
    for cmd in (
        "settings put global window_animation_scale 0",
        "settings put global transition_animation_scale 0",
        "settings put global animator_duration_scale 0",
        "settings put global stay_on_while_plugged_in 7",
        "settings put global verifier_verify_adb_installs 0",
        "settings put global package_verifier_enable 0",
    ):
        shell(serial, cmd, check=False)


# Android 14+ ART can use the CMC (userfaultfd) garbage collector. Frida's Java hooks running inside the app through
# the gadget crash it on Android 16 (stack walks over hooked frames), while the older concurrent-copying collector is
# fine. The switch is a boot-time flag, so it's set once at setup and lives in the clean snapshot.
CC_GC_FLAG = "persist.device_config.runtime_native_boot.force_disable_uffd_gc"


def uses_cc_gc(serial: str) -> bool:
    return shell(serial, f"getprop {CC_GC_FLAG}", check=False).strip() == "true"


def use_cc_gc(serial: str) -> None:
    """Switch ART to the concurrent-copying collector (one reboot)."""
    if uses_cc_gc(serial):
        return
    shell(serial, "device_config put runtime_native_boot force_disable_uffd_gc true")
    shell(serial, "setprop sys.boot_completed 0", check=False)  # so the old "1" can't pass for the new boot
    adb("reboot", serial=serial, check=False, timeout=60)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and serial in serials():  # wait for it to actually go down
        time.sleep(1)
    adb("wait-for-device", serial=serial, timeout=BOOT_TIMEOUT)
    wait_booted(serial)
    settle(serial)
    root(serial)
    if not uses_cc_gc(serial):
        raise DeviceError("couldn't switch the emulator to the concurrent-copying garbage collector")


def save_snapshot(serial: str) -> None:
    out = adb("emu", "avd", "snapshot", "save", env.SNAPSHOT, serial=serial, timeout=300)
    if "KO" in out:
        raise DeviceError(f"saving the snapshot failed: {out.strip()[:300]}")


def reset(serial: str) -> None:
    """Back to the clean snapshot: no apps, no data, nothing from the last run."""
    out = adb("emu", "avd", "snapshot", "load", env.SNAPSHOT, serial=serial, timeout=300)
    if "KO" in out:
        raise DeviceError(
            "the clean snapshot wouldn't load. Snapshots are tied to the emulator version, so this usually means "
            "the emulator was updated: run `unpinned setup` again to rebuild it"
        )
    wait_booted(serial)


# frida-server 17.6+ segfaults at start-up on some older devices (Samsung, Android 9 / kernel 4.4); 17.5.2 runs there
# and the pinned client talks to it fine. https://github.com/frida/frida/issues/3715
FALLBACK_SERVER = "17.5.2"
FRIDA_OLD_DEVICE_BUG = "https://github.com/frida/frida/issues/3715"


def frida_listening(serial: str) -> bool:
    """Is frida-server listening on 27042 (0x69A2)? Frida's own client can't tell: without a server it falls back
    to adb and still lists processes."""
    return listening_on(rootsh(serial, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null", check=False, timeout=15), 27042)


def listening_on(proc_net_tcp: str, port: int) -> bool:
    """Is anything in LISTEN (state 0A) on this local port, per /proc/net/tcp{,6} text?"""
    want = f":{port:04X}"
    for ln in proc_net_tcp.splitlines():
        f = ln.split()
        if len(f) > 3 and f[1].endswith(want) and f[3] == "0A":
            return True
    return False


def _run_server(serial: str, binary: Path) -> bool:
    want = binary.stat().st_size
    have = rootsh(serial, f"stat -c %s {DEVICE_SERVER} 2>/dev/null", check=False).strip()
    if have != str(want):
        adb("push", str(binary), "/data/local/tmp/frida-server.new", serial=serial, timeout=180)
        rootsh(serial, f"mv /data/local/tmp/frida-server.new {DEVICE_SERVER} && chmod 755 {DEVICE_SERVER}")
    rootsh(serial, "pkill -f frida-server", check=False)
    # -D daemonises, but adb shell waits while anything holds its stdout, so detach every stream
    rootsh(serial, f"{DEVICE_SERVER} -D </dev/null >/dev/null 2>&1", check=False, timeout=20)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if frida_listening(serial):
            time.sleep(3)  # the broken builds listen for about a second before they crash: must still be up
            return frida_listening(serial)
        time.sleep(1)
    return False


def start_frida_server(serial: str, frida_server: Path, fallback: Callable[[], Path] | None = None) -> str:
    """(Re)start frida-server as root, falling back to an older build the device can run. → the version used."""
    from unpinned import intercept

    known = intercept.state().get("frida_server_for", {}).get(serial)
    order = [(fallback, FALLBACK_SERVER)] if known == FALLBACK_SERVER and fallback else []
    order += [(frida_server, None), (fallback, FALLBACK_SERVER)]
    for binary, version in order:
        if binary is None:
            continue
        if _run_server(serial, binary() if callable(binary) else binary):
            if version:
                remembered = intercept.state().get("frida_server_for", {}) | {serial: version}
                intercept.save_state(frida_server_for=remembered)
            return version or "pinned"
    raise DeviceError(f"frida-server won't start on this device (see {FRIDA_OLD_DEVICE_BUG})")


# Android 14+ reads system CAs from the Conscrypt APEX (read-only, per mount namespace); older versions and Flutter's
# Dart runtime read /system/etc/security/cacerts. A tmpfs copy with our CA goes over the system folder, then is bound
# over the APEX folder in zygote's namespaces (every app forks from zygote) and in ours. The approach HTTP Toolkit uses.
_SYSTEM_CA_SCRIPT = r"""
set -e
SYS=/system/etc/security/cacerts
APEX=/apex/com.android.conscrypt/cacerts
TMP=/data/local/tmp/unpinned-cacerts
rm -rf "$TMP"; mkdir -p "$TMP"
if [ -d "$APEX" ]; then cp "$APEX"/* "$TMP"/; else cp "$SYS"/* "$TMP"/; fi
cp /data/local/tmp/unpinned-ca.0 "$TMP/{name}"
mount -t tmpfs unpinned "$SYS"  # "unpinned" as the source: cleanup only ever unmounts these
cp "$TMP"/* "$SYS"/
chown root:root "$SYS"/*; chmod 644 "$SYS"/*; chcon u:object_r:system_file:s0 "$SYS" "$SYS"/*
if [ -d "$APEX" ]; then
  for Z in $(pidof zygote zygote64); do nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind "$SYS" "$APEX"; done
  mount --bind "$SYS" "$APEX"
fi
rm -rf "$TMP"
echo unpinned-ca-ok
"""


def subject_hash_old(pem_path: Path) -> str:
    """The OpenSSL subject_hash_old Android names CA files by (`<hash>.0`)."""
    r = subprocess.run(
        ["openssl", "x509", "-subject_hash_old", "-noout", "-in", str(pem_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    h = r.stdout.strip()
    if r.returncode != 0 or not re.fullmatch(r"[0-9a-f]{8}", h):
        raise DeviceError(f"couldn't hash the CA certificate: {(r.stderr or r.stdout).strip()[:200]}")
    return h


def install_system_ca(serial: str, pem_path: Path) -> None:
    """Make our CA a system CA for apps started from now on (until the next reset)."""
    name = f"{subject_hash_old(pem_path)}.0"
    adb("push", str(pem_path), "/data/local/tmp/unpinned-ca.0", serial=serial)
    remove_system_ca(serial)  # never stack a second tmpfs on top of an earlier run's
    script = _SYSTEM_CA_SCRIPT.replace("{name}", name)
    out = rootsh(serial, script, timeout=60, check=False)
    if "unpinned-ca-ok" not in out:
        raise DeviceError(f"installing the system CA failed: {out.strip()[-300:]}")


_REMOVE_CA_SCRIPT = r"""
ours_on_top() { [ "$(grep " $1 " /proc/mounts | tail -1 | cut -d' ' -f1)" = unpinned ]; }
for Z in $(pidof zygote zygote64); do
  nsenter --mount=/proc/$Z/ns/mnt -- sh -c '
    while [ "$(grep " /apex/com.android.conscrypt/cacerts " /proc/mounts | tail -1 | cut -d" " -f1)" = unpinned ]; do
      umount /apex/com.android.conscrypt/cacerts || break
    done'
done
for M in /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts; do
  while ours_on_top "$M"; do umount "$M" || break; done
done
true
"""


def remove_system_ca(serial: str) -> None:
    """Undo install_system_ca: unmount our copies, and only ours (a Magisk module may mount over the same folder;
    apps started afterwards see whatever was there before)."""
    rootsh(serial, _REMOVE_CA_SCRIPT, check=False)


def set_proxy(serial: str, host: str | None, port: int = 0) -> None:
    """The device-wide HTTP proxy apps follow when nothing hooks them (None clears it)."""
    value = f"{host}:{port}" if host else ":0"
    shell(serial, f"settings put global http_proxy {shlex.quote(value)}", check=False)


def remove_reverse(serial: str) -> None:
    adb("reverse", "--remove-all", serial=serial, check=False)


def install(serial: str, apks: list[Path]) -> None:
    args = ["install-multiple"] if len(apks) > 1 else ["install"]
    files = [str(a) for a in apks]
    out = adb(*args, "-r", "-g", *files, serial=serial, timeout=600, check=False)
    if "DEPRECATED_SDK_VERSION" in out:  # Android 14+ blocks old target SDKs unless asked
        out = adb(*args, "-r", "-g", "--bypass-low-target-sdk-block", *files, serial=serial, timeout=600, check=False)
    if "Success" not in out:
        hint = ""
        if "NO_MATCHING_ABIS" in out:
            hint = " (the app has no native code for arm64-v8a)"
        elif "UPDATE_INCOMPATIBLE" in out:
            hint = " (signed with a different key: uninstall first)"
        raise DeviceError(f"install failed{hint}: {out.strip()[-400:]}")


def uninstall(serial: str, package: str) -> None:
    adb("uninstall", package, serial=serial, check=False, timeout=120)


def stop_frida_server(serial: str) -> None:
    rootsh(serial, "pkill -f frida-server", check=False)


def reverse(serial: str, port: int) -> None:
    """Device 127.0.0.1:port → host 127.0.0.1:port, so the proxy never listens beyond localhost."""
    adb("reverse", f"tcp:{port}", f"tcp:{port}", serial=serial)


def launch(serial: str, package: str) -> None:
    shell(serial, f"monkey -p {package} -c android.intent.category.LAUNCHER 1", check=False)


def kill(serial: str) -> None:
    adb("emu", "kill", serial=serial, check=False)


def is_package(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+", name))
