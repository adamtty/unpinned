"""unpinned: setup once, then `unpinned run app.apk`."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from unpinned import analyze, apk, assets, certs, device, env, intercept, patch, watch

STRATEGIES = {
    "hooks": "root + Frida hooks: unpinning, root-detection bypass, proxy redirect (the app is untouched)",
    "ca": "system CA only, no Frida (enough when nothing is pinned; nothing for the app to detect)",
    "gadget": "patch in Frida's gadget with the same hooks (they run inside the app first; no frida-server)",
    "apk-mitm": "repackage with apk-mitm: trust user CAs and strip pins statically (no Frida at all)",
}


def say(msg: str) -> None:
    print(f"\033[36m›\033[0m {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"\033[33m⚠\033[0m {msg}", flush=True)


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def choose(question: str, options: list[tuple[str, str]], default: str, assume: bool) -> str:
    """Numbered menu; Enter (or a non-interactive run, or --yes) takes the default."""
    if assume or not interactive():
        return default
    print()
    for i, (key, text) in enumerate(options, 1):
        star = " \033[32m(recommended)\033[0m" if key == default else ""
        print(f"   \033[36m{i}\033[0m  {text}{star}")
    keys = [k for k, _ in options]
    while True:
        ans = input(f"\033[1m › {question}\033[0m [{keys.index(default) + 1}] ").strip()
        if not ans:
            return default
        if ans.isdigit() and 1 <= int(ans) <= len(keys):
            return keys[int(ans) - 1]


def cmd_doctor(a) -> int:
    rows = [
        ("adb", env.tool("adb")),
        ("emulator", env.tool("emulator")),
        ("aapt2", env.tool("aapt2")),
        ("frida (pinned)", env.frida_bin()),
        ("mitmweb", shutil.which("mitmweb")),
        ("openssl", shutil.which("openssl")),
        ("apktool (for gadget patching)", shutil.which("apktool")),
        ("npm (for gadget patching)", shutil.which("npm")),
        ("scrcpy (optional)", shutil.which("scrcpy")),
        ("apk-mitm (optional)", shutil.which("apk-mitm")),
        (
            f"Android {a.api} Google APIs arm64 image",
            str(device.image_dir(a.api)) if device.image_dir(a.api).is_dir() else None,
        ),
        ("AVD", str(device.avd_dir(a.api)) if device.avd_dir(a.api).is_dir() else None),
        ("clean snapshot", "yes" if device.has_snapshot(a.api) else None),
    ]
    ok = True
    for name, val in rows:
        mark = "\033[32m✓\033[0m" if val else ("\033[33m·\033[0m" if "optional" in name else "\033[31m✗\033[0m")
        ok &= bool(val) or "optional" in name
        print(f"  {mark} {name}: {val or 'missing'}")
    if not device.has_snapshot(a.api):
        print("\n  run `unpinned setup` to create the AVD and its clean snapshot")
    return 0 if ok else 1


def cmd_setup(a) -> int:
    say("downloading HTTP Toolkit's interception scripts (pinned commit, SHA-256 checked)")
    assets.ensure_scripts()
    say("downloading frida-server (matching the pinned frida, SHA-256 checked)")
    server = assets.ensure_frida_server()
    say(f"creating the AVD {env.avd_name(a.api)} (Android {a.api}, Google APIs, arm64)")
    device.create_avd(a.api)
    if serial := device.running(a.api):
        device.kill(serial)
    say("cold-booting it for the first time (a minute or two)")
    serial = device.boot(a.api, cold=True, window=not a.headless)
    say("rooting adbd, pushing frida-server, turning off animations and install verification")
    device.prepare(serial, server)
    say(f"saving the clean snapshot '{env.SNAPSHOT}'")
    device.save_snapshot(serial)
    say("done: `unpinned run app.apk`")
    return 0


# --- the report -------------------------------------------------------------------------------------------------
MARK = {analyze.DEFINITE: "\033[31m●\033[0m", analyze.LIKELY: "\033[33m●\033[0m", analyze.POSSIBLE: "\033[2m○\033[0m"}
TITLES = {
    "pinning": "Certificate pinning",
    "ct": "Certificate Transparency",
    "root": "Root detection",
    "integrity": "Device attestation",
    "anti_frida": "Frida detection",
    "emulator": "Emulator detection",
    "anti_debug": "Debugger detection",
    "protector": "Protector / RASP",
}


def show_report(r: analyze.Report) -> None:
    t = r.triage
    say(
        f"{t.package} {t.version}  (min SDK {t.min_sdk or '?'}, target {t.target_sdk or '?'}, "
        f"{len(t.apks)} APK{'s' if len(t.apks) != 1 else ''})"
    )
    say(f"native: {', '.join(t.abis) or 'none'}  ·  framework: {', '.join(t.frameworks) or 'Java / Kotlin'}")
    for w in t.warnings():
        warn(w)
    verdict = {
        "none": "\033[32mno pinning found\033[0m",
        "possible": "\033[2mpinning possible\033[0m",
        "likely": "\033[33mpinning likely\033[0m",
        "definite": "\033[31mpins certificates\033[0m",
    }[r.pinning()]
    print(f"\n  {verdict}")
    for cat, title in TITLES.items():
        found = r.of(cat)
        if not found:
            continue
        print(f"\n  \033[1m{title}\033[0m")
        for f in found:
            ev = "; ".join(f.evidence[:3])
            print(f"    {MARK[f.strength]} {f.label}  \033[2m{f.strength}{' · ' + ev if ev else ''}\033[0m")
    if any("TrustManager" in f.label and "hashing" in f.label for f in r.of("pinning")):
        print(
            "\n  \033[2mA TrustManager that hashes keys itself is app-specific: if a request still fails, open "
            "the class in jadx and pass your own hook with --script.\033[0m"
        )
    if r.of("integrity"):
        print(
            "\n  \033[2mPlay Integrity / SafetyNet is judged on Google's servers: an emulator fails device integrity "
            "whatever runs on it, so flows gated on it won't work here.\033[0m"
        )
    print()


def recommend(r: analyze.Report) -> str:
    if r.pinning() == "none" and not r.of("ct") and not r.detects_root:
        return "ca"
    if r.detects_frida:
        return "gadget"
    return "hooks"


def cmd_triage(a) -> int:
    with tempfile.TemporaryDirectory(prefix="unpinned-") as tmp:
        r = analyze.analyze(apk.load(Path(a.app), Path(tmp)))
        show_report(r)
        say(f"suggested: {recommend(r)} — {STRATEGIES[recommend(r)]}")
    return 0


# --- run ----------------------------------------------------------------------------------------------------------
def _launch(
    a, serial: str, package: str, strategy: str, apks: list[Path], config: Path | None, run_dir: Path, server: Path
) -> None:
    """Install and start the app the chosen way."""
    device.uninstall(serial, package)  # a patched build is signed differently from what may be there
    say(f"installing ({len(apks)} APK{'s' if len(apks) != 1 else ''})")
    device.install(serial, apks)
    if strategy == "hooks":
        say("starting frida-server and spawning the app with the hooks")
        device.start_frida_server(serial, server)
        cmd = intercept.frida_command(serial, package, config, extra=a.script)
        log = run_dir / "frida.log"
        proc = intercept.start_hooks(cmd, log)
        if not intercept.wait_for(log, "Resuming main thread", 60, proc):
            raise device.DeviceError(f"frida couldn't spawn the app (see {log})")
        for line in log.read_text(errors="replace").splitlines():
            if line.strip().startswith(("==", "!!!", "===")) or "Error" in line:
                print(f"    \033[2m{line.strip()[:150]}\033[0m")
    else:
        device.stop_frida_server(serial)  # nothing on the device for the app to find
        device.launch(serial, package)


def _ask(question: str, default: str = "") -> str:
    shown = f" [{default}]" if default else ""
    return input(f"\033[1m › {question}\033[0m{shown} ").strip() or default


def _add_cert(path: str) -> certs.StoredCert:
    c, already = certs.add(Path(path))
    if already:
        say(f"\033[32mthat certificate is already in certs/ ({c.path.name}): you're good\033[0m")
    else:
        say(f"stored {c.subject} as certs/{c.path.name}  (SHA-256 {c.fingerprint[:16]}…)")
    if not c.is_ca:
        warn("it isn't marked as a CA (basicConstraints CA:TRUE); export your proxy's CA certificate, not a leaf")
    return c


def _ask_cert() -> certs.StoredCert:
    have = certs.stored()
    if have:
        options = [(str(i), f"{c.subject}  \033[2m{c.path.name}\033[0m") for i, c in enumerate(have)]
        options.append(("new", "add another certificate"))
        pick = choose("Which CA certificate does your proxy sign with?", options, options[0][0], False)
        if pick != "new":
            return have[int(pick)]
    while True:
        try:
            return _add_cert(_ask("path to your proxy's CA certificate (PEM or DER, e.g. Burp's cacert.der)"))
        except certs.CertError as e:
            warn(str(e))


def pick_proxy(a) -> tuple[str, int, Path] | None:
    """Your own proxy as (host, port, its CA in certs/), or None for the built-in mitmweb."""
    if a.proxy:
        host, port = certs.parse_proxy(a.proxy)
        if a.ca:
            ca = _add_cert(a.ca)
        elif interactive() and not a.yes:
            ca = _ask_cert()
        else:
            raise certs.CertError("--proxy needs --ca: the CA certificate your proxy signs with")
    elif interactive() and not a.yes:
        own = choose(
            "Which proxy should the traffic go to?",
            [
                ("mitm", "unpinned's own mitmweb (started for you, on localhost)"),
                ("own", "your own proxy: Burp, HTTP Toolkit, Charles, … (ip:port)"),
            ],
            "mitm",
            False,
        )
        if own == "mitm":
            return None
        while True:
            try:
                host, port = certs.parse_proxy(_ask("proxy address (ip:port)", "127.0.0.1:8080"))
            except certs.CertError as e:
                warn(str(e))
                continue
            if intercept.listening(port, host):
                break
            warn(f"nothing answers on {host}:{port}; start the proxy's listener (bound so this Mac can reach it)")
        ca = _ask_cert()
    else:
        return None
    if not intercept.listening(port, host):
        raise certs.CertError(f"nothing answers on {host}:{port}")
    return host, port, ca.path


def cmd_run(a) -> int:
    if not device.has_snapshot(a.api):
        warn("no clean snapshot yet: run `unpinned setup` first")
        return 1
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=env.home()))
    apks = apk.load(Path(a.app), run_dir / "apks")
    r = analyze.analyze(apks)
    package = r.triage.package
    show_report(r)

    rec = a.strategy if a.strategy != "auto" else recommend(r)
    strategy = choose("How should unpinned get at the traffic?", list(STRATEGIES.items()), rec, a.yes)
    say(f"using: {strategy}")
    own = pick_proxy(a)

    assets.ensure_scripts()
    server = assets.ensure_frida_server()
    serial = device.running(a.api)
    if serial:
        say(f"resetting {serial} to the clean snapshot")
        device.reset(serial)
    else:
        say("booting from the clean snapshot")
        serial = device.boot(a.api, window=not a.headless)

    if own:
        host, port, ca_path = own
        url = None
        if certs.is_loopback(host):
            device.reverse(serial, port)  # the device's 127.0.0.1:port is this Mac's
            host = "127.0.0.1"
        say(f"proxy: {host}:{port}  ·  CA: certs/{ca_path.name}")
    else:
        port, url = intercept.start_mitmweb(a.insecure_upstream)
        host, ca_path = "127.0.0.1", intercept.mitm_ca()
        device.reverse(serial, port)
    ca = intercept.ca_pem(ca_path)  # waits for mitmweb to write its CA on first start
    say("adding the proxy's CA to the system store (covers code the hooks don't reach, like Flutter's Dart)")
    device.install_system_ca(serial, ca_path)
    config = intercept.write_config(ca, host, port, run_dir)

    if strategy == "gadget":
        say("patching in Frida's gadget with the hooks (apktool; a minute or two)")
        apks = patch.gadget(apks, package, config.read_text(), run_dir / "gadget")
    elif strategy == "apk-mitm":
        say("repackaging with apk-mitm")
        apks = patch.apk_mitm(Path(a.app), run_dir / "apk-mitm")
    if not a.headless:
        intercept.start_scrcpy(serial, f"unpinned · {package}")

    tried = {strategy}
    while True:
        _launch(a, serial, package, strategy, apks, config, run_dir, server)
        say(f"watching the app for {a.watch:.0f}s")
        outcome = watch.watch(serial, package, seconds=a.watch)
        if outcome.ok:
            break
        warn(f"the app refused to run ({'still open, showing' if outcome.alive else 'it closed'}: {outcome.reason})")
        options = [(k, STRATEGIES[k]) for k in ("gadget", "apk-mitm") if k not in tried]
        if not options:
            warn("every strategy has been tried: this one needs an app-specific hook (jadx, then --script)")
            return 2
        options.append(("stop", "stop here, and leave the app installed as it is"))
        nxt = choose("Patch it so it runs on this rooted device, and reopen it?", options, options[0][0], a.yes)
        if nxt == "stop":
            return 2
        tried.add(nxt)
        if nxt == "gadget":
            say("patching in Frida's gadget: the root-detection bypass and unpinning run before the app's own code")
            apks = patch.gadget(
                apk.load(Path(a.app), run_dir / "orig"), package, config.read_text(), run_dir / "gadget"
            )
        else:
            say("repackaging with apk-mitm")
            apks = patch.apk_mitm(Path(a.app), run_dir / "apk-mitm")
        strategy = nxt

    say(f"\033[32m{package} is running\033[0m ({strategy})")
    if url:
        say(f"traffic: {url}")
    if strategy == "hooks":
        say(f"hook output: {run_dir / 'frida.log'}")
        if interactive() and not a.yes:
            pid = device.shell(serial, f"pidof {package}", check=False).split()
            if pid and input("\033[1m › open a Frida REPL in the app? [Y/n] \033[0m").strip().lower() in ("", "y"):
                subprocess.run([env.frida_bin(), "-D", serial, "-p", pid[0]], check=False)
    elif strategy == "gadget":
        say("the hooks run inside the app; their output is in `adb logcat -s unpinned`")
    say("`unpinned stop` stops everything and discards the device's changes")
    return 0


def cmd_reset(a) -> int:
    serial = device.running(a.api)
    if not serial:
        warn("the unpinned emulator isn't running")
        return 1
    device.reset(serial)
    say("back to the clean snapshot")
    return 0


def cmd_stop(a) -> int:
    serial = device.running(a.api)
    if serial:
        device.kill(serial)
        say(f"stopped {serial} (changes discarded)")
    for name in intercept.stop_host_processes():
        say(f"stopped {name}")
    return 0


def cmd_patch(a) -> int:
    """Patch without running: writes the patched APK(s) for use elsewhere (a real device, another emulator)."""
    run_dir = Path(tempfile.mkdtemp(prefix="patch-", dir=env.home()))
    apks = apk.load(Path(a.app), run_dir / "apks")
    t = apk.triage(apks)
    if a.method == "gadget":
        host, port = certs.parse_proxy(a.proxy) if a.proxy else ("127.0.0.1", env.PROXY_PORT)
        ca = certs.to_pem(certs.read_der(_add_cert(a.ca).path)) if a.ca else intercept.ca_pem()
        assets.ensure_scripts()
        config = intercept.write_config(ca, host, port, run_dir)
        out = patch.gadget(apks, t.package, config.read_text(), run_dir / "gadget")
    else:
        out = patch.apk_mitm(Path(a.app), run_dir / "apk-mitm")
    dest = Path(a.out or Path.cwd())
    dest.mkdir(parents=True, exist_ok=True)
    for p in out:
        shutil.copyfile(p, dest / f"{t.package}-{a.method}-{p.name}")
        say(f"wrote {dest / f'{t.package}-{a.method}-{p.name}'}")
    if a.method == "gadget":
        say(f"the hooks send traffic to {a.proxy or f'127.0.0.1:{env.PROXY_PORT}'} (for 127.0.0.1, `adb reverse` it)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="unpinned", description=__doc__)
    p.add_argument(
        "--api",
        default=os.environ.get("UNPINNED_API", env.DEFAULT_API),
        help=f"Android API level of the Google APIs image (default {env.DEFAULT_API})",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check the tools, image, AVD and snapshot").set_defaults(fn=cmd_doctor)
    s = sub.add_parser("setup", help="download frida-server and the scripts, create the AVD, save a clean snapshot")
    s.add_argument("--headless", action="store_true", help="no emulator window")
    s.set_defaults(fn=cmd_setup)
    t = sub.add_parser("triage", help="what the app does about pinning, root, Frida and tampering (no device)")
    t.add_argument("app")
    t.set_defaults(fn=cmd_triage)
    r = sub.add_parser("run", help="triage, choose a strategy, run it, and patch the app if it refuses a rooted device")
    r.add_argument("app", help=".apk, or a bundle of splits (.apks / .xapk / .zip)")
    r.add_argument("--strategy", choices=["auto", *STRATEGIES], default="auto", help="skip the question")
    r.add_argument("--yes", action="store_true", help="take every recommended answer without asking")
    r.add_argument("--watch", type=float, default=20, help="seconds to watch for a refusal after launch (default 20)")
    r.add_argument("--proxy", metavar="HOST:PORT", help="your own proxy (Burp, HTTP Toolkit, …) instead of mitmweb")
    r.add_argument("--ca", help="your proxy's CA certificate, PEM or DER (stored in certs/; asked for if omitted)")
    r.add_argument("--script", action="append", help="extra Frida script to load after the hooks (repeatable)")
    r.add_argument(
        "--insecure-upstream",
        action="store_true",
        help="mitmweb doesn't verify the real servers' certificates (staging servers, self-signed test hosts)",
    )
    r.add_argument("--headless", action="store_true", help="no emulator window or scrcpy")
    r.set_defaults(fn=cmd_run)
    sub.add_parser("reset", help="put the running device back to the clean snapshot").set_defaults(fn=cmd_reset)
    sub.add_parser("stop", help="stop the emulator, the hooks, mitmweb and scrcpy").set_defaults(fn=cmd_stop)
    pa = sub.add_parser("patch", help="write a patched APK without running it")
    pa.add_argument("app")
    pa.add_argument("--method", choices=["gadget", "apk-mitm"], default="gadget")
    pa.add_argument(
        "--proxy", metavar="HOST:PORT", help="where the gadget's hooks send traffic (default 127.0.0.1:8080)"
    )
    pa.add_argument("--ca", help="CA the gadget's hooks trust, PEM or DER (default: unpinned's mitmweb CA)")
    pa.add_argument("--out", help="output directory (default: here)")
    pa.set_defaults(fn=cmd_patch)
    return p


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    try:
        sys.exit(a.fn(a))
    except (
        apk.ApkError,
        assets.AssetError,
        certs.CertError,
        device.DeviceError,
        intercept.InterceptError,
        patch.PatchError,
    ) as e:
        print(f"\033[31merror:\033[0m {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
