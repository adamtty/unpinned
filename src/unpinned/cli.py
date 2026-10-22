"""unpinned: setup once, then `unpinned run app.apk`."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from unpinned import analyze, apk, assets, certs, device, env, hooks, intercept, patch, phone, static, watch

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
    device.settle(serial)
    device.prepare(serial, server)
    say("switching ART to its concurrent-copying garbage collector (gadget-patched apps need it; one reboot)")
    device.use_cc_gc(serial)
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
    show_static(r, getattr(show_report, "show_secrets", False))
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


def show_static(r: analyze.Report, show_secrets: bool = False) -> None:
    m = r.manifest
    flags = []
    if m.debuggable:
        flags.append("\033[31mdebuggable\033[0m")
    if m.allow_backup:
        flags.append("\033[33mallowBackup\033[0m (adb backup can copy its data)")
    if m.cleartext:
        flags.append("\033[33mcleartext HTTP allowed\033[0m")
    exposed = [c for c in m.exposed if not c.launcher]
    if flags or exposed or m.deep_links:
        print("\n  \033[1mManifest\033[0m" + (f"  \033[2mtarget SDK {m.target_sdk}\033[0m" if m.target_sdk else ""))
        if flags:
            print("    " + " · ".join(flags))
        for c in exposed[:12]:
            why = " (implicitly, via an intent filter on an old target SDK)" if c.implicit else ""
            print(f"    \033[33m●\033[0m exported {c.kind} with no permission: {c.name}{why}")
        if len(exposed) > 12:
            print(f"    \033[2m+{len(exposed) - 12} more exported components\033[0m")
        for link in m.deep_links[:10]:
            print(f"    ○ deep link: {link}")
        if len(m.deep_links) > 10:
            print(f"    \033[2m+{len(m.deep_links) - 10} more deep links\033[0m")
    if r.secrets:
        hint = "" if show_secrets else "  \033[2m(masked: --show-secrets)\033[0m"
        print("\n  \033[1mHard-coded secrets\033[0m" + hint)
        for sec in r.secrets[:15]:
            value = sec.value if show_secrets else sec.masked()
            note = f"  \033[2m{sec.note}\033[0m" if sec.note else ""
            print(f"    \033[31m●\033[0m {sec.kind}: {value}  \033[2m({sec.where})\033[0m{note}")
    if r.endpoints:
        top = static.hosts(r.endpoints)
        print(f"\n  \033[1mEndpoints\033[0m  \033[2m{len(r.endpoints)} URLs on {len(top)} hosts\033[0m")
        print("    " + ", ".join(f"{h} ({n})" for h, n in top[:12]) + (" …" if len(top) > 12 else ""))


def report_json(r: analyze.Report, show_secrets: bool) -> dict:
    import dataclasses

    t = r.triage
    return {
        "package": t.package,
        "version": t.version,
        "min_sdk": t.min_sdk,
        "target_sdk": t.target_sdk,
        "abis": t.abis,
        "frameworks": t.frameworks,
        "pinning": r.pinning(),
        "findings": [dataclasses.asdict(f) for f in r.findings],
        "pin_checks": [c.label() for c in getattr(r, "pin_checks", [])],
        "manifest": dataclasses.asdict(r.manifest),
        "secrets": [
            {"kind": s.kind, "value": s.value if show_secrets else s.masked(), "where": s.where, "note": s.note}
            for s in r.secrets
        ],
        "endpoints": r.endpoints,
    }


def recommend(r: analyze.Report) -> str:
    if r.pinning() == "none" and not r.of("ct") and not r.detects_root:
        return "ca"
    if r.detects_frida:
        return "gadget"
    return "hooks"


def cmd_triage(a) -> int:
    with tempfile.TemporaryDirectory(prefix="unpinned-") as tmp:
        r = analyze.analyze(apk.load(Path(a.app), Path(tmp)))
        show_report.show_secrets = a.show_secrets
        show_report(r)
        if a.json:
            import json

            Path(a.json).write_text(json.dumps(report_json(r, a.show_secrets), indent=2))
            say(f"wrote {a.json}")
        if a.endpoints:
            print("\n".join(r.endpoints))
        say(f"suggested: {recommend(r)} — {STRATEGIES[recommend(r)]}")
    return 0


# --- run ----------------------------------------------------------------------------------------------------------
def _launch(
    a,
    serial: str,
    package: str,
    strategy: str,
    apks: list[Path] | None,
    config: Path,
    run_dir: Path,
    server: Path,
    proxy: tuple[str, int],
) -> None:
    """(Re)install if there are APKs to install, then start the app the chosen way. Hooks and the gadget redirect
    traffic themselves; the other ways rely on the device-wide proxy setting."""
    if apks:
        device.uninstall(serial, package)  # a patched build is signed differently from what may be there
        say(f"installing ({len(apks)} APK{'s' if len(apks) != 1 else ''})")
        device.install(serial, apks)
    device.shell(serial, f"am force-stop {package}", check=False)
    if strategy == "hooks":
        device.set_proxy(serial, None)
        device.remove_transparent_proxy(serial)
        say("starting frida-server and spawning the app with the hooks")
        used = device.start_frida_server(serial, server, assets.frida_server_fallback)
        if used != "pinned":
            warn(f"this device can't run current frida-server ({device.FRIDA_OLD_DEVICE_BUG}): using {used}")
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
        device.remove_transparent_proxy(serial)
        device.set_proxy(serial, None)
        if strategy in ("ca", "apk-mitm"):
            host, port = proxy
            if not a.global_proxy and host == "127.0.0.1":
                uid = device.transparent_proxy(serial, package, port)
                say(f"sending only {package}'s traffic (uid {uid}) to the proxy, whatever its proxy settings")
            else:
                device.set_proxy(serial, host, port)
                say("using the device-wide proxy setting (apps may ignore it)")
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


GADGET_STABLE_API = "34"
FRIDA_A16_BUG = "https://github.com/frida/frida/issues/3805"


def gadget_api(a) -> str:
    """Frida's Java hooks inside a gadget can crash ART's garbage collector on Android 16 (an open Frida bug), while
    Android 14 is stable: offer to run gadget builds there."""
    try:
        major = float(a.api)
    except ValueError:
        return a.api
    if major < 36:
        return a.api
    warn(f"gadget-patched apps can crash on Android 16: an open Frida bug in its Java hooks ({FRIDA_A16_BUG})")
    if not device.has_snapshot(GADGET_STABLE_API):
        say(
            f"for stable gadget runs: `unpinned --api {GADGET_STABLE_API} setup`, then run with "
            f"`--api {GADGET_STABLE_API}`"
        )
        return a.api
    pick = choose(
        "Run it on Android 14 instead (stable with the gadget)?",
        [(GADGET_STABLE_API, "yes, use the Android 14 emulator"), (a.api, f"no, stay on Android {a.api}")],
        GADGET_STABLE_API,
        a.yes,
    )
    return pick


def _pin_check_hooks(a, r: analyze.Report, run_dir: Path) -> Path | None:
    """Offer to hook the app's own certificate checks found by triage; → the generated script, or None."""
    if not r.pin_checks or a.no_auto_hooks:
        return None
    if interactive() and not a.yes:
        print()
        for c in r.pin_checks[:10]:
            print(f"    · {c.label()}")
        if input(
            f"\033[1m › hook these {len(r.pin_checks)} certificate check(s) to always pass? [Y/n] \033[0m"
        ).strip().lower() not in ("", "y"):
            return None
    path = run_dir / "pin-checks.js"
    path.write_text(hooks.script(r.pin_checks))
    say(f"hooking {len(r.pin_checks)} of the app's own certificate check(s)")
    return path


def _setup_proxy(a, serial: str, own, run_dir: Path) -> tuple[str, int, str | None, Path]:
    """Point the device at the proxy and trust its CA system-wide. → (host as the device sees it, port, mitmweb URL,
    config.js for the hooks)."""
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
    return host, port, url, intercept.write_config(ca, host, port, run_dir)


def _patch(
    kind: str,
    original: Path,
    package: str,
    config: Path,
    run_dir: Path,
    api: str | None,
    extra: list[Path] | None = None,
) -> list[Path]:
    if kind == "gadget":
        if api and not api.startswith(("1", "2", "30", "31", "32", "33", "34", "35")):
            warn(f"on Android {api} the gadget can crash ({FRIDA_A16_BUG}); `--api {GADGET_STABLE_API}` is stable")
        say("patching in Frida's gadget: the root-detection bypass and unpinning run before the app's own code")
        return patch.gadget(
            apk.load(original, run_dir / "orig"),
            package,
            config.read_text(),
            run_dir / "gadget",
            extra=[p.read_text() for p in extra or []],
        )
    say("repackaging with apk-mitm")
    return patch.apk_mitm(original, run_dir / "apk-mitm")


def _run_and_watch(
    a, serial, package, strategy, apks, original, config, run_dir, server, proxy, *, api=None, confirm_reinstall=None
) -> str | None:
    """Launch, watch for a refusal, and offer the next patch until the app runs. → the strategy that worked, or None
    when the user stops (or nothing is left to try)."""
    tried = {strategy}
    while True:
        _launch(a, serial, package, strategy, apks, config, run_dir, server, proxy)
        say(f"watching the app for {a.watch:.0f}s")
        outcome = watch.watch(serial, package, seconds=a.watch)
        if outcome.ok:
            return strategy
        warn(f"the app refused to run ({'still open, showing' if outcome.alive else 'it closed'}: {outcome.reason})")
        options = [(k, STRATEGIES[k]) for k in ("gadget", "apk-mitm") if k not in tried]
        if not options:
            warn("every strategy has been tried: this one needs an app-specific hook (jadx, then --script)")
            return None
        options.append(("stop", "stop here, and leave the app installed as it is"))
        nxt = choose("Patch it so it runs on this rooted device, and reopen it?", options, options[0][0], a.yes)
        if nxt == "stop" or (confirm_reinstall and not confirm_reinstall()):
            return None
        tried.add(nxt)
        apks = _patch(nxt, original, package, config, run_dir, api, [Path(x) for x in a.script or []])
        strategy = nxt


def _finish(a, serial: str, package: str, strategy: str, url: str | None, run_dir: Path, stop_hint: str) -> None:
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
    say(stop_hint)


def _pick_package(serial: str, query: str, yes: bool) -> str:
    """An installed app by exact package name, or by searching the phone's apps."""
    everything = phone.packages(serial, third_party=False)
    if query in everything:
        return query
    hits = phone.packages(serial, query)
    if not hits:
        raise phone.PhoneError(f"no installed app matches {query!r}")
    if len(hits) == 1 or yes or not interactive():
        if len(hits) > 1:
            raise phone.PhoneError(f"{len(hits)} apps match {query!r}: give the full package name")
        return hits[0]
    return choose("Which app?", [(h, h) for h in hits[:30]], hits[0], False)


def _from_phone(a, run_dir: Path) -> Path:
    serial = phone.find(a.device)
    say(f"phone: {phone.describe(serial)} ({serial})")
    package = _pick_package(serial, a.app, a.yes)
    say(f"pulling {package} (every split) off the phone")
    bundle = phone.pull(serial, package)
    say(f"saved {bundle}")
    return bundle


def cmd_pull(a) -> int:
    with tempfile.TemporaryDirectory(prefix="pull-") as tmp:
        bundle = _from_phone(a, Path(tmp))
    if a.out:
        dest = Path(a.out)
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(bundle, dest / bundle.name)
        say(f"copied to {dest / bundle.name}")
    say(f"next: `unpinned run {bundle}` (emulator) or `unpinned phone {bundle.name.rsplit('-', 2)[0]}` (on the phone)")
    return 0


def cmd_run(a) -> int:
    if not device.has_snapshot(a.api):
        warn("no clean snapshot yet: run `unpinned setup` first")
        return 1
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=env.home()))
    original = _from_phone(a, run_dir) if a.from_phone else Path(a.app)
    apks = apk.load(original, run_dir / "apks")
    r = analyze.analyze(apks)
    package = r.triage.package
    show_report(r)
    if auto := _pin_check_hooks(a, r, run_dir):
        a.script = [*(a.script or []), str(auto)]

    rec = a.strategy if a.strategy != "auto" else recommend(r)
    strategy = choose("How should unpinned get at the traffic?", list(STRATEGIES.items()), rec, a.yes)
    say(f"using: {strategy}")
    if strategy == "gadget":
        a.api = gadget_api(a)
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

    host, port, url, config = _setup_proxy(a, serial, own, run_dir)
    if strategy == "gadget" and not device.uses_cc_gc(serial):
        warn("this snapshot predates the garbage-collector switch: run `unpinned setup` again")
    if strategy in ("gadget", "apk-mitm"):
        apks = _patch(strategy, original, package, config, run_dir, a.api, [Path(x) for x in a.script or []])
    if not a.headless:
        intercept.start_scrcpy(serial, f"unpinned · {package}")

    done = _run_and_watch(
        a, serial, package, strategy, apks, original, config, run_dir, server, (host, port), api=a.api
    )
    if not done:
        return 2
    _finish(
        a, serial, package, done, url, run_dir, "`unpinned stop` stops everything and discards the device's changes"
    )
    return 0


def _phone_cleanup(serial: str) -> None:
    device.stop_frida_server(serial)
    device.remove_transparent_proxy(serial)
    device.remove_system_ca(serial)
    device.set_proxy(serial, None)
    device.remove_reverse(serial)
    for name in intercept.stop_host_processes():
        say(f"stopped {name}")


def cmd_phone(a) -> int:
    """The same flow on a rooted phone: frida-server, the system CA and the proxy go on through `su`, so the app keeps
    its data. Patching means reinstalling, which wipes it, so that's asked first and the original is kept."""
    serial = phone.find(a.device)
    say(f"phone: {phone.describe(serial)} ({serial}), root via {phone.check_root(serial)}")
    if a.cleanup:
        _phone_cleanup(serial)
        say("frida-server stopped, the CA unmounted, the per-app redirect, proxy setting and adb reverse removed")
        return 0
    if a.restore:
        bundle = Path(a.restore)
        apks = apk.load(bundle, Path(tempfile.mkdtemp(prefix="restore-", dir=env.home())))
        package = apk.triage(apks).package
        device.uninstall(serial, package)
        device.install(serial, apks)
        say(f"reinstalled the original {package} from {bundle} (its data from before the patch is gone)")
        return 0
    if not a.app:
        warn("which app? `unpinned phone <package or search>`")
        return 1

    run_dir = Path(tempfile.mkdtemp(prefix="phone-", dir=env.home()))
    package = _pick_package(serial, a.app, a.yes)
    say(f"pulling {package} (every split) for triage, and as a backup")
    original = phone.pull(serial, package)
    say(f"saved {original}")
    r = analyze.analyze(apk.load(original, run_dir / "apks"))
    show_report(r)
    if auto := _pin_check_hooks(a, r, run_dir):
        a.script = [*(a.script or []), str(auto)]

    rec = a.strategy if a.strategy != "auto" else recommend(r)
    if rec in ("gadget", "apk-mitm") and a.strategy == "auto":
        rec = "hooks"  # on the phone, try the ways that keep the app's data first
    strategy = choose("How should unpinned get at the traffic?", list(STRATEGIES.items()), rec, a.yes)
    say(f"using: {strategy}")
    own = pick_proxy(a)

    def confirm_reinstall() -> bool:
        if a.yes or not interactive():
            return True
        warn(
            f"patching reinstalls {package}: its data on the phone (logins, settings) is lost. The original is saved: "
            f"`unpinned phone --restore {original}` puts it back."
        )
        return input("\033[1m › go ahead? [y/N] \033[0m").strip().lower() == "y"

    apks = None
    if strategy in ("gadget", "apk-mitm"):
        if not confirm_reinstall():
            return 1
    assets.ensure_scripts()
    server = assets.ensure_frida_server()
    host, port, url, config = _setup_proxy(a, serial, own, run_dir)
    if strategy in ("gadget", "apk-mitm"):
        apks = _patch(strategy, original, package, config, run_dir, None, [Path(x) for x in a.script or []])
    if not a.headless:
        intercept.start_scrcpy(serial, f"unpinned · {package}")

    done = _run_and_watch(
        a,
        serial,
        package,
        strategy,
        apks,
        original,
        config,
        run_dir,
        server,
        (host, port),
        confirm_reinstall=confirm_reinstall,
    )
    if not done:
        return 2
    _finish(
        a,
        serial,
        package,
        done,
        url,
        run_dir,
        "`unpinned phone --cleanup` takes it all off the phone again (a reboot does too)",
    )
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
    for serial in device.serials():  # every unpinned emulator, whichever Android version
        name = device.adb("emu", "avd", "name", serial=serial, check=False).splitlines()
        if name and name[0].strip().startswith("unpinned-api"):
            device.kill(serial)
            say(f"stopped {serial} ({name[0].strip()}, changes discarded)")
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
    t = sub.add_parser("triage", help="pinning, root/Frida checks, manifest, secrets and endpoints (no device)")
    t.add_argument("app")
    t.add_argument("--show-secrets", action="store_true", help="print secrets in full (masked by default)")
    t.add_argument("--json", help="write the whole triage to this JSON file")
    t.add_argument("--endpoints", action="store_true", help="list every URL found")
    t.set_defaults(fn=cmd_triage)
    r = sub.add_parser("run", help="triage, choose a strategy, run it, and patch the app if it refuses a rooted device")
    r.add_argument("app", help=".apk or a bundle (.apks / .xapk / .zip); with --from-phone, a package name or search")
    r.add_argument("--from-phone", action="store_true", help="pull the app off a connected phone first")
    r.add_argument("--device", help="the phone's adb serial (default: the only phone connected)")
    r.add_argument("--strategy", choices=["auto", *STRATEGIES], default="auto", help="skip the question")
    r.add_argument("--yes", action="store_true", help="take every recommended answer without asking")
    r.add_argument("--watch", type=float, default=20, help="seconds to watch for a refusal after launch (default 20)")
    r.add_argument("--proxy", metavar="HOST:PORT", help="your own proxy (Burp, HTTP Toolkit, …) instead of mitmweb")
    r.add_argument("--ca", help="your proxy's CA certificate, PEM or DER (stored in certs/; asked for if omitted)")
    r.add_argument("--script", action="append", help="extra Frida script to load after the hooks (repeatable)")
    r.add_argument("--no-auto-hooks", action="store_true", help="don't hook the app's own certificate checks")
    r.add_argument(
        "--insecure-upstream",
        action="store_true",
        help="mitmweb doesn't verify the real servers' certificates (staging servers, self-signed test hosts)",
    )
    r.add_argument("--headless", action="store_true", help="no emulator window or scrcpy")
    r.add_argument(
        "--global-proxy",
        action="store_true",
        help="without Frida, use the device-wide proxy setting instead of redirecting just the app with iptables",
    )
    r.set_defaults(fn=cmd_run)
    pl = sub.add_parser("pull", help="pull an installed app (every split) off a phone into one .apks")
    pl.add_argument("app", help="package name, or part of one to search for")
    pl.add_argument("--device", help="the phone's adb serial (default: the only phone connected)")
    pl.add_argument("--out", help="also copy the bundle here")
    pl.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    pl.set_defaults(fn=cmd_pull)
    ph = sub.add_parser("phone", help="do it on a rooted phone: hooks, CA and proxy via su; patch only if asked")
    ph.add_argument("app", nargs="?", help="package name, or part of one to search for")
    ph.add_argument("--device", help="the phone's adb serial (default: the only phone connected)")
    ph.add_argument("--strategy", choices=["auto", *STRATEGIES], default="auto", help="skip the question")
    ph.add_argument("--yes", action="store_true", help="take every recommended answer without asking")
    ph.add_argument("--watch", type=float, default=20, help="seconds to watch for a refusal after launch")
    ph.add_argument("--proxy", metavar="HOST:PORT", help="your own proxy instead of mitmweb")
    ph.add_argument("--ca", help="your proxy's CA certificate, PEM or DER")
    ph.add_argument("--script", action="append", help="extra Frida script to load after the hooks")
    ph.add_argument("--no-auto-hooks", action="store_true", help="don't hook the app's own certificate checks")
    ph.add_argument("--insecure-upstream", action="store_true", help="mitmweb doesn't verify the real servers")
    ph.add_argument("--headless", action="store_true", help="no scrcpy window")
    ph.add_argument(
        "--global-proxy",
        action="store_true",
        help="without Frida, use the device-wide proxy setting instead of redirecting just the app with iptables",
    )
    ph.add_argument("--cleanup", action="store_true", help="take frida-server, the CA and the proxy off the phone")
    ph.add_argument("--restore", metavar="BUNDLE", help="reinstall an original pulled before patching")
    ph.set_defaults(fn=cmd_phone)
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
        phone.PhoneError,
    ) as e:
        print(f"\033[31merror:\033[0m {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
