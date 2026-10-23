"""Static triage: does the app pin certificates, and how; does it look for root, Frida, an emulator or a tampered
build; which framework and protector it uses. Each finding carries its evidence and how sure it is, so the choice of
bypass can follow from it."""

from __future__ import annotations

import re
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from unpinned import apk, dex, env, hooks, static

DEFINITE, LIKELY, POSSIBLE = "definite", "likely", "possible"
MAX_SCAN = 256 * 1024 * 1024  # bytes of native code / bundles scanned per member
MAX_DEX = 512 * 1024 * 1024

# OkHttp / TrustKit-style pins: sha256/<base64 of 32 bytes> (or sha1/<20 bytes>)
PIN_RE = re.compile(r"^sha(?:256/[A-Za-z0-9+/]{43}=|1/[A-Za-z0-9+/]{27}=)$")
PIN_BYTES_RE = re.compile(rb"sha256/[A-Za-z0-9+/]{43}=")
LIBRARY_PREFIXES = (
    "Lokhttp3/",
    "Lokio/",
    "Landroidx/",
    "Landroid/",
    "Lcom/google/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lorg/apache/",
    "Lio/grpc/",
    "Lcom/android/",
    "Lorg/conscrypt/",
    "Lcom/squareup/",
    "Lretrofit2/",
    "Lio/flutter/",
    "Lcom/facebook/",
    "Lio/sentry/",
    "Lcom/datatheorem/",
    "Lcom/appmattus/",
    "Lorg/chromium/",
    "Lorg/bouncycastle/",
    "Lio/netty/",
    "Lio/ktor/",
    "Lcom/amazonaws/",
    "Lcom/microsoft/",
    "Lj$/",
    "Lcom/bumptech/",
    "Lcom/fasterxml/",
    "Lcom/amazon/",
    "Lcom/huawei/",  # HMS Core and AppGallery Connect: their own TLS stack, in many apps outside China too
    # protectors / RASP SDKs: their certificate checks guard the app's own integrity, never something to hook
    "Lapp/talsec/",
    "Lcom/aheaditec/talsec",
    "Lcom/guardsquare/",
    "Lno/promon/",
    "Lcom/appdome/",
    "Lcom/pairip/",  # Google Play's automatic protection
)
CERT_FILE_RE = re.compile(r"^(assets|res)/.+\.(cer|crt|pem|der|bks|p12|pfx|jks)$", re.I)


@dataclass
class Finding:
    category: str  # pinning | ct | root | integrity | anti_frida | emulator | anti_debug | protector | play_licence
    label: str
    strength: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Report:
    triage: apk.Triage
    findings: list[Finding] = field(default_factory=list)
    nsc: dict = field(default_factory=dict)
    pin_checks: list[hooks.PinCheck] = field(default_factory=list)  # the app's own certificate checks
    manifest: static.Manifest = field(default_factory=static.Manifest)
    secrets: list[static.Secret] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    compilers: list[str] = field(default_factory=list)  # from apkid: dx, d8, r8, dexlib (rebuilt by a tool)

    def of(self, *categories: str) -> list[Finding]:
        return [f for f in self.findings if f.category in categories]

    def pinning(self) -> str:
        """none | possible | likely | definite: the strongest pinning (or CT) finding."""
        order = {POSSIBLE: 1, LIKELY: 2, DEFINITE: 3}
        best = max((order[f.strength] for f in self.of("pinning", "ct")), default=0)
        return {0: "none", 1: POSSIBLE, 2: LIKELY, 3: DEFINITE}[best]

    @property
    def detects_root(self) -> bool:
        return any(f.strength != POSSIBLE for f in self.of("root", "integrity"))

    @property
    def play_protected(self) -> bool:
        """Google Play's automatic protection: the app asks the Play Store whether Play installed it. No Play Store
        (unpinned's emulator) or a re-signed copy (the gadget, apk-mitm) fails that, whatever else is done."""
        return bool(self.of("play_licence"))

    @property
    def detects_frida(self) -> bool:
        return any(f.strength != POSSIBLE for f in self.of("anti_frida")) or bool(self.of("protector"))


# --- inputs ----------------------------------------------------------------------------------------------------
def _aapt2(*args: str) -> str:
    tool = env.tool("aapt2")
    if not tool:
        return ""
    r = subprocess.run([tool, *args], capture_output=True, text=True, timeout=120, check=False)
    return r.stdout if r.returncode == 0 else ""


def network_security_config(base: Path) -> dict:
    """The app's network security config: pinned domains and digests, trust anchors, cleartext, and whether user
    CAs are trusted. {} when there's none."""
    manifest = _aapt2("dump", "xmltree", "--file", "AndroidManifest.xml", str(base))
    m = re.search(r"networkSecurityConfig\(0x[0-9a-f]+\)=@(0x[0-9a-f]+)", manifest)
    if not m:
        return {}
    res_id = m.group(1)
    resources = _aapt2("dump", "resources", str(base))
    path = None
    lines = resources.splitlines()
    for i, ln in enumerate(lines):
        if f"resource {res_id} " in ln:
            for nxt in lines[i + 1 : i + 6]:
                fm = re.search(r"\(file\) (\S+\.xml)", nxt)
                if fm:
                    path = fm.group(1)
                    break
            break
    if not path:
        return {"present": True, "unreadable": True}
    tree = _aapt2("dump", "xmltree", "--file", path, str(base))
    out: dict = {
        "present": True,
        "file": path,
        "pins": [],
        "pinned_domains": [],
        "trust_anchors": [],
        "user_cas_trusted": False,
        "cleartext": False,
    }
    element = ""
    for ln in tree.splitlines():
        e = re.match(r"\s*E: (\S+)", ln)
        if e:
            element = e.group(1)
            continue
        a = re.match(
            r'\s*A: (?:http://schemas\.android\.com/apk/res/android:)?(\w+)(?:\(0x[0-9a-f]+\))?="?([^"]*)"?', ln
        )
        if not a:
            continue
        attr, val = a.group(1), a.group(2).split(" (Raw")[0]
        if element == "certificates" and attr == "src":
            out["trust_anchors"].append(val)
            out["user_cas_trusted"] |= val == "user"
        if attr == "cleartextTrafficPermitted" and val.lower() in ("true", "0xffffffff", "-1"):
            out["cleartext"] = True
    # pins and their domains: the raw lines are simplest to read in order
    pin_domain = None
    for ln in tree.splitlines():
        if re.match(r"\s*E: domain\b", ln):
            pin_domain = "?"
        t = re.match(r'\s*T: \'?"?([^"\']+)', ln)
        if t and pin_domain == "?":
            pin_domain = t.group(1).strip()
        if re.match(r"\s*E: pin-set\b", ln) and pin_domain:
            out["pinned_domains"].append(pin_domain)
        if re.match(r"\s*E: pin\b", ln):
            out["pins"].append(pin_domain or "?")
    out["pinned_domains"] = sorted(set(out["pinned_domains"]))
    out["trust_anchors"] = sorted(set(out["trust_anchors"]))
    return out


def _scan_bytes(z: zipfile.ZipFile, name: str, needles: dict[str, bytes]) -> set[str]:
    try:
        with z.open(name) as f:
            data = f.read(MAX_SCAN)
    except (KeyError, OSError, zipfile.BadZipFile):
        return set()
    return {label for label, n in needles.items() if n in data}


# --- signals ---------------------------------------------------------------------------------------------------
# native libraries whose names give a protection away (DVBA's libfrida-check.so, RootBeer's libtool-checker.so, …)
PROTECTION_LIBS = [
    ("anti_frida", re.compile(r"frida|anti.?hook", re.I), "Frida detection library"),
    (
        "root",
        re.compile(r"tool-?checker|root.?(check|detect|beer)|jail.?break|magisk.?detect", re.I),
        "root detection library",
    ),
    ("anti_debug", re.compile(r"anti.?debug", re.I), "debugger detection library"),
    ("protector", re.compile(r"tamper|integrity.?check|anti.?tamper", re.I), "tamper detection library"),
]

ROOT_STRINGS = [
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.koushikdutta.superuser",
    "test-keys",
    "/system/bin/.ext",
    "magisk",
    "Superuser",
]
FRIDA_STRINGS = [
    "frida-server",
    "frida-agent",
    "frida-gadget",
    "gum-js-loop",
    "gmain",
    "linjector",
    "re.frida",
    "27042",
    "LIBFRIDA",
]
EMULATOR_STRINGS = ["goldfish", "ranchu", "ro.kernel.qemu", "generic_x86", "Genymotion", "vbox86", "sdk_gphone"]
DEBUG_STRINGS = ["TracerPid", "isDebuggerConnected"]
# native libraries that are someone else's code: Chromium's Cronet carries its own pin list, crash reporters
# mention debuggers, and so on. Signals there say nothing about the app.
THIRD_PARTY_LIBS = re.compile(
    r"^lib(cronet|flutter|chrome|webview|monochrome|sentry|crashlytics|bugsnag|"
    r"conscrypt|ssl|crypto|c\+\+_shared|hermes|jsc|reactnativejni|realm|sqlcipher|"
    r"tensorflowlite|mlkit|barhopper|opencv)",
    re.I,
)
NATIVE_NEEDLES = {
    "frida": b"frida-agent",
    "frida-server": b"frida-server",
    "frida-gadget": b"frida-gadget",
    "re.frida": b"re.frida",
    "linjector": b"linjector",
    "gum-js-loop": b"gum-js-loop",
    "su path": b"/system/xbin/su",
    "magisk": b"magisk",
    "TracerPid": b"TracerPid",
    "sha256 pin": b"sha256/",
}
FLUTTER_NEEDLES = {
    "badCertificateCallback": b"badCertificateCallback",
    "SecurityContext": b"SecurityContext",
    "setTrustedCertificates": b"setTrustedCertificates",
    "http_certificate_pinning": b"http_certificate_pinning",
    "ssl_pinning_plugin": b"ssl_pinning_plugin",
    "flutter_jailbreak_detection": b"flutter_jailbreak_detection",
    "safe_device": b"safe_device",
    "freerasp": b"freerasp",
}
RN_NEEDLES = {
    "react-native-ssl-pinning": b"react-native-ssl-pinning",
    "react-native-ssl-public-key-pinning": b"react-native-ssl-public-key-pinning",
    "jail-monkey": b"jail-monkey",
    "isJailBroken": b"isJailBroken",
    "freerasp": b"freerasp",
}


def analyze(apks: list[Path]) -> Report:
    t = apk.triage(apks)
    rep = Report(t)
    add = rep.findings.append
    base = apk.base_apk(apks)

    # network security config
    nsc = network_security_config(base)
    rep.nsc = nsc
    if nsc.get("pinned_domains") or nsc.get("pins"):
        add(
            Finding(
                "pinning",
                "network security config <pin-set>",
                DEFINITE,
                [f"{nsc.get('file')}: {', '.join(nsc['pinned_domains']) or 'pins'}"],
            )
        )
    custom_anchors = [a for a in nsc.get("trust_anchors", []) if a not in ("system", "user")]
    if custom_anchors:
        add(Finding("pinning", "network security config trusts only bundled CAs", LIKELY, custom_anchors))

    # dex: strings and classes
    strings: set[str] = set()
    classes: list[tuple[str, str, list[str]]] = []
    methods: list[tuple[str, str, list[str], str]] = []
    names: list[str] = []
    native_hits: dict[str, set[str]] = {}
    flutter_hits: set[str] = set()
    rn_hits: set[str] = set()
    cert_files: list[str] = []
    asset_texts: list[str] = []
    for a in apks:
        with zipfile.ZipFile(a) as z:
            for info in z.infolist():
                n = info.filename
                names.append(n)
                if re.fullmatch(r"classes\d*\.dex", n):
                    try:
                        with z.open(n) as f:
                            data = f.read(MAX_DEX + 1)
                        if len(data) > MAX_DEX:
                            continue
                        d = dex.parse(data)
                    except (dex.DexError, OSError, zipfile.BadZipFile):
                        continue
                    strings.update(d.strings)
                    classes += d.classes
                    methods += d.methods
                elif n.endswith("/libapp.so"):
                    flutter_hits |= _scan_bytes(z, n, FLUTTER_NEEDLES)
                elif n == "assets/index.android.bundle":
                    rn_hits |= _scan_bytes(z, n, RN_NEEDLES)
                elif n.startswith("lib/") and n.endswith(".so") and not THIRD_PARTY_LIBS.match(n.rsplit("/", 1)[-1]):
                    for hit in _scan_bytes(z, n, NATIVE_NEEDLES):
                        native_hits.setdefault(hit, set()).add(n.rsplit("/", 1)[-1])
                if CERT_FILE_RE.match(n):
                    cert_files.append(n)
                if static.TEXT_ASSET.match(n) and info.file_size <= 4 * 1024 * 1024:
                    try:
                        asset_texts.append(z.read(n).decode("utf-8", "replace"))
                    except (OSError, zipfile.BadZipFile):
                        pass

    def has_type(prefix: str) -> bool:
        return any(s.startswith(prefix) for s in strings)

    pins = sorted(s for s in strings if PIN_RE.match(s))
    if pins:
        add(
            Finding(
                "pinning",
                "hard-coded public key pins (OkHttp / TrustKit format)",
                DEFINITE,
                [f"{len(pins)} pin(s), e.g. {pins[0]}"],
            )
        )
    if "Lokhttp3/CertificatePinner$Builder;" in strings and not pins:
        add(
            Finding(
                "pinning",
                "OkHttp CertificatePinner is used",
                POSSIBLE,
                ["the builder is referenced, but no pins are hard-coded (they may be built at run time)"],
            )
        )
    if has_type("Lcom/datatheorem/android/trustkit/"):
        add(Finding("pinning", "TrustKit", LIKELY, ["com.datatheorem.android.trustkit"]))
    if has_type("Lcom/appmattus/certificatetransparency/"):
        add(
            Finding(
                "ct", "Certificate Transparency checks (Appmattus)", DEFINITE, ["com.appmattus.certificatetransparency"]
            )
        )
    trust_ifaces = {"Ljavax/net/ssl/X509TrustManager;", "Ljavax/net/ssl/TrustManager;"}
    trust_supers = {"Ljavax/net/ssl/X509ExtendedTrustManager;"}
    own_tms = sorted(
        c
        for c, sup, ifs in classes
        if (sup in trust_supers or trust_ifaces & set(ifs)) and not c.startswith(LIBRARY_PREFIXES)
    )
    if own_tms:
        digest = "Ljava/security/MessageDigest;" in strings and "getPublicKey" in strings
        add(
            Finding(
                "pinning",
                "the app's own TrustManager" + (" (with public key hashing)" if digest else ""),
                LIKELY if digest else POSSIBLE,
                [_java(c) for c in own_tms[:5]],
            )
        )
    app_classes = {c for c, _, _ in classes if not c.startswith(LIBRARY_PREFIXES)}
    rep.pin_checks = hooks.candidates(methods, app_classes, set(own_tms))
    if rep.pin_checks:
        add(
            Finding(
                "pinning",
                "the app's own certificate checks (unpinned can hook these)",
                LIKELY,
                [c.label() for c in rep.pin_checks[:4]]
                + ([f"+{len(rep.pin_checks) - 4} more"] if len(rep.pin_checks) > 4 else []),
            )
        )
    rep.manifest = static.manifest(base)
    res_strings = static.resource_strings(base)
    rep.secrets = static.secrets({"code": strings, "resources": res_strings, "assets": asset_texts})
    rep.endpoints = static.endpoints([*strings, *res_strings, *asset_texts])
    own_hv = sorted(
        c for c, _, ifs in classes if "Ljavax/net/ssl/HostnameVerifier;" in ifs and not c.startswith(LIBRARY_PREFIXES)
    )
    if own_hv:
        add(Finding("pinning", "the app's own HostnameVerifier", POSSIBLE, [_java(c) for c in own_hv[:5]]))
    if cert_files:
        add(Finding("pinning", "bundled certificate / keystore files", POSSIBLE, cert_files[:5]))
    if "sha256 pin" in native_hits:
        add(Finding("pinning", "pins in native code", LIKELY, sorted(native_hits["sha256 pin"])[:5]))

    if flutter_hits & {"http_certificate_pinning", "ssl_pinning_plugin"}:
        add(Finding("pinning", "Flutter pinning plugin", DEFINITE, sorted(flutter_hits)))
    elif flutter_hits & {"badCertificateCallback", "setTrustedCertificates"}:
        add(
            Finding(
                "pinning",
                "Flutter custom certificate handling",
                LIKELY,
                sorted(flutter_hits & {"badCertificateCallback", "setTrustedCertificates"}),
            )
        )
    if rn_hits & {"react-native-ssl-pinning", "react-native-ssl-public-key-pinning"}:
        add(Finding("pinning", "React Native pinning library", DEFINITE, sorted(rn_hits)))

    # root, integrity, Frida, emulator, debugger
    if has_type("Lcom/scottyab/rootbeer/"):
        add(Finding("root", "RootBeer", DEFINITE, ["com.scottyab.rootbeer"]))
    root_hits = [s for s in ROOT_STRINGS if s in strings]
    if root_hits:
        add(Finding("root", "root-detection strings", LIKELY if len(root_hits) > 1 else POSSIBLE, root_hits[:6]))
    if {"su path", "magisk"} & set(native_hits):
        add(
            Finding(
                "root",
                "root checks in native code",
                LIKELY,
                sorted(native_hits.get("su path", set()) | native_hits.get("magisk", set()))[:5],
            )
        )
    if flutter_hits & {"flutter_jailbreak_detection", "safe_device", "freerasp"} or rn_hits & {
        "jail-monkey",
        "isJailBroken",
    }:
        add(
            Finding(
                "root",
                "root-detection plugin",
                DEFINITE,
                sorted(
                    (flutter_hits | rn_hits)
                    & {"flutter_jailbreak_detection", "safe_device", "freerasp", "jail-monkey", "isJailBroken"}
                ),
            )
        )
    if has_type("Lcom/google/android/play/core/integrity/") or has_type("Lcom/google/android/play/integrity/"):
        add(
            Finding(
                "integrity",
                "Play Integrity API",
                LIKELY,
                ["the server decides; an emulator fails device integrity whatever is hooked"],
            )
        )
    if has_type("Lcom/pairip/licensecheck/"):
        ev = ["com.pairip.licensecheck: asks the Play Store whether Play installed the app"]
        if any(n.endswith("/libpairipcore.so") for n in names):
            ev.append("libpairipcore.so: code protection and tamper checks too")
        add(Finding("play_licence", "Google Play automatic protection", DEFINITE, ev))
    if has_type("Lcom/google/android/gms/safetynet/"):
        add(Finding("integrity", "SafetyNet attestation (deprecated)", LIKELY, ["com.google.android.gms.safetynet"]))
    if has_type("Lcom/aheaditec/talsec/") or "freerasp" in flutter_hits | rn_hits:
        add(Finding("protector", "Talsec freeRASP", DEFINITE, ["root, Frida, emulator and tamper checks"]))
    frida_hits = [s for s in FRIDA_STRINGS if s in strings]
    frida_native = {"frida", "frida-server", "frida-gadget", "re.frida", "linjector", "gum-js-loop"} & set(native_hits)
    if frida_hits or frida_native:
        ev = frida_hits + sorted({lib for k in frida_native for lib in native_hits[k]})
        add(Finding("anti_frida", "Frida detection", LIKELY, ev[:6]))
    emu_hits = [s for s in EMULATOR_STRINGS if s in strings]
    if len(emu_hits) > 1:
        add(Finding("emulator", "emulator detection", LIKELY, emu_hits[:6]))
    dbg = [s for s in DEBUG_STRINGS if s in strings] + sorted(native_hits.get("TracerPid", set()))
    if dbg:
        add(Finding("anti_debug", "debugger detection", POSSIBLE, dbg[:4]))
    native_libs = sorted({n.rsplit("/", 1)[-1] for n in names if n.startswith("lib/") and n.endswith(".so")})
    for category, rx, label in PROTECTION_LIBS:
        hits = [lib for lib in native_libs if rx.search(lib) and not lib.startswith("libfrida-gadget")]
        if hits:
            add(Finding(category, label, LIKELY, hits[:4]))
    for label in t.protectors:
        add(Finding("protector", label, LIKELY, ["native library names"]))
    more, rep.compilers = apkid(apks)
    rep.findings += more
    return rep


# apkid (https://github.com/rednaga/APKiD): known packers, protectors, obfuscators and anti-analysis tricks, by
# signature. Optional: used when it's installed. Its categories map onto triage's.
APKID_CATEGORIES = {
    "anti_vm": ("emulator", LIKELY),
    "anti_debug": ("anti_debug", LIKELY),
    "anti_root": ("root", LIKELY),
    "packer": ("protector", DEFINITE),
    "protector": ("protector", DEFINITE),
    "obfuscator": ("obfuscation", LIKELY),
    "anti_disassembly": ("anti_analysis", LIKELY),
    "abnormal": ("anti_analysis", POSSIBLE),
    "manipulator": ("tampering", LIKELY),
}


# apkid files Google's own protections under "protector"; triage has its own categories for them (they aren't RASP:
# nothing in them looks for root or Frida)
APKID_GOOGLE = [
    (re.compile(r"google automatic integrity|pairip", re.I), "play_licence", DEFINITE),
    (re.compile(r"play integrity", re.I), "integrity", LIKELY),
]


def apkid(apks: list[Path]) -> tuple[list[Finding], list[str]]:
    """Run apkid over the APKs. → (findings, compilers seen); ([], []) when apkid isn't installed or fails."""
    import json
    import shutil

    tool = shutil.which("apkid")
    if not tool:
        return [], []
    found: dict[tuple[str, str], set[str]] = {}
    compilers: set[str] = set()
    for a in apks:
        try:
            r = subprocess.run(
                [tool, "-j", "-t", "120", str(a)], capture_output=True, text=True, timeout=600, check=False
            )
            data = json.loads(r.stdout or "{}")
        except (subprocess.TimeoutExpired, ValueError, RecursionError):
            continue
        for f in data.get("files", []) if isinstance(data, dict) else []:
            if not isinstance(f, dict) or not isinstance(f.get("matches"), dict):
                continue
            where = str(f.get("filename", "")).split("!", 1)[-1].rsplit("/", 1)[-1][:60]
            for category, labels in f["matches"].items():
                for label in labels if isinstance(labels, list) else []:
                    label = str(label)[:80]
                    if category == "compiler":
                        if "unknown" not in label:
                            compilers.add(label)
                    elif category in APKID_CATEGORIES:
                        found.setdefault((category, label), set()).add(where)
    findings = []
    named = {"packer", "protector", "obfuscator", "manipulator"}  # the name is the finding: one line each
    grouped: dict[str, list[str]] = {}
    for (category, label), wheres in sorted(found.items()):
        ours, strength = APKID_CATEGORIES[category]
        if category in named:
            ours, strength = next(((c, st) for rx, c, st in APKID_GOOGLE if rx.search(label)), (ours, strength))
            findings.append(Finding(ours, f"{label} (apkid)", strength, sorted(wheres)[:4]))
        else:
            grouped.setdefault(category, []).append(label)
    descriptions = {
        "anti_vm": "emulator checks",
        "anti_debug": "debugger checks",
        "anti_root": "root checks",
        "anti_disassembly": "anti-disassembly tricks",
        "abnormal": "unusual structure",
    }
    for category, labels in grouped.items():
        ours, strength = APKID_CATEGORIES[category]
        findings.append(Finding(ours, f"{descriptions.get(category, category)} (apkid)", strength, labels[:8]))
    return findings, sorted(compilers)


def _java(descriptor: str) -> str:
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") else descriptor
