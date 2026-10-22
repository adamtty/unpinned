"""Reading what was dropped in: a single .apk, or a bundle of splits (.apks from bundletool, .xapk, or a plain .zip
of APKs), plus a quick static triage: package, versions, native ABIs, the app framework and hints of a protector."""

from __future__ import annotations

import re
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from unpinned import env

MAX_APKS = 64
MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024  # all the APKs of a bundle together

# (label, regex over the zip's member names)
FRAMEWORKS = [
    ("Flutter", r"^lib/[^/]+/lib(flutter|app)\.so$"),
    ("React Native", r"^assets/index\.android\.bundle$|^lib/[^/]+/lib(reactnativejni|hermes)\.so$"),
    ("Xamarin / .NET MAUI", r"^lib/[^/]+/lib(monodroid|monosgen-2\.0)\.so$|^assemblies/"),
    ("Unity", r"^lib/[^/]+/lib(unity|il2cpp)\.so$"),
    ("Cordova / Capacitor", r"^assets/www/cordova\.js$|^assets/capacitor\.config\.json$"),
]
PROTECTORS = [
    ("Promon SHIELD", r"^lib/[^/]+/libshield\.so$"),
    ("Qihoo 360 Jiagu", r"^lib/[^/]+/libjiagu[^/]*\.so$|^assets/libjiagu"),
    ("Bangcle / SecNeo", r"^lib/[^/]+/lib(secexe|secmain|DexHelper)[^/]*\.so$"),
    ("Tencent Legu", r"^lib/[^/]+/libshell[ax]?[^/]*\.so$"),
    ("Appdome", r"^lib/[^/]+/libloader\.so$|^assets/appdome"),
    ("DexProtector", r"^lib/[^/]+/libdexprotector[^/]*\.so$|^assets/dp\.arm"),
]


class ApkError(RuntimeError):
    pass


@dataclass
class Triage:
    package: str
    version: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    apks: list[Path] = field(default_factory=list)
    abis: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    protectors: list[str] = field(default_factory=list)

    def warnings(self) -> list[str]:
        out = []
        if self.abis and "arm64-v8a" not in self.abis:
            out.append(
                f"no arm64-v8a native code ({', '.join(self.abis)}): it may not install or run on this "
                "64-bit-only arm64 emulator"
            )
        if self.protectors:
            out.append(
                f"looks protected ({', '.join(self.protectors)}): expect anti-Frida / anti-root checks that "
                "the generic hooks won't beat"
            )
        return out


def load(path: Path, workdir: Path) -> list[Path]:
    """The APK files to install. A bundle is unpacked into workdir: only `*.apk` members, flattened to their base
    names (no paths taken from the archive), with count and size limits."""
    path = Path(path)
    if not path.is_file():
        raise ApkError(f"not a file: {path}")
    if not zipfile.is_zipfile(path):
        raise ApkError(f"{path.name} isn't an APK or a bundle of APKs (not a zip)")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "AndroidManifest.xml" in names:
            return [path]  # a plain APK
        members = [i for i in z.infolist() if not i.is_dir() and i.filename.lower().endswith(".apk")]
        if not members:
            raise ApkError(f"{path.name} has no AndroidManifest.xml and no .apk files inside")
        if len(members) > MAX_APKS:
            raise ApkError(f"{path.name} has more than {MAX_APKS} APKs")
        workdir.mkdir(parents=True, exist_ok=True)
        out, seen = [], set()
        total = [MAX_BUNDLE_BYTES]
        for i in members:
            base = Path(i.filename.replace("\\", "/")).name
            if not re.fullmatch(r"[A-Za-z0-9._-]+\.apk", base, flags=re.I) or base in seen:
                raise ApkError(f"{path.name}: unexpected APK name in the bundle: {i.filename!r}")
            if i.file_size > MAX_APK_BYTES:
                raise ApkError(f"{path.name}: {base} is larger than {MAX_APK_BYTES // (1024**3)} GB")
            seen.add(base)
            dest = workdir / base
            with z.open(i) as src, open(dest, "xb") as dst:
                left = MAX_APK_BYTES
                while chunk := src.read(1 << 20):
                    left -= len(chunk)
                    total[0] -= len(chunk)
                    if left < 0:
                        raise ApkError(f"{path.name}: {base} is larger than {MAX_APK_BYTES // (1024**3)} GB")
                    if total[0] < 0:
                        raise ApkError(f"{path.name}: the APKs add up to more than {MAX_BUNDLE_BYTES // (1024**3)} GB")
                    dst.write(chunk)
            out.append(dest)
    return sorted(out, key=lambda p: (p.name != "base.apk", p.name))


def _members(apks: list[Path]) -> list[str]:
    names = []
    for a in apks:
        with zipfile.ZipFile(a) as z:
            names += z.namelist()
    return names


def _badging(apk: Path) -> str:
    aapt2 = env.tool("aapt2")
    if not aapt2:
        raise ApkError("aapt2 not found (it comes with the Android SDK build-tools)")
    r = subprocess.run([aapt2, "dump", "badging", str(apk)], capture_output=True, text=True, timeout=120, check=False)
    if "package: name=" not in r.stdout:
        raise ApkError(f"aapt2 couldn't read {apk.name}: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout


def base_apk(apks: list[Path]) -> Path:
    """The APK with code in it (bundles also carry config / density / language splits)."""
    for a in apks:
        with zipfile.ZipFile(a) as z:
            if "classes.dex" in z.namelist():
                return a
    return apks[0]


def parse_badging(text: str) -> dict[str, str]:
    def one(pattern: str) -> str:
        m = re.search(pattern, text)
        return m.group(1) if m else ""

    return {
        "package": one(r"package: name='([^']+)'"),
        "version": one(r"versionName='([^']*)'"),
        "min_sdk": one(r"(?:minSdkVersion|sdkVersion):'([^']+)'"),
        "target_sdk": one(r"targetSdkVersion:'([^']+)'"),
    }


def classify(names: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(native ABIs, frameworks, protector hints) from the member names of every APK."""
    abis = sorted({m.group(1) for n in names if (m := re.match(r"^lib/([^/]+)/[^/]+\.so$", n))})
    fw = [label for label, rx in FRAMEWORKS if any(re.search(rx, n) for n in names)]
    prot = [label for label, rx in PROTECTORS if any(re.search(rx, n) for n in names)]
    return abis, fw, prot


def triage(apks: list[Path]) -> Triage:
    info = parse_badging(_badging(base_apk(apks)))
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+", info["package"]):
        raise ApkError(f"unexpected package name {info['package']!r}")
    abis, fw, prot = classify(_members(apks))
    return Triage(info["package"], info["version"], info["min_sdk"], info["target_sdk"], list(apks), abis, fw, prot)
