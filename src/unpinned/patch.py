"""Repackaging, for apps that refuse a rooted device or spot frida-server.

`gadget`: embeds Frida's gadget in the app with the interception hooks bundled as its script, loaded from the
Application class's (or launcher activity's) static initialiser, so the root-detection and unpinning hooks run inside
the app before any of its own code, with no frida-server and no root needed. `apk_mitm`: apk-mitm's static rewrite
(trust user CAs, strip pins), no Frida at all. Every APK of a bundle is re-signed with one local key."""

from __future__ import annotations

import json
import lzma
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

import frida

from unpinned import apk, assets, env

GADGET = "frida-gadget"


class PatchError(RuntimeError):
    pass


def _run(cmd: list[str], timeout: float = 900, cwd: Path | None = None, env_: dict | None = None) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd, env=env_)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout).strip().splitlines()[-6:]
        raise PatchError(f"{Path(cmd[0]).name} failed: " + " / ".join(tail))
    return r.stdout


def _build_tool(name: str) -> str:
    found = sorted(
        (env.sdk() / "build-tools").glob(f"*/{name}"),
        key=lambda q: [int(x) for x in q.parent.name.split(".") if x.isdigit()],
    )
    if not found:
        raise PatchError(f"{name} not found (Android SDK build-tools)")
    return str(found[-1])


def _need(name: str, hint: str) -> str:
    p = shutil.which(name)
    if not p:
        raise PatchError(f"{name} not found ({hint})")
    return p


# --- signing --------------------------------------------------------------------------------------------------
def _keystore() -> tuple[Path, str]:
    """A local signing key for patched builds, made once. Its password lives next to it (0600); it signs nothing
    but throwaway test builds."""
    ks, pw_file = env.home() / "patch-key.p12", env.home() / "patch-key.pass"
    if ks.is_file() and pw_file.is_file():
        return ks, pw_file.read_text().strip()
    pw = secrets.token_hex(16)
    fd = os.open(pw_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(pw)
    ks.unlink(missing_ok=True)
    _run(
        [
            _need("keytool", "a JDK"),
            "-genkeypair",
            "-keystore",
            str(ks),
            "-storetype",
            "PKCS12",
            "-alias",
            "unpinned",
            "-keyalg",
            "RSA",
            "-keysize",
            "3072",
            "-validity",
            "10000",
            "-dname",
            "CN=unpinned",
            "-storepass:env",
            "UNPINNED_KS_PASS",
        ],
        env_=dict(os.environ, UNPINNED_KS_PASS=pw),
    )
    os.chmod(ks, 0o600)
    return ks, pw


def sign(src: Path, out: Path) -> Path:
    ks, pw = _keystore()
    aligned = out.with_suffix(".aligned.apk")
    _run([_build_tool("zipalign"), "-P", "16", "-f", "4", str(src), str(aligned)])
    _run(
        [
            _build_tool("apksigner"),
            "sign",
            "--ks",
            str(ks),
            "--ks-pass",
            "env:UNPINNED_KS_PASS",
            "--ks-key-alias",
            "unpinned",
            "--out",
            str(out),
            str(aligned),
        ],
        env_=dict(os.environ, UNPINNED_KS_PASS=pw),
    )
    aligned.unlink(missing_ok=True)
    out.with_name(out.name + ".idsig").unlink(missing_ok=True)
    return out


# --- the gadget script --------------------------------------------------------------------------------------------
# The gadget loads from the Application class's static initialiser, before Android has made the Application object:
# the Java bridge can then only see boot classes, so app-level hooks (OkHttp, TrustKit…) would silently miss. The hooks
# therefore run when Android is about to call Application.onCreate (app class loader ready, app code not yet run).
# Their console output goes to logcat (tag "unpinned"), since a gadget has no host to print to.
GADGET_PRELUDE = r"""globalThis.Java = bridge;
const unpinnedLog = (() => {
  try {
    const write = new NativeFunction(Process.getModuleByName("liblog.so").getExportByName("__android_log_write"),
                                     "int", ["int", "pointer", "pointer"]);
    const tag = Memory.allocUtf8String("unpinned");
    return (level, args) => write(level, tag, Memory.allocUtf8String(args.map(String).join(" ")));
  } catch (e) {
    return () => {};
  }
})();
console.log = (...a) => unpinnedLog(4, a);
console.warn = (...a) => unpinnedLog(5, a);
console.error = (...a) => unpinnedLog(6, a);
"""
GADGET_START = r"""
Java.perform(() => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  if (ActivityThread.currentApplication() !== null) {
    unpinnedHooks();
    return;
  }
  const Instrumentation = Java.use("android.app.Instrumentation");
  const onCreate = Instrumentation.callApplicationOnCreate;
  let started = false;
  onCreate.implementation = function (app) {
    if (!started) {
      started = true;
      Java.classFactory.loader = app.getClassLoader();
      try {
        unpinnedHooks();
      } catch (e) {
        console.error("unpinned: hooks failed: " + e + "\n" + e.stack);
      }
    }
    return onCreate.call(this, app);
  };
});
"""


def gadget_script(config_js: str, extra: list[str] | None = None) -> str:
    """config.js + every hook as one plain script for the gadget, preceded by the Java bridge (Frida 17's gadget has
    none built in). The bridge is the exact build frida-tools ships, the one the frida-server path loads too."""
    import frida_tools

    bridge = (Path(frida_tools.__file__).parent / "bridges" / "java.js").read_text(encoding="utf-8")
    d = assets.ensure_scripts()
    hooks = "\n;\n".join(
        [config_js] + [(d / rel).read_text() for rel in assets.SCRIPTS if rel != "config.js"] + list(extra or [])
    )
    return bridge + "\n;\n" + GADGET_PRELUDE + "function unpinnedHooks() {\n" + hooks + "\n}\n" + GADGET_START


def ensure_gadget(version: str | None = None) -> Path:
    """frida-gadget for arm64 Android, same version and verification as frida-server."""
    version = version or frida.__version__
    out = env.home() / f"frida-gadget-{version}-android-arm64.so"
    if out.is_file():
        return out
    rel = json.loads(
        assets._get(
            f"https://api.github.com/repos/frida/frida/releases/tags/{version}",
            10 << 20,
            accept="application/vnd.github+json",
        )
    )
    name = f"frida-gadget-{version}-android-arm64.so.xz"
    asset = next((a for a in rel.get("assets", []) if a.get("name") == name), None)
    digest = (asset or {}).get("digest") or ""
    url = (asset or {}).get("browser_download_url", "")
    if not digest.startswith("sha256:") or not url.startswith(
        f"https://github.com/frida/frida/releases/download/{version}/"
    ):
        raise PatchError(f"frida {version}: no {name} with a published SHA-256 digest")
    data = assets._get(url)
    if assets._sha256(data) != digest.removeprefix("sha256:"):
        raise PatchError(f"{name}: SHA-256 doesn't match the digest GitHub publishes")
    assets._write(out, lzma.decompress(data), mode=0o600)
    return out


# --- smali / manifest edits ---------------------------------------------------------------------------------------
LOAD = '    const-string v0, "{lib}"\n    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'


def inject_load(smali: str, lib: str = GADGET) -> str:
    """Load lib first thing in the class's static initialiser (adding one if there's none)."""
    call = LOAD.format(lib=lib)
    m = re.search(r"\.method (?:[\w ]*?)static constructor <clinit>\(\)V\n(\s*\.(locals|registers) (\d+)\n)", smali)
    if m:
        kind, n = m.group(2), int(m.group(3))
        if kind == "registers":  # registers = locals + params (none here); v0 must exist
            decl = f"    .registers {max(n, 1)}\n"
        else:
            decl = f"    .locals {max(n, 1)}\n"
        return smali[: m.start(1)] + decl + call + smali[m.end(1) :]
    method = ".method static constructor <clinit>()V\n    .locals 1\n" + call + "    return-void\n.end method\n"
    return smali.rstrip("\n") + "\n\n" + method


def set_extract_native_libs(manifest: str) -> str:
    """The gadget finds its config and script next to itself on disk, so native libraries must be extracted."""
    if "android:extractNativeLibs=" in manifest:
        return re.sub(r'android:extractNativeLibs="[^"]*"', 'android:extractNativeLibs="true"', manifest, count=1)
    return re.sub(r"<application\b", '<application android:extractNativeLibs="true"', manifest, count=1)


TRUST_BOTH = '<certificates src="system" />\n<certificates src="user" />'
DEFAULT_NSC = (
    '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n<base-config>\n<trust-anchors>\n'
    + TRUST_BOTH
    + "\n</trust-anchors>\n</base-config>\n</network-security-config>\n"
)


def relax_network_security_config(xml: str) -> str:
    """No pin sets, system + user CAs trusted in every trust-anchors block and the base config, TrustKit pinning not
    enforced, Certificate Transparency off. Android applies this config before any app code (or a deferred hook)
    runs, so it has to change in the APK itself."""
    xml = re.sub(r"<pin-set\b[^>]*/>|<pin-set\b.*?</pin-set>", "", xml, flags=re.S)
    xml = re.sub(r'(enforcePinning=)"true"', r'\1"false"', xml)
    xml = re.sub(r'(<certificateTransparency\b[^>]*enabled=)"true"', r'\1"false"', xml)

    def anchors(m: re.Match) -> str:
        body = m.group(2)
        for src in ("system", "user"):
            if not re.search(rf'src="{src}"', body):
                body += f'\n<certificates src="{src}" />'
        return m.group(1) + body + m.group(3)

    xml = re.sub(r"(<trust-anchors\b[^>]*>)(.*?)(</trust-anchors>)", anchors, xml, flags=re.S)
    xml = re.sub(r"<trust-anchors\b[^>]*/>", "<trust-anchors>\n" + TRUST_BOTH + "\n</trust-anchors>", xml)
    if "<base-config" not in xml:
        xml = re.sub(
            r"(<network-security-config\b[^>]*>)",
            r"\1\n<base-config>\n<trust-anchors>\n"
            + TRUST_BOTH.replace("\\", "")
            + "\n</trust-anchors>\n</base-config>",
            xml,
            count=1,
        )
    return xml


def patch_network_security_config(decoded: Path, manifest: str) -> str:
    """Relax the app's network security config, or give it one; returns the (possibly updated) manifest."""
    m = re.search(r'android:networkSecurityConfig="@xml/([A-Za-z0-9_.]+)"', manifest)
    if m and (decoded / "res" / "xml" / f"{m.group(1)}.xml").is_file():
        f = decoded / "res" / "xml" / f"{m.group(1)}.xml"
        f.write_text(relax_network_security_config(f.read_text()))
        return manifest
    (decoded / "res" / "xml").mkdir(parents=True, exist_ok=True)
    (decoded / "res" / "xml" / "unpinned_network_security_config.xml").write_text(DEFAULT_NSC)
    manifest = re.sub(r'\s*android:networkSecurityConfig="[^"]*"', "", manifest)
    return re.sub(
        r"<application\b",
        '<application android:networkSecurityConfig="@xml/unpinned_network_security_config"',
        manifest,
        count=1,
    )


def _entry_class(manifest: str, launcher: str) -> str:
    m = re.search(r'<application\b[^>]*?android:name="([^"]+)"', manifest, flags=re.S)
    name = m.group(1) if m else ""
    if name and not name.startswith(("android.", "androidx.")):
        return name
    return launcher


def _launcher(base: Path) -> str:
    out = subprocess.run(
        [env.tool("aapt2") or "aapt2", "dump", "badging", str(base)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    ).stdout
    m = re.search(r"launchable-activity: name='([^']+)'", out)
    if not m:
        raise PatchError("no launcher activity to load the gadget from")
    return m.group(1)


CLASS_RE = re.compile(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*")


def _find_smali(decoded: Path, cls: str, package: str) -> Path:
    if cls.startswith("."):
        cls = package + cls
    if not CLASS_RE.fullmatch(cls):  # the manifest is the app's: never let it name a path
        raise PatchError(f"unexpected class name in the manifest: {cls[:80]!r}")
    rel = cls.replace(".", "/") + ".smali"
    for d in sorted(decoded.glob("smali*")):
        if (d / rel).is_file():
            return d / rel
    raise PatchError(f"couldn't find {cls} in the decoded app")


def gadget(apks: list[Path], package: str, config_js: str, workdir: Path, extra: list[str] | None = None) -> list[Path]:
    """Patch the base APK with the gadget and the bundled hooks; re-sign every APK of the set with one key."""
    apktool = _need("apktool", "brew install apktool")
    base = apk.base_apk(apks)
    workdir.mkdir(parents=True, exist_ok=True)
    decoded = workdir / "decoded"
    shutil.rmtree(decoded, ignore_errors=True)
    _run([apktool, "d", "-f", "-o", str(decoded), str(base)])

    manifest_path = decoded / "AndroidManifest.xml"
    manifest = manifest_path.read_text()
    manifest_path.write_text(patch_network_security_config(decoded, set_extract_native_libs(manifest)))
    target = _find_smali(decoded, _entry_class(manifest, _launcher(base)), package)
    target.write_text(inject_load(target.read_text()))

    lib = decoded / "lib" / "arm64-v8a"
    lib.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ensure_gadget(), lib / f"lib{GADGET}.so")
    (lib / f"lib{GADGET}.config.so").write_text(
        json.dumps({"interaction": {"type": "script", "path": f"lib{GADGET}.script.so", "on_change": "ignore"}})
    )
    (lib / f"lib{GADGET}.script.so").write_text(gadget_script(config_js, extra))

    unsigned = workdir / "unsigned.apk"
    _run([apktool, "b", "-o", str(unsigned), str(decoded)])
    out = [sign(unsigned, workdir / base.name)]
    out += [sign(a, workdir / a.name) for a in apks if a != base]
    return sorted(out, key=lambda p: (p.name != base.name, p.name))


def apk_mitm(app: Path, workdir: Path) -> list[Path]:
    """apk-mitm's rewrite of the original file (it handles bundles itself), unpacked again for install."""
    tool = _need("apk-mitm", "npm install -g apk-mitm")
    workdir.mkdir(parents=True, exist_ok=True)
    src = workdir / app.name
    shutil.copyfile(app, src)
    _run([tool, str(src)], timeout=1800, cwd=workdir)  # it writes a logs/ folder wherever it runs
    patched = src.with_name(src.stem + "-patched" + src.suffix)
    if not patched.is_file():
        raise PatchError("apk-mitm didn't produce a -patched file")
    return apk.load(patched, workdir / "apks")
