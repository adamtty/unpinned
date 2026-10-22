"""The parts that don't need a device: reading APKs and bundles, triage, config rendering, ports, the frida command."""

import socket
import zipfile

import pytest

from unpinned import apk, assets, device, env, intercept

PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----"
TEMPLATE = """const CERT_PEM = `-----BEGIN CERTIFICATE-----
[!! Put your CA certificate data here, in PEM format !!]
-----END CERTIFICATE-----`;
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 8000;
"""


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("UNPINNED_HOME", str(tmp_path / "home"))


def _zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


def _apk(path, extra=()):
    return _zip(path, {"AndroidManifest.xml": b"x", "classes.dex": b"dex", **{n: b"" for n in extra}})


def test_a_plain_apk_is_used_as_is(tmp_path):
    a = _apk(tmp_path / "app.apk")
    assert apk.load(a, tmp_path / "w") == [a]


def test_a_bundle_is_unpacked_base_first(tmp_path):
    inner = {n: _apk(tmp_path / n).read_bytes() for n in ("split_config.arm64_v8a.apk", "base.apk")}
    b = _zip(tmp_path / "app.apks", {f"splits/{n}": d for n, d in inner.items()} | {"toc.pb": b""})
    out = apk.load(b, tmp_path / "w")
    assert [p.name for p in out] == ["base.apk", "split_config.arm64_v8a.apk"]
    assert all(p.parent == tmp_path / "w" for p in out)


@pytest.mark.parametrize("name", ["../evil.apk", "a b.apk", "dup.apk"])
def test_bundle_names_cannot_escape_or_collide(tmp_path, name):
    members = {name: b"x"} if name != "dup.apk" else {"a/dup.apk": b"x", "b/dup.apk": b"y"}
    b = _zip(tmp_path / "x.xapk", members)
    if name == "../evil.apk":  # flattened to its base name, inside workdir
        assert [p.name for p in apk.load(b, tmp_path / "w")] == ["evil.apk"]
        assert not (tmp_path / "evil.apk").exists()
    else:
        with pytest.raises(apk.ApkError):
            apk.load(b, tmp_path / "w")


def test_not_an_apk(tmp_path):
    (tmp_path / "x.apk").write_text("nope")
    with pytest.raises(apk.ApkError, match="not a zip"):
        apk.load(tmp_path / "x.apk", tmp_path / "w")
    with pytest.raises(apk.ApkError, match=r"no \.apk files"):
        apk.load(_zip(tmp_path / "y.zip", {"readme.txt": b""}), tmp_path / "w")


def test_classify_frameworks_abis_and_protectors():
    abis, fw, prot = apk.classify(
        [
            "lib/arm64-v8a/libflutter.so",
            "lib/armeabi-v7a/libapp.so",
            "assets/index.android.bundle",
            "lib/arm64-v8a/libshield.so",
            "res/raw/x.png",
        ]
    )
    assert abis == ["arm64-v8a", "armeabi-v7a"] and fw == ["Flutter", "React Native"] and prot == ["Promon SHIELD"]


def test_triage_warnings():
    t = apk.Triage("a.b", abis=["armeabi-v7a"], protectors=["Promon SHIELD"])
    assert len(t.warnings()) == 2
    assert apk.Triage("a.b", abis=["arm64-v8a"]).warnings() == []


def test_parse_badging():
    text = (
        "package: name='tech.example.app' versionCode='7' versionName='1.2.3' platformBuildVersionName='16'\n"
        "minSdkVersion:'24'\ntargetSdkVersion:'36'\n"
    )
    assert apk.parse_badging(text) == {
        "package": "tech.example.app",
        "version": "1.2.3",
        "min_sdk": "24",
        "target_sdk": "36",
    }


def test_render_config_fills_in_ca_and_proxy():
    out = assets.render_config(TEMPLATE, PEM, "127.0.0.1", 54024)
    assert f"const CERT_PEM = `{PEM}`;" in out and "PROXY_PORT = 54024;" in out and "[!!" not in out


@pytest.mark.parametrize("pem", ["not a cert", PEM.replace("fake", "`;evil()//"), PEM.replace("fake", "${x}")])
def test_render_config_refuses_bad_or_injecting_pem(pem):
    with pytest.raises(assets.AssetError):
        assets.render_config(TEMPLATE, pem, "127.0.0.1", 1)


def test_render_config_fails_when_the_template_changes():
    with pytest.raises(assets.AssetError, match="expected"):
        assets.render_config(TEMPLATE.replace("PROXY_PORT", "PORT"), PEM, "127.0.0.1", 1)


def test_scripts_are_pinned_and_config_loads_first():
    assert next(iter(assets.SCRIPTS)) == "config.js"
    assert all(len(h) == 64 for h in assets.SCRIPTS.values()) and len(assets.SCRIPTS_COMMIT) == 40


def test_frida_command_order(tmp_path):
    cmd = intercept.frida_command("emulator-5554", "a.b", tmp_path / "config.js", extra=["mine.js"])
    loads = [cmd[i + 1] for i, x in enumerate(cmd) if x == "-l"]
    assert loads[0] == str(tmp_path / "config.js") and loads[-1] == "mine.js"
    assert len(loads) == len(assets.SCRIPTS) + 1 and cmd[-2:] == ["-f", "a.b"] and cmd[1:3] == ["-D", "emulator-5554"]


def test_a_busy_port_is_never_taken_for_the_proxy():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        busy = s.getsockname()[1]
        assert intercept.free_port(busy) != busy


def test_a_reused_pid_is_not_mistaken_for_ours():
    import os

    assert not intercept._alive(os.getpid(), "mitmweb")  # this is pytest, not mitmweb
    assert not intercept._alive(None, "mitmweb")


def test_avd_config_is_a_rootable_google_apis_image():
    cfg = device.avd_config("36.1")
    assert "PlayStore.enabled=false" in cfg and "google_apis/arm64-v8a" in cfg and env.avd_name("36.1") in cfg


def test_package_names():
    assert device.is_package("tech.httptoolkit.pinning_demo")
    assert not device.is_package("a; rm -rf /") and not device.is_package("single")


# --- your own proxy's certificate ------------------------------------------------------------------------------
from unpinned import certs, patch  # noqa: E402


def _make_cert(tmp_path, name="ca", ca=True):
    import subprocess

    key, pem = tmp_path / f"{name}.key", tmp_path / f"{name}.pem"
    ext = ["-addext", "basicConstraints=critical,CA:TRUE"] if ca else ["-addext", "basicConstraints=CA:FALSE"]
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(pem),
            "-days",
            "2",
            "-subj",
            f"/CN=test {name}",
            *ext,
        ],
        check=True,
        capture_output=True,
    )
    der = tmp_path / f"{name}.der"
    subprocess.run(
        ["openssl", "x509", "-in", str(pem), "-outform", "DER", "-out", str(der)], check=True, capture_output=True
    )
    return pem, der


@pytest.fixture
def store(tmp_path, monkeypatch):
    d = tmp_path / "certs"
    monkeypatch.setenv("UNPINNED_CERTS", str(d))
    return d


def test_a_certificate_is_stored_once_whether_pem_or_der(tmp_path, store):
    pem, der = _make_cert(tmp_path)
    c, already = certs.add(pem)
    assert not already and c.is_ca and "test ca" in c.subject and c.path.parent == store
    c2, already = certs.add(der)  # the same certificate as DER: same fingerprint
    assert already and c2.path == c.path and len(list(store.glob("*.pem"))) == 1
    assert certs.read_der(c.path) == der.read_bytes()


def test_a_second_certificate_is_kept_alongside(tmp_path, store):
    certs.add(_make_cert(tmp_path, "one")[0])
    certs.add(_make_cert(tmp_path, "two")[1])
    assert len(certs.stored()) == 2


def test_a_leaf_certificate_is_flagged(tmp_path, store):
    c, _ = certs.add(_make_cert(tmp_path, "leaf", ca=False)[0])
    assert not c.is_ca


@pytest.mark.parametrize(
    "content", [b"hello", b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----", b"\x30junk"]
)
def test_junk_is_not_a_certificate(tmp_path, store, content):
    (tmp_path / "x.cer").write_bytes(content)
    with pytest.raises(certs.CertError):
        certs.add(tmp_path / "x.cer")
    assert list(store.glob("*")) == []


@pytest.mark.parametrize(
    "text,want",
    [
        ("127.0.0.1:8080", ("127.0.0.1", 8080)),
        ("localhost:8000", ("127.0.0.1", 8000)),
        ("192.168.1.20:8080", ("192.168.1.20", 8080)),
        ("[::1]:9090", ("::1", 9090)),
    ],
)
def test_proxy_addresses(text, want):
    assert certs.parse_proxy(text) == want


@pytest.mark.parametrize("text", ["8080", "burp:8080", "1.2.3.4:0", "1.2.3.4:70000", "1.2.3.4:80; rm -rf /"])
def test_bad_proxy_addresses(text):
    with pytest.raises(certs.CertError):
        certs.parse_proxy(text)


def test_loopback():
    assert certs.is_loopback("127.0.0.1") and certs.is_loopback("::1") and not certs.is_loopback("192.168.1.2")


# --- patching -------------------------------------------------------------------------------------------------
def test_network_security_config_is_relaxed():
    xml = (
        '<network-security-config><domain-config><domain>a</domain><pin-set><pin digest="SHA-256">X</pin></pin-set>'
        '<trust-anchors><certificates src="@raw/r" /></trust-anchors><trustkit-config enforcePinning="true"/>'
        '</domain-config><domain-config><certificateTransparency enabled="true" /></domain-config>'
        "</network-security-config>"
    )
    out = patch.relax_network_security_config(xml)
    assert "pin-set" not in out and 'enforcePinning="false"' in out and 'enabled="false"' in out
    assert out.count('src="user"') == 2 and out.count('src="system"') == 2 and "<base-config>" in out


def test_gadget_load_goes_first_in_the_static_initialiser():
    smali = (
        ".class public Lx/App;\n.method static constructor <clinit>()V\n    .locals 0\n    return-void\n.end method\n"
    )
    out = patch.inject_load(smali)
    assert '.locals 1\n    const-string v0, "frida-gadget"' in out and out.count("<clinit>") == 1
    added = patch.inject_load(".class public Lx/App;\n")
    assert "static constructor <clinit>()V" in added and "loadLibrary" in added


def test_extract_native_libs():
    assert 'extractNativeLibs="true"' in patch.set_extract_native_libs(
        '<application android:extractNativeLibs="false">'
    )
    assert patch.set_extract_native_libs("<application>").startswith('<application android:extractNativeLibs="true"')


# --- dex ------------------------------------------------------------------------------------------------------
from dexbuild import build  # noqa: E402

from unpinned import dex  # noqa: E402


def test_dex_strings_and_classes():
    data = build(
        ["Lcom/x/Pin;", "Ljava/lang/Object;", "Ljavax/net/ssl/X509TrustManager;", "sha256/" + "A" * 43 + "="],
        [("Lcom/x/Pin;", "Ljava/lang/Object;", ["Ljavax/net/ssl/X509TrustManager;"])],
    )
    d = dex.parse(data)
    assert "sha256/" + "A" * 43 + "=" in d.strings
    assert d.classes == [("Lcom/x/Pin;", "Ljava/lang/Object;", ["Ljavax/net/ssl/X509TrustManager;"])]


@pytest.mark.parametrize("cut", [0, 8, 0x70, 0x72])
def test_truncated_dex_is_a_dex_error(cut):
    data = build(["La;", "Ljava/lang/Object;"], [("La;", "Ljava/lang/Object;", [])])
    with pytest.raises(dex.DexError):
        dex.parse(data[:cut])


def test_a_string_offset_past_the_end_is_a_dex_error():
    import struct

    data = bytearray(build(["La;", "Ljava/lang/Object;"], [("La;", "Ljava/lang/Object;", [])]))
    struct.pack_into("<I", data, 0x70, 0x7FFFFFFF)  # the first string id points nowhere
    with pytest.raises(dex.DexError):
        dex.parse(bytes(data))


def test_manifest_class_names_cannot_be_paths(tmp_path):
    with pytest.raises(patch.PatchError):
        patch._find_smali(tmp_path, "../../../etc/x", "a.b")


# --- phones ---------------------------------------------------------------------------------------------------
from unpinned import phone  # noqa: E402

TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:E2F4 00000000:0000 0A 00000000:00000000 00:00000000 00000000  2000        0 3797695 1 0
   1: 0100007F:69A2 0100007F:9A9B 06 00000000:00000000 03:00001508 00000000     0        0 0 3 0
"""


def test_frida_port_only_counts_when_listening():
    assert not device.listening_on(TCP, 27042)  # 69A2 is there, but in TIME_WAIT (a crashed server)
    assert device.listening_on(TCP.replace("9A9B 06", "9A9B 0A"), 27042)
    assert device.listening_on(TCP, 0xE2F4)


@pytest.mark.parametrize(
    "path,ok",
    [
        ("/data/app/com.x-AbC==/base.apk", True),
        ("/data/app/~~q1w2==/com.x-9z==/split_config.arm64_v8a.apk", True),
        ("/system/priv-app/Foo/Foo.apk", True),
        ("/data/app/x/base.apk; rm -rf /", False),
        ("/sdcard/evil.apk", False),
        ("../../etc/passwd.apk", False),
    ],
)
def test_phone_apk_paths(path, ok):
    assert bool(phone.APK_PATH_RE.match(path)) is ok


def test_remove_ca_only_touches_unpinned_mounts():
    assert (
        "= unpinned" in device._REMOVE_CA_SCRIPT
        and "umount /system/etc/security/cacerts\n" not in device._REMOVE_CA_SCRIPT
    )
    assert 'mount -t tmpfs unpinned "$SYS"' in device._SYSTEM_CA_SCRIPT
