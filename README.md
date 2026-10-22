<p align="center">
  <img src="docs/assets/logo.png" alt="unpinned" width="640">
</p>

<p align="center">
  <b>Drop in an APK. Get a fresh rooted Android emulator with the app running,<br>
  its certificate pinning bypassed and its traffic in your proxy.</b>
</p>

<p align="center">
  <a href="https://github.com/adamtty/unpinned/actions/workflows/ci.yml"><img src="https://github.com/adamtty/unpinned/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/adamtty/unpinned"><img src="https://api.scorecard.dev/projects/github.com/adamtty/unpinned/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/status-work%20in%20progress-orange" alt="Work in progress">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT">
</p>

> [!WARNING]
> **Work in progress.** unpinned is a young, Mac-first proof of concept. The core flow works and is tested against
> a pinning demo app, but expect rough edges, changing commands, and the [known issues](#known-issues) below.

**New here? The [user guide](USER_GUIDE.md) covers everything in depth.**

A self-hosted start on "Corellium for Android", for **authorised** mobile app security testing: bug bounties in
scope, your own apps, or apps you have permission to assess.

```bash
unpinned setup              # once: a dedicated emulator, frida-server and the hooks, a clean snapshot (~30 s)
unpinned run app.apk        # triage → choose → reset → install → unpin → watch → (patch and reopen if refused)
```

## What `run` does

1. **Triage, before anything runs.** It reads the APK directly (DEX tables, manifest, network security config,
   native libraries, Flutter and React Native code) and reports what the app does, with evidence and how sure it is:

   | Looks for | For example |
   |---|---|
   | Certificate pinning | `<pin-set>` in the network security config, hard-coded `sha256/` pins, TrustKit, the app's own `TrustManager` classes (and whether they hash keys themselves), bundled CA files, Flutter and React Native pinning plugins |
   | Certificate Transparency | Appmattus CT, Android's own CT setting |
   | Root, Frida, emulator and debugger checks | RootBeer, `su` paths, Magisk, Frida strings in DEX or native code, emulator properties |
   | Attestation and protectors | Play Integrity, SafetyNet, freeRASP, Promon, Jiagu, Bangcle, Legu, Appdome, DexProtector |

   It also finds **the app's own certificate checks**: its methods that take a certificate or TLS session and return
   a boolean (a hand-written pin check), and `checkServerTrusted` on its own TrustManagers. `run` and `phone` offer
   to hook those to pass, logging every call they override (`--no-auto-hooks` to skip). Methods that only take a
   public key are left alone: those verify signatures, like license or purchase receipts, not certificates.

   It also runs the standard static checks:
   - **Manifest:** `debuggable`, `allowBackup`, cleartext HTTP; exported activities, services, receivers and
     providers with no permission guarding them (including the implicit exports older target SDKs get); deep links.
   - **Hard-coded secrets:** Google API keys, Firebase database URLs, AWS keys, private keys, Slack, Stripe and
     GitHub tokens, JWTs. Masked unless you pass `--show-secrets`.
   - **Endpoints:** every URL in the code, resources and assets, by host. Documentation links are filtered out.

   `unpinned triage APP --json report.json` writes all of it out, and `--endpoints` lists every URL.

   Known third-party libraries (Cronet, Flutter's engine, crash reporters…) are skipped, so their strings don't
   count against the app.

2. **Choose how to get at the traffic.** It recommends one, and you pick:

   | Method | What it does | When |
   |---|---|---|
   | **Root + Frida hooks** | frida-server spawns the app with [HTTP Toolkit's interception and unpinning scripts](https://github.com/httptoolkit/frida-interception-and-unpinning). The app itself is untouched. | Pinning found (the default) |
   | **System CA only** | No Frida at all, so there's nothing for the app to detect | Nothing pinned |
   | **Frida gadget patch** | Embeds Frida's gadget in the app with the same hooks, so they run inside the app before its own code, with no frida-server on the device. Also relaxes the network security config. | Apps that detect frida-server or root |
   | **apk-mitm** | A static rewrite: trust user CAs and strip pins, with no Frida | When Frida itself is caught |

3. **Choose the proxy.** Either unpinned's own **mitmweb**, started for you on localhost with its own CA, or
   **your own proxy** (Burp, HTTP Toolkit, Charles…) at `ip:port`; see [your own proxy](#your-own-proxy).

4. **Run it.** The emulator goes back to a clean snapshot, so nothing survives from the last run.
   - **The CA:** your proxy's CA goes into the **system** CA store (which on Android 14+ means mounting over the
     Conscrypt APEX in every app's namespace). That covers code the hooks don't reach, like Flutter's Dart.
   - **Install:** single APKs and split bundles (`.apks`, `.xapk`, a `.zip` of APKs) both work.
   - **Hand over:** scrcpy shows the screen, the proxy shows the traffic, and with hooks you can open a Frida REPL
     inside the app.

5. **Watch for a refusal.** For the first 20 seconds it checks whether the app closed (with Android's recorded exit
   reason) or shows text about root, tampering, Frida, an emulator or integrity. If it does, unpinned offers to
   **patch the app so it runs on the rooted device**, then reinstalls and reopens it.

## Commands

| | |
|---|---|
| `unpinned doctor` | Check the tools, the system image, the emulator and its snapshot. |
| `unpinned setup` | Download and verify frida-server and the hooks, create the emulator, root it, save the clean snapshot. |
| `unpinned triage APP` | The static report and a suggested method, with no emulator. |
| `unpinned run APP` | The whole flow, interactively. |
| `unpinned pull APP` | Pull an app installed on your phone (every split) into one `.apks`. `APP` is a package name or part of one to search for. |
| `unpinned run --from-phone APP` | Pull it off your phone, then the whole emulator flow. |
| `unpinned phone APP` | The same flow **on your rooted phone** (see [your phone](#your-phone)). |
| `unpinned patch APP` | Write a patched APK (`--method gadget` or `apk-mitm`) without running it, e.g. for a real device. |
| `unpinned reset` | Put the running emulator back to its clean snapshot. |
| `unpinned stop` | Stop the emulator (discarding its changes), the hooks, mitmweb and scrcpy. |

Useful `run` options:
- `--strategy hooks|ca|gadget|apk-mitm` and `--yes` skip the questions.
- `--proxy HOST:PORT --ca cert.der` sends traffic to your own proxy.
- `--insecure-upstream` stops mitmweb verifying the real servers (staging or self-signed hosts).
- `--script hook.js` loads your own Frida hook after the built-in ones.
- `--headless` runs with no windows.
- `--api` picks the Android version. The default is `36.1` (Android 16); any Google APIs arm64 image works, since
  those are the rootable ones.

### Your own proxy

Choose **your own proxy** when `run` asks, and give its `ip:port`. It checks that something answers there. Then
give its CA certificate, PEM or DER: Burp's `cacert.der` export works as it is.

- **Where it goes:** each certificate is stored in `certs/` (git-ignored), named by its SHA-256 fingerprint.
- **Adding one twice:** the same certificate again, in either format, just says you're good.
- **Next time:** certificates you've stored are offered as a list.
- **Leaf certificates:** one that isn't a CA gets a warning.
- **Reaching the proxy:** a proxy on this Mac is reached through `adb reverse`. One elsewhere on your network is
  reached directly from the emulator.

Without the questions: `unpinned run app.apk --proxy 127.0.0.1:8080 --ca ~/Downloads/cacert.der`.

### Your phone

Plug in a rooted phone (Magisk or KernelSU) with USB debugging on, and grant the shell root once. Then:

```bash
unpinned run --from-phone spotify   # pull it off the phone, run it in the emulator
unpinned phone spotify              # or do it on the phone itself
```

- **The app keeps its data.** On the phone, frida-server, the proxy's CA and the proxy go on through `su`, and the app
  isn't reinstalled. A copy of the app is pulled first anyway, for triage and as a backup.
- **Patching is asked first.** If the app still refuses to run, patching it means reinstalling it, which wipes its
  data, so `phone` asks before doing it. The original goes back with `unpinned phone --restore <the pulled .apks>`.
- **Traffic reaches your Mac** through `adb reverse` over the USB cable, or goes straight to your own proxy on the
  network.
- **Without Frida** (the system-CA and apk-mitm methods), only the app's own traffic is sent to the proxy, with
  `iptables` rules matched on its user ID. So it's caught even when the app ignores proxy settings (Flutter, raw
  sockets), and nothing else on the device is touched. QUIC and IPv6 TCP are blocked for the app so it falls back to
  IPv4 TCP. `--global-proxy` uses the device-wide proxy setting instead. The rules live in their own `UNPINNED_*`
  chains, which cleanup removes, and nothing else.
- **Root is hidden from the app** with Magisk's DenyList (`--no-hide-root` to skip): unpinned adds the app, and
  cleanup takes it off again, only if unpinned added it. This needs Zygisk and "Enforce DenyList" on in Magisk
  (`phone` tells you if they're off). The DenyList also hides the proxy's system-store CA from that app, so root is
  hidden only for the hooks and the gadget, which trust the CA inside the app. The CA-only and apk-mitm methods
  leave root visible rather than lose HTTPS.
- **Cleanup:** `unpinned phone --cleanup` stops frida-server, unmounts the CA and clears the proxy setting. A reboot
  does too.
- **It leaves your own setup alone.**
  - unpinned's frida-server has its own filename, so a frida-server you keep on the phone isn't overwritten.
  - The CA mount is labelled, and cleanup only removes those, so Magisk modules that mount over the same CA
    folder are left untouched.
- **Older phones:** current frida-server crashes on some older devices (Samsung on Android 9, for one:
  [frida#3715](https://github.com/frida/frida/issues/3715)). unpinned notices and uses frida-server 17.5.2 instead,
  verified the same way, and remembers that for the phone.

Tested on a Galaxy Note 8 (Android 9, Magisk 26.4) with the pinning demo: every request, including Flutter, HTTP/3,
TrustKit and the Certificate Transparency checks, decrypted on the phone without reinstalling the app.

## Install

You need an Apple Silicon Mac, where arm64 Android runs natively, and:

- **Android SDK:** the emulator, platform-tools, build-tools (for `aapt2`, `zipalign` and `apksigner`), and a
  Google APIs arm64 system image:
  `sdkmanager "system-images;android-36.1;google_apis;arm64-v8a"`
- **mitmproxy** (`brew install mitmproxy`) and **openssl**
- **uv**
- **For patching:** apktool (`brew install apktool`) and a JDK (`keytool`). apk-mitm is optional.
- **Optional:** scrcpy.

```bash
git clone https://github.com/adamtty/unpinned && cd unpinned
uv sync
uv run unpinned doctor
uv run unpinned setup
```

**Uninstall.** Run `uv run unpinned stop`, then delete:
- `~/.cache/unpinned` (downloads, its own mitmproxy CA, logs and the patch signing key)
- `~/.android/avd/unpinned-*` (the emulator)
- this folder (including `certs/`)

## Tested

Against HTTP Toolkit's [pinning demo](https://github.com/httptoolkit/android-ssl-pinning-demo) (v1.7.1), with
`--insecure-upstream` (its test servers use an untrusted root on purpose). Hooks on Android 16; the gadget on
Android 14, where it's stable ([why](#known-issues)):

| Pinning / check | Root + Frida hooks | Gadget patch |
|---|---|---|
| Plain HTTP, unpinned HTTPS, WebView | ✅ | ✅ |
| Network security config pin, context pin, OkHttp, Volley, TrustKit | ✅ | ✅ |
| Certificate Transparency (Android, Appmattus, Appmattus + OkHttp, Appmattus + raw TLS) | ✅ | ✅ |
| Flutter (via the system CA) | ✅ | ✅ |
| HTTP/3 (Cronet) | ✅ | ✅ |
| Raw custom pinning (the app hashes the key itself) | ✅ auto-hooked | ✅ auto-hooked |

Triage on the same app reports every one of those techniques, including the raw custom `TrustManager` by class name.

## Known issues

- **Gadget patch on Android 16:** Frida's Java hooks, run inside the app through the gadget, can crash ART's garbage
  collector while it walks a hooked thread's stack. This is an open Frida bug
  ([frida#3805](https://github.com/frida/frida/issues/3805),
  [frida-java-bridge#387](https://github.com/frida/frida-java-bridge/issues/387)): Android 16's `libart` no longer
  ships the symbols Frida uses to install its GC hook.
  - **Use Android 14 for gadget runs.** It's stable there (6 of 6 runs). When you choose the gadget on Android 16,
    `run` offers to switch to the Android 14 emulator if you've set it up (`unpinned --api 34 setup`).
  - **On Android 16 it's flaky, not hopeless.** `setup` switches unpinned's emulator to ART's concurrent-copying
    collector, which helps (5 of 7 runs survive, against 0 of 4 on the default collector) but doesn't fix it.
  - The frida-server route (root + hooks) isn't affected.
- **Emulator updates break the snapshot.** Snapshots are tied to the emulator version, so after the Android SDK
  updates the emulator, `run` asks you to run `unpinned setup` again.
- **Without `--insecure-upstream`,** a pinned request to a server the proxy can't verify can make HTTP Toolkit's
  native TLS hook crash the app on Android 16. On Android 14 it fails cleanly.
- **Root is mostly invisible:** the emulator is rooted through `adbd`, and SELinux hides `su` from apps, so many
  simple root checks never fire. Good for testing; but it means the refuse → patch → reopen path is hard to show
  with demo apps.
- **Apps behind runtime protection (RASP)**, such as freeRASP, Promon, DexGuard or Appdome, are built to spot
  emulators, root and instrumentation, and they win on an emulator. Triage says so when it finds one. A real phone
  with root hidden gets further (the freeRASP demo kept running under the gadget on a Note 8). On an authorised
  test, ask for a build with the protection in development or report-only mode, or with your device allowlisted.
  Most apps aren't protected like this.
- **Play Integrity / SafetyNet** are judged on Google's servers. An emulator fails device integrity whatever runs on
  it, so flows gated on them won't work here.
- **Localhost only:** mitmweb listens on 127.0.0.1, behind a random web password kept in a private config file. The
  device reaches it through `adb reverse`.
- **Separate from your own setup:** a dedicated emulator, never your own ones. Its own mitmproxy CA under
  `~/.cache/unpinned/mitmproxy`, never your `~/.mitmproxy` one.
- **Verified downloads:** frida-server and frida-gadget are the exact version of the pinned `frida` package, checked
  against the SHA-256 digest GitHub publishes for each release asset. HTTP Toolkit's scripts are pinned to one commit
  and checked against hashes in `assets.py`.
- **The APK is treated as hostile:**
  - bundles are unpacked to `*.apk` members only, flattened to their base names, with per-file and total size limits
  - DEX and native code are read with size caps
  - manifest class and resource names are validated before they're used in a path
  - the DEX, bundle, certificate and rewrite parsers are fuzzed in CI
- **Patched builds** are signed with a local key made on first use (`~/.cache/unpinned/patch-key.p12`). It signs
  nothing but throwaway test builds.
- A rooted emulator running unknown apps is still a hostile machine. Don't sign into real accounts on it.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Licences

unpinned is MIT.
- **HTTP Toolkit's scripts** are AGPL-3.0-or-later. They're downloaded at setup, not included here.
- **Frida** is under the wxWindows Library Licence 3.1. A gadget-patched APK contains Frida's gadget and Java bridge
  plus those scripts, so keep patched builds to your own testing.

## Roadmap

- A container fleet: Redroid on an ARM server, with Tailscale for access.
- The gadget on Android 16, once Frida's GC fix lands; broader tests of the refuse → patch → reopen loop.
- Flutter pattern updates, and reFlutter as a fallback.
- apkid in triage, plus a scrcpy-in-the-browser view.
