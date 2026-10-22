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

Against HTTP Toolkit's [pinning demo](https://github.com/httptoolkit/android-ssl-pinning-demo) (v1.7.1) on
Android 16, with `--insecure-upstream` (its test servers use an untrusted root on purpose):

| Pinning / check | Root + Frida hooks | Gadget patch |
|---|---|---|
| Plain HTTP, unpinned HTTPS, WebView | ✅ | ✅ |
| Network security config pin, context pin, OkHttp, Volley, TrustKit | ✅ | ✅ |
| Certificate Transparency (Android, Appmattus, Appmattus + OkHttp, Appmattus + raw TLS) | ✅ | ✅ |
| Flutter (via the system CA) | ✅ | ✅ |
| HTTP/3 (Cronet) | ✅ | ❌ crashes the app ([known issue](#known-issues)) |
| Raw custom pinning (the app hashes the key itself) | ❌ needs an app-specific hook | ❌ |

Triage on the same app reports every one of those techniques, including the raw custom `TrustManager` by class name.

## Known issues

- **Gadget patch on Android 16:** the patched app can crash in ART's new garbage collector while Frida's Java bridge
  is loaded through the gadget (seen on the HTTP/3 request). The frida-server route doesn't do this. Treat the gadget
  as experimental on Android 16.
- **Without `--insecure-upstream`,** a pinned request to a server the proxy can't verify can make HTTP Toolkit's
  native TLS hook crash the app on Android 16. On Android 14 it fails cleanly.
- **Root is mostly invisible:** the emulator is rooted through `adbd`, and SELinux hides `su` from apps, so many
  simple root checks never fire. Good for testing; but it means the refuse → patch → reopen path is hard to show
  with demo apps.
- **Play Integrity / SafetyNet** are judged on Google's servers. An emulator fails device integrity whatever runs on
  it, so flows gated on them won't work here.
- **Raw custom pinning** (an app hashing keys in its own code) needs a hook written for that app: triage names the
  class, then pass your hook with `--script`.

## Security

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

- **Real rooted devices:** point unpinned at an app already installed on a rooted phone. It pulls a copy (every
  split) off the device, triages and patches it, installs the fixed build back, and sets up the proxy and CA on the
  device.
- **Phone to emulator:** connect your own phone, pick an installed app, and unpinned pulls it off (every split),
  patches it, installs it on the emulator and sets up the proxy. You get the exact build you use, without having to
  find the APK.
- A container fleet: Redroid on an ARM server, with Tailscale for access.
- A fix or workaround for the gadget on Android 16, and broader tests of the refuse → patch → reopen loop.
- Flutter pattern updates, and reFlutter as a fallback.
- apkid in triage, plus a scrcpy-in-the-browser view.
