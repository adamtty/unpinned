# unpinned user guide

> [!WARNING]
> unpinned is a **work in progress**. This guide describes `main` as it is now; commands and defaults may change.

This guide covers everything unpinned does, why it does it, and what to do when an app fights back. If you only
want to get going, read [Quick start](#2-quick-start), then come back when something surprises you.

unpinned is for **authorised** testing: your own apps, bug bounty programmes where the app is in scope, or
assessments you've been engaged for. Several things it does (bypassing certificate pinning, hiding root,
repackaging apps) are exactly what an app's developers are trying to prevent, so only use it where you have
permission.

## Contents

1. [What unpinned does](#1-what-unpinned-does)
2. [Quick start](#2-quick-start)
3. [Installing](#3-installing)
4. [Setting up the emulator](#4-setting-up-the-emulator)
5. [Triage: reading an app before running it](#5-triage-reading-an-app-before-running-it)
6. [Choosing how to get at the traffic](#6-choosing-how-to-get-at-the-traffic)
7. [The proxy](#7-the-proxy)
8. [Running on the emulator: `unpinned run`](#8-running-on-the-emulator-unpinned-run)
9. [Using your phone](#9-using-your-phone)
10. [When the app refuses: the watcher and the patch loop](#10-when-the-app-refuses-the-watcher-and-the-patch-loop)
11. [Working with the app: the screen, the traffic, Frida](#11-working-with-the-app-the-screen-the-traffic-frida)
12. [Patching an APK on its own: `unpinned patch`](#12-patching-an-apk-on-its-own-unpinned-patch)
13. [Recipes](#13-recipes)
14. [Command reference](#14-command-reference)
15. [Files, folders and settings](#15-files-folders-and-settings)
16. [How it works](#16-how-it-works)
17. [Limits: what unpinned can't do](#17-limits-what-unpinned-cant-do)
18. [Troubleshooting](#18-troubleshooting)
19. [Security and safety](#19-security-and-safety)
20. [Glossary](#20-glossary)

---

## 1. What unpinned does

Most Android apps talk to their servers over HTTPS, and many of them **pin** their certificates: they refuse to
talk through a proxy whose certificate they don't recognise, which is exactly what you need to do to see their
traffic. Many also check whether they're running on a rooted device, an emulator, or under Frida, and refuse to run
if they are.

unpinned turns all of that into one command:

```text
drop in an APK (or pick an app on your phone)
  → triage: what does it pin, what does it check for, what does it expose?
  → choose a way in (it recommends one)
  → a fresh rooted emulator from a clean snapshot (or your own phone)
  → install, point it at a proxy, trust the proxy's certificate, bypass the pinning
  → watch: did the app refuse? if so, patch it and try again
  → you get the screen, the decrypted traffic, and (with Frida) a REPL inside the app
```

It's built from well-known pieces: the Android emulator, [Frida](https://frida.re), [HTTP Toolkit's unpinning
scripts](https://github.com/httptoolkit/frida-interception-and-unpinning), [mitmproxy](https://mitmproxy.org),
apktool, apk-mitm and scrcpy. unpinned's job is choosing between them, wiring them together, and cleaning up after.

## 2. Quick start

```bash
git clone https://github.com/adamtty/unpinned && cd unpinned
uv sync
uv run unpinned doctor          # what's installed, what's missing
uv run unpinned setup           # once: the emulator, frida-server, the hooks (about 30 s)
uv run unpinned run app.apk     # triage → choose → run → watch
```

`run` asks a few questions (how to get at the traffic, which proxy). Press Enter to take the recommendation each
time. When it's done:

- the **emulator window** or **scrcpy window** shows the app: click and type in it normally
- the **mitmweb link** it prints shows every request and response, decrypted
- with the Frida hooks, it offers a **Frida REPL** inside the app

`uv run unpinned stop` stops everything, and the emulator throws away whatever the app did.

To run unpinned from anywhere without `uv run`, install it once as a command:

```bash
uv tool install --editable .    # then just: unpinned run app.apk
```

`--editable` means it always runs the code in this folder, so a `git pull` updates it.

## 3. Installing

### Requirements

| What | Why | How |
|---|---|---|
| **An Apple Silicon Mac** | arm64 Android runs natively and fast | |
| **Android SDK**: emulator, platform-tools, build-tools | the emulator, `adb`, `aapt2`, `zipalign`, `apksigner` | Android Studio, or `brew install --cask android-commandlinetools` then `sdkmanager` |
| **A Google APIs arm64 system image** | the emulator's Android, and the rootable kind | `sdkmanager "system-images;android-36.1;google_apis;arm64-v8a"` |
| **mitmproxy** | the built-in proxy (mitmweb) | `brew install mitmproxy` |
| **openssl** | certificate hashes | built into macOS |
| **uv** | runs unpinned and pins its Python dependencies | `brew install uv` |
| apktool *(for patching)* | the gadget patch | `brew install apktool` |
| a JDK *(for patching)* | `keytool`, to make the signing key | `brew install openjdk` |
| scrcpy *(optional)* | the phone/emulator screen on your Mac | `brew install scrcpy` |
| apk-mitm *(optional)* | the apk-mitm patch | `npm install -g apk-mitm` |
| apkid *(optional)* | extra triage findings: packers, protectors, obfuscators, compilers ([section 5](#apkid-optional)) | `uv tool install apkid` |

**Use a Google APIs image, not a "Google Play" one.** Play Store images can't be rooted, and unpinned needs root on
the emulator. Android 16 (`android-36.1`) is the default. Android 14 (`android-34`) is worth having too, because the
gadget patch is more stable there ([section 10](#gadget-and-android-16)).

### Checking it

```bash
uv run unpinned doctor
```

prints a ✓ or ✗ for each tool, the system image, the emulator and its snapshot. Optional tools show as · when
they're missing.

## 4. Setting up the emulator

```bash
uv run unpinned setup                 # Android 16
uv run unpinned --api 34 setup        # Android 14, for gadget work
```

`setup` does all of this, once per Android version:

1. **Downloads and verifies** HTTP Toolkit's scripts (pinned to one commit, each checked against a SHA-256 in
   `assets.py`) and frida-server (the exact version of the pinned `frida` Python package, checked against the
   SHA-256 GitHub publishes for it).
2. **Creates unpinned's own emulator** (`unpinned-api36_1`, `unpinned-api34`, …). It never touches your own
   emulators.
3. **Cold-boots it**, roots `adbd`, pushes frida-server, turns off animations and install verification.
4. **Switches Android's garbage collector** to the older concurrent-copying one (one reboot), which makes
   gadget-patched apps steadier on Android 16.
5. **Saves a clean snapshot** called `unpinned-clean`. Every `run` starts from it, so nothing from one app leaks
   into the next.

### When to run `setup` again

- **After the Android emulator updates.** Snapshots are tied to the emulator version. If `run` says the clean
  snapshot won't load, that's why: run `setup` again.
- **After upgrading unpinned**, if its notes say the snapshot needs rebuilding.
- **If the emulator is in a bad state.** `setup` rebuilds it from scratch.

## 5. Triage: reading an app before running it

```bash
uv run unpinned triage app.apk
uv run unpinned triage app.apks --json report.json --endpoints
```

Triage reads the APK directly (the DEX files, the manifest, native libraries, resources and assets). Nothing is
installed or run, and nothing is decompiled. `run` and `phone` show the same report before they start.

### What the report shows

**Basics:** the package, version, minimum and target SDK, how many APKs (splits), native ABIs, and the framework
(Flutter, React Native, Xamarin / .NET MAUI, Unity, Cordova / Capacitor, or plain Java / Kotlin).

**The pinning verdict:** *no pinning found*, *pinning possible*, *pinning likely* or *pins certificates*, from the
strongest finding.

Then each kind of finding, marked ● definite, ● likely or ○ possible, with its evidence:

| Section | What triage looks for |
|---|---|
| **Certificate pinning** | `<pin-set>` in the network security config; a config that trusts only bundled CAs; hard-coded `sha256/…` pins (OkHttp / TrustKit format); TrustKit; OkHttp's `CertificatePinner`; the app's own `TrustManager` and `HostnameVerifier` classes; bundled certificate and keystore files; pins in native code; Flutter and React Native pinning plugins; **the app's own certificate checks** (see below) |
| **Certificate Transparency** | Appmattus CT |
| **Root detection** | RootBeer; `su` paths, Magisk and similar strings; root checks in native code; root-detection plugins (Flutter, React Native); native libraries named for root checks (RootBeer's `libtool-checker.so`, …) |
| **Device attestation** | Play Integrity, SafetyNet |
| **Frida detection** | Frida strings in DEX or native code; native libraries named for Frida checks (`libfrida-check.so`, …) |
| **Emulator detection** | emulator property and hardware names |
| **Debugger detection** | `isDebuggerConnected`, `TracerPid` |
| **Protector / RASP** | Talsec freeRASP, Promon SHIELD, Jiagu, Bangcle / SecNeo, Tencent Legu, Appdome, DexProtector, and tamper-check libraries |
| **Obfuscation**, **Anti-analysis**, **Signs of repackaging** | only with apkid installed ([below](#apkid-optional)) |
| **Manifest** | `debuggable`; `allowBackup`; cleartext HTTP; exported activities, services, receivers and providers with no permission guarding them (including implicit exports on old target SDKs); deep links |
| **Hard-coded secrets** | Google API keys, Firebase database URLs, AWS access keys, private keys, Slack / Stripe live / GitHub tokens, JWTs |
| **Endpoints** | every URL in the code, resources and assets, by host |

Known third-party libraries (OkHttp, AndroidX, Google, Chromium/Cronet, Flutter's engine, crash reporters, RASP
SDKs, …) are skipped where it matters, so their code doesn't count as the app's.

### The app's own certificate checks

Some apps check certificates in their own code: a method that takes a certificate and returns true or false, or
their own `checkServerTrusted`. No generic hook can reach those, so triage finds them in the DEX method table and
lists them, for example:

```text
tech.httptoolkit.pinning_demo.MainActivity.doesCertMatchPin(String, Certificate) → boolean
```

`run` and `phone` offer to **hook them to always pass** (logging every call they override). Deliberately excluded:

- methods that only take a **public key**: those verify signatures (licences, purchase receipts), not certificates
- anything in library or **protector** code: a RASP's own certificate check guards the app's integrity, and
  unpinned never forces that to pass

`--no-auto-hooks` skips the question and the hooks.

### Secrets

Secrets are **masked** by default (`AIzaSyCg…yo (39 chars)`). `--show-secrets` prints them in full. Firebase
database URLs are shown in full anyway: they're addresses to check, not secrets. Each comes with a hint: check a
Google API key's restrictions, check a Firebase database's rules.

### Saving it

- `--json report.json` writes everything (findings, the app's certificate checks, the manifest, secrets (masked
  unless `--show-secrets`), and every endpoint).
- `--endpoints` prints every URL found.

### Protected apps

If triage finds a runtime protector (RASP), it says so plainly, with what works best: a real phone with root
hidden, or on an authorised test a build with the protection in development mode or your device allowlisted. See
[section 17](#17-limits-what-unpinned-cant-do).

### apkid (optional)

[apkid](https://github.com/rednaga/APKiD) recognises packers, protectors, obfuscators, anti-analysis tricks and the
compiler that built each DEX file, by signature (YARA rules). Triage works without it. With it installed, every
triage (and the report at the start of `run` and `phone`) runs it too, and adds what it finds to the same report,
marked **(apkid)**.

```bash
uv tool install apkid
uv run unpinned doctor        # shows "apkid (optional, for triage)" as ✓
```

How its findings show up:

| apkid category | Shown under | Strength | Shown as |
|---|---|---|---|
| `packer`, `protector` | Protector / RASP | ● definite | one line per name, with the files it was found in (for example `DexProtector (apkid)`) |
| `obfuscator` | Obfuscation | ● likely | one line per name |
| `manipulator` | Signs of repackaging | ● likely | one line per name |
| `anti_root` | Root detection | ● likely | "root checks (apkid)", with apkid's labels as the evidence |
| `anti_vm` | Emulator detection | ● likely | "emulator checks (apkid)" |
| `anti_debug` | Debugger detection | ● likely | "debugger checks (apkid)" |
| `anti_disassembly` | Anti-analysis | ● likely | "anti-disassembly tricks (apkid)" |
| `abnormal` | Anti-analysis | ○ possible | "unusual structure (apkid)" |

**The compiler** goes on the report's second line: `built with r8` (or `dx`, `d8`, `r8 without marker`, …). If it
says **dexlib**, the DEX was rebuilt by a tool such as apktool or smali rather than by Google's compilers, and
triage warns you: the app has probably been repackaged by someone, which is worth knowing before you trust what you
see.

What it changes:

- **A packer or protector counts as a protector.** You get the plain advice from [Protected apps](#protected-apps),
  and the watcher waits 60 seconds instead of 20 after launch, since protectors act after their background checks.
- **None of it changes the recommended strategy**, which goes by pinning and Frida detection. The rest tells you
  what you'll find when you open the app in jadx.
- **`--json` includes them**, like every other finding.

Notes:

- It adds a few seconds per APK (apkid gives up on a file after two minutes). A split app (`.apks`, `.xapk`) is
  checked APK by APK.
- If apkid is missing, times out or prints something unexpected, triage simply goes on without it.
- Signatures only know what they've been taught: a protector apkid doesn't recognise can still be there, and
  triage's own checks (native library names, RASP SDK classes) look for those separately.

## 6. Choosing how to get at the traffic

There are four ways in. `run` and `phone` recommend one; press Enter to take it, or pick another, or pass
`--strategy`.

| Method | What happens | Good for | Watch out for |
|---|---|---|---|
| **`hooks`**: root + Frida hooks | frida-server spawns the app with HTTP Toolkit's scripts: every TCP connection redirected to the proxy, the proxy's CA trusted inside the app, pinning removed (OkHttp, Volley, TrustKit, Conscrypt, network security config, Certificate Transparency, Flutter), root detection off | **pinned apps** (the default when something is pinned) | apps that detect Frida |
| **`ca`**: system CA only, no Frida | the proxy's CA goes into the system store, and only the app's traffic is redirected (iptables) | apps that **don't pin**: nothing for the app to detect | doesn't bypass pinning |
| **`gadget`**: patch in Frida's gadget | the app is repackaged with Frida's gadget and the same hooks, which run inside the app before its own code; no frida-server on the device; its network security config is relaxed too | apps that spot **frida-server** or root | reinstalls the app (new signature); unstable on Android 16 ([why](#gadget-and-android-16)); spotted by apps that look for Frida itself |
| **`apk-mitm`**: static repackage | apk-mitm rewrites the app to trust user CAs and strips known pins; no Frida at all | apps that detect **Frida** in any form | reinstalls the app; can't handle unusual pinning; tamper checks notice the new signature |

### What gets recommended

- **Nothing pinned** (and no Certificate Transparency): **`ca`**. No Frida at all, so there's nothing for root or
  Frida checks to find (and root on unpinned's emulator is invisible to apps anyway). If the app still refuses, the
  watcher offers a patch.
- **Pinned, and the app detects Frida:** **`gadget`**.
- **Otherwise:** **`hooks`**.

On your phone, `phone` starts with the methods that keep the app's data (`hooks`, `ca`) and only patches if you say
so ([section 9](#patching-on-the-phone)).

## 7. The proxy

### unpinned's own mitmweb (the default)

`run` starts **mitmweb** (mitmproxy's web interface) for you:

- on `127.0.0.1` only, on free ports (it never takes a port something else is using)
- behind a random password, kept in a private config file, and printed as a link: `traffic: http://127.0.0.1:…/?token=…`
- with **its own CA**, under `~/.cache/unpinned/mitmproxy`, separate from your `~/.mitmproxy` one

Open the link to see the traffic. It's reused across runs until `unpinned stop`.

`--insecure-upstream` stops mitmweb verifying the **real** servers' certificates. Use it for staging servers or
self-signed test hosts (the pinning demo's test servers need it). Without it, a server mitmproxy can't verify shows
as an error in mitmweb, not as a response.

### Your own proxy (Burp, HTTP Toolkit, Charles…)

When `run` or `phone` asks *which proxy*, choose **your own proxy** and give its `ip:port` (it's checked that
something answers there). Then give its CA certificate:

- **PEM or DER.** Burp's `cacert.der` export works as it is.
- **Stored in `certs/`** (git-ignored), named by the certificate's SHA-256 fingerprint.
- **Adding the same one again**, in either format, just says *"that certificate is already in certs/ … you're
  good"*.
- **Next time,** stored certificates are offered as a list.
- **Not a CA?** You'll get a warning: export your proxy's CA certificate, not a site certificate.

Without the questions:

```bash
uv run unpinned run app.apk --proxy 127.0.0.1:8080 --ca ~/Downloads/cacert.der
```

**How the device reaches it:** a proxy on your Mac (`127.0.0.1`) is reached through `adb reverse` over the adb
connection. A proxy elsewhere on your network is reached directly from the device.

**Burp tips:** set its listener to *Support invisible proxying* if you see requests without a host. unpinned's
redirect sends traffic without a CONNECT request, and mitmproxy handles that from the TLS server name. In Burp,
invisible proxying does the same.

## 8. Running on the emulator: `unpinned run`

```bash
uv run unpinned run app.apk
uv run unpinned run app.apks --strategy hooks --yes
uv run unpinned run --from-phone spotify
```

### What it accepts

- a single `.apk`
- a bundle of splits: `.apks` (bundletool), `.xapk`, or a `.zip` of APKs
- with `--from-phone`, an app installed on your phone: a package name or part of one to search for
  ([section 9](#9-using-your-phone))

### What it does, in order

1. **Triage** ([section 5](#5-triage-reading-an-app-before-running-it)), then the offer to hook the app's own
   certificate checks.
2. **The method** ([section 6](#6-choosing-how-to-get-at-the-traffic)). Picking the gadget on Android 16 offers to
   switch to the Android 14 emulator if it's set up.
3. **The proxy** ([section 7](#7-the-proxy)).
4. **The emulator:** boots from the clean snapshot, or resets the running one to it, and waits for its network.
5. **The proxy's CA into the system store**, so code the hooks don't reach (Flutter's Dart, for one) trusts it.
6. **Patching**, for the gadget or apk-mitm methods.
7. **Install and launch**, the chosen way.
8. **The watcher** ([section 10](#10-when-the-app-refuses-the-watcher-and-the-patch-loop)): 20 seconds, or 60 when
   triage found a protector.
9. **Hand-over:** the traffic link, the hook log, and (with hooks) the offer of a Frida REPL.

### Useful options

| Option | What it's for |
|---|---|
| `--strategy hooks\|ca\|gadget\|apk-mitm` | skip the method question |
| `--yes` | take every recommended answer, including patching if the app refuses |
| `--watch SECONDS` | how long to watch for a refusal |
| `--proxy HOST:PORT --ca CERT` | your own proxy |
| `--insecure-upstream` | mitmweb doesn't verify real servers |
| `--script hook.js` | load your own Frida script after the built-in hooks (repeatable; also bundled into gadget builds) |
| `--no-auto-hooks` | don't hook the app's own certificate checks |
| `--global-proxy` | without Frida, use the device-wide proxy setting instead of redirecting only the app |
| `--headless` | no emulator window or scrcpy |
| `--api 34` | use the Android 14 emulator (any version you've run `setup` for) |

### Between apps

- `uv run unpinned reset`: back to the clean snapshot, emulator still running
- `uv run unpinned stop`: stop every unpinned emulator (discarding their changes), the Frida session, mitmweb and
  scrcpy

## 9. Using your phone

A real phone is closer to how the app really runs, and it can't be detected as an emulator. unpinned needs it
**rooted** (Magisk or KernelSU) and connected over adb.

### Getting the phone ready

1. **Developer options → USB debugging** on, and accept the *"Allow USB debugging?"* prompt on the phone.
2. **Root for the shell:** `adb shell su -c id` should print `uid=0`. Magisk asks the first time: allow it.
3. *(Recommended)* **Developer options → Stay awake**, so the screen doesn't lock while you test.
4. *(For hiding root)* **Magisk → Settings: Zygisk on, Enforce DenyList on**, then reboot. See
   [Hiding root](#hiding-root).

### Pulling apps: `unpinned pull`

```bash
uv run unpinned pull spotify              # search, pick, pull
uv run unpinned pull com.spotify.music --out ~/apks
```

Pulls an installed app with **every split** into one `.apks` bundle, under `~/.cache/unpinned/pulled/` (and a copy
in `--out`). Use it with `run`, `triage` or `patch`, or keep it as a backup. If the phone keeps app files where
the shell can't read them, unpinned copies them out as root first.

### Phone to emulator: `run --from-phone`

```bash
uv run unpinned run --from-phone spotify
```

Pulls the app off the phone, then the whole emulator flow. You test the exact build you use, without hunting for
an APK, and the copy on your phone isn't touched.

### On the phone itself: `unpinned phone`

```bash
uv run unpinned phone spotify
```

The same flow, on the phone:

- **The app keeps its data.** frida-server, the proxy's CA and the redirect go on through `su`. The app isn't
  reinstalled.
- **A copy is pulled first** anyway, for triage and as a backup.
- **Traffic reaches your Mac** through `adb reverse` over the USB cable.

When you're done:

```bash
uv run unpinned phone --cleanup
```

stops frida-server, unmounts the CA, removes the redirect and the proxy setting, takes the app off Magisk's
DenyList if unpinned put it there, and removes `adb reverse`. A reboot clears everything except the DenyList entry
too.

### Patching on the phone

If the app refuses to run, patching it means **reinstalling** it, which **wipes its data on the phone** (logins,
settings). So `phone` asks first, and the pulled original is kept:

```bash
uv run unpinned phone --restore ~/.cache/unpinned/pulled/com.example-20261022-213941.apks
```

puts the original back (its data from before the patch is gone either way).

### Hiding root

`phone` puts the app on **Magisk's DenyList**: Magisk hides itself and undoes its changes inside that app. It needs
Zygisk and *Enforce DenyList* on (Magisk app → Settings, then reboot); if they're off, `phone` says so and carries
on with root visible.

**The catch:** the DenyList also hides **the proxy's system-store CA** from that app. Magisk reverts mounts in the
app's namespace, and SELinux blocks putting it back. So:

| Method | Root hidden? | Why |
|---|---|---|
| `hooks`, `gadget` | **yes** | they trust the CA inside the app, so HTTPS still works |
| `ca`, `apk-mitm` | **no** | the CA would disappear and HTTPS would break; `phone` says so |

`--no-hide-root` turns it off entirely. KernelSU and other root solutions have their own per-app settings; unpinned
doesn't manage those.

### Older phones and frida-server

Current frida-server crashes at start-up on some older devices (Samsung phones on Android 9, for one:
[frida#3715](https://github.com/frida/frida/issues/3715)). unpinned notices (it checks frida-server is actually
listening, and still listening 3 seconds later) and falls back to frida-server **17.5.2**, verified the same way,
which the current client works with. It remembers that per phone.

### What unpinned leaves alone on your phone

- **Your own frida-server.** unpinned's has its own filename (`/data/local/tmp/unpinned-frida-server`).
- **Magisk modules.** unpinned's CA mount is labelled `unpinned`, and cleanup only ever removes mounts with that
  label, so a module that mounts over the same CA folder (HTTP Toolkit's, say) is untouched.
- **Other apps' traffic.** The redirect matches only the target app's user ID.
- **Your iptables rules.** unpinned's rules live in their own `UNPINNED_*` chains.

## 10. When the app refuses: the watcher and the patch loop

After launch, the **watcher** checks the app for 20 seconds (60 when triage found a protector, since RASPs act after
their background checks). The app has **refused** if:

- **it exited**: unpinned reports Android's own exit reason and the exception that ended the app
- **it's showing** text about root, tampering, Frida, an emulator, integrity or a debugger
- **it closed its window** but kept its process (some Frida checks do this)

With each refusal, unpinned quotes **the app's own log line** when there is one, e.g.
*"it closed its window; the app logged: FRIDA Server DETECTED"*.

Then it offers the next method: the **gadget** patch, then **apk-mitm**, reinstalling and reopening each time.
`--yes` takes them in order without asking. On the phone, each reinstall is confirmed first.

### Gadget and Android 16

Frida's Java hooks running inside an app through the gadget can crash Android 16's garbage collector. This is an
open Frida bug ([frida#3805](https://github.com/frida/frida/issues/3805)): Android 16's `libart` no longer ships
the symbols Frida uses to make hooked methods safe for the collector. What unpinned does about it:

- choosing the gadget on Android 16 **offers to switch to the Android 14 emulator** (`unpinned --api 34 setup`
  first), where it's stable
- `setup` switches the emulator to the older garbage collector, which helps but doesn't fix it
- the frida-server route (`hooks`) isn't affected

## 11. Working with the app: the screen, the traffic, Frida

### The screen

Unless you pass `--headless`, you get the **emulator window** (emulator runs) and a **scrcpy window** (both). Both
are live remote controls:

| Do this | To |
|---|---|
| click | tap |
| click and drag | swipe |
| scroll wheel | scroll |
| type | type into the app |
| right-click | Back |
| Cmd-H / Cmd-S | Home / app switcher |
| Cmd-C, Cmd-V | copy and paste, both ways between your Mac and the device |
| drag an APK onto the window | install it |
| drag another file onto it | copy it onto the device |

On your phone you can also just use the phone.

### The traffic

Open the `traffic:` link from `run`. Each request appears as the app makes it, with the response. You can
filter, inspect, replay and edit in mitmweb as usual. With your own proxy, the traffic is in Burp / HTTP Toolkit /
Charles instead.

Some apps encrypt their request and response bodies themselves, on top of HTTPS (Damn Vulnerable Bank's
`{"enc_data": …}`). unpinned shows you the traffic, but reading those bodies takes app-specific work.

### Frida

- **The REPL:** with the hooks, `run` and `phone` offer a Frida REPL attached to the app when it's running. Or any
  time: `uv run frida -D <serial> -n <process name>`.
- **The hook log:** `run` prints where it is (`~/.cache/unpinned/run-…/frida.log`). Each hook group logs a
  `== … ==` line when it's installed.
- **Gadget builds** log to logcat instead: `adb logcat -s unpinned`.
- **Your own scripts:** `--script hook.js` (repeatable) loads them after the built-in hooks, and bakes them into
  gadget builds too.

Use the `frida` in unpinned's environment (`uv run frida`): it matches frida-server's version exactly.

## 12. Patching an APK on its own: `unpinned patch`

```bash
uv run unpinned patch app.apk                                   # gadget, into the current folder
uv run unpinned patch app.apks --method apk-mitm --out ~/patched
uv run unpinned patch app.apk --proxy 192.168.1.20:8080 --ca ~/Downloads/cacert.der
```

Writes patched APK(s) without running them: for a real device unpinned doesn't manage, or another emulator.

- **`gadget`** (the default) embeds Frida's gadget with the hooks. `--proxy` is where the hooks send traffic
  (default `127.0.0.1:8080`, so `adb reverse tcp:8080 tcp:8080` on the device), and `--ca` is the CA they trust
  (default: unpinned's mitmweb CA).
- **`apk-mitm`** writes apk-mitm's rewrite.
- Every APK of a bundle is re-signed with one local key (`~/.cache/unpinned/patch-key.p12`, made on first use),
  so install them together: `adb install-multiple *.apk`.

## 13. Recipes

**An app that doesn't pin.** `run app.apk`, Enter, Enter. Triage says *no pinning found* and recommends `ca`: no
Frida at all.

**A pinned app.** `run app.apk`. Triage shows *how* it pins; `hooks` handles the common libraries, and if the app
has its own certificate checks, say yes to hooking them.

**A Flutter app.** Flutter ignores Android's proxy settings and its own trust settings. `hooks` covers it (the
system CA plus HTTP Toolkit's Flutter hooks), and so does `ca` (the system CA plus the per-app redirect).

**An app that detects Frida** (triage shows *Frida detection*). If nothing is pinned, `ca` needs no Frida. If it is
pinned, try `gadget` (no frida-server to find), then `apk-mitm`.

**An app that refuses rooted devices.** Let the watcher handle it: it'll offer the gadget (which bypasses root
checks from inside), then apk-mitm. On your phone, root hiding is on by default for `hooks` and `gadget`.

**An app with runtime protection (RASP).** Expect to lose on the emulator. Try `phone` with root hidden; on an
authorised test, ask for a build with the protection in development mode.

**A staging server with a self-signed certificate.** Add `--insecure-upstream`.

**Testing through Burp.** `run app.apk --proxy 127.0.0.1:8080 --ca ~/Downloads/cacert.der`, with Burp's listener
on 127.0.0.1:8080.

**The same app you use, from your phone, on the emulator.** `run --from-phone <name>`.

**Scripting it.** `run app.apk --strategy hooks --yes --headless`: no questions, no windows.

**Just reading an app.** `triage app.apk --json report.json`.

## 14. Command reference

All commands take `--api VERSION` before the command (default `36.1`, or `$UNPINNED_API`) to pick the emulator.

| Command | What it does | Options |
|---|---|---|
| `doctor` | checks the tools, the system image, the emulator and its snapshot | |
| `setup` | downloads and verifies frida-server and the hooks; creates, roots and snapshots the emulator | `--headless` |
| `triage APP` | the static report, no device | `--show-secrets`, `--json FILE`, `--endpoints` |
| `run APP` | triage → method → proxy → emulator → watch → patch loop | `--from-phone`, `--device`, `--strategy`, `--yes`, `--watch`, `--proxy`, `--ca`, `--script`, `--no-auto-hooks`, `--insecure-upstream`, `--global-proxy`, `--headless` |
| `phone APP` | the same on a rooted phone | as `run` (without `--from-phone`), plus `--no-hide-root`, `--cleanup`, `--restore BUNDLE` |
| `pull APP` | an installed app off the phone into one `.apks` | `--device`, `--out DIR` |
| `patch APP` | write a patched APK | `--method gadget\|apk-mitm`, `--proxy`, `--ca`, `--out DIR` |
| `reset` | the running emulator back to its clean snapshot | |
| `stop` | stop every unpinned emulator, Frida, mitmweb and scrcpy | |

**Exit codes:** `0` done; `1` an error (the message says what); `2` the app refused and nothing more was tried (or
you stopped).

## 15. Files, folders and settings

### Environment variables

| Variable | What it changes |
|---|---|
| `UNPINNED_API` | the default Android version (`36.1`) |
| `UNPINNED_HOME` | unpinned's cache folder (`~/.cache/unpinned`) |
| `UNPINNED_CERTS` | where your own proxies' CAs are stored (`certs/` in the project) |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | the Android SDK (`~/Library/Android/sdk`) |
| `ANDROID_AVD_HOME` | where emulators live (`~/.android/avd`) |

### What lives where

| Path | What |
|---|---|
| `~/.cache/unpinned/frida-server-<version>-android-arm64` | verified frida-server builds |
| `~/.cache/unpinned/frida-gadget-<version>-android-arm64.so` | verified gadget builds |
| `~/.cache/unpinned/scripts/<commit>/` | HTTP Toolkit's scripts, verified |
| `~/.cache/unpinned/mitmproxy/` | mitmweb's own CA and config (the web password lives here) |
| `~/.cache/unpinned/run-*/`, `phone-*/` | one folder per run: the unpacked APKs, `config.js`, `frida.log`, generated hooks, patched builds |
| `~/.cache/unpinned/pulled/` | apps pulled off your phone |
| `~/.cache/unpinned/patch-key.p12` (+ `.pass`) | the local key that signs patched builds |
| `~/.cache/unpinned/state.json` | what's running, which mitmweb, which phones need the frida-server fallback, which DenyList entries unpinned added |
| `~/.cache/unpinned/emulator.log`, `mitmweb.log`, `scrcpy.log` | logs |
| `~/.android/avd/unpinned-*` | unpinned's emulators and their snapshots |
| `certs/` (in the project) | your own proxies' CAs, git-ignored |

### On the device

| Where | What | Removed by |
|---|---|---|
| `/data/local/tmp/unpinned-frida-server` | frida-server | stays (stopped); `rm` it if you like |
| a tmpfs labelled `unpinned` over the system CA folder | the proxy's CA | `phone --cleanup`, `reset`, reboot |
| `UNPINNED_NAT` / `UNPINNED_FILTER` iptables chains | the per-app redirect | `phone --cleanup`, `reset`, reboot |
| `settings global http_proxy` | the device-wide proxy (`--global-proxy`, or methods without the redirect) | `phone --cleanup`, `reset` |
| `adb reverse` rules | the device's `127.0.0.1:port` → your Mac | `phone --cleanup` (on the emulator they go with it) |
| Magisk DenyList entries unpinned added | hiding root | `phone --cleanup` |

## 16. How it works

**The clean snapshot.** `run` loads the `unpinned-clean` snapshot, which takes seconds and throws away everything
from the last run: apps, data, hooks, mounts.

**The system CA.** Android 14+ reads system CAs from the Conscrypt APEX, which is read-only and per mount
namespace. unpinned mounts a writable copy (with the proxy's CA added) over the system CA folder, then binds it
over the APEX folder inside zygote's namespaces, which every app forks from. Older Android and Flutter's Dart read
the system folder directly. The approach is HTTP Toolkit's.

**The per-app redirect.** On a rooted device, an iptables `REDIRECT` rule matched on the app's user ID sends its
TCP to the local end of `adb reverse`, and so to the proxy on your Mac. The proxy reads where each connection was
meant to go from the TLS server name (or the Host header for plain HTTP). QUIC and IPv6 TCP are refused for the
app so it falls back to IPv4 TCP.

**The hooks.** HTTP Toolkit's scripts, loaded by frida-server into the spawned app: a native `connect()` hook
redirects every TCP connection to the proxy; the proxy's CA is added to the app's Java trust; OkHttp, TrustKit,
Conscrypt, the network security config, Appmattus CT and others are unpinned; a fallback patches pinning failures
it sees at run time; native TLS (BoringSSL in `libssl` and Flutter's engine) is hooked; root checks are blocked.
unpinned adds hooks for the app's own certificate checks.

**The gadget patch.** apktool decodes the app; the network security config is relaxed (no pins, system and user
CAs trusted, TrustKit not enforced, CT off); a `System.loadLibrary` call is added to the Application class's
static initialiser; Frida's gadget, its config and a script (frida-tools' Java bridge plus every hook) are added
as native libraries; the hooks wait until Android is about to create the Application, when the app's classes can
be found. Then it's rebuilt, aligned and signed.

**frida-server versions.** unpinned pins one `frida` version and downloads the matching frida-server, verified
against GitHub's published SHA-256. On devices where it won't run, it uses 17.5.2.

## 17. Limits: what unpinned can't do

- **Play Integrity / SafetyNet** are judged on Google's servers. An emulator, and usually a rooted phone, fails
  them whatever runs on it, so features gated on them won't work.
- **Runtime protection (RASP)** such as freeRASP, Promon, DexGuard or Appdome is built to spot emulators, root and
  instrumentation, and often ends the app. It wins on the emulator. A real phone with root hidden gets further (the
  freeRASP demo kept running under the gadget on a real phone). Beating a RASP properly means per-app work or a
  stealth build of Frida; on an authorised test, ask for a build with the protection in development mode instead.
  Most apps aren't protected like this.
- **Apps that look for Frida itself** (its strings or thread names in memory) spot the gadget too. Use the
  no-Frida methods: `ca` if nothing is pinned, otherwise `apk-mitm`.
- **Hand-written pin checks** that triage can't recognise (no certificate in the method's arguments, say) need your
  own hook: find the code in jadx, then `--script`.
- **App-level encryption** of request and response bodies is still encrypted in the proxy.
- **The gadget on Android 16** is unstable ([section 10](#gadget-and-android-16)).

## 18. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `no clean snapshot yet` | `setup` hasn't been run for this Android version | `unpinned setup` (or `--api 34 setup`) |
| `the clean snapshot wouldn't load` | the emulator was updated; snapshots are tied to its version | `unpinned setup` again |
| `the Android … Google APIs arm64 image isn't installed` | no system image | the `sdkmanager` command it prints |
| An app's first requests fail with `UnknownHostException` | the emulator's network wasn't back yet after the snapshot loaded | unpinned waits for it now; if it persists, `reset` and try again |
| mitmweb shows `Certificate verify failed` against the real server | the server's certificate doesn't verify (staging, self-signed, or a root mitmproxy doesn't know) | `--insecure-upstream` |
| Requests reach a different program, not your proxy | another program owns the port | unpinned picks free ports for its mitmweb; for your own proxy, check `--proxy` |
| `frida couldn't spawn the app` / `need Gadget to attach on jailed Android` | frida-server isn't running on the device | unpinned retries with frida-server 17.5.2; if it still fails, the device can't run frida-server (see [frida#3715](https://github.com/frida/frida/issues/3715)) |
| The app closes and the log says `FRIDA … DETECTED` | the app detects Frida | `ca` if nothing is pinned, otherwise `apk-mitm` |
| A gadget-patched app crashes in `DecodeGcMasksOnly` (garbage collector) | the Android 16 Frida bug | `--api 34` (after `--api 34 setup`) |
| `Unable to start activity … IllegalStateException` after relaunching the app by hand | some apps can't be relaunched in the same process (a library initialised twice) | stop it and start it once (`am force-stop`, then launch) |
| The app's HTTPS fails on the phone with root hidden | the DenyList hid the system CA from it | use `hooks` or `gadget` there, or `--no-hide-root` |
| `Magisk's DenyList isn't enforced` | Zygisk or Enforce DenyList is off | Magisk app → Settings, then reboot |
| `su didn't give root` | the shell hasn't been granted root | allow it in Magisk (it prompts on the phone) |
| `the phone is waiting for you to allow USB debugging` | the prompt is on the phone | accept it |
| The phone's screen locked during a run | the app is behind the lock screen | unlock it; turn on Developer options → Stay awake |
| `install failed (signed with a different key)` | a patched build over the original, or the reverse | unpinned uninstalls first; by hand, `adb uninstall <package>` |
| `install failed (no native code for arm64-v8a)` | the app only ships 32-bit or x86 native code | a different build of the app |

## 19. Security and safety

- **Localhost only.** mitmweb listens on `127.0.0.1` behind a random password. The device reaches it through
  `adb reverse`. Nothing listens on your network unless you point unpinned at your own proxy there.
- **Separate from your setup.** unpinned's own emulators, its own mitmproxy CA, its own frida-server filename,
  labelled mounts, its own iptables chains, and only DenyList entries it added.
- **Verified downloads.** frida-server and the gadget against GitHub's published SHA-256 for the exact pinned
  version; HTTP Toolkit's scripts against hashes pinned in the code.
- **The APK is treated as hostile.** Bundles are unpacked to `*.apk` members only, flattened, with size limits;
  DEX and native code are read with size caps; manifest class and resource names are validated before they're used
  in paths; the parsers are fuzzed in CI.
- **A rooted emulator running unknown apps is still a hostile machine.** Don't sign into accounts you care about
  on it.
- **On your phone,** frida-server runs as root while you test, and the app's traffic goes through your Mac. Run
  `phone --cleanup` when you're done.
- **Patched builds** are signed with a local key that signs nothing but test builds. Don't distribute them: they
  contain Frida and HTTP Toolkit's AGPL scripts.

## 20. Glossary

| Term | Meaning |
|---|---|
| **Certificate pinning** | an app accepting only specific certificates or keys for its servers, so a proxy's certificate is refused |
| **CA** | certificate authority: the certificate a proxy signs its fake site certificates with; the device has to trust it |
| **System store / user store** | Android's two places for trusted CAs. Apps targeting Android 7+ trust only the system store unless they opt in to the user store |
| **Network security config** | an app's XML file declaring which CAs it trusts and which certificates it pins |
| **Certificate Transparency (CT)** | checking that a certificate was publicly logged; proxy certificates aren't, so CT checks refuse them |
| **Frida** | a toolkit for injecting JavaScript into running apps to inspect and change them |
| **frida-server** | Frida's daemon on a rooted device, which injects into apps |
| **Gadget** | Frida packaged as a library inside the app itself, for devices without frida-server |
| **Hook** | replacing a function's behaviour at run time |
| **Triage** | unpinned's static read of the app before running it |
| **RASP** | runtime application self-protection: a library inside the app that detects tampering, rooting, emulators and instrumentation, and reacts |
| **Magisk / Zygisk / DenyList** | Magisk is the common Android root tool; Zygisk runs its code inside apps; the DenyList is Magisk's per-app list of apps to hide from |
| **Snapshot** | a saved state of the emulator that it can return to in seconds |
| **adb reverse** | makes a port on the device lead to a port on your Mac, over the adb connection |
| **Split APKs / bundle** | modern apps are several APKs (base, per-ABI, per-density, per-language); a bundle (`.apks`, `.xapk`) holds them together |
