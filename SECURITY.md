# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub:
[**Report a vulnerability**](https://github.com/adamtty/unpinned/security/advisories/new).
Don't open a public issue for them.

Include what you found, how to reproduce it (a small APK or bundle is ideal), and what an attacker could do with
it. You'll get a reply within a week. Once it's fixed, you'll be credited in the advisory unless you'd rather not
be.

## Supported versions

Only the latest commit on `main` is supported; there are no release branches.

## Scope

unpinned reads apps you didn't write, so the APK is the attacker here. The most interesting reports are ones where
a crafted APK or bundle can:

- write, read or overwrite files on the host outside unpinned's working folders (through bundle member names,
  manifest class or resource names during patching, or anything else)
- run commands on the host, or make unpinned run a tool with arguments it controls
- crash or hang triage, or hide a pinning / root-detection finding it should report
- inject terminal escape sequences or misleading text into unpinned's output

Also in scope: anything that exposes the proxy, the mitmweb UI, frida-server or adb beyond localhost, or that lets
a stale state file make unpinned signal the wrong process.

Out of scope: vulnerabilities in Frida, mitmproxy, apktool, the Android emulator or HTTP Toolkit's scripts (report
those upstream), what an app can do inside the emulator (it's a disposable, rooted test device), and findings that
need an attacker who can already change unpinned's install or your environment.
