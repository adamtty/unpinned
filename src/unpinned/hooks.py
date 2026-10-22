"""Generated Frida hooks for the app's own certificate checks, found by triage: methods of the app's own classes that
take a certificate or TLS session and return a boolean, and the app's own TrustManagers. (A bare PublicKey isn't
enough: methods like that verify signatures, such as license or purchase receipts, which aren't pinning and are left
alone.) Each is made to
pass, and every call it overrides is logged, so it's clear what was skipped."""

from __future__ import annotations

import json
from dataclasses import dataclass

CERT_TYPES = {
    "Ljava/security/cert/Certificate;",
    "Ljava/security/cert/X509Certificate;",
    "[Ljava/security/cert/Certificate;",
    "[Ljava/security/cert/X509Certificate;",
    "Ljavax/net/ssl/SSLSession;",
    "Ljavax/net/ssl/SSLSocket;",
}
PRIMITIVES = {
    "Z": "boolean",
    "B": "byte",
    "C": "char",
    "S": "short",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}


@dataclass(frozen=True)
class PinCheck:
    cls: str  # java.lang.Class name, e.g. tech.example.Pins$Checker
    method: str
    params: tuple[str, ...]  # Frida overload type names
    returns: str  # "boolean" or "void"

    def label(self) -> str:
        short = [p.rsplit(".", 1)[-1].rstrip(";") + ("[]" if p.startswith("[") else "") for p in self.params]
        return f"{self.cls}.{self.method}({', '.join(short)}) → {self.returns}"


def frida_type(descriptor: str) -> str:
    """A dex type descriptor as Frida's overload() wants it."""
    if descriptor in PRIMITIVES:
        return PRIMITIVES[descriptor]
    if descriptor.startswith("["):
        return descriptor.replace("/", ".")  # arrays keep JNI form: [Ljava.lang.String;  [B
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def candidates(methods, app_classes: set[str], trust_managers: set[str]) -> list[PinCheck]:
    """From dex method ids: boolean methods of the app's classes that take a certificate-ish argument (not the
    compiler's access$ bridges, which call the real one), plus checkServerTrusted on the app's own TrustManagers."""
    out = set()
    for cls, name, params, ret in methods:
        if cls not in app_classes or name.startswith("access$") or name in ("<init>", "<clinit>", "equals"):
            continue
        is_check = ret == "Z" and CERT_TYPES & set(params)
        is_tm = cls in trust_managers and name == "checkServerTrusted" and ret == "V"
        if is_check or is_tm:
            out.add(
                PinCheck(
                    frida_type(cls), name, tuple(frida_type(p) for p in params), "boolean" if ret == "Z" else "void"
                )
            )
    return sorted(out, key=lambda c: (c.cls, c.method, c.params))


def script(checks: list[PinCheck]) -> str:
    """A Frida script that makes each check pass. App classes may not be loadable yet when hooks start (spawned app):
    then it waits for Android to create the Application and uses the app's class loader."""
    targets = json.dumps([[c.cls, c.method, list(c.params), c.returns] for c in checks])
    return (
        """
Java.perform(() => {
  const targets = """
        + targets
        + """;
  let installed = false;
  const install = () => {
    for (const [cls, method, params, returns] of targets) {
      const C = Java.use(cls);
      const m = C[method].overload(...params);
      m.implementation = function () {
        console.log(`== unpinned: ${cls}.${method} passed (app's own certificate check) ==`);
        return returns === "boolean" ? true : undefined;
      };
    }
    installed = true;
    console.log(`== unpinned: ${targets.length} app certificate check(s) hooked ==`);
  };
  try {
    install();
  } catch (e) {
    const Instrumentation = Java.use("android.app.Instrumentation");
    const onCreate = Instrumentation.callApplicationOnCreate;
    onCreate.implementation = function (app) {
      if (!installed) {
        Java.classFactory.loader = app.getClassLoader();
        try {
          install();
        } catch (e2) {
          console.log("!!! unpinned: couldn't hook the app's certificate checks: " + e2);
        }
      }
      return onCreate.call(this, app);
    };
  }
});
"""
    )
