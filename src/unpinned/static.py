"""The standard static checks: what the manifest exposes (exported components, deep links, debuggable, backups,
cleartext), hard-coded secrets, and every endpoint the app mentions. Read from aapt2's dumps and the strings triage
already collected; nothing is decompiled."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from unpinned import env

COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")

# (kind, regex, note). Google API keys are often meant to be public, but only when restricted.
SECRET_PATTERNS = [
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "check its restrictions in the Google Cloud console"),
    ("Firebase database", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "check its rules don't allow open reads"),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), ""),
    # the header alone is in every PEM parser; a real key has its base64 body after it
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{100,}"), ""),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"), ""),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}"), ""),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), ""),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "decode it: what does it grant?",
    ),
]
URL_RE = re.compile(r"\bhttps?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s\"'<>\\{}|^`]*)?")
NOISE_HOSTS = re.compile(
    r"(^|\.)(schemas\.android\.com|w3\.org|xmlpull\.org|ns\.adobe\.com|apache\.org|purl\.org|json-schema\.org|"
    r"xml\.org|schemas\.xmlsoap\.org|schemas\.microsoft\.com|example\.(com|org|net)|localhost|"
    # documentation and issue links from library code and comments
    r"github\.com|developer\.android\.com|issuetracker\.google\.com|youtrack\.jetbrains\.com|crbug\.com|"
    r"slf4j\.org|docs\.flutter\.dev|flutter\.dev|kotlinlang\.org|dashif\.org|bugs\.chromium\.org|"
    r"source\.android\.com|goo\.gl|g\.co|stackoverflow\.com|mozilla\.org|ietf\.org|unicode\.org)$",
    re.I,
)
TEXT_ASSET = re.compile(r"^(assets|res/raw)/.+\.(json|xml|txt|properties|js|html?|cfg|ini|ya?ml|conf|bundle)$", re.I)


@dataclass
class Node:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[Node] = field(default_factory=list)

    def find(self, tag: str) -> list[Node]:
        out = []
        for c in self.children:
            if c.tag == tag:
                out.append(c)
            out += c.find(tag)
        return out


ATTR_RE = re.compile(r"A: (?:http://schemas\.android\.com/apk/res/android:)?([\w]+)(?:\(0x[0-9a-f]+\))?=(.*)$")


def parse_xmltree(text: str) -> Node:
    """aapt2's `dump xmltree` output → a tree (elements nest by indentation)."""
    root = Node("#root")
    stack: list[tuple[int, Node]] = [(-1, root)]
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if s.startswith("E: "):
            node = Node(s[3:].split(" ", 1)[0])
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack[-1][1].children.append(node)
            stack.append((indent, node))
        elif s.startswith("A: "):
            m = ATTR_RE.match(s)
            if m and stack:
                value = m.group(2)
                if value.startswith('"'):
                    value = value[1:].split('" (Raw', 1)[0].rstrip('"')
                stack[-1][1].attrs[m.group(1)] = value
    return root


def _true(v: str | None) -> bool | None:
    if v is None:
        return None
    return v.lower() in ("true", "0xffffffff", "-1")


@dataclass
class Component:
    kind: str
    name: str
    exported: bool
    implicit: bool  # exported only because it has an intent filter and targets an old SDK
    permission: str
    launcher: bool


@dataclass
class Manifest:
    target_sdk: int = 0
    debuggable: bool = False
    allow_backup: bool = True
    cleartext: bool = False
    exposed: list[Component] = field(default_factory=list)  # exported with no permission guarding it
    deep_links: list[str] = field(default_factory=list)


def manifest(base: Path) -> Manifest:
    aapt2 = env.tool("aapt2")
    if not aapt2:
        return Manifest()
    out = subprocess.run(
        [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(base)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    ).stdout
    return manifest_from_xmltree(out)


def manifest_from_xmltree(text: str) -> Manifest:
    tree = parse_xmltree(text)
    m = Manifest()
    sdk = tree.find("uses-sdk")
    try:
        m.target_sdk = int(sdk[0].attrs.get("targetSdkVersion", "0"), 0) if sdk else 0
    except ValueError:
        m.target_sdk = 0
    app = (tree.find("application") or [Node("application")])[0]
    m.debuggable = bool(_true(app.attrs.get("debuggable")))
    backup = _true(app.attrs.get("allowBackup"))
    m.allow_backup = True if backup is None else backup
    clear = _true(app.attrs.get("usesCleartextTraffic"))
    m.cleartext = (m.target_sdk < 28) if clear is None else clear
    for kind in COMPONENTS:
        for c in app.find(kind):
            filters = c.find("intent-filter")
            explicit = _true(c.attrs.get("exported"))
            implicit_default = bool(filters) and m.target_sdk < 31
            if kind == "provider":
                implicit_default = m.target_sdk < 17
            exported = implicit_default if explicit is None else explicit
            permission = c.attrs.get("permission", "") or (
                c.attrs.get("readPermission", "") if kind == "provider" else ""
            )
            launcher = any(
                a.attrs.get("name") == "android.intent.action.MAIN" for f in filters for a in f.find("action")
            ) and any(
                x.attrs.get("name") == "android.intent.category.LAUNCHER" for f in filters for x in f.find("category")
            )
            if exported and not permission:
                m.exposed.append(
                    Component(kind, c.attrs.get("name", "?"), True, explicit is None, permission, launcher)
                )
            for f in filters:
                cats = {x.attrs.get("name") for x in f.find("category")}
                if "android.intent.category.BROWSABLE" not in cats:
                    continue
                # Android merges every <data> of a filter: every scheme with every host and path
                datas = f.find("data")
                schemes = [d.attrs["scheme"] for d in datas if d.attrs.get("scheme")]
                hosts_ = [d.attrs["host"] for d in datas if d.attrs.get("host")] or ["*"]
                paths = [
                    d.attrs.get("path") or d.attrs.get("pathPrefix") or d.attrs.get("pathPattern")
                    for d in datas
                    if d.attrs.get("path") or d.attrs.get("pathPrefix") or d.attrs.get("pathPattern")
                ] or [""]
                for scheme in schemes:
                    for host in hosts_:
                        for path in paths:
                            link = f"{scheme}://{host}{path}"
                            if link not in m.deep_links:
                                m.deep_links.append(link)
    return m


@dataclass(frozen=True)
class Secret:
    kind: str
    value: str
    where: str
    note: str

    def masked(self) -> str:
        v = self.value
        if self.kind == "Firebase database":  # an address to check, not a secret
            return v
        return v if len(v) <= 12 else f"{v[:8]}…{v[-2:]} ({len(v)} chars)"


def secrets(sources: dict[str, set[str] | list[str]]) -> list[Secret]:
    """sources: where → texts. Each distinct value once, at the first place it was seen."""
    seen: dict[tuple[str, str], Secret] = {}
    for where, texts in sources.items():
        for t in texts:
            for kind, rx, note in SECRET_PATTERNS:
                for m in rx.finditer(t):
                    seen.setdefault((kind, m.group(0)), Secret(kind, m.group(0), where, note))
    return sorted(seen.values(), key=lambda s: (s.kind, s.value))


def endpoints(texts) -> list[str]:
    urls = set()
    for t in texts:
        for m in URL_RE.finditer(t):
            u = m.group(0).rstrip(".,;:)]")
            host = re.sub(r"^https?://", "", u).split("/", 1)[0].split(":", 1)[0]
            if host and "." in host and not NOISE_HOSTS.search(host) and not host.endswith("."):
                urls.add(u)
    return sorted(urls)


def hosts(urls: list[str]) -> list[tuple[str, int]]:
    count: dict[str, int] = {}
    for u in urls:
        h = re.sub(r"^https?://", "", u).split("/", 1)[0]
        count[h] = count.get(h, 0) + 1
    return sorted(count.items(), key=lambda x: (-x[1], x[0]))


def resource_strings(base: Path) -> list[str]:
    aapt2 = env.tool("aapt2")
    if not aapt2:
        return []
    out = subprocess.run(
        [aapt2, "dump", "strings", str(base)], capture_output=True, text=True, timeout=120, check=False
    ).stdout
    return [ln.split(" : ", 1)[1] for ln in out.splitlines() if ln.startswith("String #") and " : " in ln]
