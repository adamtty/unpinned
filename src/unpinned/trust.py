"""The CA roots unpinned's downloads trust: Python's default roots, minus eMudhra's and Sectigo's legacy AAA root.

In October 2026 the private keys of 8 eMudhra (emSign) intermediate CAs turned out to be guessable. Browsers block
those intermediates, but the system bundles Python reads still trust the roots above them, so anyone holding one of
the keys could pass for GitHub and hand us a frida-server. (The downloads are checked against GitHub's digest too, but
that comes over the same connection.) Each of those intermediates also has a twin cross-signed by Sectigo's AAA root,
so that goes too.
"""

from __future__ import annotations

import functools
import hashlib
import os
import re
import ssl

# SHA-256 of each distrusted root's DER; any other root naming eMudhra is dropped too
DISTRUSTED_ROOTS = {
    "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367",  # emSign Root CA - G1
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",  # emSign ECC Root CA - G3
    "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f",  # emSign Root CA - C1
    "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3",  # emSign ECC Root CA - C3
    # Sectigo's legacy AAA root: it cross-signed twins of the 8 compromised intermediates. Browsers and certifi
    # stopped trusting it for websites in 2025, but macOS's /etc/ssl/cert.pem still does.
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",  # AAA Certificate Services (Comodo)
}
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def distrusted(pem: str) -> bool:
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest() in DISTRUSTED_ROOTS or b"eMudhra" in der


def default_bundle() -> str:
    """Python's default roots as PEM: $SSL_CERT_FILE, else its default file, else every file in its default folder."""
    paths = ssl.get_default_verify_paths()
    cafile = os.environ.get(paths.openssl_cafile_env) or paths.cafile
    if cafile:
        files = [cafile]
    elif paths.capath and os.path.isdir(paths.capath):
        files = [os.path.join(paths.capath, n) for n in sorted(os.listdir(paths.capath))]
    else:
        files = []
    out = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:  # labels in comments can be non-ASCII
                out.append(fh.read())
        except (OSError, ValueError):
            pass
    return "\n".join(out)


@functools.cache
def context() -> ssl.SSLContext:
    pems = list(dict.fromkeys(p for p in PEM_RE.findall(default_bundle()) if not distrusted(p)))  # a folder repeats
    return ssl.create_default_context(cadata="\n".join(pems)) if pems else ssl.create_default_context()
