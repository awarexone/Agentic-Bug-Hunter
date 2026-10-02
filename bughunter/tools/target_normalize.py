#!/usr/bin/env python3
"""
target_normalize.py — canonical target parsing for the recon pipeline.

Everything a user might type ("https://9am.io/", "9am.io", "localhost:3000",
"http://10.0.0.5:8080/path") has to become a bare host that scanners such as
nmap and subfinder accept, plus (optionally) the port a live-probe should hit.

Before this existed, `recon_engine.sh` used the raw argument verbatim, so
`bughunter recon https://9am.io/` ran `nmap https://9am.io/` (→ "0 hosts up")
and wrote output to `recon/https:/9am.io`. The shell script has an identical
normalizer; this module is the Python source of truth for the output directory
name and the target-type decision, and the two are cross-checked in tests.

Public API:
    normalize_target("https://9am.io/")   -> ("9am.io", None)
    normalize_target("localhost:3000")    -> ("localhost", "3000")
    detect_target_type("127.0.0.1")       -> "local"
    is_local_target("10.2.3.4")           -> True
"""

from __future__ import annotations

import ipaddress
import os
import re

__all__ = [
    "normalize_target",
    "detect_target_type",
    "is_local_target",
    "is_safe_host",
    "safe_target_dirname",
]

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def normalize_target(raw: str) -> tuple[str, str | None]:
    """Reduce any URL/host/host:port string to ``(host, port_or_None)``.

    - strips a leading scheme (``https://``), userinfo (``user:pass@``),
      any path/query/fragment, and a trailing dot;
    - lowercases the host;
    - pulls off an explicit ``:port`` (IPv6 in ``[..]`` brackets supported).

    A path-like argument (an existing file) is returned unchanged with no port
    so the caller's "list of hosts" mode still works.
    """
    if raw is None:
        return "", None
    s = raw.strip()
    if not s:
        return "", None

    # A readable file is a host-list, not a URL — leave it alone.
    if os.path.isfile(s):
        return s, None

    # scheme://
    s = _SCHEME_RE.sub("", s)
    # drop path / query / fragment (first of / ? #)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    # userinfo (user:pass@host) — keep only what follows the last '@'
    if "@" in s:
        s = s.rsplit("@", 1)[1]

    port: str | None = None
    host = s

    if s.startswith("["):
        # bracketed IPv6, optionally [::1]:3000
        end = s.find("]")
        if end != -1:
            host = s[1:end]
            rest = s[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                port = rest[1:]
    else:
        # Split a trailing :port only when it's unambiguous — exactly one colon
        # and digits after it. Multiple colons ⇒ bare IPv6, leave intact.
        if s.count(":") == 1:
            head, _, tail = s.partition(":")
            if tail.isdigit():
                host, port = head, tail

    host = host.rstrip(".").lower()
    return host, port


_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_172_PRIVATE_RE = re.compile(r"^172\.(\d{1,3})\.")


def is_local_target(host: str) -> bool:
    """True for loopback / RFC-1918 private / link-local / .local hosts.

    Uses explicit prefixes rather than ``ipaddress.is_private`` so it matches
    the shell's ``_detect_target_type`` byte-for-byte — in particular the
    RFC-5737 documentation range (192.0.2.0/24, used as a public stand-in in
    the tests) stays classified as a normal public IP, not local.
    """
    h = (host or "").lower()
    if h in ("localhost", "ip6-localhost", "::1"):
        return True
    if h.endswith(".localhost") or h.endswith(".local"):
        return True
    if h.startswith(("127.", "10.", "192.168.", "169.254.")):
        return True
    m = _172_PRIVATE_RE.match(h)
    if m and 16 <= int(m.group(1)) <= 31:  # 172.16.0.0 – 172.31.255.255
        return True
    return False


def detect_target_type(target: str) -> str:
    """Return one of 'list', 'local', 'cidr', 'ip', 'domain'.

    Order matters: a CIDR is recognized *before* normalization (which would
    otherwise strip the ``/NN`` as if it were a URL path), and 'cidr' outranks
    'local' so ``10.0.0.0/24`` is a range, not a single local host. ``target``
    may still carry a scheme/port; it is normalized so ``http://10.0.0.5:3000/``
    classifies as 'local', not 'domain'.
    """
    if os.path.isfile(target):
        return "list"

    # CIDR first, on the scheme-stripped raw value (a mask has no scheme/port).
    stripped = _SCHEME_RE.sub("", target.strip()).rstrip("/")
    if _CIDR_RE.match(stripped):
        try:
            net = ipaddress.ip_network(stripped, strict=False)
            return "cidr" if net.num_addresses > 1 else "ip"
        except ValueError:
            pass

    host, _ = normalize_target(target)
    if not host:
        return "domain"
    if is_local_target(host):
        return "local"
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


# A host that is safe to use as a *single* filesystem path component: a
# hostname, IPv4, or IPv6 literal. Deliberately excludes '/', '\', NUL and any
# '..' so a target can never be turned into a path that escapes the recon dir.
_SAFE_HOST_RE = re.compile(r"^[a-z0-9._:\[\]-]+$")


def is_safe_host(host: str) -> bool:
    """True if `host` is a safe single path component (no traversal)."""
    if not host or host in (".", ".."):
        return False
    if any(c in host for c in ("/", "\\", "\x00")):
        return False
    if ".." in host:
        return False
    return _SAFE_HOST_RE.fullmatch(host) is not None


def safe_target_dirname(raw: str) -> str | None:
    """Normalized host safe to use as an output directory name, or None.

    Callers MUST treat None as "reject the target" — never fall back to the raw
    value, which is what let `recon ../../etc/x` and `recon /etc/x` write
    outside the recon/ sandbox (pathlib does not collapse '..' and resets on an
    absolute component).
    """
    host, _ = normalize_target(raw)
    return host if is_safe_host(host) else None


if __name__ == "__main__":  # tiny CLI for shell/debug parity checks
    import sys

    for arg in sys.argv[1:]:
        h, p = normalize_target(arg)
        print(f"{arg}\thost={h}\tport={p or ''}\ttype={detect_target_type(arg)}")
