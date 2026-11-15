"""Redirect-safe wrapper around urllib.request.urlopen. Plain urlopen
follows 3xx redirects with no check on the destination — a hostile target
can 302 a scanner into cloud metadata (169.254.169.254), localhost, or an
RFC1918 address, turning the tool into an SSRF proxy against the
operator's own network. See SECURITY-REVIEW-2026-08-22.md finding #8."""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal"}

# Networks that are actually dangerous as a redirect destination: the
# operator's own loopback / private LAN / link-local (incl. cloud
# metadata) addresses. Deliberately NOT ipaddress.is_private /
# is_reserved: those properties are far broader than this set — they also
# cover CGNAT 100.64/10, the 198.18/15 benchmarking range, and the
# TEST-NET documentation ranges — so any hostname resolving into one of
# those ranges was wrongly blocked. In environments whose resolver maps
# public names into 198.18/15 (e.g. sandboxed / egress-proxy resolvers)
# that meant EVERY redirect was refused and the scope guard never ran.
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),       # "this" network
    ipaddress.ip_network("10.0.0.0/8"),      # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),   # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved (class E), unroutable
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("::/128"),          # IPv6 unspecified
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),        # IPv6 multicast
)


def _is_blocked_redirect_target(hostname: str) -> bool:
    if not hostname:
        return True
    if hostname.lower() in ("localhost",) or hostname.lower() in _METADATA_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(hostname))
        except (socket.gaierror, ValueError):
            return False  # can't resolve — let the real request fail naturally
    # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1) so it is judged as its IPv4.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _one_hop(req: urllib.request.Request, timeout: float, **kwargs):
    # OpenerDirector.open() (used below) does NOT accept a context=
    # kwarg — only the module-level urllib.request.urlopen() does. Callers
    # that pass context=<ssl.SSLContext>, expecting the same behavior as
    # passing it straight to urlopen(), would otherwise hit a TypeError on
    # every single call. Bind the SSL context to the opener itself via an
    # HTTPSHandler instead of forwarding it as a kwarg to .open().
    context = kwargs.pop("context", None)
    handlers = [_NoRedirectHandler]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        return opener.open(req, timeout=timeout, **kwargs)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            # _NoRedirectHandler.redirect_request returning None makes every
            # installed redirect handler decline, so urllib's chain falls
            # through to HTTPDefaultErrorHandler, which raises HTTPError
            # instead of returning the response. HTTPError doubles as a
            # response object (.status/.code, .headers) — hand it back to
            # the caller's redirect-driving loop instead of letting it
            # propagate as an error.
            return e
        raise


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never auto-follow; safe_urlopen drives redirects itself


def safe_urlopen(req: urllib.request.Request, timeout: float = 10, max_redirects: int = 5,
                 scope_checker=None, **kwargs):
    """Like urllib.request.urlopen(req), but validates every redirect hop's
    hostname before following it, rejecting private/loopback/link-local/
    metadata addresses.

    If a scope_checker is supplied, each redirect hop's URL must also be in
    program scope — a target that 302s to an out-of-scope (but public) host
    would otherwise cause out-of-scope traffic. When scope_checker is None
    (the default) behavior is unchanged: SSRF guard only.

    Extra keyword arguments are forwarded to the underlying opener on
    every hop, so callers that pass a custom SSL context to urlopen()
    keep that behavior unchanged. context=<ssl.SSLContext> is handled
    specially by _one_hop: OpenerDirector.open() doesn't accept a
    context= kwarg the way module-level urlopen() does, so it's bound to
    an HTTPSHandler on the opener instead of being forwarded as-is."""
    current = req
    for _ in range(max_redirects + 1):
        resp = _one_hop(current, timeout, **kwargs)
        if resp.status not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        next_url = urljoin(current.full_url, location)
        hostname = urlparse(next_url).hostname
        if _is_blocked_redirect_target(hostname):
            raise urllib.error.URLError(
                f"blocked redirect to disallowed host (SSRF guard): {hostname!r}"
            )
        if scope_checker is not None and not scope_checker.is_in_scope(next_url):
            raise urllib.error.URLError(
                f"blocked redirect to out-of-scope host (scope guard): {hostname!r}"
            )
        preserve_body = resp.status in (307, 308)
        current = urllib.request.Request(
            next_url,
            data=current.data if preserve_body else None,
            headers=dict(current.header_items()),
            method=current.get_method() if preserve_body else None,
        )
    raise urllib.error.URLError(f"too many redirects (>{max_redirects})")
