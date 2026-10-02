#!/usr/bin/env python3
"""Shared primitives for the deterministic verifier library.

The verifier library is the false-positive killer: a candidate finding is only
a *lead* until an independent, **non-AI** verifier reproduces it against the
live target and a deterministic oracle fires. Verifiers never emit a confidence
score — they return a boolean plus a reproducible request/response trace.

This mirrors XBOW's discovery/validation split: the agent that surfaces a bug is
never the system that confirms it. Everything here is pure plumbing + an
SSRF-safe single-hop fetch; the per-class oracles live in the sibling modules.
"""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Prefer certifi's CA bundle when available; never disable verification.
_SSL_CTX = ssl.create_default_context()
try:  # pragma: no cover - depends on local install
    import certifi

    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX = ssl.create_default_context()

USER_AGENT = "agentic-bug-hunter/verifier"


@dataclass
class HttpExchange:
    """One request/response pair in a verifier's reproducible trace."""

    method: str
    url: str
    status: int | None
    request_headers: dict
    response_headers: dict
    response_snippet: str
    elapsed_ms: float
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VerifyResult:
    """The verdict of a verifier run.

    confirmed=True means a deterministic oracle fired — the bug is real and
    reproducible via `trace`. skipped=True means the verifier could not run
    (missing dependency, missing creds, no OOB callback); it is NOT a pass and
    NOT a fail — the finding stays an unverified lead.
    """

    confirmed: bool
    vuln_class: str
    oracle: str
    trace: list[HttpExchange] = field(default_factory=list)
    evidence: str = ""
    error: str | None = None
    skipped: bool = False

    def to_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "vuln_class": self.vuln_class,
            "oracle": self.oracle,
            "evidence": self.evidence,
            "error": self.error,
            "skipped": self.skipped,
            "trace": [x.to_dict() for x in self.trace],
        }


def confirmed(vuln_class: str, oracle: str, trace: list[HttpExchange], evidence: str) -> VerifyResult:
    return VerifyResult(True, vuln_class, oracle, trace, evidence)


def rejected(vuln_class: str, oracle: str, trace: list[HttpExchange], evidence: str = "") -> VerifyResult:
    return VerifyResult(False, vuln_class, oracle, trace, evidence or "oracle did not fire")


def skipped(vuln_class: str, reason: str) -> VerifyResult:
    return VerifyResult(False, vuln_class, reason, [], "", error=reason, skipped=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow; verifiers inspect raw 3xx + Location themselves."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _opener(context: ssl.SSLContext | None):
    handlers: list = [_NoRedirect]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    data: bytes | None = None,
    timeout: float = 15.0,
    scope_checker=None,
    note: str = "",
    max_body: int = 65536,
) -> tuple[HttpExchange, bytes]:
    """Single-hop fetch (no redirect following) returning a trace entry + body.

    Redirects are never followed, so a target cannot 302 us into cloud metadata
    or an RFC1918 host — the SSRF seam `safe_http` guards. When a scope_checker
    is supplied, an out-of-scope URL is refused before any socket is opened.
    """
    headers = dict(headers or {})
    headers.setdefault("User-Agent", USER_AGENT)

    if scope_checker is not None and not scope_checker.is_in_scope(url):
        ex = HttpExchange(method, url, None, headers, {}, "", 0.0,
                          note or "blocked: out of scope")
        return ex, b""

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = _opener(_SSL_CTX)
    start = time.perf_counter()
    status: int | None
    resp_headers: dict = {}
    body = b""
    try:
        resp = opener.open(req, timeout=timeout)
        status = getattr(resp, "status", None) or resp.getcode()
        resp_headers = dict(resp.headers.items())
        body = resp.read(max_body)
    except urllib.error.HTTPError as exc:
        # HTTPError doubles as a response object (incl. 3xx when not followed).
        status = exc.code
        try:
            resp_headers = dict(exc.headers.items())
        except Exception:  # noqa: BLE001
            resp_headers = {}
        try:
            body = exc.read(max_body)
        except Exception:  # noqa: BLE001
            body = b""
    except Exception as exc:  # noqa: BLE001 - a dead host shouldn't crash the sweep
        elapsed = (time.perf_counter() - start) * 1000
        ex = HttpExchange(method, url, None, headers, {}, "", elapsed,
                          note or f"{type(exc).__name__}: {exc}")
        return ex, b""

    elapsed = (time.perf_counter() - start) * 1000
    snippet = body[:2048].decode("utf-8", "replace")
    ex = HttpExchange(method, url, status, headers, resp_headers, snippet, elapsed, note)
    return ex, body


def set_param(url: str, param: str, value: str) -> str:
    """Return `url` with query `param` set to `value` (preserving the rest)."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def finding_url(finding: dict) -> str:
    """Pull the testable URL out of a finding dict (url or endpoint)."""
    return str(finding.get("url") or finding.get("endpoint") or "").strip()
