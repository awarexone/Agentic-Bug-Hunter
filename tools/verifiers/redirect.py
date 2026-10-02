#!/usr/bin/env python3
"""Open-redirect verifier — deterministic Location-header oracle.

Confirmed only when the target emits a 3xx whose Location resolves to an
attacker-controlled external host. A reflected `?next=` value that never turns
into a redirect is NOT confirmed (that is the single most common open-redirect
false positive).
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from tools.verifiers.base import (
    VerifyResult, confirmed, rejected, skipped, fetch, set_param, finding_url,
)

VULN_CLASS = "open-redirect"
_ATTACKER_HOST = "evil.example"


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    url = finding_url(finding)
    param = finding.get("param")
    if not url:
        return skipped(VULN_CLASS, "no url in finding")

    attacker = str(finding.get("attacker_host") or _ATTACKER_HOST)
    payload = str(finding.get("payload") or f"https://{attacker}/")
    test_url = set_param(url, param, payload) if param else url

    ex, _ = fetch(test_url, scope_checker=scope_checker, note="open-redirect probe")
    trace = [ex]

    if ex.status not in (301, 302, 303, 307, 308):
        return rejected(VULN_CLASS, "no 3xx redirect returned", trace,
                        f"status {ex.status} is not a redirect")

    location = ex.response_headers.get("Location") or ex.response_headers.get("location")
    if not location:
        return rejected(VULN_CLASS, "3xx without Location header", trace)

    dest = urljoin(test_url, location)
    dest_host = (urlparse(dest).hostname or "").lower()
    if dest_host == attacker.lower() or dest_host.endswith("." + attacker.lower()):
        return confirmed(
            VULN_CLASS,
            "3xx Location resolves to attacker-controlled external host",
            trace,
            f"{ex.status} -> Location: {location} (host={dest_host})",
        )
    return rejected(VULN_CLASS, "redirect did not honor attacker host", trace,
                    f"redirected to {dest_host!r}, not {attacker!r}")
