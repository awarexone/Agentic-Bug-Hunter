#!/usr/bin/env python3
"""Auth-bypass / forced-browse verifier — anon-vs-protected differential oracle.

Confirmed only when an UNauthenticated request to a privileged path returns 200
AND a caller-supplied `success_marker` (content that must only appear to an
authorized user) is present in the body. Without a success_marker we cannot
deterministically distinguish "bypass" from "public page", so we skip rather
than risk a false positive — a 200 alone is never a confirmation.
"""
from __future__ import annotations

from tools.verifiers.base import (
    VerifyResult, confirmed, rejected, skipped, fetch, finding_url,
)

VULN_CLASS = "auth-bypass"
_LOGIN_SIGNALS = ("login", "sign in", "sign-in", "password", "unauthorized",
                  "forbidden", "please log in")


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    url = finding_url(finding)
    if not url:
        return skipped(VULN_CLASS, "no url in finding")

    marker = finding.get("success_marker")
    if not marker:
        return skipped(
            VULN_CLASS,
            "no success_marker provided — cannot deterministically confirm a bypass",
        )

    # Deliberately send NO auth material: this is the unauthenticated attacker.
    ex, body = fetch(url, scope_checker=scope_checker, note="anon forced-browse")
    trace = [ex]

    if ex.status != 200:
        return rejected(VULN_CLASS, "privileged path not reachable anonymously",
                        trace, f"status {ex.status}")

    text = body.decode("utf-8", "replace")
    low = text.lower()
    if str(marker) not in text:
        return rejected(VULN_CLASS, "200 but privileged marker absent", trace,
                        f"marker {marker!r} not in anonymous response")
    if any(sig in low for sig in _LOGIN_SIGNALS):
        return rejected(VULN_CLASS, "response looks like a login/denied page", trace)

    return confirmed(
        VULN_CLASS,
        "anonymous request returned 200 containing an authorized-only marker",
        trace,
        f"privileged marker {marker!r} served without authentication",
    )
