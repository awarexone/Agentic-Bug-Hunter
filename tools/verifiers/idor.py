#!/usr/bin/env python3
"""IDOR / BOLA verifier — two-identity cross-tenant differential oracle.

The #1 reason "confirmed IDOR" comes back N/A is the tester only read their own
data. This verifier refuses to confirm without TWO identities and proves the
cross-tenant read deterministically:

  - attacker identity A fetches the victim's object and the victim's unique
    marker (e.g. the victim's email/id) IS returned, AND
  - an unauthenticated request for the same object is denied (control), so a
    plain-public resource cannot masquerade as an access-control break.

Without two identities + a victim marker we cannot prove cross-tenant access, so
we skip rather than emit a false positive.
"""
from __future__ import annotations

from tools.verifiers.base import (
    VerifyResult, HttpExchange, confirmed, rejected, skipped, fetch, finding_url,
)

VULN_CLASS = "idor"


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    # The URL is the victim's object as requested BY the attacker.
    url = str(finding.get("victim_object_url") or finding_url(finding)).strip()
    attacker_headers = finding.get("attacker_headers") or finding.get("identity_a")
    victim_marker = finding.get("victim_marker")

    if not url:
        return skipped(VULN_CLASS, "no victim_object_url in finding")
    if not attacker_headers:
        return skipped(VULN_CLASS, "no attacker identity (attacker_headers) provided")
    if not victim_marker:
        return skipped(VULN_CLASS, "no victim_marker to prove cross-tenant read")

    trace: list[HttpExchange] = []

    # 1) Attacker A requests the victim's object.
    ex_a, body_a = fetch(url, headers=attacker_headers, scope_checker=scope_checker,
                         note="attacker reads victim object")
    trace.append(ex_a)
    text_a = body_a.decode("utf-8", "replace")

    if ex_a.status != 200 or str(victim_marker) not in text_a:
        return rejected(
            VULN_CLASS,
            "attacker could not read victim's object",
            trace,
            f"status {ex_a.status}, victim marker present={str(victim_marker) in text_a}",
        )

    # 2) Control: anonymous request for the same object must be denied.
    ex_anon, body_anon = fetch(url, scope_checker=scope_checker, note="anon control")
    trace.append(ex_anon)
    anon_text = body_anon.decode("utf-8", "replace")
    if ex_anon.status == 200 and str(victim_marker) in anon_text:
        return rejected(
            VULN_CLASS,
            "object is public (anonymous read also succeeds) — not an access-control break",
            trace,
        )

    return confirmed(
        VULN_CLASS,
        "attacker identity read another tenant's object; anonymous access denied",
        trace,
        f"victim marker {victim_marker!r} returned to attacker (anon status {ex_anon.status})",
    )
