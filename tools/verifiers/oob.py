#!/usr/bin/env python3
"""Blind-bug verifier (SSRF / XXE / RCE / Log4Shell) — OOB callback oracle.

Blind vulnerabilities have no in-band tell, so the only trustworthy oracle is an
out-of-band interaction: the target must reach out to a unique collaborator host
we planted in the payload. This verifier wraps `tools/oob_listener.py`:

  - `payloads_for(domain, vuln_class)` generates marker-embedded payloads.
  - `verify(finding)` correlates recorded interactsh interactions back to those
    markers and confirms ONLY when a matching callback was received.

A finding with no recorded `oob_interactions` is skipped — "we injected a
payload and nothing called back" is never a confirmation.
"""
from __future__ import annotations

from tools.verifiers.base import VerifyResult, confirmed, rejected, skipped
from tools.oob_listener import oob_payloads, correlate

# map incoming finding classes onto the oob_listener taxonomy
_CLASS_MAP = {
    "ssrf": "ssrf", "server-side request forgery": "ssrf",
    "xxe": "xxe", "xml external entity": "xxe",
    "rce": "rce", "command injection": "rce", "os command injection": "rce",
    "log4shell": "log4shell", "log4j": "log4shell",
}


def payloads_for(domain: str, vuln_class: str) -> dict:
    cls = _CLASS_MAP.get(vuln_class.lower(), vuln_class.lower())
    return oob_payloads(domain, [cls])


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    raw_class = str(finding.get("vuln_class") or finding.get("vuln_type") or "ssrf")
    cls = _CLASS_MAP.get(raw_class.lower(), "ssrf")

    payloads = finding.get("oob_payloads")
    interactions = finding.get("oob_interactions")

    if not payloads:
        return skipped(cls, "no oob_payloads recorded (inject payloads_for() first)")
    if not interactions:
        return skipped(cls, "no oob_interactions recorded — no callback means no confirmation")

    hits = correlate(interactions, payloads)
    relevant = [h for h in hits if h.vuln_class == cls] or hits
    if relevant:
        h = relevant[0]
        return confirmed(
            cls,
            "out-of-band callback correlated to the injected marker",
            [],
            f"blind {h.vuln_class} via {h.protocol} — marker {h.marker}",
        )
    return rejected(cls, "no interaction correlated to the planted marker", [])
