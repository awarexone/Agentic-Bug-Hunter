#!/usr/bin/env python3
"""Sensitive-file / info-disclosure verifier — content-pattern oracle.

Confirmed only when the URL returns 200 AND the body actually contains
sensitive content (secret-looking key/value pairs, cloud creds, DB URIs). A 200
that returns an HTML app shell or a generic page is NOT confirmed — a reachable
path alone is not a disclosure.
"""
from __future__ import annotations

import re

from tools.verifiers.base import (
    VerifyResult, confirmed, rejected, skipped, fetch, finding_url,
)

VULN_CLASS = "sensitive-file"

# Default content oracles: each is a high-signal secret pattern. A finding may
# override via finding["markers"] = [regex, ...] for a precise, tailored oracle.
_DEFAULT_MARKERS = [
    r"AKIA[0-9A-Z]{16}",                                 # AWS access key id
    # env-style secret assignments (uppercase keys like AWS_SECRET_ACCESS_KEY=…)
    r"(?i)(aws_secret_access_key|aws_access_key_id|db_password|jwt_signing_key|"
    r"secret_key|signing_key|private_key|client_secret|api[_-]?key|password|passwd|token)"
    r"\s*[:=]\s*\S{4,}",
    r"(?i)(postgres|mysql|mongodb(\+srv)?|redis)://[^\s\"']+:[^\s\"']+@",  # DB URI w/ creds
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # JWT
]


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    url = finding_url(finding)
    if not url:
        return skipped(VULN_CLASS, "no url in finding")

    markers = finding.get("markers") or _DEFAULT_MARKERS
    ex, body = fetch(url, scope_checker=scope_checker, note="sensitive-file probe")
    trace = [ex]

    if ex.status != 200:
        return rejected(VULN_CLASS, "non-200 response", trace, f"status {ex.status}")

    text = body.decode("utf-8", "replace")
    for pat in markers:
        m = re.search(pat, text)
        if m:
            hit = m.group(0)
            masked = hit[:6] + "…" if len(hit) > 8 else hit
            return confirmed(
                VULN_CLASS,
                "200 response body matched a secret-content pattern",
                trace,
                f"matched {pat!r} (sample: {masked!r})",
            )
    return rejected(VULN_CLASS, "200 but no sensitive content pattern matched", trace)
