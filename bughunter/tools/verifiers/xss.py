#!/usr/bin/env python3
"""XSS verifier — real-browser JS-execution oracle.

Reflection is not execution. CSP, framework auto-escaping, or a sink that never
reaches `eval`/`innerHTML` all neuter a reflected payload. This verifier drives
`tools/dom_xss_harness.py`, which loads a uniquely-tagged payload in headless
Chromium and only reports CONFIRMED when the canary actually fires through an
execution channel (dialog / hooked sink / console).

If Playwright/Chromium is not installed the verifier skips (not a fail) so the
pure test-suite stays browser-free.
"""
from __future__ import annotations

from tools.verifiers.base import VerifyResult, confirmed, rejected, skipped, finding_url
from tools import dom_xss_harness

VULN_CLASS = "xss"


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    url = finding_url(finding)
    if not url:
        return skipped(VULN_CLASS, "no url in finding")

    params = finding.get("params") or ([finding["param"]] if finding.get("param") else [])
    timeout_ms = int(finding.get("timeout_ms") or 10000)
    shot = finding.get("screenshot")

    try:
        results = dom_xss_harness.run(url, params, timeout_ms, shot)
    except FileNotFoundError:
        return skipped(VULN_CLASS, "playwright/chromium not installed")
    except ValueError as exc:
        return skipped(VULN_CLASS, f"nothing to test: {exc}")
    except Exception as exc:  # noqa: BLE001
        return skipped(VULN_CLASS, f"browser run failed: {type(exc).__name__}: {exc}")

    fired = [r for r in results if r.severity == dom_xss_harness.CONFIRMED]
    if fired:
        r = fired[0]
        return confirmed(
            VULN_CLASS,
            "payload canary executed in a real headless browser",
            [],
            f"{r.evidence} on param {r.param} via {r.vector}",
        )
    reflected = [r for r in results if r.severity == dom_xss_harness.POSSIBLE]
    note = "reflected but did not execute (likely CSP/escaping)" if reflected else "no reflection/execution"
    return rejected(VULN_CLASS, note, [])
