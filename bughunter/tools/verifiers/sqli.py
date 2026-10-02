#!/usr/bin/env python3
"""SQL-injection verifier — error-signature + time-based oracles.

Two deterministic oracles, in order of reliability:

1. error-based: if the finding supplies an `error_signature`, inject a syntax
   breaker and confirm the signature appears (and is absent on a benign value).
2. time-based: inject a SLEEP/benchmark payload and a baseline payload N times
   each; confirm ONLY when the timing distributions are cleanly separated
   (min(sleep) > max(baseline) AND median delta >= sleep_seconds threshold).

The XBOW teardown flagged naive timing as the one real false-positive source
(apps that naturally sleep / jittery latency). Requiring fully separated
distributions over repeated trials is what makes this an oracle rather than a
guess.
"""
from __future__ import annotations

from statistics import median

from tools.verifiers.base import (
    VerifyResult, HttpExchange, confirmed, rejected, skipped, fetch, set_param, finding_url,
)

VULN_CLASS = "sqli"


def _median_ms(samples: list[float]) -> float:
    return median(samples) if samples else 0.0


def verify(finding: dict, scope_checker=None) -> VerifyResult:
    url = finding_url(finding)
    param = finding.get("param")
    if not url or not param:
        return skipped(VULN_CLASS, "sqli verifier needs both url and param")

    trace: list[HttpExchange] = []

    # ---- Oracle 1: error-based (deterministic, preferred) --------------------
    sig = finding.get("error_signature")
    if sig:
        breaker = str(finding.get("breaker_payload") or "'")
        benign = str(finding.get("benign_value") or "1")
        ex_b, body_b = fetch(set_param(url, param, breaker), scope_checker=scope_checker,
                             note="sqli error breaker")
        ex_n, body_n = fetch(set_param(url, param, benign), scope_checker=scope_checker,
                             note="sqli benign baseline")
        trace += [ex_b, ex_n]
        in_breaker = str(sig) in body_b.decode("utf-8", "replace")
        in_benign = str(sig) in body_n.decode("utf-8", "replace")
        if in_breaker and not in_benign:
            return confirmed(VULN_CLASS,
                             "DB error signature appears only on the injection payload",
                             trace, f"signature {sig!r} surfaced by {breaker!r}")
        # fall through to timing if the error oracle didn't fire

    # ---- Oracle 2: time-based with separated distributions -------------------
    sleep_payload = finding.get("sleep_payload")
    if not sleep_payload:
        if sig:
            return rejected(VULN_CLASS, "error signature not reflected; no timing payload", trace)
        return skipped(VULN_CLASS, "no error_signature or sleep_payload to test")

    baseline_payload = str(finding.get("baseline_payload") or "1")
    sleep_seconds = float(finding.get("sleep_seconds") or 5)
    trials = int(finding.get("trials") or 3)

    sleep_ms: list[float] = []
    base_ms: list[float] = []
    for _ in range(trials):
        ex_s, _ = fetch(set_param(url, param, str(sleep_payload)), scope_checker=scope_checker,
                        timeout=sleep_seconds * 3 + 10, note="sqli sleep trial")
        ex_b, _ = fetch(set_param(url, param, baseline_payload), scope_checker=scope_checker,
                        note="sqli baseline trial")
        trace += [ex_s, ex_b]
        if ex_s.status is not None:
            sleep_ms.append(ex_s.elapsed_ms)
        if ex_b.status is not None:
            base_ms.append(ex_b.elapsed_ms)

    if len(sleep_ms) < trials or len(base_ms) < trials:
        return rejected(VULN_CLASS, "requests failed during timing trials", trace)

    delta = _median_ms(sleep_ms) - _median_ms(base_ms)
    separated = min(sleep_ms) > max(base_ms)
    threshold = sleep_seconds * 1000 * 0.6  # 60% of the injected delay, conservatively
    if separated and delta >= threshold:
        return confirmed(
            VULN_CLASS,
            "time-based: sleep/baseline distributions fully separated across trials",
            trace,
            f"median delta {delta:.0f}ms >= {threshold:.0f}ms, min(sleep)>max(baseline)",
        )
    return rejected(
        VULN_CLASS,
        "timing not separable from latency noise",
        trace,
        f"median delta {delta:.0f}ms, separated={separated}",
    )
