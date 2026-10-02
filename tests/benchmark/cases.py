#!/usr/bin/env python3
"""Benchmark case definitions.

Each case is a finding dict (what a hunter would hand the verifier) plus the
expected verdict. Recall cases target the vulnerable app and must confirm;
precision cases target the hardened demo and must NOT confirm.
"""
from __future__ import annotations


def recall_cases(base: str, flag: str) -> list[dict]:
    """Cases against the vulnerable target — every one must be confirmed.

    The sensitive-file / idor / auth cases assert the EXACT per-run flag, so a
    confirm cannot be fabricated (canary oracle).
    """
    return [
        {
            "name": "open-redirect",
            "finding": {
                "vuln_class": "open-redirect",
                "url": f"{base}/go?url=https://evil.example/",
                "param": "url",
                "attacker_host": "evil.example",
                "chain_proven": True,  # chain is a reporting policy; prove the oracle here
                "target": "bench",
            },
        },
        {
            "name": "sensitive-file",
            "finding": {
                "vuln_class": "sensitive-file",
                "url": f"{base}/.env",
                "markers": [flag.replace("{", r"\{").replace("}", r"\}")],
                "target": "bench",
            },
        },
        {
            "name": "sqli-time-based",
            "finding": {
                "vuln_class": "sqli",
                "url": f"{base}/search?q=1",
                "param": "q",
                "sleep_payload": "1 AND SLEEP(2)",
                "baseline_payload": "1",
                "sleep_seconds": 2,
                "trials": 2,
                "target": "bench",
            },
        },
        {
            "name": "sqli-error-based",
            "finding": {
                "vuln_class": "sqli",
                "url": f"{base}/search?q=1",
                "param": "q",
                "error_signature": "SQL syntax error near",
                "breaker_payload": "1'",
                "benign_value": "1",
                "target": "bench",
            },
        },
        {
            "name": "idor",
            "finding": {
                "vuln_class": "idor",
                "victim_object_url": f"{base}/api/account?id=2",
                "attacker_headers": {"X-User": "attacker"},
                "victim_marker": flag,
                "target": "bench",
            },
        },
        {
            "name": "auth-bypass",
            "finding": {
                "vuln_class": "auth-bypass",
                "url": f"{base}/admin",
                "success_marker": flag,
                "target": "bench",
            },
        },
    ]


def precision_cases(base: str) -> list[dict]:
    """Cases against the HARDENED demo — every one must NOT confirm (any confirm
    is a false positive)."""
    return [
        {
            "name": "open-redirect-hardened",
            "finding": {
                "vuln_class": "open-redirect", "url": f"{base}/go?url=https://evil.example/",
                "param": "url", "attacker_host": "evil.example", "chain_proven": True,
                "target": "demo",
            },
        },
        {
            "name": "sensitive-file-hardened",
            "finding": {"vuln_class": "sensitive-file", "url": f"{base}/.env", "target": "demo"},
        },
        {
            "name": "auth-bypass-hardened",
            "finding": {
                "vuln_class": "auth-bypass", "url": f"{base}/admin",
                "success_marker": "Admin Panel", "target": "demo",
            },
        },
        {
            "name": "sqli-hardened",
            "finding": {
                "vuln_class": "sqli", "url": f"{base}/search?q=1", "param": "q",
                "sleep_payload": "1 AND SLEEP(2)", "baseline_payload": "1",
                "sleep_seconds": 2, "trials": 2, "target": "demo",
            },
        },
        {
            "name": "idor-missing-endpoint",
            "finding": {
                "vuln_class": "idor", "victim_object_url": f"{base}/api/account?id=2",
                "attacker_headers": {"X-User": "attacker"}, "victim_marker": "FLAG{nope}",
                "target": "demo",
            },
        },
    ]
