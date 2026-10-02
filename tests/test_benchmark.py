"""CI smoke test for the deterministic verifier benchmark.

Targets from the plan:
  * recall == 1.0 on live demo bugs (the canary-injected vulnerable target)
  * 0 unverified findings reach report (no false positive on the hardened demo)

Also asserts the shipped demo app stays hardened so a reintroduced bug or a
verifier that drifts into false positives fails loudly.
"""
import socket

import pytest

from tests.benchmark import demo as bench_demo
from tests.benchmark import score as bench_score


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_verifier_benchmark_recall_and_no_false_positives():
    report = bench_score.run_benchmark(
        vuln_port=_free_port(), demo_port=_free_port(),
    )
    # No unverified finding may reach report.
    assert report["counts"]["FP"] == 0, report["results"]["precision"]
    # Every live bug must be deterministically confirmed.
    assert report["recall"] == 1.0, report["results"]["recall"]
    assert report["precision"] == 1.0


def test_shipped_demo_is_hardened():
    out = bench_demo.check_demo_hardened(port=_free_port())
    assert out["hardened"], f"demo app regressed — false positives: {out['false_positives']}"
    assert out["rejected"], "no precision probes ran"
