"""Benchmark harness for the deterministic verifier library.

Measures precision / recall / false-positive-rate of the verifier gate against
two ground-truth targets:

  * tests/benchmark/vuln_target.py — an intentionally-vulnerable app with a
    per-run FLAG{random} canary (XBOW-style): a 'confirm' only counts when the
    exploit exfiltrates the exact planted flag, so fabricated solves are
    impossible.
  * demo/app.py (hardened) — the precision / true-negative target: every bug is
    fixed, so any 'confirm' here is a false positive.
"""
