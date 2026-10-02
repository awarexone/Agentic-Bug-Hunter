#!/usr/bin/env python3
"""Benchmark scorer — precision / recall / FP-rate for the verifier gate.

Boots the vulnerable target (recall) and the hardened demo (precision), runs
every case through the real `verify_finding_programmatic` gate, and scores:

  TP  expected-confirm  AND confirmed      FN  expected-confirm  AND not
  FP  expected-reject   AND confirmed      TN  expected-reject   AND not

The headline metrics (the ones the plan targets): recall == 1.0 on live bugs,
and FP == 0 (no unverified finding reaches report).

Usage:
  python3 tests/benchmark/score.py            # run everything, print scoreboard
  python3 tests/benchmark/score.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.validate_core import verify_finding_programmatic  # noqa: E402
from tests.benchmark import cases as bench_cases  # noqa: E402


def _wait_port(host: str, port: int, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def _confirmed(finding: dict) -> tuple[bool, dict]:
    """Run the real gate; 'confirmed' == report-ready (validated_finding)."""
    res = verify_finding_programmatic(finding, log_research=False)
    return res.get("status") == "validated_finding", res


def run_benchmark(host: str = "127.0.0.1",
                  vuln_port: int = 8097, demo_port: int = 8096) -> dict:
    flag = f"FLAG{{{secrets.token_hex(8)}}}"
    env = dict(os.environ, SHUVONSEC_QUIET="1")
    # serve.py now lives under bughunter/, but the `demo` package it launches
    # stays at the repo root — put the root on PYTHONPATH so `demo.app` resolves.
    env["PYTHONPATH"] = _REPO + os.pathsep + env.get("PYTHONPATH", "")

    vuln = subprocess.Popen(
        [sys.executable, os.path.join(_REPO, "tests", "benchmark", "vuln_target.py")],
        env={**env, "BENCH_HOST": host, "BENCH_PORT": str(vuln_port), "BENCH_FLAG": flag},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    demo = subprocess.Popen(
        [sys.executable, os.path.join(_REPO, "bughunter", "serve.py")],
        env={**env, "APP_HOST": host, "APP_PORT": str(demo_port)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    results = {"recall": [], "precision": []}
    try:
        if not _wait_port(host, vuln_port) or not _wait_port(host, demo_port):
            raise RuntimeError("benchmark targets failed to start")

        vbase = f"http://{host}:{vuln_port}"
        dbase = f"http://{host}:{demo_port}"

        for case in bench_cases.recall_cases(vbase, flag):
            ok, res = _confirmed(case["finding"])
            results["recall"].append({
                "name": case["name"], "confirmed": ok,
                "oracle": res.get("verifier", {}).get("oracle"),
                "verdict": "TP" if ok else "FN",
            })
        for case in bench_cases.precision_cases(dbase):
            ok, res = _confirmed(case["finding"])
            results["precision"].append({
                "name": case["name"], "confirmed": ok,
                "oracle": res.get("verifier", {}).get("oracle"),
                "verdict": "FP" if ok else "TN",
            })
    finally:
        for proc in (vuln, demo):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    tp = sum(1 for r in results["recall"] if r["verdict"] == "TP")
    fn = sum(1 for r in results["recall"] if r["verdict"] == "FN")
    fp = sum(1 for r in results["precision"] if r["verdict"] == "FP")
    tn = sum(1 for r in results["precision"] if r["verdict"] == "TN")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "flag": flag,
        "counts": {"TP": tp, "FN": fn, "FP": fp, "TN": tn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fp_rate": round(fp_rate, 4),
        "unverified_reaching_report": fp,
        "results": results,
    }


def _print_board(report: dict) -> None:
    c = report["counts"]
    print("\n=== VERIFIER BENCHMARK ===")
    print(f"  flag: {report['flag']}")
    print("\n  RECALL (vulnerable target — must confirm):")
    for r in report["results"]["recall"]:
        mark = "✓" if r["confirmed"] else "✗ MISS"
        print(f"    [{r['verdict']}] {mark:>6} {r['name']:<20} {r.get('oracle','')}")
    print("\n  PRECISION (hardened demo — must NOT confirm):")
    for r in report["results"]["precision"]:
        mark = "FALSE POSITIVE" if r["confirmed"] else "✓ rejected"
        print(f"    [{r['verdict']}] {mark:>14} {r['name']:<24} {r.get('oracle','')}")
    print(f"\n  counts: TP={c['TP']} FN={c['FN']} FP={c['FP']} TN={c['TN']}")
    print(f"  precision={report['precision']}  recall={report['recall']}  "
          f"fp_rate={report['fp_rate']}")
    print(f"  unverified findings reaching report: {report['unverified_reaching_report']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verifier precision/recall benchmark")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--vuln-port", type=int, default=8097)
    ap.add_argument("--demo-port", type=int, default=8096)
    args = ap.parse_args(argv)

    report = run_benchmark(vuln_port=args.vuln_port, demo_port=args.demo_port)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_board(report)
    # Non-zero if any false positive slipped through or recall is imperfect.
    return 0 if (report["counts"]["FP"] == 0 and report["recall"] == 1.0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
