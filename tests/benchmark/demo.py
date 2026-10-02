#!/usr/bin/env python3
"""Demo-target driver — asserts the shipped demo app is hardened.

The plan requires confirming live-vs-hardened BEFORE trusting the demo as a
benchmark target. `demo/app.py` ships fully hardened (all 6 tutorial bugs
fixed), so it is our PRECISION / true-negative target: the verifier must reject
every probe against it. This driver boots serve.py and asserts exactly that, so
a future regression that re-introduces a demo bug (or weakens a verifier into a
false positive) fails loudly.

Usage:
  python3 tests/benchmark/demo.py        # prints per-probe verdicts, exits non-zero on any FP
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.validate_core import verify_finding_programmatic  # noqa: E402
from tests.benchmark import cases as bench_cases  # noqa: E402


def _wait(host, port, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def check_demo_hardened(host="127.0.0.1", port=8095) -> dict:
    # serve.py now lives under bughunter/, but the `demo` package it launches
    # stays at the repo root — put the root on PYTHONPATH so `demo.app` resolves.
    env = {**os.environ, "APP_HOST": host, "APP_PORT": str(port), "SHUVONSEC_QUIET": "1"}
    env["PYTHONPATH"] = _REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(_REPO, "bughunter", "serve.py")],
        env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    out = {"false_positives": [], "rejected": []}
    try:
        if not _wait(host, port):
            raise RuntimeError("demo app failed to start")
        base = f"http://{host}:{port}"
        for case in bench_cases.precision_cases(base):
            res = verify_finding_programmatic(case["finding"], log_research=False)
            if res.get("status") == "validated_finding":
                out["false_positives"].append(case["name"])
            else:
                out["rejected"].append(case["name"])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    out["hardened"] = not out["false_positives"]
    return out


def main() -> int:
    out = check_demo_hardened()
    print("demo hardened:", out["hardened"])
    print("  rejected (expected):", ", ".join(out["rejected"]))
    if out["false_positives"]:
        print("  FALSE POSITIVES:", ", ".join(out["false_positives"]))
    return 0 if out["hardened"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
