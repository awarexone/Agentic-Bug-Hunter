#!/usr/bin/env python3
"""CLI for the deterministic verifier library.

    python3 -m tools.verifiers --finding finding.json
    echo '{"vuln_class":"open-redirect","url":"https://t/go?url=x","param":"url"}' \
        | python3 -m tools.verifiers --stdin

Exit codes: 0 confirmed, 1 rejected, 2 skipped/unverifiable, 3 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.verifiers import verify_finding  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Deterministic exploit verifier")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--finding", help="path to a finding JSON file")
    src.add_argument("--stdin", action="store_true", help="read finding JSON from stdin")
    ap.add_argument("--json", action="store_true", help="emit the full VerifyResult as JSON")
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.stdin else open(args.finding).read()
        finding = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"[-] bad finding input: {exc}", file=sys.stderr)
        return 3

    result = verify_finding(finding)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        tag = "CONFIRMED" if result.confirmed else ("SKIPPED" if result.skipped else "REJECTED")
        print(f"[{tag}] {result.vuln_class}: {result.oracle}")
        if result.evidence:
            print(f"    evidence: {result.evidence}")

    if result.confirmed:
        return 0
    return 2 if result.skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
