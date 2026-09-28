#!/usr/bin/env python3
"""
report_gate.py — the enforcement point: no report without a PROVEN verification.

Part 3 of the Verification Spine, the piece that makes the guarantee real:

    /poc      produces PROOF        — the reproducible evidence bundle
    /verify   the GATE              — decides reportability, writes verification.json
    /bench    MEASURES the gate     — proves its false-accept rate is ~0
    report_gate (this)  ENFORCES it — a finding may only be reported if a PROVEN
                                      verification record exists; otherwise blocked

Deliberately decoupled: this reads only the `verification/1` record that /verify
writes — it does not import the verifier. Producing a decision and enforcing it
are separate concerns, and the split keeps this independently mergeable.

The one rule that matters: FAIL CLOSED. No verification record, an unreadable
one, or a non-reportable verdict → BLOCKED. Absence of proof is denial, never
permission. That is what stops an unproven (possibly hallucinated) finding from
ever reaching a triager.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from dataclasses import dataclass

_VERIFICATION_SCHEMA = "verification/1"


@dataclass
class Decision:
    allowed: bool
    reason: str
    verdict: str | None = None


def gate(record: dict | None, expected_evidence_sha: str | None = None) -> Decision:
    """Pure, fail-closed policy: only a well-formed, reportable verification/1
    record allows a report. Everything else is BLOCKED.

    When `expected_evidence_sha` is supplied (the response SHA-256 recorded in the
    bundle's manifest), the record's `evidence_sha256` must match it. This binds
    the verdict to *this* bundle's evidence, so a verification.json copied from a
    different finding — or left over from an earlier, different response — can't
    authorize a report. It is not a signature (anyone who can write both files can
    still forge both); it detects stale/mismatched records, which is the practical
    integrity gain given both files live in the same local bundle dir."""
    if record is None:
        return Decision(False, "no verification record — run /verify before reporting (fail-closed)")
    if record.get("schema") != _VERIFICATION_SCHEMA:
        return Decision(False, f"unrecognized verification schema {record.get('schema')!r}")
    verdict = record.get("verdict")
    if expected_evidence_sha is not None and record.get("evidence_sha256") != expected_evidence_sha:
        return Decision(False, "verification does not match this bundle's evidence "
                        "(stale or mismatched record)", verdict)
    if record.get("reportable") is True and verdict == "PROVEN":
        return Decision(True, "PROVEN — verification bound to this bundle's evidence", verdict)
    return Decision(False, f"not reportable (verdict: {verdict})", verdict)


def read_record(bundle_dir: str) -> dict | None:
    """Load a bundle's verification.json, or None if absent/unreadable. Unreadable
    is treated as absent — which fail-closes to BLOCKED, the safe direction."""
    path = os.path.join(bundle_dir, "verification.json")
    try:
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
        return rec if isinstance(rec, dict) else None
    except (OSError, ValueError):
        return None


def _bundle_evidence_sha(bundle_dir: str) -> str | None:
    """The response SHA-256 recorded in the bundle's manifest, used to bind a
    verification record to this specific bundle. None if unavailable."""
    try:
        with open(os.path.join(bundle_dir, "bundle.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        return (manifest.get("exchange") or {}).get("response_sha256")
    except (OSError, ValueError, AttributeError):
        return None


def check_bundle(bundle_dir: str) -> Decision:
    return gate(read_record(bundle_dir), _bundle_evidence_sha(bundle_dir))


def find_bundles(root: str) -> list[str]:
    out = []
    for m in glob.glob(os.path.join(root, "**", "bundle.json"), recursive=True):
        try:
            with open(m, encoding="utf-8") as fh:
                if json.load(fh).get("schema") == "poc-bundle/1":
                    out.append(os.path.dirname(m))
        except (OSError, ValueError):
            continue
    return sorted(out)


def main(argv=None) -> int:
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        description="Report gate — block any report without a PROVEN verification.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="is this finding allowed to be reported?")
    pc.add_argument("bundle_dir")
    pc.add_argument("--json", dest="as_json", action="store_true")

    ps = sub.add_parser("sweep", help="check every bundle under a root")
    ps.add_argument("root")
    ps.add_argument("--json", dest="as_json", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "check":
        d = check_bundle(args.bundle_dir)
        if args.as_json:
            print(json.dumps({"allowed": d.allowed, "verdict": d.verdict, "reason": d.reason}, indent=2))
        else:
            print(f"{'✅ ALLOWED' if d.allowed else '⛔ BLOCKED'} — {d.reason}")
        return 0 if d.allowed else 1

    if args.cmd == "sweep":
        bundles = find_bundles(args.root)
        if not bundles:
            print(f"[!] no PoC bundles under {args.root}.")
            return 0
        blocked = 0
        for b in bundles:
            d = check_bundle(b)
            if not d.allowed:
                blocked += 1
            print(f"{'✅' if d.allowed else '⛔'} {os.path.relpath(b, args.root)} — {d.reason}")
        print(f"\n{len(bundles)} finding(s): {len(bundles)-blocked} reportable, {blocked} blocked")
        return 1 if blocked else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
