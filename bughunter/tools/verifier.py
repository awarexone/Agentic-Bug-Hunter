#!/usr/bin/env python3
"""
verifier.py — the report gate: prove a finding, or suppress it.

The Verification Spine, and where this sits:

    /poc  (poc_bundler)   produces PROOF        — the reproducible evidence bundle
    /verify (this)        the GATE              — independently re-derives a finding;
                                                  PROVEN -> reportable, else SUPPRESSED
    /bench (bench.py)     MEASURES the gate     — proves its false-accept rate is ~0
    report path (next)    ENFORCES it           — nothing unproven ever ships

The problem this attacks head-on: an agent (or a noisy scanner) can *claim* a bug
that isn't real. The single most reputation-defining thing a security tool can do
is refuse to report anything it cannot independently prove. This gate enforces
exactly that policy and writes a verification record the report step consumes.

Policy — a finding is only reportable when it is independently PROVEN:

    PROVEN         has an evidence bundle AND re-derivation confirms it
                   (the confirmation marker is present in a fresh response)  -> reportable
    REFUTED        re-derivation ran but the marker is gone / endpoint safe  -> suppress
    UNPROVEN       no bundle, or no confirmable marker at all                -> suppress
    INCONCLUSIVE   couldn't re-derive (unreachable / missing secret /
                   mutating method not re-fired)                             -> hold, don't ship

Only PROVEN is reportable. "Can't confirm" is deliberately NOT "probably fine" —
the burden of proof is on the finding, which is what keeps false accepts near zero.

Reuses only merged code (poc_bundler) so it stands alone on main. It composes with
/replay (ongoing liveness monitoring) but does a different job: replay watches a
known bug over time; verify makes the one-shot decision "may this be reported?".

Design: decide() is a pure policy function, exhaustively unit-tested; only
rederive() (via poc_bundler.capture) touches the network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone

_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../bughunter
_TOOLS = os.path.join(_PKG, "tools")
for _p in (_PKG, _TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import poc_bundler as poc  # noqa: E402  (merged: capture / parse_raw_request / sha256_hex)

# Verdicts
PROVEN = "PROVEN"
REFUTED = "REFUTED"
UNPROVEN = "UNPROVEN"
INCONCLUSIVE = "INCONCLUSIVE"

_REPORTABLE = {PROVEN}
_ICON = {PROVEN: "✅", REFUTED: "❌", UNPROVEN: "🚫", INCONCLUSIVE: "⏸"}

# poc_bundler redacts secrets as "‹redacted:$AUTHORIZATION›" — resolve from env.
_REDACTED_RE = re.compile(r"^‹redacted:\$([A-Z0-9_]+)›$")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Pure policy core
# ---------------------------------------------------------------------------


@dataclass
class Rederivation:
    """The observable result of trying to independently reproduce a finding."""
    attempted: bool                 # did we get to actually re-send?
    reachable: bool = False
    marker_available: bool = False  # do we even have a signal that proves the bug?
    marker_present: bool = False    # was that signal in the fresh response?
    status: int | None = None
    detail: str = ""


@dataclass
class Verdict:
    verdict: str
    reportable: bool
    reason: str


def decide(has_bundle: bool, rd: Rederivation) -> Verdict:
    """Map (do we have proof?) + (what did re-derivation show?) to a reportability
    decision. Pure and total — every path returns a verdict. This is the whole
    trust policy in one readable function."""
    if not has_bundle:
        return Verdict(UNPROVEN, False, "no evidence bundle — nothing to verify")
    if not rd.attempted:
        return Verdict(INCONCLUSIVE, False, rd.detail or "re-derivation not attempted")
    if not rd.reachable:
        return Verdict(INCONCLUSIVE, False, rd.detail or "endpoint unreachable")
    if not rd.marker_available:
        # We reproduced the request but have no signal that would prove the bug.
        # By policy that is UNPROVEN, never a silent pass.
        return Verdict(UNPROVEN, False,
                       "no confirmation marker — cannot independently prove; add --marker")
    if rd.marker_present:
        return Verdict(PROVEN, True, f"marker confirmed in fresh response ({rd.status})")
    return Verdict(REFUTED, False, f"marker absent on re-derivation ({rd.status})")


def resolve_headers(headers: list[tuple[str, str]],
                    env: dict[str, str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Resolve redacted secret placeholders from env; report any that are missing
    so we can hold (INCONCLUSIVE) rather than silently send an unauthenticated
    request and wrongly conclude the bug is gone."""
    resolved, missing = [], []
    for name, value in headers:
        m = _REDACTED_RE.match(value)
        if m:
            var = m.group(1)
            if env.get(var):
                resolved.append((name, env[var]))
            else:
                missing.append(var)
        else:
            resolved.append((name, value))
    return resolved, missing


# ---------------------------------------------------------------------------
# Bundle I/O + marker
# ---------------------------------------------------------------------------


def load_marker(bundle_dir: str, manifest: dict, override: str | None = None) -> str | None:
    """Marker precedence: explicit override → manifest field → marker.txt sidecar
    (the same sidecar /replay writes, so a marker set once is reused everywhere)."""
    if override:
        return override
    if manifest.get("marker"):
        return manifest["marker"]
    sidecar = os.path.join(bundle_dir, "marker.txt")
    if os.path.isfile(sidecar):
        with open(sidecar, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip() or None
    return None


def load_bundle(bundle_dir: str) -> dict:
    """Read a poc-bundle/1 folder. Raises (OSError/ValueError) if it isn't one."""
    with open(os.path.join(bundle_dir, "bundle.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    if manifest.get("schema") != "poc-bundle/1":
        raise ValueError("not a poc-bundle/1 manifest")
    with open(os.path.join(bundle_dir, "request.http"), encoding="utf-8",
              errors="replace") as fh:
        ex = poc.parse_raw_request(fh.read())
    meta = manifest.get("exchange", {})
    if meta.get("url"):      # manifest URL is authoritative (keeps the right scheme)
        ex.url = meta["url"]
    if meta.get("method"):
        ex.method = meta["method"]
    return {"manifest": manifest, "exchange": ex}


# ---------------------------------------------------------------------------
# Re-derivation (network) — thin; reuses the merged SSRF-guarded capture.
# ---------------------------------------------------------------------------


def rederive(bundle_dir: str, marker: str | None, confirm_unsafe: bool,
             env: dict[str, str], timeout: float = 15) -> Rederivation:
    try:
        bundle = load_bundle(bundle_dir)
    except (OSError, ValueError) as e:
        return Rederivation(attempted=False, detail=f"unreadable bundle: {e}")
    ex = bundle["exchange"]

    if ex.method.upper() in poc.UNSAFE_METHODS and not confirm_unsafe:
        # Never silently re-fire a mutating request to "verify" it.
        return Rederivation(attempted=False,
                            detail=f"{ex.method} not re-fired without --confirm-unsafe")

    headers, missing = resolve_headers(ex.request_headers, env)
    if missing:
        return Rederivation(attempted=False,
                            detail="missing secret env var(s): " + ", ".join(sorted(set(missing))))

    try:
        fresh = poc.capture(ex.url, ex.method, headers, ex.request_body or None, timeout)
    except urllib.error.URLError as e:
        return Rederivation(attempted=True, reachable=False,
                            detail=str(getattr(e, "reason", e)))
    except Exception as e:  # one bad bundle must never break a sweep
        return Rederivation(attempted=True, reachable=False,
                            detail=f"{type(e).__name__}: {e}")

    return Rederivation(
        attempted=True, reachable=True,
        marker_available=bool(marker),
        marker_present=bool(marker) and marker in (fresh.response_body or ""),
        status=fresh.response_status,
        detail="",
    )


def verify(bundle_dir: str, marker_override: str | None = None,
           confirm_unsafe: bool = False, env: dict[str, str] | None = None,
           timeout: float = 15) -> dict:
    """Verify one bundle; return a result dict and write verification.json."""
    env = env if env is not None else dict(os.environ)
    has_bundle = os.path.isfile(os.path.join(bundle_dir, "bundle.json"))
    manifest = {}
    if has_bundle:
        try:
            with open(os.path.join(bundle_dir, "bundle.json"), encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (OSError, ValueError):
            has_bundle = False

    marker = load_marker(bundle_dir, manifest, marker_override) if has_bundle else None
    rd = rederive(bundle_dir, marker, confirm_unsafe, env, timeout) if has_bundle \
        else Rederivation(attempted=False, detail="no bundle")
    v = decide(has_bundle, rd)

    record = {
        "schema": "verification/1",
        "verified_at": now_iso(),
        "verdict": v.verdict,
        "reportable": v.reportable,
        "reason": v.reason,
        "method": "marker-rederivation",
        "marker_used": bool(marker),
        "response_status": rd.status,
        "finding": manifest.get("finding", {}) if has_bundle else {},
        "evidence_sha256": manifest.get("exchange", {}).get("response_sha256"),
        "bundle": bundle_dir,
    }
    if has_bundle:
        try:
            with open(os.path.join(bundle_dir, "verification.json"), "w",
                      encoding="utf-8", newline="\n") as fh:
                json.dump(record, fh, indent=2)
        except OSError:
            pass
    return record


def find_bundles(root: str) -> list[str]:
    import glob
    out = []
    for m in glob.glob(os.path.join(root, "**", "bundle.json"), recursive=True):
        try:
            with open(m, encoding="utf-8") as fh:
                if json.load(fh).get("schema") == "poc-bundle/1":
                    out.append(os.path.dirname(m))
        except (OSError, ValueError):
            continue
    return sorted(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print(record: dict) -> None:
    icon = _ICON.get(record["verdict"], "")
    ship = "REPORTABLE" if record["reportable"] else "suppressed"
    print(f"{icon} {record['verdict']}  ({ship})")
    f = record.get("finding") or {}
    if f.get("finding_id") or f.get("target"):
        print(f"    finding: {f.get('finding_id', '—')}  target: {f.get('target', '—')}")
    print(f"    {record['reason']}")


def main(argv=None) -> int:
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description="Verifier gate — prove a finding or suppress it.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="verify one PoC bundle")
    pc.add_argument("bundle_dir")
    pc.add_argument("--marker", help="signal string that proves the bug (persisted for reuse)")
    pc.add_argument("--confirm-unsafe", action="store_true",
                    help="allow re-firing PUT/DELETE/PATCH during verification")
    pc.add_argument("--require-proof", action="store_true",
                    help="exit 1 unless the verdict is reportable (for gating)")
    pc.add_argument("--timeout", type=float, default=15)
    pc.add_argument("--json", dest="as_json", action="store_true")

    ps = sub.add_parser("sweep", help="verify every PoC bundle under a root")
    ps.add_argument("root", nargs="?", default=os.path.join(poc._REPO, "findings"))
    ps.add_argument("--confirm-unsafe", action="store_true")
    ps.add_argument("--require-proof", action="store_true",
                    help="exit 1 if ANY bundle is not reportable")
    ps.add_argument("--timeout", type=float, default=15)
    ps.add_argument("--json", dest="as_json", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "check":
        if args.marker:
            try:
                with open(os.path.join(args.bundle_dir, "marker.txt"), "w",
                          encoding="utf-8", newline="\n") as fh:
                    fh.write(args.marker)
            except OSError:
                pass
        rec = verify(args.bundle_dir, args.marker, args.confirm_unsafe, timeout=args.timeout)
        print(json.dumps(rec, indent=2) if args.as_json else "", end="")
        if not args.as_json:
            _print(rec)
        return 1 if (args.require_proof and not rec["reportable"]) else 0

    if args.cmd == "sweep":
        bundles = find_bundles(args.root)
        if not bundles:
            print(f"[!] no PoC bundles under {args.root}. Create one with /poc.")
            return 0
        records = [verify(d, None, args.confirm_unsafe, timeout=args.timeout) for d in bundles]
        if args.as_json:
            print(json.dumps(records, indent=2))
        else:
            counts: dict[str, int] = {}
            for r in records:
                counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
            summary = "  ".join(f"{_ICON.get(k,'')} {k}:{counts[k]}"
                                for k in (PROVEN, REFUTED, UNPROVEN, INCONCLUSIVE) if k in counts)
            print(f"{len(records)} bundle(s).  {summary}\n")
            for r in records:
                _print(r)
        not_reportable = any(not r["reportable"] for r in records)
        return 1 if (args.require_proof and not_reportable) else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
