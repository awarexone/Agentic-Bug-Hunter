#!/usr/bin/env python3
"""
replay.py — re-verify a past finding against its PoC evidence bundle.

The gap this closes (docs/CAPABILITY-GAPS.md → "No finding-replay/regression to
re-verify past bugs on a target"): once /poc has captured a finding, nothing
re-checks whether it's *still* live. Retests pay again, and programs increasingly
reward regression checks — but today that's a manual re-send-and-eyeball.

This replays the exact request stored in a PoC bundle (produced by poc_bundler)
through the repo's SSRF-guarded opener, compares the fresh response against the
recorded evidence, and returns a verdict:

    STILL_VULNERABLE  the vuln signal is still present
    FIXED             the vuln signal is gone
    CHANGED           response differs from the PoC; a human should look
    UNREACHABLE       the host/endpoint no longer answers
    INDETERMINATE     can't judge (missing marker + no baseline, or missing secret)
    SKIPPED_UNSAFE    a mutating method (PUT/DELETE/PATCH) — needs --confirm-unsafe
    ERROR             the bundle could not be read

Two modes:

  replay.py run <bundle-dir> [--marker "signal"]   replay one finding
  replay.py all [root]                             sweep every bundle (retest day)

How the verdict is decided:
  * A **marker** (a string that proves the bug — the leaked email, the reflected
    payload, an error string) is the reliable signal: present -> STILL_VULNERABLE,
    absent -> FIXED  (confidence: confirmed). Pass it with --marker; it's saved as
    `marker.txt` in the bundle so later sweeps reuse it automatically.
  * Without a marker we fall back to an integrity **heuristic**: byte-identical to
    the recorded response (status + SHA-256) -> STILL_VULNERABLE(unchanged), else
    CHANGED. This is honestly labelled "heuristic" — it never claims FIXED.

Secrets: redacted bundles reference secrets via env vars ($AUTHORIZATION, …),
exactly like the bundle's repro.sh. replay reads those from the environment and
never writes secret values or full response bodies into its own artifacts.

Design: resolve_headers() and decide_verdict() are pure and unit-tested without a
socket; only replay_one() (via poc_bundler.capture) touches the network.
"""
from __future__ import annotations

import argparse
import glob
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
import poc_bundler as poc  # noqa: E402  (reuse capture/parse/hash/constants)

# Verdicts
STILL_VULNERABLE = "STILL_VULNERABLE"
FIXED = "FIXED"
CHANGED = "CHANGED"
UNREACHABLE = "UNREACHABLE"
INDETERMINATE = "INDETERMINATE"
SKIPPED_UNSAFE = "SKIPPED_UNSAFE"
ERROR = "ERROR"

# Matches poc_bundler's redacted placeholder: "‹redacted:$AUTHORIZATION›"
_REDACTED_RE = re.compile(r"^‹redacted:\$([A-Z0-9_]+)›$")

_ICON = {
    STILL_VULNERABLE: "🔴", FIXED: "🟢", CHANGED: "🟡", UNREACHABLE: "⚫",
    INDETERMINATE: "⚪", SKIPPED_UNSAFE: "⏭", ERROR: "✖",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Pure core
# ---------------------------------------------------------------------------


@dataclass
class Observed:
    reachable: bool
    status: int | None = None
    sha256: str | None = None
    body: str = ""
    elapsed_ms: int = 0
    error: str = ""


@dataclass
class Verdict:
    verdict: str
    confidence: str  # "confirmed" (marker) | "heuristic" (hash) | "n/a"
    detail: str


def resolve_headers(headers: list[tuple[str, str]],
                    env: dict[str, str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Turn a recorded (possibly redacted) header list into one we can actually
    send: redacted secret placeholders are resolved from `env`. Returns the
    resolved headers and the list of env vars that were referenced but missing."""
    resolved: list[tuple[str, str]] = []
    missing: list[str] = []
    for name, value in headers:
        m = _REDACTED_RE.match(value)
        if m:
            var = m.group(1)
            if env.get(var):
                resolved.append((name, env[var]))
            else:
                missing.append(var)  # drop it; caller decides how to react
        else:
            resolved.append((name, value))
    return resolved, missing


def decide_verdict(baseline_status: int | None, baseline_sha: str | None,
                   marker: str | None, observed: Observed) -> Verdict:
    """The heart of replay — pure, deterministic, exhaustively tested."""
    if not observed.reachable:
        return Verdict(UNREACHABLE, "confirmed", observed.error or "host did not respond")
    if marker:
        if marker in (observed.body or ""):
            return Verdict(STILL_VULNERABLE, "confirmed",
                           f"marker still present in response ({observed.status})")
        return Verdict(FIXED, "confirmed", f"marker no longer present ({observed.status})")
    # No marker → integrity heuristic. Never claims FIXED from a hash alone.
    if baseline_sha is None:
        return Verdict(INDETERMINATE, "n/a",
                       "no marker and no recorded response baseline — pass --marker")
    if observed.status == baseline_status and observed.sha256 == baseline_sha:
        return Verdict(STILL_VULNERABLE, "heuristic",
                       f"response byte-identical to recorded PoC ({observed.status})")
    return Verdict(CHANGED, "heuristic",
                   f"response differs from PoC (was {baseline_status}, now {observed.status}) — review")


# ---------------------------------------------------------------------------
# Bundle I/O
# ---------------------------------------------------------------------------


def load_bundle(bundle_dir: str) -> dict:
    """Read a poc-bundle/1 folder into the pieces replay needs. Raises
    ValueError/OSError if it isn't a readable bundle."""
    manifest_path = os.path.join(bundle_dir, "bundle.json")
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if manifest.get("schema") != "poc-bundle/1":
        raise ValueError(f"not a poc-bundle/1 manifest: {manifest_path}")
    req_path = os.path.join(bundle_dir, "request.http")
    with open(req_path, encoding="utf-8", errors="replace") as fh:
        exchange = poc.parse_raw_request(fh.read())
    ex_meta = manifest.get("exchange", {})
    # request.http is origin-form and loses the scheme (parse_raw_request would
    # guess https). The manifest records the exact original URL — trust it, so we
    # replay against the right scheme/host and don't false-report UNREACHABLE.
    if ex_meta.get("url"):
        exchange.url = ex_meta["url"]
    if ex_meta.get("method"):
        exchange.method = ex_meta["method"]
    marker = load_marker(bundle_dir, manifest)
    return {
        "dir": bundle_dir,
        "manifest": manifest,
        "exchange": exchange,
        "baseline_status": ex_meta.get("response_status"),
        "baseline_sha": ex_meta.get("response_sha256"),
        "marker": marker,
    }


def load_marker(bundle_dir: str, manifest: dict) -> str | None:
    """Marker lookup order: manifest field (forward-compat) → marker.txt sidecar."""
    if manifest.get("marker"):
        return manifest["marker"]
    sidecar = os.path.join(bundle_dir, "marker.txt")
    if os.path.isfile(sidecar):
        with open(sidecar, encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
        return text or None
    return None


def save_marker(bundle_dir: str, marker: str) -> None:
    with open(os.path.join(bundle_dir, "marker.txt"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(marker)


def find_bundles(root: str) -> list[str]:
    """Every poc-bundle/1 directory under `root`, sorted for stable output."""
    out = []
    for manifest in glob.glob(os.path.join(root, "**", "bundle.json"), recursive=True):
        try:
            with open(manifest, encoding="utf-8") as fh:
                if json.load(fh).get("schema") == "poc-bundle/1":
                    out.append(os.path.dirname(manifest))
        except (OSError, ValueError):
            continue
    return sorted(out)


# ---------------------------------------------------------------------------
# Replay (network) + result assembly
# ---------------------------------------------------------------------------


def replay_one(bundle_dir: str, timeout: float, confirm_unsafe: bool,
               marker_override: str | None, env: dict[str, str] | None = None) -> dict:
    """Replay a single bundle and return a result dict (never raises)."""
    env = env if env is not None else dict(os.environ)
    result = {
        "dir": bundle_dir, "replayed_at": now_iso(),
        "finding": {}, "baseline": {}, "observed": {},
        "verdict": ERROR, "confidence": "n/a", "detail": "",
    }
    try:
        bundle = load_bundle(bundle_dir)
    except (OSError, ValueError) as e:
        result["detail"] = f"could not read bundle: {e}"
        return result

    ex = bundle["exchange"]
    marker = marker_override if marker_override is not None else bundle["marker"]
    result["finding"] = bundle["manifest"].get("finding", {})
    result["baseline"] = {"status": bundle["baseline_status"], "sha256": bundle["baseline_sha"]}

    def finalize(v: Verdict, observed: Observed | None = None):
        result["verdict"], result["confidence"], result["detail"] = v.verdict, v.confidence, v.detail
        if observed is not None:
            result["observed"] = {
                "reachable": observed.reachable, "status": observed.status,
                "sha256": observed.sha256, "elapsed_ms": observed.elapsed_ms,
                "error": observed.error,
            }
        result["marker_used"] = bool(marker)
        return result

    # Guard mutating methods — replaying a DELETE could re-trigger the action.
    if ex.method.upper() in poc.UNSAFE_METHODS and not confirm_unsafe:
        return finalize(Verdict(SKIPPED_UNSAFE, "n/a",
                                f"{ex.method} may mutate state; re-run with --confirm-unsafe"))

    headers, missing = resolve_headers(ex.request_headers, env)
    if missing:
        return finalize(Verdict(INDETERMINATE, "n/a",
                                "missing secret env var(s): " + ", ".join(sorted(set(missing)))
                                + " — export them (see repro.sh) and retry"))

    try:
        fresh = poc.capture(ex.url, ex.method, headers, ex.request_body or None, timeout)
        observed = Observed(
            reachable=True, status=fresh.response_status,
            sha256=poc.sha256_hex(fresh.response_body_bytes) if fresh.response_body_bytes else None,
            body=fresh.response_body, elapsed_ms=fresh.elapsed_ms,
        )
    except urllib.error.URLError as e:
        observed = Observed(reachable=False, error=str(getattr(e, "reason", e)))
    except Exception as e:  # never let one bundle break a sweep
        observed = Observed(reachable=False, error=f"{type(e).__name__}: {e}")

    return finalize(decide_verdict(bundle["baseline_status"], bundle["baseline_sha"],
                                   marker, observed), observed)


# ---------------------------------------------------------------------------
# Rendering (pure)
# ---------------------------------------------------------------------------


def render_report(results: list[dict]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    order = [STILL_VULNERABLE, CHANGED, INDETERMINATE, FIXED, UNREACHABLE,
             SKIPPED_UNSAFE, ERROR]
    summary = "  ".join(f"{_ICON.get(k, '')} {k}:{counts[k]}"
                        for k in order if k in counts)
    lines = [f"# Regression sweep — {now_iso()}", "",
             f"{len(results)} bundle(s).  {summary}", "",
             "| verdict | conf | finding | target | detail |", "|---|---|---|---|---|"]
    rank = {k: i for i, k in enumerate(order)}
    for r in sorted(results, key=lambda x: rank.get(x["verdict"], 99)):
        f = r.get("finding", {})
        lines.append(
            f"| {_ICON.get(r['verdict'], '')} {r['verdict']} | {r['confidence']} | "
            f"{f.get('finding_id') or f.get('title') or os.path.basename(r['dir'])} | "
            f"{f.get('target', '')} | {r['detail']} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_replay_json(bundle_dir: str, result: dict) -> None:
    payload = {"schema": "replay/1", **result}
    with open(os.path.join(bundle_dir, "replay.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2)


def _print_one(result: dict) -> None:
    icon = _ICON.get(result["verdict"], "")
    print(f"{icon} {result['verdict']}  ({result['confidence']})")
    f = result.get("finding", {})
    if f.get("finding_id") or f.get("target"):
        print(f"    finding: {f.get('finding_id', '—')}  target: {f.get('target', '—')}")
    print(f"    {result['detail']}")
    obs = result.get("observed") or {}
    if obs:
        print(f"    observed: status={obs.get('status')} "
              f"reachable={obs.get('reachable')} {obs.get('elapsed_ms', 0)}ms")


def main(argv=None) -> int:
    # Verdict icons are non-ASCII; make sure a non-UTF-8 console (e.g. Windows
    # cp1252) degrades gracefully instead of crashing on print.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        description="Finding replay / regression — re-verify a PoC bundle.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="replay one PoC bundle")
    pr.add_argument("bundle_dir")
    pr.add_argument("--marker", help="signal string that proves the bug (saved for future sweeps)")
    pr.add_argument("--timeout", type=float, default=15)
    pr.add_argument("--confirm-unsafe", action="store_true",
                    help="allow replaying PUT/DELETE/PATCH (may mutate state)")
    pr.add_argument("--json", dest="as_json", action="store_true")
    pr.add_argument("--fail-if-vulnerable", action="store_true",
                    help="exit 3 if the verdict is STILL_VULNERABLE (for CI/monitoring)")

    pa = sub.add_parser("all", help="sweep every PoC bundle under a root")
    pa.add_argument("root", nargs="?", default=os.path.join(poc._REPO, "findings"),
                    help="root to search (default: findings/)")
    pa.add_argument("--timeout", type=float, default=15)
    pa.add_argument("--confirm-unsafe", action="store_true")
    pa.add_argument("--json", dest="as_json", action="store_true")
    pa.add_argument("--fail-if-vulnerable", action="store_true",
                    help="exit 3 if any verdict is STILL_VULNERABLE")

    args = ap.parse_args(argv)

    if args.cmd == "run":
        if args.marker:
            try:
                save_marker(args.bundle_dir, args.marker)
            except OSError:
                pass
        result = replay_one(args.bundle_dir, args.timeout, args.confirm_unsafe, args.marker)
        try:
            _write_replay_json(args.bundle_dir, result)
        except OSError:
            pass
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            _print_one(result)
        return 3 if (args.fail_if_vulnerable and result["verdict"] == STILL_VULNERABLE) else 0

    if args.cmd == "all":
        bundles = find_bundles(args.root)
        if not bundles:
            print(f"[!] no PoC bundles found under {args.root}. Create one with /poc.")
            return 0
        results = []
        for d in bundles:
            r = replay_one(d, args.timeout, args.confirm_unsafe, None)
            try:
                _write_replay_json(d, r)
            except OSError:
                pass
            results.append(r)
        report = render_report(results)
        report_path = os.path.join(args.root, "regression-report.md")
        try:
            with open(report_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(report)
            with open(os.path.join(args.root, "regression.json"), "w",
                      encoding="utf-8", newline="\n") as fh:
                json.dump(results, fh, indent=2)
        except OSError:
            report_path = None
        if args.as_json:
            print(json.dumps(results, indent=2))
        else:
            print(report)
            if report_path:
                print(f"[+] report: {report_path}")
        vulnerable = any(r["verdict"] == STILL_VULNERABLE for r in results)
        return 3 if (args.fail_if_vulnerable and vulnerable) else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
