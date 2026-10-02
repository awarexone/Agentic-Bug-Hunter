#!/usr/bin/env python3
"""Swarm coordinator — parallel ephemeral hunters over the lead board.

XBOW's orchestration pattern: one persistent coordinator decomposes an
assessment into many narrow tasks and dispatches short-lived, single-objective
agents in parallel waves; each is retired after its mission so context/bias
doesn't compound; results are merged into a shared, adjudicated worldview.

Here the shared worldview is the lead board (`tools/lead_board.py`). The
coordinator reads untouched leads, groups them by `hunt-*` skill, and fans out a
bounded pool of workers. Each worker:

  1. claims one lead (touch -> investigating),
  2. builds a finding from the lead and runs the DETERMINISTIC verifier gate
     (`tools/validate_core.verify_finding_programmatic`) in its own isolated
     session dir + scope checker,
  3. writes the verdict back to the board (verified / killed / parked), then is
     retired.

Discovery and verification stay separate: a worker can only mark a lead VERIFIED
when a non-AI oracle fired. Everything else becomes killed (rejected) or parked
(needs authenticated input a bare recon lead can't supply).

Usage:
  tools/swarm.py <target> [--recon-dir DIR] [--workers N] [--max-leads M]
                 [--skills hunt-ssrf,hunt-open-redirect] [--scope-domain d ...]
                 [--ingest] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, parse_qs

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools import lead_board  # noqa: E402
from tools.verifiers import normalize_class  # noqa: E402
from tools.validate_core import verify_finding_programmatic  # noqa: E402

FINDINGS_DIR = os.path.join(_REPO, "findings")


def _scope_checker(domains: list[str]):
    if not domains:
        return None
    try:
        from tools.scope_checker import ScopeChecker

        return ScopeChecker(domains)
    except Exception:  # noqa: BLE001
        return None


def _first_param(url: str) -> str | None:
    try:
        q = parse_qs(urlparse(url).query)
        return next(iter(q), None)
    except Exception:  # noqa: BLE001
        return None


def finding_from_lead(lead: dict, target: str) -> dict:
    """Translate a recon lead into a finding dict the verifier understands."""
    skill = str(lead.get("skill", ""))
    canon = normalize_class(skill.replace("hunt-", "").replace("-", " "))
    evidence = str(lead.get("evidence", ""))
    url = evidence if evidence.lower().startswith(("http://", "https://")) else ""
    finding = {
        "vuln_class": canon or skill.replace("hunt-", ""),
        "url": url,
        "target": target,
        "lead_id": lead.get("id"),
    }
    param = _first_param(url)
    if param:
        finding["param"] = param
    return finding


def run_worker(lead: dict, target: str, scope_domains: list[str]) -> dict:
    """One ephemeral, single-objective worker. Runs in a thread."""
    lead_id = lead["id"]
    skill = lead.get("skill", "")
    session_dir = os.path.join(FINDINGS_DIR, _safe(target), "swarm", lead_id)

    lead_board.touch(target, lead_id, "investigating", f"swarm claimed ({skill})")

    finding = finding_from_lead(lead, target)
    canon = normalize_class(skill.replace("hunt-", "").replace("-", " "))
    if not canon:
        lead_board.touch(target, lead_id, "parked", f"no verifier for {skill}")
        return {"lead_id": lead_id, "skill": skill, "outcome": "parked",
                "reason": f"no deterministic verifier for {skill}"}

    try:
        result = verify_finding_programmatic(
            finding,
            scope_checker=_scope_checker(scope_domains),
            session_dir=session_dir,
            write_dir=session_dir,
        )
    except Exception as exc:  # noqa: BLE001 - a worker crash must not kill the wave
        lead_board.touch(target, lead_id, "parked", f"worker error: {exc}")
        return {"lead_id": lead_id, "skill": skill, "outcome": "error", "reason": str(exc)}

    verifier = result.get("verifier", {})
    if result.get("status") == "validated_finding":
        lead_board.touch(target, lead_id, "investigating",
                         "VERIFIED by swarm — report-ready",
                         finding_id=result.get("finding_id"))
        outcome = "verified"
    elif result.get("technically_confirmed") and result.get("chain_required_unproven"):
        lead_board.touch(target, lead_id, "investigating",
                         "oracle fired; chain required before report",
                         finding_id=result.get("finding_id"))
        outcome = "needs-chain"
    elif verifier.get("skipped"):
        lead_board.touch(target, lead_id, "parked",
                         f"needs manual input: {verifier.get('oracle','')}"[:160])
        outcome = "parked"
    else:
        lead_board.touch(target, lead_id, "killed",
                         f"verifier rejected: {verifier.get('oracle','')}"[:160])
        outcome = "killed"

    return {
        "lead_id": lead_id, "skill": skill, "outcome": outcome,
        "status": result.get("status"), "finding_id": result.get("finding_id"),
        "oracle": verifier.get("oracle"), "session_dir": session_dir,
    }


def _safe(s: str) -> str:
    import re

    return re.sub(r"[^\w.-]", "_", s)


def coordinate(target, *, recon_dir=None, workers=6, max_leads=0,
               skills=None, scope_domains=None, do_ingest=False) -> dict:
    scope_domains = scope_domains or []
    if do_ingest and recon_dir:
        lead_board.ingest(target, recon_dir)

    leads = [l for l in lead_board.load_ledger(target) if l.get("status") == "new"]
    if skills:
        wanted = set(skills)
        leads = [l for l in leads if l.get("skill") in wanted]
    # Only leads whose skill maps to a deterministic verifier are worth a wave;
    # the rest are parked immediately so the board reflects reality.
    leads.sort(key=lead_board.rank_key)
    if max_leads:
        leads = leads[:max_leads]

    if not leads:
        return {"target": target, "dispatched": 0, "results": [],
                "summary": {"note": "no untouched leads to verify"}}

    results = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(run_worker, l, target, scope_domains): l for l in leads}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"lead_id": futs[fut].get("id"), "outcome": "error",
                                "reason": str(exc)})

    summary = {}
    for r in results:
        summary[r["outcome"]] = summary.get(r["outcome"], 0) + 1

    report = {
        "target": target,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "dispatched": len(results),
        "workers": workers,
        "summary": summary,
        "results": results,
    }
    out_dir = os.path.join(FINDINGS_DIR, _safe(target), "swarm")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "swarm_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Swarm coordinator — parallel verified hunting")
    ap.add_argument("target")
    ap.add_argument("--recon-dir", default=None)
    ap.add_argument("--ingest", action="store_true", help="ingest recon into the board first")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--max-leads", type=int, default=0, help="0 = all")
    ap.add_argument("--skills", default="", help="comma list, e.g. hunt-ssrf,hunt-open-redirect")
    ap.add_argument("--scope-domain", action="append", default=[], dest="scope_domains")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    skills = [s.strip() for s in args.skills.split(",") if s.strip()] or None
    report = coordinate(
        args.target, recon_dir=args.recon_dir, workers=args.workers,
        max_leads=args.max_leads, skills=skills,
        scope_domains=args.scope_domains, do_ingest=args.ingest,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\n=== SWARM {args.target} — {report['dispatched']} leads, "
              f"{args.workers} workers ===")
        for r in report["results"]:
            tag = {"verified": "[VERIFIED]", "needs-chain": "[chain?]  ",
                   "killed": "[killed]  ", "parked": "[parked]  ",
                   "error": "[error]   "}.get(r["outcome"], "[?]")
            print(f"  {tag} {r.get('skill',''):<20} {r['lead_id']}  {r.get('oracle','') or r.get('reason','')}")
        print(f"\n  summary: {report['summary']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
