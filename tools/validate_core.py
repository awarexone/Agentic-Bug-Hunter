#!/usr/bin/env python3
"""Programmatic (non-tty) validation core — the hard gate between a candidate
finding and a report.

`tools/validate.py` is the interactive, human-driven validator. This module is
its callable twin: it runs the deterministic verifier for a finding's class,
then enforces the triage rules from `skills/triage-validation/SKILL.md` as code
(never-submit list, kill-signal table, chain-required table, the Q8 identity
check), and only stamps `validated_finding` when a verifier oracle actually
fired AND a reproducible evidence record was linked.

Nothing here prompts or reads stdin, so the swarm coordinator, the report gate,
and CI can all call it. The two states match the schema (`memory/schemas.py`):
`validated_finding` (confirmed + evidence) or `scanner_hit` (everything else).
"""
from __future__ import annotations

import os
from datetime import datetime

from tools.verifiers import verify_finding, normalize_class

# ---------------------------------------------------------------------------
# NEVER-SUBMIT / kill-signal predicates (skills/triage-validation/SKILL.md)
# Each predicate returns a kill reason string, or None if it does not fire.
# They operate purely on fields the caller supplies on the finding dict, so a
# finding that lacks the field is simply not killed by that rule.
# ---------------------------------------------------------------------------

def _kill_cors_no_creds(f: dict, canon: str) -> str | None:
    if canon != "cors" and "cors" not in str(f.get("vuln_class", "")).lower():
        return None
    # CORS wildcard/reflection is informational without credentialed exfil.
    if f.get("acao") in ("*", None) and not f.get("acac"):
        return "CORS without Access-Control-Allow-Credentials:true — no credentialed exfil"
    if not f.get("pii_exfiltrated"):
        return "CORS reflection without proof of PII exfiltration"
    return None


def _kill_nuclei_info(f: dict, canon: str) -> str | None:
    sev = str(f.get("nuclei_severity") or "").lower()
    if sev == "info":
        return "nuclei info-severity match — version detection, not exploitation"
    return None


def _kill_ssrf_dns_only(f: dict, canon: str) -> str | None:
    if canon != "ssrf":
        return None
    proto = str(f.get("oob_protocol") or "").lower()
    if proto == "dns" and not f.get("internal_data"):
        return "SSRF DNS callback only — no internal service data returned"
    return None


_KILL_SIGNALS = [_kill_cors_no_creds, _kill_nuclei_info, _kill_ssrf_dns_only]

# ---------------------------------------------------------------------------
# CHAIN-REQUIRED table — these classes are only valid once a chain is proven.
# The caller signals a proven chain with finding["chain_proven"] = True (plus
# optional finding["chain"] describing it).
# ---------------------------------------------------------------------------
_CHAIN_REQUIRED = {
    "open-redirect": "OAuth redirect_uri -> auth-code/token theft (ATO)",
    "cors": "credentialed request that exfiltrates user PII",
    "csrf": "sensitive action (funds transfer, email/password change, delete)",
    "host-header": "password-reset email that uses the injected host",
    "self-xss": "CSRF that triggers it on a victim",
    "subdomain-takeover": "OAuth redirect_uri or cookie scope on the taken-over host",
    "graphql-introspection": "auth-bypass mutation or IDOR reachable via the schema",
}

# ---------------------------------------------------------------------------
# Q8 IDENTITY CHECK — auth-class findings must prove cross-identity access.
# The idor / auth-bypass verifiers enforce this with live requests; this is the
# static backstop for callers that route an auth finding without the fields a
# verifier needs.
# ---------------------------------------------------------------------------
_AUTH_CLASSES = {"idor", "auth-bypass", "ato"}


def _identity_satisfied(f: dict, canon: str) -> tuple[bool, str | None]:
    if canon not in _AUTH_CLASSES:
        return True, None
    if canon == "idor":
        ok = bool((f.get("attacker_headers") or f.get("identity_a")) and f.get("victim_marker"))
        return ok, None if ok else "idor needs a second identity + victim marker (Q8)"
    if canon == "auth-bypass":
        ok = bool(f.get("success_marker"))
        return ok, None if ok else "auth-bypass needs an authorized-only success marker (Q8)"
    return True, None


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def verify_finding_programmatic(
    finding: dict,
    *,
    scope_checker=None,
    session_dir: str | None = None,
    memory_dir: str | None = None,
    write_dir: str | None = None,
    log_research: bool = True,
) -> dict:
    """Run the full programmatic gate for one finding.

    Returns a validation.json-shaped dict. `status` is `validated_finding` only
    when (a) no kill signal fired, (b) any required chain is proven, (c) the Q8
    identity check holds for auth classes, (d) the deterministic verifier
    confirmed the bug, and (e) a reproducible evidence record was linked.
    """
    raw_class = finding.get("vuln_class") or finding.get("vuln_type") or ""
    canon = normalize_class(raw_class)
    rejection_reasons: list[str] = []
    gate_verdict = "pass"

    # Gate A — never-submit / kill-signal table (static, pre-verify) ----------
    for pred in _KILL_SIGNALS:
        reason = pred(finding, canon)
        if reason:
            rejection_reasons.append(reason)
            gate_verdict = "kill"

    # Gate B — chain-required table -------------------------------------------
    chain_need = _CHAIN_REQUIRED.get(canon)
    if chain_need and not finding.get("chain_proven"):
        rejection_reasons.append(f"chain required but not proven: {chain_need}")
        if gate_verdict != "kill":
            gate_verdict = "downgrade"

    # Gate C — Q8 identity check for auth classes -----------------------------
    id_ok, id_reason = _identity_satisfied(finding, canon)
    if not id_ok:
        rejection_reasons.append(id_reason)
        gate_verdict = "kill"

    # Gate D — deterministic verifier --------------------------------------
    # A hard kill (never-submit / identity) short-circuits; a chain-required
    # downgrade does NOT — we still run the oracle so the technical confirmation
    # is recorded, then hold the report back until the chain is proven.
    verifier = None
    chain_block = bool(chain_need and not finding.get("chain_proven"))
    if gate_verdict == "kill":
        verifier_dict = {
            "confirmed": False, "skipped": True,
            "vuln_class": canon or str(raw_class),
            "oracle": "verifier skipped — triage kill-signal fired",
            "evidence": "", "trace": [], "error": None,
        }
    else:
        verifier = verify_finding(finding, scope_checker=scope_checker)
        verifier_dict = verifier.to_dict()
        if verifier.skipped:
            rejection_reasons.append(f"verifier could not confirm: {verifier.oracle}")
        elif not verifier.confirmed:
            rejection_reasons.append(f"verifier rejected: {verifier.oracle}")

    technically_confirmed = bool(verifier and verifier.confirmed)
    # "confirmed" for reporting = oracle fired AND no outstanding chain requirement.
    confirmed = technically_confirmed and not chain_block

    # Gate E — link reproducible evidence -------------------------------------
    finding_id = None
    evidence_id = None
    evidence_linked = False
    if session_dir and (technically_confirmed or finding.get("always_capture")):
        try:
            from memory.evidence import EvidenceStore, new_finding_id

            store = EvidenceStore(session_dir)
            finding_id = new_finding_id()
            first = verifier.trace[0] if (verifier and verifier.trace) else None
            rec = store.capture(
                kind="finding",
                tool="verifiers",
                target=str(finding.get("target") or ""),
                url=(first.url if first else None),
                method=(first.method if first else None),
                status=(str(first.status) if first and first.status else None),
                observation=(verifier.oracle if verifier else "verified"),
                finding_id=finding_id,
                extra={"verifier": verifier_dict},
            )
            evidence_id = rec.get("evidence_id")
            store.link_finding(evidence_id, finding_id, note=verifier_dict["oracle"])
            evidence_linked = True
        except Exception as exc:  # noqa: BLE001 - evidence must never crash the gate
            rejection_reasons.append(f"evidence linking failed: {exc}")

    status = "validated_finding" if (confirmed and (evidence_linked or not session_dir)) else "scanner_hit"
    if confirmed and session_dir and not evidence_linked:
        rejection_reasons.append("confirmed but evidence could not be linked")
    if status == "validated_finding":
        gate_verdict = "pass"
        rejection_reasons = []

    payload = {
        "generated_at": _now(),
        "status": status,
        "gate_verdict": gate_verdict,
        "technically_confirmed": technically_confirmed,
        "chain_required_unproven": chain_block,
        "vuln_class": canon or str(raw_class),
        "finding_id": finding_id,
        "evidence_id": evidence_id,
        "evidence_linked": evidence_linked,
        "rejection_reasons": rejection_reasons,
        "verifier": verifier_dict,
        "finding": {
            "program": finding.get("target"),
            "vulnerability_type": raw_class,
            "endpoint": finding.get("url") or finding.get("endpoint"),
        },
    }

    # Mirror into the research journal, like the interactive validator does.
    if log_research:
        try:
            from tools.research_log import draft_from_validation, new_finding_id as _nfid

            fid = finding_id or _nfid()
            payload["finding_id"] = payload["finding_id"] or fid
            draft_from_validation(
                target=str(finding.get("target") or "unknown"),
                vuln_class=str(raw_class or canon or "unknown"),
                endpoint=str(finding.get("url") or finding.get("endpoint") or "unknown"),
                status=status,
                rejection_reasons=rejection_reasons,
                finding_id=fid,
                memory_dir=memory_dir or os.environ.get("BBHUNT_MEMORY_DIR", "hunt-memory"),
                write=True,
            )
        except Exception:  # noqa: BLE001 - learning must never break validation
            pass

    if write_dir:
        import json

        os.makedirs(write_dir, exist_ok=True)
        with open(os.path.join(write_dir, "validation.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")

    return payload


def is_report_ready(validation: dict) -> bool:
    """The single predicate the report gate consults: a finding may only be
    reported when it was programmatically validated with linked evidence."""
    if not isinstance(validation, dict):
        return False
    if validation.get("status") != "validated_finding":
        return False
    v = validation.get("verifier") or {}
    return bool(v.get("confirmed"))
