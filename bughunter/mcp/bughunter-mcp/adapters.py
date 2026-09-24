"""Adapters over existing BugHunter tools (no second engine)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]


def _sys_path() -> None:
    import sys
    root = str(REPO)
    if root not in sys.path:
        sys.path.insert(0, root)


class UnsafeTargetError(ValueError):
    """Raised when a target/relative path would escape the repo sandbox."""


def _safe_under(base: Path, *parts: str) -> Path:
    """Join parts under `base` and confirm the result stays inside it.

    `target` reaches these tools from an MCP client and is explicitly untrusted
    (server.py), so a value like '../../../../etc' must not escape REPO/recon.
    Mirrors the resolve()+containment check bughunter_get_finding already uses.
    """
    base_r = base.resolve()
    candidate = base_r.joinpath(*parts).resolve()
    if candidate != base_r and base_r not in candidate.parents:
        raise UnsafeTargetError(f"path escapes {base_r}")
    return candidate


def scope_check(target: str, domains: list[str], excluded: list[str] | None = None) -> dict[str, Any]:
    _sys_path()
    from tools.scope_checker import ScopeChecker

    checker = ScopeChecker(domains=domains, excluded_domains=excluded)
    ok = checker.is_in_scope(target)
    return {
        "status": "completed",
        "target": target,
        "scope": {"status": "authorized" if ok else "out_of_scope", "domains": domains},
        "in_scope": ok,
        "summary": f"{target} is {'in' if ok else 'OUT OF'} scope",
        "next_action": "continue" if ok else "stop",
    }


def run_recon(target: str, *, timeout: int = 600) -> dict[str, Any]:
    """Invoke tools/recon_engine.sh (existing recon)."""
    script = REPO / "tools" / "recon_engine.sh"
    if not script.exists():
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": "recon_engine.sh missing"}
    try:
        recon_dir = _safe_under(REPO / "recon", target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc)}
    env = os.environ.copy()
    env["BB_TARGET"] = target
    # Pin the output dir to the contained path so recon_engine.sh cannot be
    # steered outside REPO/recon by a crafted target.
    env["RECON_OUT_DIR"] = str(recon_dir)
    try:
        proc = subprocess.run(
            ["bash", str(script), target],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "RESOURCE_LIMIT", "reason": "recon timed out"}
    summary = {
        "status": "completed" if proc.returncode == 0 else "failed",
        "target": target,
        "research": {"stage": "recon"},
        "exit_code": proc.returncode,
        "recon_dir": str(recon_dir) if recon_dir.is_dir() else None,
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-1000:],
        "next_action": "review_attack_surface",
    }
    # ingest leads if recon produced output
    if recon_dir.is_dir():
        try:
            _sys_path()
            from tools.lead_board import ingest
            ingest(target, str(recon_dir))
            summary["memory_updates"] = ["lead_board.ingest"]
        except Exception as exc:  # noqa: BLE001
            summary["lead_ingest_error"] = str(exc)
    return summary


def read_recon_file(target: str, relative: str, limit: int = 50) -> dict[str, Any]:
    # Both `target` and `relative` are untrusted; contain the joined path so it
    # cannot become an arbitrary-file-read primitive outside REPO/recon.
    try:
        path = _safe_under(REPO / "recon", target, relative)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc), "target": target}
    if not path.exists():
        return {
            "status": "completed",
            "target": target,
            "items": [],
            "summary": f"No file at recon/{target}/{relative}",
        }
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    return {
        "status": "completed",
        "target": target,
        "path": str(path),
        "total": len(lines),
        "items": lines[:limit],
        "summary": f"{min(limit, len(lines))} of {len(lines)} lines",
        "next_action": "expand_on_demand",
    }


def attack_surface(target: str) -> dict[str, Any]:
    """Summarize existing recon artifacts (passive)."""
    try:
        base = _safe_under(REPO / "recon", target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc), "target": target}
    if not base.is_dir():
        return {
            "status": "completed",
            "target": target,
            "summary": "No recon artifacts yet — run bughunter_recon first",
            "next_action": "bughunter_recon",
        }
    counts = {}
    for rel in ("subdomains/all.txt", "live/urls.txt", "urls/all.txt", "params/all.txt"):
        p = base / rel
        if p.exists():
            counts[rel] = sum(1 for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
    return {
        "status": "completed",
        "target": target,
        "research": {"stage": "attack_surface"},
        "counts": counts,
        "summary": f"Attack surface snapshot for {target}",
        "next_action": "bughunter_next_lead",
    }


def run_hunt(target: str, *, quick: bool = False, timeout: int = 900) -> dict[str, Any]:
    _sys_path()
    try:
        from tools import hunt as hunt_mod
    except Exception:
        hunt_mod = None
    if hunt_mod and hasattr(hunt_mod, "hunt_target"):
        try:
            # Many hunt_target signatures take target string
            result = hunt_mod.hunt_target(target) if not quick else hunt_mod.hunt_target(target)
            return {
                "status": "completed",
                "target": target,
                "research": {"stage": "hunt"},
                "result": str(result)[:3000],
                "summary": f"Hunt finished for {target}",
                "next_action": "bughunter_list_findings",
            }
        except TypeError:
            pass
        except Exception as exc:  # noqa: BLE001
            return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}
    # Fallback: vuln_scanner.sh if present
    scanner = REPO / "tools" / "vuln_scanner.sh"
    if scanner.exists():
        try:
            proc = subprocess.run(
                ["bash", str(scanner), target],
                cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
            )
            return {
                "status": "completed" if proc.returncode == 0 else "failed",
                "target": target,
                "research": {"stage": "hunt"},
                "exit_code": proc.returncode,
                "stdout_tail": (proc.stdout or "")[-2000:],
                "summary": f"vuln_scanner finished for {target}",
                "next_action": "bughunter_list_findings",
            }
        except subprocess.TimeoutExpired:
            return {"status": "failed", "error": "RESOURCE_LIMIT", "reason": "hunt timed out"}
    return {
        "status": "completed",
        "target": target,
        "research": {"stage": "hunt"},
        "summary": "Hunt adapter: use slash /hunt or agent mode for full tool-calling hunt",
        "next_action": "bughunter_next_lead",
    }


def list_findings(target: str, limit: int = 20) -> dict[str, Any]:
    try:
        root = _safe_under(REPO / "findings", target)
    except UnsafeTargetError as exc:
        return {"status": "failed", "error": "INVALID_TARGET", "reason": str(exc), "target": target}
    if not root.is_dir():
        return {"status": "completed", "target": target, "findings": [], "summary": "No findings directory"}
    items = []
    for p in sorted(root.rglob("*"))[:200]:
        if p.is_file() and p.suffix in {".json", ".md", ".txt"}:
            items.append(str(p.relative_to(REPO)))
            if len(items) >= limit:
                break
    return {
        "status": "completed",
        "target": target,
        "findings": items,
        "summary": f"{len(items)} finding artifacts",
        "next_action": "bughunter_validate",
    }


def get_validation(target: str) -> dict[str, Any]:
    # search validation.json under findings
    root = REPO / "findings"
    hits = list(root.rglob("validation.json")) if root.is_dir() else []
    if target:
        hits = [h for h in hits if target in str(h)]
    if not hits:
        return {"status": "completed", "validation": None, "summary": "No validation.json found"}
    path = hits[0]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": "corrupt validation.json"}
    return {
        "status": "completed",
        "path": str(path),
        "validation": data,
        "summary": f"status={data.get('status')}",
        "next_action": "bughunter_generate_report" if data.get("status") == "validated_finding" else "investigate",
    }


def generate_report_stub(target: str, finding_id: str | None = None) -> dict[str, Any]:
    """Point at existing report artifacts; do not invent content."""
    reports = REPO / "reports" / target
    findings = REPO / "findings" / target
    files = []
    for base in (reports, findings):
        if base.is_dir():
            files.extend(str(p.relative_to(REPO)) for p in base.rglob("*-report.md"))
            files.extend(str(p.relative_to(REPO)) for p in base.rglob("*report*.md"))
    if not files:
        return {
            "status": "completed",
            "error": "INSUFFICIENT_EVIDENCE",
            "summary": "No report artifacts — run /validate then /report (or bughunter report)",
            "finding_id": finding_id,
            "next_action": "bughunter_validate",
        }
    return {
        "status": "completed",
        "target": target,
        "reports": files[:20],
        "summary": "Existing report drafts (reuse project report format; do not auto-submit)",
        "next_action": "human_review",
    }


def memory_patterns(target: str | None = None, tech: list[str] | None = None) -> dict[str, Any]:
    _sys_path()
    mem = Path(os.environ.get("BBHUNT_MEMORY_DIR", "hunt-memory"))
    path = mem / "patterns.jsonl"
    if not path.exists():
        return {"status": "completed", "patterns": [], "summary": "No patterns.jsonl yet"}
    from memory.pattern_db import PatternDB

    db = PatternDB(path)
    if tech:
        matched = db.match(tech)
    else:
        matched = db.read_all()
    if target:
        matched = [p for p in matched if p.get("target") == target or not target]
    # generalized patterns may omit target filter for cross-target — still redact
    return {
        "status": "completed",
        "patterns": matched[:50],
        "summary": f"{len(matched)} patterns",
        "isolation": "target filter applied" if target else "generalized + all local patterns",
    }


def memory_search(query: str, target: str | None = None, limit: int = 30) -> dict[str, Any]:
    _sys_path()
    mem = Path(os.environ.get("BBHUNT_MEMORY_DIR", "hunt-memory"))
    journal = mem / "journal.jsonl"
    hits = []
    q = query.lower()
    if journal.exists():
        from memory.hunt_journal import HuntJournal
        for row in HuntJournal(journal).read_all():
            if target and row.get("target") != target:
                continue
            blob = json.dumps(row, ensure_ascii=False).lower()
            if q in blob:
                hits.append(row)
            if len(hits) >= limit:
                break
    return {
        "status": "completed",
        "query": query,
        "target": target,
        "hits": hits,
        "summary": f"{len(hits)} journal hits",
    }


def leads_show(target: str) -> dict[str, Any]:
    _sys_path()
    from tools.lead_board import load_ledger
    leads = load_ledger(target)
    return {
        "status": "completed",
        "target": target,
        "leads": leads[:50],
        "summary": f"{len(leads)} leads",
        "next_action": "bughunter_next_lead",
    }


def leads_next(target: str) -> dict[str, Any]:
    _sys_path()
    from tools.lead_board import load_ledger, rank_key
    leads = [l for l in load_ledger(target) if l.get("status") == "new"]
    if not leads:
        return {"status": "completed", "target": target, "lead": None, "summary": "No untouched leads"}
    lead = sorted(leads, key=rank_key)[0]
    return {
        "status": "completed",
        "target": target,
        "lead": lead,
        "summary": f"Next: {lead.get('id')} {lead.get('skill')} — {lead.get('why')}",
        "next_action": "investigate_then_touch",
    }


def leads_update(target: str, lead_id: str, status: str, note: str | None = None,
                 finding_id: str | None = None) -> dict[str, Any]:
    _sys_path()
    from tools.lead_board import touch
    touch(target, lead_id, status, note, finding_id=finding_id)
    return {
        "status": "completed",
        "target": target,
        "lead_id": lead_id,
        "new_status": status,
        "summary": f"Updated {lead_id} → {status}",
    }


def program_stats(handle: str) -> dict[str, Any]:
    _sys_path()
    try:
        from mcp.hackerone_mcp_server import get_program_stats  # type: ignore
    except Exception:
        try:
            import importlib.util
            path = REPO / "mcp" / "hackerone-mcp" / "server.py"
            spec = importlib.util.spec_from_file_location("h1mcp", path)
            mod = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(mod)
            get_program_stats = mod.get_program_stats
        except Exception as exc:  # noqa: BLE001
            return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}
    try:
        data = get_program_stats(handle)
        return {"status": "completed", "program": handle, "data": data, "summary": f"Stats for {handle}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}


def program_policy(handle: str) -> dict[str, Any]:
    _sys_path()
    try:
        import importlib.util
        path = REPO / "mcp" / "hackerone-mcp" / "server.py"
        spec = importlib.util.spec_from_file_location("h1mcp", path)
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
        data = mod.get_program_policy(handle)
        return {"status": "completed", "program": handle, "policy": data, "summary": f"Policy for {handle}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": "RESEARCH_FAILED", "reason": str(exc)}


def research(
    target: str,
    mode: str,
    domains: list[str],
    *,
    approve: bool = False,
) -> dict[str, Any]:
    """High-level workflow stages — does not auto-run everything."""
    mode = (mode or "RECON").upper()
    stages: list[dict[str, Any]] = []
    out: dict[str, Any] = {
        "status": "completed",
        "target": target,
        "scope": {"status": "authorized", "domains": domains},
        "research": {"stage": mode.lower()},
        "findings": [],
        "leads": [],
        "evidence": [],
        "memory_updates": [],
        "next_action": "continue",
    }
    if mode in {"RECON", "FULL"}:
        stages.append(run_recon(target))
        out["research"]["stage"] = "recon"
    if mode in {"HUNT", "FULL"}:
        stages.append(run_hunt(target))
        out["research"]["stage"] = "hunt"
        out["findings"] = list_findings(target).get("findings", [])
    if mode == "VALIDATE":
        stages.append(get_validation(target))
        out["research"]["stage"] = "validation"
    if mode == "REPORT":
        stages.append(generate_report_stub(target))
        out["research"]["stage"] = "report"
    if mode in {"RECON", "HUNT", "FULL"}:
        lead = leads_next(target)
        out["leads"] = [lead.get("lead")] if lead.get("lead") else []
    out["stages"] = stages
    out["summary"] = f"Mode {mode} finished for {target} (approve={approve})"
    if mode == "FULL":
        out["next_action"] = "bughunter_validate"
    elif mode == "RECON":
        out["next_action"] = "bughunter_next_lead"
    return out
