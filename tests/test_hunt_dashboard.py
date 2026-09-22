"""Tests for tools/hunt_dashboard.py — the local Hunt Dashboard (web view).

Covers the pure collection + render layer (no server needed) and the
path-traversal guard used by serve mode. `tools/` is on sys.path via
tests/conftest.py, so we import the module directly.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import hunt_dashboard as db


# ---------------------------------------------------------------------------
# Fixtures — build a realistic repo-output tree under tmp_path.
# ---------------------------------------------------------------------------


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _iso(days_ago=0):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def hunt_root(tmp_path):
    root = str(tmp_path)
    leads = [
        {"id": "lb-aaa", "target": "acme.com", "skill": "hunt-idor", "priority": "high",
         "signal": "numeric object ref", "why": "IDOR", "evidence": "https://acme.com/api/user?id=1",
         "status": "new", "created": _iso(5), "last_seen": _iso(0)},   # stale HIGH
        {"id": "lb-bbb", "target": "acme.com", "skill": "hunt-xss", "priority": "med",
         "signal": "reflected", "why": "XSS", "evidence": "https://acme.com/?q=x",
         "status": "investigating", "created": _iso(1), "last_seen": _iso(0)},
        {"id": "lb-ccc", "target": "acme.com", "skill": "hunt-ssrf", "priority": "high",
         "signal": "url param", "why": "SSRF", "evidence": "https://acme.com/?url=x",
         "status": "reported", "created": _iso(3), "last_seen": _iso(0)},
    ]
    lp = os.path.join(root, "memory", "leads", "acme.com.jsonl")
    os.makedirs(os.path.dirname(lp), exist_ok=True)
    with open(lp, "w", encoding="utf-8") as fh:
        for l in leads:
            fh.write(json.dumps(l) + "\n")

    _write(os.path.join(root, "recon", "acme.com", "subdomains.txt"),
           "a.acme.com\nb.acme.com\n")
    _write(os.path.join(root, "recon", "acme.com", "live-hosts.txt"),
           "https://a.acme.com\n")
    _write(os.path.join(root, "recon", "acme.com", "urls.txt"),
           "https://a.acme.com/1\nhttps://a.acme.com/2\n# comment ignored\n")

    _write(os.path.join(root, "findings", "acme.com", "idor.md"), "# IDOR finding\nbody")
    _write(os.path.join(root, "reports", "acme.com", "report.md"), "# Report\nbody")

    _write(os.path.join(root, "recon", "acme.com", "screens", "gallery.html"),
           "<html>gallery</html>")

    hm = os.path.join(root, "hunt-memory")
    _write(os.path.join(hm, "journal.jsonl"),
           json.dumps({"ts": _iso(0), "target": "acme.com", "action": "hunt",
                       "vuln_class": "idor", "result": "validated_finding",
                       "schema_version": 1}) + "\n")
    _write(os.path.join(hm, "patterns.jsonl"),
           json.dumps({"ts": _iso(0), "target": "acme.com", "vuln_class": "idor",
                       "technique": "id swap", "tech_stack": "node",
                       "schema_version": 1}) + "\n")
    return root


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def test_collect_leads_counts_and_sorting(hunt_root):
    boards = db.collect_leads(hunt_root)
    assert "acme.com" in boards
    board = boards["acme.com"]
    assert board["counts"] == {"new": 1, "investigating": 1, "reported": 1}
    assert board["stale"] == 1  # the 5-day-old HIGH/new lead
    # 'new' leads sort before other statuses
    assert board["leads"][0]["status"] == "new"


def test_lead_age_and_staleness():
    stale = {"status": "new", "priority": "high", "created": _iso(5)}
    fresh = {"status": "new", "priority": "high", "created": _iso(0)}
    touched = {"status": "investigating", "priority": "high", "created": _iso(9)}
    assert db.lead_age_days(stale) >= 2
    assert db.is_stale(stale) is True
    assert db.is_stale(fresh) is False
    assert db.is_stale(touched) is False  # not 'new' → not stale


def test_lead_age_bad_timestamp_is_zero():
    assert db.lead_age_days({"created": "not-a-date"}) == 0
    assert db.lead_age_days({}) == 0


def test_collect_recon_counts(hunt_root):
    recon = db.collect_recon(hunt_root)
    assert recon["acme.com"]["subdomains"] == 2
    assert recon["acme.com"]["live_hosts"] == 1
    assert recon["acme.com"]["urls"] == 2  # comment line excluded


def test_collect_docs_and_galleries(hunt_root):
    state = db.collect_state(hunt_root)
    assert any(f["name"] == "idor.md" for f in state["findings"])
    assert any(r["name"] == "report.md" for r in state["reports"])
    assert state["findings"][0]["target"] == "acme.com"
    assert len(state["galleries"]) == 1


def test_collect_memory(hunt_root):
    m = db.collect_memory(hunt_root)
    assert m["journal"] == 1
    assert m["patterns"] == 1
    assert m["recent"][0]["target"] == "acme.com"


def test_collect_state_totals(hunt_root):
    t = db.collect_state(hunt_root)["totals"]
    assert t["targets"] == 1
    assert t["leads"] == 3
    assert t["untouched"] == 1
    assert t["investigating"] == 1
    assert t["findings"] == 1
    assert t["stale"] == 1


def test_empty_root_does_not_raise(tmp_path):
    state = db.collect_state(str(tmp_path))
    assert state["totals"]["leads"] == 0
    assert state["boards"] == {}
    # render must still produce a valid page
    html = db.render_dashboard(state)
    assert "Hunt Dashboard" in html
    assert "No leads yet" in html


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_contains_key_data(hunt_root):
    html = db.render_dashboard(db.collect_state(hunt_root))
    assert "acme.com" in html
    assert "hunt-idor" in html
    assert "stale" in html.lower()
    assert "idor.md" in html


def test_render_escapes_attacker_controlled_evidence(tmp_path):
    """Recon data is attacker-controlled — evidence must never render as live HTML."""
    root = str(tmp_path)
    payload = '"><script>alert(1)</script>'
    lead = {"id": "lb-xss", "target": "evil", "skill": "hunt-xss", "priority": "high",
            "signal": payload, "why": payload, "evidence": payload,
            "status": "new", "created": _iso(0)}
    lp = os.path.join(root, "memory", "leads", "evil.jsonl")
    os.makedirs(os.path.dirname(lp), exist_ok=True)
    with open(lp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(lead) + "\n")
    html = db.render_dashboard(db.collect_state(root))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_live_mode_adds_refresh_and_badge(tmp_path):
    state = db.collect_state(str(tmp_path))
    live = db.render_dashboard(state, live=True)
    static = db.render_dashboard(state, live=False)
    assert "http-equiv" in live and "LIVE" in live
    assert "http-equiv" not in static


# ---------------------------------------------------------------------------
# Path-traversal guard
# ---------------------------------------------------------------------------


def test_safe_path_allows_file_within_root(hunt_root):
    assert db.safe_path(hunt_root, "findings/acme.com/idor.md") is not None


def test_safe_path_blocks_traversal(hunt_root):
    assert db.safe_path(hunt_root, "../../../etc/passwd") is None
    assert db.safe_path(hunt_root, "../secret.txt") is None


def test_safe_path_blocks_non_viewable_extension(hunt_root):
    _write(os.path.join(hunt_root, "danger.exe"), "x")
    assert db.safe_path(hunt_root, "danger.exe") is None


def test_safe_path_missing_file(hunt_root):
    assert db.safe_path(hunt_root, "findings/nope.md") is None


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_export_writes_self_contained_file(hunt_root, tmp_path):
    out = os.path.join(str(tmp_path), "dash.html")
    rc = db.main(["export", "-o", out, "--root", hunt_root])
    assert rc == 0
    with open(out, encoding="utf-8") as fh:
        content = fh.read()
    assert "Hunt Dashboard" in content
    assert "http-equiv" not in content  # static export never auto-refreshes
    assert "acme.com" in content
