"""Tests for BugHunter MCP policy layer and adapters (no live network)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "bughunter" / "mcp" / "bughunter-mcp"
sys.path.insert(0, str(MCP))
sys.path.insert(0, str(ROOT))

from policy import PolicyEngine, denied_payload  # noqa: E402
from policy.decisions import ACTIVE_TEST_APPROVAL_REQUIRED, SCOPE_REQUIRED  # noqa: E402
from policy.tool_meta import list_tool_catalog  # noqa: E402
from redact import redact_text  # noqa: E402
import adapters  # noqa: E402


def test_tool_catalog_nonempty():
    rows = list_tool_catalog()
    names = {r["tool"] for r in rows}
    assert "bughunter_research" in names
    assert "bughunter_scope_check" in names


def test_scope_required_blocks_active():
    p = PolicyEngine()
    d = p.authorize_tool("bughunter_recon", {"target": "example.com", "approve": True})
    assert d.error_code == SCOPE_REQUIRED


def test_out_of_scope_blocked():
    p = PolicyEngine(domains=["*.in-scope.test"])
    d = p.authorize_tool(
        "bughunter_recon",
        {"target": "evil.com", "approve": True, "scope_domains": ["*.in-scope.test"]},
    )
    assert d.kind.value == "block"


def test_approval_required():
    p = PolicyEngine(domains=["*.example.com"], auto_approve=False)
    d = p.authorize_tool(
        "bughunter_hunt",
        {"target": "app.example.com", "scope_domains": ["*.example.com"]},
    )
    assert d.error_code == ACTIVE_TEST_APPROVAL_REQUIRED
    payload = denied_payload(d)
    assert payload["status"] == "denied"


def test_approve_allows():
    p = PolicyEngine(domains=["*.example.com"], auto_approve=False)
    d = p.authorize_tool(
        "bughunter_hunt",
        {"target": "app.example.com", "scope_domains": ["*.example.com"], "approve": True},
    )
    assert d.allowed


def test_readonly_scope_check_no_approve():
    p = PolicyEngine()
    d = p.authorize_tool("bughunter_scope_check", {"target": "x.com"})
    assert d.allowed


def test_discovered_not_auto_authorized():
    p = PolicyEngine(domains=["*.example.com"])
    p.note_discovered("cdn.other.net")
    assert "cdn.other.net" in p.discovered
    assert "cdn.other.net" not in p.authorized


def test_redact_secrets():
    out = redact_text("api_key=sk-abcdefghijklmnopqrstuvwxyz")
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in out
    assert "REDACTED" in out


def test_scope_adapter():
    out = adapters.scope_check("api.example.com", ["*.example.com"])
    assert out["in_scope"] is True


def test_attack_surface_missing_recon():
    out = adapters.attack_surface("no-such-target-xyz")
    assert out["next_action"] == "bughunter_recon"
