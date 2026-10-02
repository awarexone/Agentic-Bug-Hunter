"""Phase 2 enforcement-path tests — the SECOND half of the invariant.

A scope decision of "deny" is worthless if some execution path still sends
traffic. These tests prove that for every entrypoint that can spawn a scanner
(the direct CLI in tools/hunt.py and the MCP adapters), an out-of-scope target
is not merely reported out of scope but that NO subprocess is launched, and that
recon-discovered out-of-scope hosts are filtered before any scanner reads them.

The agent/dispatch entrypoint is covered by tests/test_agent_dispatcher_scope.py
(asserts the real tool never runs); this file covers the CLI and MCP paths.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "bughunter" / "mcp" / "bughunter-mcp"
for p in (str(MCP), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import tools.hunt as hunt
from tools.scope_checker import ScopeChecker


class _ExplodingPopen:
    """subprocess.Popen replacement that fails the test if ever constructed —
    proof that a blocked target never reaches process spawn."""

    def __init__(self, *a, **k):  # noqa: D401
        raise AssertionError(f"subprocess spawned for a blocked target: {a!r}")


class _FakeProc:
    def __init__(self, rc=0):
        self.returncode = rc

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


@pytest.fixture(autouse=True)
def _reset_scope():
    """Never leak the process-wide CLI scope between tests."""
    hunt.set_scope_checker(None)
    yield
    hunt.set_scope_checker(None)


# --- tools/hunt.py CLI: out-of-scope target never spawns a scanner ----------

class TestHuntCliNonExecution:
    @pytest.mark.parametrize("fn", [
        "run_recon", "run_vuln_scan", "run_graphql_audit",
        "run_cve_hunt", "run_zero_day_fuzzer",
    ])
    def test_out_of_scope_target_blocks_before_spawn(self, fn, monkeypatch):
        monkeypatch.setattr(hunt.subprocess, "Popen", _ExplodingPopen)
        hunt.set_scope_checker(ScopeChecker(["example.com", "*.example.com"]))
        result = getattr(hunt, fn)("evil.com")
        assert result is False  # refused
        # _ExplodingPopen would have raised if reached — reaching here proves
        # no subprocess was launched.

    def test_lookalike_target_blocked(self, monkeypatch):
        monkeypatch.setattr(hunt.subprocess, "Popen", _ExplodingPopen)
        hunt.set_scope_checker(ScopeChecker(["*.example.com"]))
        assert hunt.run_recon("evil-example.com") is False

    def test_in_scope_target_proceeds(self, monkeypatch):
        """A permitted target must still run (enforcement must not over-block)."""
        spawned = {}

        def _fake_popen(cmd, *a, **k):
            spawned["cmd"] = cmd
            return _FakeProc(0)

        monkeypatch.setattr(hunt.subprocess, "Popen", _fake_popen)
        monkeypatch.setattr(hunt, "_filter_recon_scope", lambda d: None)
        hunt.set_scope_checker(ScopeChecker(["example.com", "*.example.com"]))
        assert hunt.run_recon("example.com") is True
        assert "example.com" in spawned["cmd"]

    def test_no_scope_does_not_block_legacy_cli(self, monkeypatch):
        """With no --scope-domain, the legacy CLI still runs (fail-open by
        explicit operator choice, with a loud warning surfaced in main())."""
        monkeypatch.setattr(hunt.subprocess, "Popen", lambda *a, **k: _FakeProc(0))
        hunt.set_scope_checker(None)
        assert hunt.run_recon("evil.com") is True

    def test_cidr_target_with_domain_only_scope_blocked(self, monkeypatch):
        """A domain-only scope must NOT authorize a CIDR sweep (fail closed)."""
        monkeypatch.setattr(hunt.subprocess, "Popen", _ExplodingPopen)
        hunt.set_scope_checker(ScopeChecker(["example.com", "*.example.com"]))
        assert hunt.run_recon("10.0.0.0/24") is False

    def test_cidr_target_with_matching_ip_scope_allowed(self, monkeypatch):
        """A CIDR fully covered by an IP/CIDR scope rule proceeds."""
        monkeypatch.setattr(hunt.subprocess, "Popen", lambda *a, **k: _FakeProc(0))
        monkeypatch.setattr(hunt, "_filter_recon_scope", lambda d: None)
        hunt.set_scope_checker(ScopeChecker(["10.0.0.0/16"]))
        assert hunt.run_recon("10.0.0.0/24") is True

    def test_list_target_with_out_of_scope_entry_blocked(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hunt.subprocess, "Popen", _ExplodingPopen)
        listing = tmp_path / "hosts.txt"
        listing.write_text("api.example.com\nevil.com\n")
        hunt.set_scope_checker(ScopeChecker(["example.com", "*.example.com"]))
        assert hunt.run_recon(str(listing)) is False


# --- Redirect containment: recon must not follow redirects off-scope --------

class TestReconRedirectScopeEnv:
    """When a scope is active, run_recon must tell recon_engine.sh to disable
    httpx redirect-following (SCOPE_ENFORCED=1), so an in-scope host cannot 302
    the probe onto an out-of-scope host. This is the trigger for the recon_engine
    fix that keeps out-of-scope traffic off the wire on the desktop agent path
    (run_agent_hunt installs the same checker into the hunt module)."""

    def _capture_run_recon(self, monkeypatch, checker):
        spawned = {}

        def _fake_popen(cmd, *a, **k):
            spawned["cmd"] = cmd
            spawned["env"] = k.get("env") or {}
            return _FakeProc(0)

        monkeypatch.setattr(hunt.subprocess, "Popen", _fake_popen)
        monkeypatch.setattr(hunt, "_filter_recon_scope", lambda d: None)
        hunt.set_scope_checker(checker)
        assert hunt.run_recon("example.com") is True
        return spawned

    def test_scope_enforced_flag_exported_when_scoped(self, monkeypatch):
        spawned = self._capture_run_recon(
            monkeypatch, ScopeChecker(["example.com", "*.example.com"]))
        assert spawned["env"].get("SCOPE_ENFORCED") == "1"

    def test_no_scope_enforced_flag_when_unscoped(self, monkeypatch):
        spawned = self._capture_run_recon(monkeypatch, None)
        assert "SCOPE_ENFORCED" not in spawned["env"]

    def test_recon_engine_drops_follow_redirects_under_enforcement(self):
        """The recon script itself must clear -follow-redirects when
        SCOPE_ENFORCED=1 (static guard on the bash source)."""
        src = (ROOT / "bughunter" / "tools" / "recon_engine.sh").read_text()
        assert 'SCOPE_ENFORCED:-0' in src
        assert "HTTPX_REDIRECT_ARGS=()" in src


# --- tools/hunt.py CLI: recon-discovered URLs are filtered to scope ---------

class TestHuntReconFiltering:
    def test_filter_recon_scope_drops_out_of_scope(self, tmp_path, monkeypatch):
        recon = tmp_path / "recon" / "example.com"
        (recon / "urls").mkdir(parents=True)
        (recon / "live").mkdir(parents=True)
        allf = recon / "urls" / "all.txt"
        allf.write_text(
            "https://api.example.com/a\n"
            "https://evil.com/x\n"
            "https://sub.example.com/b\n"
            "https://evil-example.com/y\n"
        )
        live = recon / "live" / "urls.txt"
        live.write_text("https://cdn.example.com/z\nhttps://attacker.net/p\n")

        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        hunt.set_scope_checker(ScopeChecker(["example.com", "*.example.com"]))
        hunt._filter_recon_scope("example.com")

        kept_all = allf.read_text().split()
        assert kept_all == ["https://api.example.com/a", "https://sub.example.com/b"]
        kept_live = live.read_text().split()
        assert kept_live == ["https://cdn.example.com/z"]

    def test_filter_noop_without_scope(self, tmp_path, monkeypatch):
        recon = tmp_path / "recon" / "example.com" / "urls"
        recon.mkdir(parents=True)
        allf = recon / "all.txt"
        allf.write_text("https://evil.com/x\n")
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        hunt.set_scope_checker(None)
        hunt._filter_recon_scope("example.com")
        assert allf.read_text() == "https://evil.com/x\n"  # untouched


# --- MCP adapters: out-of-scope hunt is denied, no scanner spawned ----------

class TestMcpAdapterEnforcement:
    def test_run_hunt_out_of_scope_denied_no_spawn(self, monkeypatch):
        import adapters

        # If hunt_target or vuln_scanner.sh were reached it would try to run;
        # make both explode to prove they are never called.
        import tools.hunt as hunt_mod
        monkeypatch.setattr(hunt_mod, "hunt_target",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("hunt_target ran")))
        monkeypatch.setattr(adapters.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("scanner ran")))
        checker = ScopeChecker(["example.com", "*.example.com"])
        out = adapters.run_hunt("evil.com", scope_checker=checker)
        assert out["status"] == "denied"
        assert out["error"] == "OUT_OF_SCOPE"

    def test_run_hunt_installs_scope_around_hunt_target(self, monkeypatch):
        """In-scope MCP hunt must install the shared checker into hunt.py for the
        duration of hunt_target (so its re-run recon + scan are scope-enforced),
        then restore it — closing the 'filter once then repopulate' gap."""
        import adapters
        import tools.hunt as hunt_mod

        seen = {}

        def _fake_hunt_target(target, *a, **k):
            seen["during"] = hunt_mod._SCOPE_CHECKER
            return {"ok": True}

        monkeypatch.setattr(hunt_mod, "hunt_target", _fake_hunt_target)
        hunt_mod.set_scope_checker(None)
        checker = ScopeChecker(["example.com", "*.example.com"])
        adapters.run_hunt("example.com", scope_checker=checker)
        assert seen["during"] is checker          # installed during hunt_target
        assert hunt_mod._SCOPE_CHECKER is None     # restored afterward

    def test_run_recon_filters_discovered_urls(self, tmp_path, monkeypatch):
        import adapters

        target = "example.com"
        recon = tmp_path / "recon" / target
        (recon / "urls").mkdir(parents=True)
        allf = recon / "urls" / "all.txt"
        allf.write_text("https://api.example.com/a\nhttps://evil.com/x\n")

        monkeypatch.setattr(adapters, "REPO", tmp_path)
        # recon_engine.sh "runs" successfully but produces nothing new.
        monkeypatch.setattr(adapters.subprocess, "run",
                            lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})())
        # avoid lead ingest touching real memory
        monkeypatch.setattr(adapters, "_sys_path", lambda: None)
        import types
        fake_lb = types.SimpleNamespace(ingest=lambda *a, **k: None)
        monkeypatch.setitem(sys.modules, "tools.lead_board", fake_lb)

        checker = ScopeChecker(["example.com", "*.example.com"])
        # recon_engine.sh missing under tmp REPO -> adapter returns early; create it
        (tmp_path / "tools").mkdir(parents=True, exist_ok=True)
        (tmp_path / "tools" / "recon_engine.sh").write_text("#!/bin/bash\n")

        out = adapters.run_recon(target, scope_checker=checker)
        assert allf.read_text().split() == ["https://api.example.com/a"]
        assert out.get("scope_filtered_out_of_scope", {}).get("urls/all.txt") == 1


# --- MCP policy authorize_url: guard fix (method approval restored) ----------

class TestMcpAuthorizeUrl:
    def _engine(self):
        from policy import PolicyEngine
        return PolicyEngine(domains=["example.com", "*.example.com"])

    def test_get_in_scope_allow(self):
        from policy.decisions import DecisionKind
        assert self._engine().authorize_url("GET", "https://api.example.com/x").kind == DecisionKind.ALLOW

    def test_get_out_of_scope_block(self):
        from policy.decisions import DecisionKind
        assert self._engine().authorize_url("GET", "https://evil.com/x").kind == DecisionKind.BLOCK

    def test_unsafe_method_in_scope_requires_approval(self):
        """The pre-fix bug compared a dict to a string, silently ALLOWing POST.
        The fix must surface REQUIRE_APPROVAL for a state-changing method."""
        from policy.decisions import DecisionKind
        assert self._engine().authorize_url("POST", "https://api.example.com/x").kind == DecisionKind.REQUIRE_APPROVAL

    def test_no_scope_blocks(self):
        from policy import PolicyEngine
        from policy.decisions import DecisionKind
        assert PolicyEngine().authorize_url("GET", "https://anything.com/").kind == DecisionKind.BLOCK
