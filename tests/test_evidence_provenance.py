"""Evidence store: provenance, integrity, scope snapshot, export, replay, trace."""

import json

import pytest

import agent
from agent import AgentTracer, HuntMemory, ToolDispatcher
from memory.evidence import EvidenceError, EvidenceStore, build_replay, export_bundle
from tools.scope_checker import ScopeChecker

TOKEN = "Bearer super-secret-token-value-xyz"


def _store(tmp_path):
    return EvidenceStore(tmp_path)


def test_chain_verifies_and_survives_reopen(tmp_path):
    store = _store(tmp_path)
    a = store.capture(kind="action", tool="run_recon", target="example.com",
                      scope={"decision": "allow", "matched_rule": "*.example.com"})
    b = store.capture(kind="action", tool="run_vuln_scan", parent_id=a["evidence_id"])
    assert a["prev_hash"] != b["prev_hash"]
    assert store.verify_chain()["ok"] is True
    again = EvidenceStore(tmp_path)
    assert again.verify_chain()["ok"] is True
    assert {r["evidence_id"] for r in again.read_all()} == {a["evidence_id"], b["evidence_id"]}


def test_scope_snapshot_is_not_rewritten(tmp_path):
    store = _store(tmp_path)
    scope = {"decision": "allow", "matched_rule": "*.example.com", "rules": ["*.example.com"]}
    store.capture(kind="scope_decision", scope=scope)
    scope["matched_rule"] = "MUTATED"
    scope["rules"].append("evil.com")
    saved = store.read_all()[0]["scope"]
    assert saved["matched_rule"] == "*.example.com"
    assert saved["rules"] == ["*.example.com"]


def test_link_finding_and_missing_id(tmp_path):
    store = _store(tmp_path)
    rec = store.capture(kind="action", tool="run_recon", observation="ok")
    store.link_finding(rec["evidence_id"], "fnd-abc")
    # The original record is unchanged (append-only).
    original = [r for r in store.read_all() if r["evidence_id"] == rec["evidence_id"]][0]
    assert original["digest"] == rec["digest"]
    linked = store.provenance_for("fnd-abc")
    assert rec["evidence_id"] in {r["evidence_id"] for r in linked}
    with pytest.raises(EvidenceError):
        store.link_finding("ev-does-not-exist", "fnd-other")


def test_modified_reordered_deleted_and_malformed(tmp_path):
    store = _store(tmp_path)
    store.capture(kind="action", tool="a", observation="one")
    store.capture(kind="action", tool="b", observation="two")
    store.capture(kind="action", tool="c", observation="three")
    path = store.path
    lines = path.read_text().splitlines()

    # Modified field.
    rec = json.loads(lines[0])
    rec["observation"] = "tampered"
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    bad = store.verify_chain()
    assert bad["ok"] is False
    assert any(e["error"] == "digest_mismatch" for e in bad["errors"])

    # Restore by recapturing into a fresh dir for the other cases.
    store2 = EvidenceStore(tmp_path / "b")
    store2.capture(kind="action", tool="a", observation="one")
    store2.capture(kind="action", tool="b", observation="two")
    store2.capture(kind="action", tool="c", observation="three")
    lines = store2.path.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    store2.path.write_text("\n".join(lines) + "\n")
    reordered = store2.verify_chain()
    assert reordered["ok"] is False
    assert any(e["error"] == "prev_hash_mismatch" for e in reordered["errors"])

    store3 = EvidenceStore(tmp_path / "c")
    store3.capture(kind="action", tool="a", observation="one")
    store3.capture(kind="action", tool="b", observation="two")
    store3.capture(kind="action", tool="c", observation="three")
    lines = store3.path.read_text().splitlines()
    # Delete the middle record.
    store3.path.write_text(lines[0] + "\n" + lines[2] + "\n")
    deleted = store3.verify_chain()
    assert deleted["ok"] is False

    store4 = EvidenceStore(tmp_path / "d")
    store4.capture(kind="action", tool="a", observation="one")
    store4.capture(kind="action", tool="b", observation="two")
    lines = store4.path.read_text().splitlines()
    store4.path.write_text(lines[0] + "\n")  # tail deleted, head left behind
    tail = store4.verify_chain()
    assert tail["ok"] is False
    assert any(e["error"] == "head_anchor_mismatch" for e in tail["errors"])

    store5 = EvidenceStore(tmp_path / "e")
    store5.capture(kind="action", tool="a", observation="one")
    store5.head_path.unlink()
    missing = store5.verify_chain()
    assert missing["ok"] is False
    assert any(e["error"] == "missing_head_anchor" for e in missing["errors"])

    store6 = EvidenceStore(tmp_path / "f")
    store6.capture(kind="action", tool="a", observation="one")
    with store6.path.open("a") as f:
        f.write("{not json\n")
    malformed = store6.verify_chain()
    assert malformed["ok"] is False
    assert any(e["error"] == "malformed_record" for e in malformed["errors"])

    store7 = EvidenceStore(tmp_path / "g")
    store7.session_dir.mkdir(parents=True, exist_ok=True)
    store7.path.write_text('{"a": 1, "a": 2}\n')
    dup = store7.verify_chain()
    assert dup["ok"] is False


def test_corrupt_tail_refuses_to_append(tmp_path):
    store = _store(tmp_path)
    store.capture(kind="action", tool="a")
    store.path.write_text("{not json\n")
    with pytest.raises(EvidenceError):
        store.capture(kind="action", tool="b")


def test_export_redacts_and_keeps_provenance(tmp_path):
    store = _store(tmp_path)
    rec = store.capture(
        kind="action",
        tool="run_recon",
        url="https://example.com/a?token=abcdef123456",
        request={"headers": {"Authorization": TOKEN}, "body": '{"password": "hunter2secret"}'},
        scope={"decision": "allow", "matched_rule": "example.com"},
    )
    store.link_finding(rec["evidence_id"], "fnd-1")
    (tmp_path / "validation.json").write_text(json.dumps({
        "finding_id": "fnd-1",
        "status": "validated_finding",
        "authorization": TOKEN,
    }))
    out = tmp_path / "bundle.json"
    bundle = export_bundle(tmp_path, finding_id="fnd-1", out_path=out)
    blob = out.read_text()
    assert "super-secret-token-value-xyz" not in blob
    assert "hunter2secret" not in blob
    assert "abcdef123456" not in blob
    assert bundle["provenance_ok"] is True
    assert bundle["integrity"]["ok"] is True
    assert bundle["validation"]["finding_id"] == "fnd-1"
    assert bundle["validation"]["authorization"] == "[REDACTED]"
    assert any(r["evidence_id"] == rec["evidence_id"] for r in bundle["evidence"])
    replay = build_replay(store.read_all()[0])
    assert "super-secret-token-value-xyz" not in replay
    assert "hunter2secret" not in replay


def test_export_rejects_other_findings_validation(tmp_path):
    store = _store(tmp_path)
    rec = store.capture(kind="action", tool="run_recon")
    store.link_finding(rec["evidence_id"], "fnd-mine")
    (tmp_path / "validation.json").write_text(json.dumps({"finding_id": "fnd-other"}))
    bundle = export_bundle(tmp_path, finding_id="fnd-mine")
    assert "validation" not in bundle
    assert bundle["provenance_ok"] is False
    with pytest.raises(EvidenceError):
        export_bundle(tmp_path, finding_id="fnd-missing", strict=True)


def test_post_capture_secret_is_not_exported(tmp_path):
    store = _store(tmp_path)
    store.capture(kind="action", tool="run_recon", observation="clean")
    lines = store.path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["observation"] = "leak " + TOKEN
    lines[0] = json.dumps(rec)
    store.path.write_text("\n".join(lines) + "\n")
    bundle = export_bundle(tmp_path)
    blob = json.dumps(bundle)
    assert "super-secret-token-value-xyz" not in blob
    assert bundle["integrity"]["ok"] is False
    assert bundle["export_redacted_post_capture"]


def test_trace_redacts_result_and_records_evidence_id(tmp_path):
    log = tmp_path / "agent_trace.jsonl"
    tracer = AgentTracer(str(log))
    tracer.tool_result("run_recon", f"saw {TOKEN}", 0.1, 1, evidence_id="ev-abc")
    tracer.close()
    text = log.read_text()
    assert "super-secret-token-value-xyz" not in text
    assert "ev-abc" in text


def test_session_file_redacts_before_write(tmp_path):
    mem = HuntMemory(str(tmp_path / "agent_session.json"))
    mem.working_memory = f"cookie jar {TOKEN}"
    mem.save()
    disk = (tmp_path / "agent_session.json").read_text()
    assert "super-secret-token-value-xyz" not in disk
    # In-memory copy is not wiped; only the durable copy is.
    assert "super-secret-token-value-xyz" in mem.working_memory


def test_dispatch_block_captures_scope_and_does_not_run(tmp_path, monkeypatch):
    class FakeHunt:
        def __init__(self):
            self.calls = []

        def run_recon(self, domain, **kwargs):
            self.calls.append(domain)
            return True

        def _resolve_recon_dir(self, domain):
            return str(tmp_path)

    fake = FakeHunt()
    monkeypatch.setattr(agent, "_h", lambda: fake)
    store = EvidenceStore(tmp_path / "sess")
    memory = HuntMemory(str(tmp_path / "sess" / "agent_session.json"))
    checker = ScopeChecker(["example.com", "*.example.com"])
    dispatcher = ToolDispatcher(
        "evil.com", memory, scope_checker=checker,
        evidence_store=store, session_id="sess-1",
    )
    result = dispatcher.dispatch("run_recon", {})
    assert result.startswith("BLOCKED by scope guard:")
    assert fake.calls == []
    recs = store.read_all()
    assert len(recs) == 1
    assert recs[0]["status"] == "blocked"
    assert recs[0]["scope"]["in_scope"] is False
    assert recs[0]["scope"]["rules"] == ["example.com", "*.example.com"]
    assert store.verify_chain()["ok"] is True
    # Changing the live checker does not rewrite the snapshot.
    checker.domains.append("evil.com")
    assert store.read_all()[0]["scope"]["rules"] == ["example.com", "*.example.com"]


def test_dispatch_allow_links_finding(tmp_path, monkeypatch):
    class FakeHunt:
        def run_recon(self, domain, **kwargs):
            return True

        def _resolve_recon_dir(self, domain):
            return str(tmp_path)

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(
        ToolDispatcher, "_summarize_recon",
        lambda self, domain, ok: "critical injectable finding on /login",
    )
    monkeypatch.setattr(ToolDispatcher, "_filter_recon_urls_to_scope", lambda self, domain: None)
    store = EvidenceStore(tmp_path / "sess")
    memory = HuntMemory(str(tmp_path / "sess" / "agent_session.json"))
    checker = ScopeChecker(["example.com", "*.example.com"])
    dispatcher = ToolDispatcher(
        "example.com", memory, scope_checker=checker,
        evidence_store=store, session_id="sess-1",
    )
    result = dispatcher.dispatch("run_recon", {})
    assert not result.startswith("BLOCKED")
    kinds = [r["kind"] for r in store.read_all()]
    assert "action" in kinds
    # Discovery/validation split: a scanner keyword hit is a CANDIDATE lead,
    # not a confirmed finding. Only a deterministic verifier promotes it.
    assert "candidate" in kinds
    assert "finding" not in kinds
    assert memory.findings_log == []
    cand = memory.candidate_leads[0]
    assert cand["candidate_id"].startswith("fnd-")
    assert cand["status"] == "candidate"
    assert cand["skill"]  # routed to a hunt-* verifier skill
    assert store.verify_chain()["ok"] is True
