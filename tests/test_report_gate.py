"""Tests for tools/report_gate.py — the enforcement point.

Depends only on the verification/1 record format (not on the verifier), so these
build records directly. The load-bearing behaviour is FAIL-CLOSED: anything other
than a well-formed PROVEN record blocks the report. `bughunter/tools` is on
sys.path via conftest.
"""

import json

import report_gate as rg


# ---------------------------------------------------------------------------
# The pure policy — fail closed
# ---------------------------------------------------------------------------


def test_missing_record_blocks():
    d = rg.gate(None)
    assert d.allowed is False
    assert "no verification record" in d.reason


def test_proven_reportable_allows():
    d = rg.gate({"schema": "verification/1", "verdict": "PROVEN", "reportable": True})
    assert d.allowed is True


def test_reportable_false_blocks():
    d = rg.gate({"schema": "verification/1", "verdict": "REFUTED", "reportable": False})
    assert d.allowed is False


def test_wrong_schema_blocks():
    d = rg.gate({"schema": "something-else", "verdict": "PROVEN", "reportable": True})
    assert d.allowed is False


def test_reportable_true_but_not_proven_verdict_blocks():
    """Defense in depth: even if 'reportable' is somehow true, the verdict must be
    PROVEN. A malformed/tampered record can't sneak a report through."""
    d = rg.gate({"schema": "verification/1", "verdict": "UNPROVEN", "reportable": True})
    assert d.allowed is False


def test_proven_verdict_but_reportable_missing_blocks():
    """The mirror of the above: the verdict may be PROVEN, but if `reportable`
    isn't explicitly True the report is still BLOCKED (both halves of the AND)."""
    assert rg.gate({"schema": "verification/1", "verdict": "PROVEN"}).allowed is False


def test_proven_verdict_but_reportable_false_blocks():
    assert rg.gate({"schema": "verification/1", "verdict": "PROVEN",
                    "reportable": False}).allowed is False


# ---------------------------------------------------------------------------
# Evidence binding — the record must match THIS bundle's evidence hash
# ---------------------------------------------------------------------------


def test_gate_binding_mismatch_blocks():
    rec = {"schema": "verification/1", "verdict": "PROVEN", "reportable": True,
           "evidence_sha256": "abc123"}
    assert rg.gate(rec, expected_evidence_sha="abc123").allowed is True
    assert rg.gate(rec, expected_evidence_sha="DIFFERENT").allowed is False       # stale/mismatched
    assert rg.gate(rec, expected_evidence_sha="abc123").allowed is True


def test_gate_binding_missing_evidence_in_record_blocks():
    rec = {"schema": "verification/1", "verdict": "PROVEN", "reportable": True}  # no evidence_sha256
    assert rg.gate(rec, expected_evidence_sha="abc123").allowed is False


def _bundle_with_sha(tmp_path, manifest_sha, record):
    d = tmp_path / "b"
    d.mkdir(parents=True, exist_ok=True)
    (d / "bundle.json").write_text(json.dumps(
        {"schema": "poc-bundle/1", "exchange": {"response_sha256": manifest_sha}}),
        encoding="utf-8")
    (d / "verification.json").write_text(json.dumps(record), encoding="utf-8")
    return str(d)


def test_check_bundle_binds_record_to_manifest_evidence(tmp_path):
    proven = {"schema": "verification/1", "verdict": "PROVEN", "reportable": True}
    # matching evidence hash → allowed
    ok = _bundle_with_sha(tmp_path / "ok", "sha-xyz", {**proven, "evidence_sha256": "sha-xyz"})
    assert rg.check_bundle(ok).allowed is True
    # a PROVEN record whose evidence hash is from a DIFFERENT bundle → blocked
    stale = _bundle_with_sha(tmp_path / "stale", "sha-xyz", {**proven, "evidence_sha256": "sha-OTHER"})
    assert rg.check_bundle(stale).allowed is False


def test_empty_record_blocks():
    assert rg.gate({}).allowed is False


# ---------------------------------------------------------------------------
# Reading the record from disk (unreadable == absent == blocked)
# ---------------------------------------------------------------------------


def _bundle(tmp_path, record=None):
    d = tmp_path / "bundle"
    d.mkdir(parents=True, exist_ok=True)
    (d / "bundle.json").write_text(json.dumps({"schema": "poc-bundle/1"}), encoding="utf-8")
    if record is not None:
        (d / "verification.json").write_text(json.dumps(record), encoding="utf-8")
    return str(d)


def test_check_bundle_without_verification_blocks(tmp_path):
    d = _bundle(tmp_path)  # PoC bundle but never verified
    assert rg.check_bundle(d).allowed is False


def test_check_bundle_with_proven_allows(tmp_path):
    d = _bundle(tmp_path, {"schema": "verification/1", "verdict": "PROVEN", "reportable": True})
    assert rg.check_bundle(d).allowed is True


def test_unreadable_record_is_treated_as_absent(tmp_path):
    d = tmp_path / "bundle"
    d.mkdir()
    (d / "verification.json").write_text("{ not json", encoding="utf-8")
    assert rg.check_bundle(str(d)).allowed is False


# ---------------------------------------------------------------------------
# CLI + exit codes (used by the report step / CI)
# ---------------------------------------------------------------------------


def test_cli_check_blocks_with_exit_1(tmp_path, capsys):
    d = _bundle(tmp_path)
    rc = rg.main(["check", d])
    assert rc == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_cli_check_allows_with_exit_0(tmp_path):
    d = _bundle(tmp_path, {"schema": "verification/1", "verdict": "PROVEN", "reportable": True})
    assert rg.main(["check", d]) == 0


def test_find_bundles_finds_nested_and_skips_invalid(tmp_path):
    # a valid poc-bundle/1, nested a few levels deep
    good = tmp_path / "findings" / "acme.com-idor" / "evidence" / "F-1"
    good.mkdir(parents=True)
    (good / "bundle.json").write_text(json.dumps({"schema": "poc-bundle/1"}), encoding="utf-8")
    # a dir with a bundle.json of the wrong schema → must be skipped
    bad = tmp_path / "notabundle"
    bad.mkdir()
    (bad / "bundle.json").write_text(json.dumps({"schema": "something-else"}), encoding="utf-8")
    # a dir with an unreadable bundle.json → skipped, not a crash
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "bundle.json").write_text("{ not json", encoding="utf-8")

    found = rg.find_bundles(str(tmp_path))
    assert str(good) in found
    assert str(bad) not in found
    assert str(broken) not in found


def test_cli_sweep_reports_blocked_count(tmp_path, capsys):
    _bundle(tmp_path / "a", {"schema": "verification/1", "verdict": "PROVEN", "reportable": True})
    (tmp_path / "b" / "bundle").mkdir(parents=True)
    (tmp_path / "b" / "bundle" / "bundle.json").write_text(
        json.dumps({"schema": "poc-bundle/1"}), encoding="utf-8")  # unverified → blocked
    rc = rg.main(["sweep", str(tmp_path)])
    assert rc == 1
    assert "1 blocked" in capsys.readouterr().out
