"""Tests for tools/verifier.py — the report gate (prove-or-suppress).

The policy engine (decide) is tested exhaustively; re-derivation and the CLI are
tested offline by monkeypatching poc_bundler.capture and by building real bundles
with poc_bundler's own offline `from-request` path. `bughunter/tools` is on
sys.path via conftest.
"""

import json

import pytest

import poc_bundler as poc
import verifier as vf


# ---------------------------------------------------------------------------
# The policy core — every branch
# ---------------------------------------------------------------------------


def test_no_bundle_is_unproven():
    v = vf.decide(has_bundle=False, rd=vf.Rederivation(attempted=False))
    assert v.verdict == vf.UNPROVEN and v.reportable is False


def test_not_attempted_is_inconclusive():
    v = vf.decide(True, vf.Rederivation(attempted=False, detail="unsafe method"))
    assert v.verdict == vf.INCONCLUSIVE and v.reportable is False


def test_unreachable_is_inconclusive():
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=False))
    assert v.verdict == vf.INCONCLUSIVE and v.reportable is False


def test_no_marker_available_is_unproven_not_a_pass():
    """The anti-hallucination rule: reproduced the request but nothing proves the
    bug → UNPROVEN, never a silent pass."""
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=True,
                                        marker_available=False))
    assert v.verdict == vf.UNPROVEN and v.reportable is False


def test_marker_present_is_proven_and_reportable():
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=True,
                                        marker_available=True, marker_present=True,
                                        status=200))
    assert v.verdict == vf.PROVEN and v.reportable is True


def test_marker_absent_is_refuted():
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=True,
                                        marker_available=True, marker_present=False,
                                        status=403))
    assert v.verdict == vf.REFUTED and v.reportable is False


def test_only_proven_is_ever_reportable():
    """Guardrail: exactly one verdict may ship. If someone adds a verdict later,
    this test forces them to consciously decide its reportability."""
    reportable = set()
    for hb in (True, False):
        for att in (True, False):
            for reach in (True, False):
                for avail in (True, False):
                    for present in (True, False):
                        v = vf.decide(hb, vf.Rederivation(att, reach, avail, present))
                        if v.reportable:
                            reportable.add(v.verdict)
    assert reportable == {vf.PROVEN}


# ---------------------------------------------------------------------------
# resolve_headers
# ---------------------------------------------------------------------------


def test_resolve_headers_from_env_and_missing():
    hdrs = [("Host", "x"), ("Authorization", "‹redacted:$AUTHORIZATION›")]
    ok, missing = vf.resolve_headers(hdrs, {"AUTHORIZATION": "Bearer real"})
    assert ("Authorization", "Bearer real") in ok and missing == []
    _, missing2 = vf.resolve_headers(hdrs, {})
    assert missing2 == ["AUTHORIZATION"]


# ---------------------------------------------------------------------------
# Helpers to build real bundles offline
# ---------------------------------------------------------------------------


def make_bundle(tmp_path, *, method="GET", auth=False, resp_body="ok", status="200 OK"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    lines = [f"{method} /r HTTP/1.1", "Host: api.acme.com"]
    if auth:
        lines.append("Authorization: Bearer SECRET")
    (tmp_path / "req.txt").write_text("\n".join(lines) + "\n\n", encoding="utf-8")
    (tmp_path / "resp.txt").write_text(
        f"HTTP/1.1 {status}\nContent-Type: text/plain\n\n{resp_body}", encoding="utf-8")
    out = tmp_path / "bundle"
    poc.main(["from-request", str(tmp_path / "req.txt"), "--response", str(tmp_path / "resp.txt"),
              "--target", "acme.com", "--vuln-class", "idor", "--finding-id", "F-1", "-o", str(out)])
    return str(out)


def fake_capture(body, status=200):
    def _c(url, method, headers, reqbody, timeout):
        return poc.Exchange(method=method, url=url, response_status=status,
                            response_body=body, response_body_bytes=body.encode())
    return _c


# ---------------------------------------------------------------------------
# verify() end to end (offline)
# ---------------------------------------------------------------------------


def test_verify_proven_writes_reportable_record(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, resp_body="the-secret-flag-123")
    monkeypatch.setattr(poc, "capture", fake_capture("...the-secret-flag-123..."))
    rec = vf.verify(d, marker_override="the-secret-flag-123", env={})
    assert rec["verdict"] == vf.PROVEN and rec["reportable"] is True
    saved = json.loads((__import__("pathlib").Path(d) / "verification.json").read_text(encoding="utf-8"))
    assert saved["schema"] == "verification/1" and saved["reportable"] is True


def test_verify_refuted_when_marker_gone(tmp_path, monkeypatch):
    d = make_bundle(tmp_path)
    monkeypatch.setattr(poc, "capture", fake_capture("access denied", status=403))
    rec = vf.verify(d, marker_override="the-secret-flag-123", env={})
    assert rec["verdict"] == vf.REFUTED and rec["reportable"] is False


def test_verify_unproven_without_marker(tmp_path, monkeypatch):
    d = make_bundle(tmp_path)
    monkeypatch.setattr(poc, "capture", fake_capture("anything"))
    rec = vf.verify(d, marker_override=None, env={})  # no marker anywhere
    assert rec["verdict"] == vf.UNPROVEN and rec["reportable"] is False


def test_verify_inconclusive_missing_secret(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, auth=True)   # request.http has redacted Authorization
    monkeypatch.setattr(poc, "capture", fake_capture("x"))  # should never be reached
    rec = vf.verify(d, marker_override="x", env={})  # AUTHORIZATION not in env
    assert rec["verdict"] == vf.INCONCLUSIVE and rec["reportable"] is False


def test_verify_inconclusive_unsafe_method(tmp_path):
    d = make_bundle(tmp_path, method="DELETE")
    rec = vf.verify(d, marker_override="x", env={})
    assert rec["verdict"] == vf.INCONCLUSIVE
    assert "DELETE" in rec["reason"]


def test_verify_no_secret_leaks_into_record(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, auth=True, resp_body="ok")
    monkeypatch.setattr(poc, "capture", fake_capture("ok"))
    rec = vf.verify(d, marker_override="ok", env={"AUTHORIZATION": "Bearer TOPSECRET"})
    assert "TOPSECRET" not in json.dumps(rec)


# ---------------------------------------------------------------------------
# CLI + gate exit codes
# ---------------------------------------------------------------------------


def test_cli_check_require_proof_blocks_unproven(tmp_path, monkeypatch):
    d = make_bundle(tmp_path)
    monkeypatch.setattr(poc, "capture", fake_capture("whatever"))
    rc = vf.main(["check", d, "--require-proof"])  # no marker → UNPROVEN
    assert rc == 1


def test_cli_check_proven_passes_gate(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, resp_body="flagX")
    monkeypatch.setattr(poc, "capture", fake_capture("flagX"))
    rc = vf.main(["check", d, "--marker", "flagX", "--require-proof"])
    assert rc == 0


def test_cli_sweep_require_proof_fails_if_any_unproven(tmp_path, monkeypatch):
    make_bundle(tmp_path / "b1", resp_body="q")
    monkeypatch.setattr(poc, "capture", fake_capture("q"))  # no marker → UNPROVEN
    rc = vf.main(["sweep", str(tmp_path), "--require-proof"])
    assert rc == 1
