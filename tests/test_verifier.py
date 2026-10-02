"""Tests for tools/verifier.py — the report gate (prove-or-suppress).

The policy engine (decide) is tested exhaustively; re-derivation and the CLI are
tested offline by monkeypatching poc_bundler.capture and by building real bundles
with poc_bundler's own offline `from-request` path. `bughunter/tools` is on
sys.path via conftest.
"""

import json
import urllib.error

import pytest

import poc_bundler as poc
import verifier as vf

# Real initial-host SSRF guard, captured before the autouse fixture stubs it out.
_REAL_HOST_GUARD = vf.initial_host_blocked


@pytest.fixture(autouse=True)
def _offline_ssrf_guard(monkeypatch):
    """Keep tests offline/fast — the guard would otherwise DNS-resolve. The
    SSRF-specific test restores the real guard via _REAL_HOST_GUARD."""
    monkeypatch.setattr(vf, "initial_host_blocked", lambda url: False)


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


def test_marker_present_in_both_is_proven_and_reportable():
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=True,
                                        marker_available=True, marker_in_baseline=True,
                                        marker_present=True, status=200))
    assert v.verdict == vf.PROVEN and v.reportable is True


def test_marker_absent_from_fresh_is_refuted():
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=True,
                                        marker_available=True, marker_in_baseline=True,
                                        marker_present=False, status=403))
    assert v.verdict == vf.REFUTED and v.reportable is False


def test_marker_not_in_baseline_is_unproven_not_proven():
    """False-PROVEN guard: a marker present in the fresh response but NOT in the
    original recorded response is not proof of this finding → UNPROVEN, not PROVEN."""
    v = vf.decide(True, vf.Rederivation(attempted=True, reachable=True,
                                        marker_available=True, marker_in_baseline=False,
                                        marker_present=True, status=200))
    assert v.verdict == vf.UNPROVEN and v.reportable is False


def test_only_proven_is_ever_reportable():
    """Guardrail: exactly one verdict may ship. Iterates every combination of the
    policy inputs, so any new verdict forces a conscious reportability decision."""
    reportable = set()
    for hb in (True, False):
        for att in (True, False):
            for reach in (True, False):
                for avail in (True, False):
                    for base in (True, False):
                        for present in (True, False):
                            v = vf.decide(hb, vf.Rederivation(
                                attempted=att, reachable=reach, marker_available=avail,
                                marker_in_baseline=base, marker_present=present))
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


def make_bundle(tmp_path, *, method="GET", auth=False, host="api.acme.com",
                resp_body="ok", status="200 OK", resp_headers=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    lines = [f"{method} /r HTTP/1.1", f"Host: {host}"]
    if auth:
        lines.append("Authorization: Bearer SECRET")
    (tmp_path / "req.txt").write_text("\n".join(lines) + "\n\n", encoding="utf-8")
    hdrs = "Content-Type: text/plain"
    if resp_headers:
        hdrs += "\n" + "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
    (tmp_path / "resp.txt").write_text(
        f"HTTP/1.1 {status}\n{hdrs}\n\n{resp_body}", encoding="utf-8")
    out = tmp_path / "bundle"
    poc.main(["from-request", str(tmp_path / "req.txt"), "--response", str(tmp_path / "resp.txt"),
              "--target", "acme.com", "--vuln-class", "idor", "--finding-id", "F-1", "-o", str(out)])
    return str(out)


def fake_capture(body, status=200, headers=None):
    def _c(url, method, hdrs, reqbody, timeout):
        return poc.Exchange(method=method, url=url, response_status=status,
                            response_headers=list((headers or {}).items()),
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
    # marker WAS in the original response (a genuine finding), and is now gone
    d = make_bundle(tmp_path, resp_body="the-secret-flag-123")
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


# ---------------------------------------------------------------------------
# Review fix 1 — false-PROVEN: marker must be in the ORIGINAL response too
# ---------------------------------------------------------------------------


def test_marker_only_in_fresh_not_baseline_is_unproven(tmp_path, monkeypatch):
    """A banner / reflected input that appears now but was never in the original
    finding must NOT mint PROVEN."""
    d = make_bundle(tmp_path, resp_body="ordinary body")           # marker NOT here
    monkeypatch.setattr(poc, "capture", fake_capture("Server: nginx banner-XYZ"))
    rec = vf.verify(d, marker_override="banner-XYZ", env={})
    assert rec["verdict"] == vf.UNPROVEN and rec["reportable"] is False


def test_record_binds_to_refetched_response(tmp_path, monkeypatch):
    """The record captures what was actually re-fetched (fresh sha + status), not
    just the original's hash."""
    d = make_bundle(tmp_path, resp_body="flagZ")
    monkeypatch.setattr(poc, "capture", fake_capture("flagZ", status=200))
    rec = vf.verify(d, marker_override="flagZ", env={})
    assert rec["verdict"] == vf.PROVEN
    assert rec["rederived_sha256"] == poc.sha256_hex(b"flagZ")
    assert rec["rederived_status"] == 200


# ---------------------------------------------------------------------------
# Review fix 2 — false-SUPPRESS: header-based markers must be matched
# ---------------------------------------------------------------------------


def test_marker_in_response_header_is_proven(tmp_path, monkeypatch):
    """Open-redirect / CORS / Set-Cookie live in headers. A marker present in the
    original AND fresh *headers* (body empty) must be PROVEN, not REFUTED."""
    payload = "https://evil.example/callback"
    d = make_bundle(tmp_path, resp_body="", resp_headers={"Location": payload}, status="302 Found")
    monkeypatch.setattr(poc, "capture",
                        fake_capture("", status=302, headers={"Location": payload}))
    rec = vf.verify(d, marker_override=payload, env={})
    assert rec["verdict"] == vf.PROVEN and rec["reportable"] is True


# ---------------------------------------------------------------------------
# Review fix 3 — SSRF initial-host guard + requested test gaps
# ---------------------------------------------------------------------------


def test_initial_host_guard_holds_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(vf, "initial_host_blocked", _REAL_HOST_GUARD)  # real guard
    d = make_bundle(tmp_path, host="169.254.169.254", resp_body="flag")
    sent = {"n": 0}
    monkeypatch.setattr(poc, "capture", lambda *a, **k: sent.__setitem__("n", 1))
    rec = vf.verify(d, marker_override="flag", env={})
    assert rec["verdict"] == vf.INCONCLUSIVE
    assert sent["n"] == 0  # never sent to cloud metadata


def test_confirm_unsafe_actually_refires(tmp_path, monkeypatch):
    """The positive path: with --confirm-unsafe, a mutating method IS re-sent."""
    d = make_bundle(tmp_path, method="DELETE", resp_body="gonezo")
    sent = {"n": 0}
    monkeypatch.setattr(poc, "capture",
                        lambda *a, **k: sent.__setitem__("n", 1) or fake_capture("gonezo")(*a, **k))
    rec = vf.verify(d, marker_override="gonezo", confirm_unsafe=True, env={})
    assert sent["n"] == 1                     # it re-fired
    assert rec["verdict"] == vf.PROVEN


def test_load_marker_precedence():
    # override wins over manifest wins over sidecar
    assert vf.load_marker("/nope", {"marker": "m"}, override="o") == "o"
    assert vf.load_marker("/nope", {"marker": "m"}) == "m"


def test_load_marker_sidecar(tmp_path):
    (tmp_path / "marker.txt").write_text("side", encoding="utf-8")
    assert vf.load_marker(str(tmp_path), {}) == "side"
    # manifest field beats the sidecar
    assert vf.load_marker(str(tmp_path), {"marker": "m"}) == "m"


def test_find_bundles_filters_schema(tmp_path):
    good = tmp_path / "a" / "evidence" / "F1"
    good.mkdir(parents=True)
    (good / "bundle.json").write_text(json.dumps({"schema": "poc-bundle/1"}), encoding="utf-8")
    bad = tmp_path / "b"
    bad.mkdir()
    (bad / "bundle.json").write_text(json.dumps({"schema": "other"}), encoding="utf-8")
    found = vf.find_bundles(str(tmp_path))
    assert str(good) in found and str(bad) not in found
