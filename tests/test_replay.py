"""Tests for tools/replay.py — finding replay / regression.

The pure core (decide_verdict, resolve_headers, render_report) is tested
directly. replay_one and the CLI are tested offline by monkeypatching
poc_bundler.capture, and bundles are built on disk with poc_bundler's own
offline `from-request` path. `bughunter/tools` is on sys.path via conftest.
"""

import json
import os

import pytest

import poc_bundler as poc
import replay as rp


# ---------------------------------------------------------------------------
# Helpers — build a real PoC bundle offline, then replay it.
# ---------------------------------------------------------------------------


def make_bundle(tmp_path, *, method="GET", body="", auth=True,
                resp_status="200 OK", resp_body='{"email":"victim@acme.com"}'):
    tmp_path.mkdir(parents=True, exist_ok=True)
    req_lines = [f"{method} /users/1 HTTP/1.1", "Host: api.acme.com"]
    if auth:
        req_lines.append("Authorization: Bearer SECRET")
    req = "\n".join(req_lines) + "\n\n" + body
    resp = f"HTTP/1.1 {resp_status}\nContent-Type: application/json\n\n{resp_body}"
    reqf, respf = tmp_path / "req.txt", tmp_path / "resp.txt"
    reqf.write_text(req, encoding="utf-8")
    respf.write_text(resp, encoding="utf-8")
    out = tmp_path / "bundle"
    poc.main(["from-request", str(reqf), "--response", str(respf),
              "--target", "acme.com", "--vuln-class", "idor",
              "--finding-id", "F-1", "-o", str(out)])
    return str(out)


def fake_capture_returning(body, status=200):
    """A poc.capture stand-in that returns a fixed response, no network."""
    def _cap(url, method, headers, reqbody, timeout):
        raw = body.encode("utf-8")
        return poc.Exchange(method=method, url=url, response_status=status,
                            response_reason="OK", response_body=body,
                            response_body_bytes=raw)
    return _cap


# ---------------------------------------------------------------------------
# decide_verdict — the heart, all branches
# ---------------------------------------------------------------------------


def test_verdict_unreachable():
    v = rp.decide_verdict(200, "sha", "marker", rp.Observed(reachable=False, error="dns"))
    assert v.verdict == rp.UNREACHABLE


def test_verdict_marker_present_is_still_vulnerable():
    obs = rp.Observed(reachable=True, status=200, body='...victim@acme.com...')
    v = rp.decide_verdict(200, "sha", "victim@acme.com", obs)
    assert v.verdict == rp.STILL_VULNERABLE
    assert v.confidence == "confirmed"


def test_verdict_marker_absent_is_fixed():
    obs = rp.Observed(reachable=True, status=403, body="access denied")
    v = rp.decide_verdict(200, "sha", "victim@acme.com", obs)
    assert v.verdict == rp.FIXED
    assert v.confidence == "confirmed"


def test_verdict_no_marker_identical_is_still_vulnerable_heuristic():
    obs = rp.Observed(reachable=True, status=200, sha256="abc")
    v = rp.decide_verdict(200, "abc", None, obs)
    assert v.verdict == rp.STILL_VULNERABLE
    assert v.confidence == "heuristic"


def test_verdict_no_marker_changed():
    obs = rp.Observed(reachable=True, status=404, sha256="different")
    v = rp.decide_verdict(200, "abc", None, obs)
    assert v.verdict == rp.CHANGED
    assert v.confidence == "heuristic"


def test_verdict_no_marker_no_baseline_is_indeterminate():
    obs = rp.Observed(reachable=True, status=200, sha256="abc")
    v = rp.decide_verdict(None, None, None, obs)
    assert v.verdict == rp.INDETERMINATE


def test_verdict_never_claims_fixed_without_a_marker():
    """A hash mismatch alone must not be reported as FIXED (could be dynamic content)."""
    obs = rp.Observed(reachable=True, status=200, sha256="x")
    v = rp.decide_verdict(200, "y", None, obs)
    assert v.verdict != rp.FIXED


# ---------------------------------------------------------------------------
# resolve_headers
# ---------------------------------------------------------------------------


def test_resolve_headers_substitutes_env_secret():
    headers = [("Host", "acme.com"), ("Authorization", "‹redacted:$AUTHORIZATION›")]
    resolved, missing = rp.resolve_headers(headers, {"AUTHORIZATION": "Bearer real"})
    assert ("Authorization", "Bearer real") in resolved
    assert missing == []


def test_resolve_headers_reports_missing_secret():
    headers = [("Authorization", "‹redacted:$AUTHORIZATION›")]
    resolved, missing = rp.resolve_headers(headers, {})
    assert missing == ["AUTHORIZATION"]
    assert resolved == []  # unresolved secret is dropped, not sent blank


def test_resolve_headers_passthrough_plain():
    headers = [("Accept", "application/json")]
    resolved, missing = rp.resolve_headers(headers, {})
    assert resolved == headers and missing == []


# ---------------------------------------------------------------------------
# marker + bundle discovery
# ---------------------------------------------------------------------------


def test_marker_sidecar_and_manifest(tmp_path):
    d = tmp_path / "b"
    d.mkdir()
    assert rp.load_marker(str(d), {}) is None
    rp.save_marker(str(d), "leaked@x.com")
    assert rp.load_marker(str(d), {}) == "leaked@x.com"
    # manifest field wins over sidecar
    assert rp.load_marker(str(d), {"marker": "from-manifest"}) == "from-manifest"


def test_find_bundles_only_matches_poc_schema(tmp_path):
    good = make_bundle(tmp_path / "g")
    (tmp_path / "decoy").mkdir()
    (tmp_path / "decoy" / "bundle.json").write_text('{"schema":"other"}', encoding="utf-8")
    found = rp.find_bundles(str(tmp_path))
    assert good in found
    assert not any("decoy" in f for f in found)


def test_load_bundle_reads_baseline_and_request(tmp_path):
    d = make_bundle(tmp_path)
    b = rp.load_bundle(d)
    assert b["exchange"].method == "GET"
    assert b["exchange"].url == "https://api.acme.com/users/1"
    assert b["baseline_status"] == 200
    assert b["baseline_sha"] is not None


def test_load_bundle_trusts_manifest_url_scheme(tmp_path):
    """request.http loses the scheme; the manifest URL is authoritative so an
    http:// finding isn't replayed over https (the WRONG_VERSION_NUMBER trap)."""
    d = make_bundle(tmp_path)
    mpath = os.path.join(d, "bundle.json")
    manifest = json.loads(open(mpath, encoding="utf-8").read())
    manifest["exchange"]["url"] = "http://api.acme.com:8080/users/1"
    open(mpath, "w", encoding="utf-8").write(json.dumps(manifest))
    assert rp.load_bundle(d)["exchange"].url == "http://api.acme.com:8080/users/1"


# ---------------------------------------------------------------------------
# replay_one (offline via monkeypatch)
# ---------------------------------------------------------------------------


def test_replay_unsafe_method_is_skipped(tmp_path):
    d = make_bundle(tmp_path, method="DELETE", auth=False)
    r = rp.replay_one(d, timeout=5, confirm_unsafe=False, marker_override=None)
    assert r["verdict"] == rp.SKIPPED_UNSAFE


def test_replay_missing_secret_is_indeterminate(tmp_path):
    d = make_bundle(tmp_path, auth=True)  # request.http has redacted Authorization
    r = rp.replay_one(d, timeout=5, confirm_unsafe=False, marker_override=None, env={})
    assert r["verdict"] == rp.INDETERMINATE
    assert "AUTHORIZATION" in r["detail"]


def test_replay_still_vulnerable_via_marker(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, auth=False, resp_body='{"email":"victim@acme.com"}')
    monkeypatch.setattr(poc, "capture", fake_capture_returning('{"email":"victim@acme.com"}'))
    r = rp.replay_one(d, timeout=5, confirm_unsafe=False,
                      marker_override="victim@acme.com", env={})
    assert r["verdict"] == rp.STILL_VULNERABLE
    assert r["observed"]["reachable"] is True


def test_replay_fixed_via_marker(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, auth=False)
    monkeypatch.setattr(poc, "capture", fake_capture_returning("Access Denied", status=403))
    r = rp.replay_one(d, timeout=5, confirm_unsafe=False,
                      marker_override="victim@acme.com", env={})
    assert r["verdict"] == rp.FIXED


def test_replay_unreachable(tmp_path, monkeypatch):
    import urllib.error
    d = make_bundle(tmp_path, auth=False)

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr(poc, "capture", boom)
    r = rp.replay_one(d, timeout=5, confirm_unsafe=False, marker_override=None, env={})
    assert r["verdict"] == rp.UNREACHABLE
    assert r["observed"]["reachable"] is False


def test_replay_bad_bundle_is_error(tmp_path):
    (tmp_path / "empty").mkdir()
    r = rp.replay_one(str(tmp_path / "empty"), timeout=5, confirm_unsafe=False,
                      marker_override=None)
    assert r["verdict"] == rp.ERROR


def test_replay_writes_no_secret_into_replay_json(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, auth=True, resp_body="ok")
    monkeypatch.setattr(poc, "capture", fake_capture_returning("ok"))
    r = rp.replay_one(d, timeout=5, confirm_unsafe=False, marker_override=None,
                      env={"AUTHORIZATION": "Bearer TOPSECRET"})
    assert "TOPSECRET" not in json.dumps(r)


# ---------------------------------------------------------------------------
# render_report
# ---------------------------------------------------------------------------


def test_render_report_counts_and_orders():
    results = [
        {"verdict": rp.FIXED, "confidence": "confirmed", "detail": "gone", "dir": "a",
         "finding": {"finding_id": "F-2", "target": "acme.com"}},
        {"verdict": rp.STILL_VULNERABLE, "confidence": "confirmed", "detail": "present",
         "dir": "b", "finding": {"finding_id": "F-1", "target": "acme.com"}},
    ]
    md = rp.render_report(results)
    assert "STILL_VULNERABLE:1" in md and "FIXED:1" in md
    # most-severe first: STILL_VULNERABLE row appears before FIXED row
    assert md.index("F-1") < md.index("F-2")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_run_writes_replay_json_and_exit_code(tmp_path, monkeypatch):
    d = make_bundle(tmp_path, auth=False, resp_body="pwned")
    monkeypatch.setattr(poc, "capture", fake_capture_returning("pwned"))
    rc = rp.main(["run", d, "--marker", "pwned", "--fail-if-vulnerable"])
    assert rc == 3  # STILL_VULNERABLE + fail flag
    saved = json.loads((tmp_path / "bundle" / "replay.json").read_text(encoding="utf-8"))
    assert saved["schema"] == "replay/1"
    assert saved["verdict"] == rp.STILL_VULNERABLE
    # marker persisted for future sweeps
    assert (tmp_path / "bundle" / "marker.txt").read_text(encoding="utf-8") == "pwned"


def test_cli_all_sweep_writes_report(tmp_path, monkeypatch):
    make_bundle(tmp_path / "b1", auth=False, resp_body="x")
    monkeypatch.setattr(poc, "capture", fake_capture_returning("x"))
    rc = rp.main(["all", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "regression-report.md").exists()
    assert (tmp_path / "regression.json").exists()


def test_cli_all_empty_root(tmp_path, capsys):
    rc = rp.main(["all", str(tmp_path)])
    assert rc == 0
    assert "no PoC bundles" in capsys.readouterr().out
