"""Tests for tools/poc_bundler.py — the PoC evidence bundler.

Exercises the pure artifact builders, raw-HTTP parsers, redaction, and the
offline `from-request` CLI path end-to-end (no network). `tools/` is on
sys.path via tests/conftest.py.
"""

import json
import os

import pytest

import poc_bundler as pb


def _ex(**over):
    base = dict(
        method="GET",
        url="https://api.acme.com/v1/users/1?admin=true",
        request_headers=[("Host", "api.acme.com"),
                         ("Authorization", "Bearer secret-token-123"),
                         ("Cookie", "session=abc123"),
                         ("Accept", "application/json")],
        request_body="",
        response_status=200,
        response_reason="OK",
        response_headers=[("Content-Type", "application/json"),
                          ("Set-Cookie", "session=rotated; HttpOnly")],
        response_body='{"id":1,"email":"victim@acme.com","role":"admin"}',
        response_body_bytes=b'{"id":1,"email":"victim@acme.com","role":"admin"}',
        started_at="2026-09-20T10:00:00Z",
        elapsed_ms=42,
    )
    base.update(over)
    return pb.Exchange(**base)


# ---------------------------------------------------------------------------
# Redaction — the security-critical part.
# ---------------------------------------------------------------------------


def test_sensitive_header_detection():
    assert pb.is_sensitive("Authorization")
    assert pb.is_sensitive("cookie")
    assert pb.is_sensitive("X-API-Key")
    assert not pb.is_sensitive("Accept")
    assert not pb.is_sensitive("Content-Type")


def test_collect_secrets_maps_env_vars():
    secrets = pb.collect_secrets(_ex().request_headers)
    assert secrets == {"AUTHORIZATION": "Bearer secret-token-123", "COOKIE": "session=abc123"}


def test_display_headers_redacts_by_default():
    disp = dict(pb.display_headers(_ex().request_headers, redact=True))
    assert "secret-token-123" not in disp["Authorization"]
    assert disp["Authorization"] == "‹redacted:$AUTHORIZATION›"
    assert disp["Accept"] == "application/json"  # non-sensitive untouched


def test_no_redact_keeps_raw_values():
    disp = dict(pb.display_headers(_ex().request_headers, redact=False))
    assert disp["Authorization"] == "Bearer secret-token-123"


def test_secrets_never_leak_into_any_default_artifact():
    ex = _ex()
    blob = "\n".join([
        pb.build_raw_request(ex, redact=True),
        pb.build_raw_response(ex, redact=True),
        pb.build_curl(ex, redact=True),
        json.dumps(pb.build_har(ex, redact=True)),
        pb.render_evidence_md(pb.Meta(), ex, [], redact=True),
    ])
    assert "secret-token-123" not in blob
    assert "session=abc123" not in blob
    assert "session=rotated" not in blob  # Set-Cookie in response redacted too


# ---------------------------------------------------------------------------
# curl / repro
# ---------------------------------------------------------------------------


def test_build_curl_uses_env_placeholders_when_redacted():
    sh = pb.build_curl(_ex(), redact=True)
    assert '-H "Authorization: $AUTHORIZATION"' in sh
    assert "export AUTHORIZATION=" in sh  # guidance comment present
    assert "secret-token-123" not in sh
    assert "'https://api.acme.com/v1/users/1?admin=true'" in sh


def test_build_curl_post_includes_method_and_body():
    sh = pb.build_curl(_ex(method="POST", request_body='{"x":1}'), redact=True)
    assert "-X POST" in sh
    assert "--data-raw" in sh


def test_build_curl_get_omits_dash_x():
    assert "-X GET" not in pb.build_curl(_ex(), redact=True)


def test_curl_single_quote_escaping():
    ex = _ex(request_headers=[("X-Note", "it's a test")])
    sh = pb.build_curl(ex, redact=True)
    assert "'\\''" in sh  # embedded single quote is POSIX-escaped


# ---------------------------------------------------------------------------
# raw request / response
# ---------------------------------------------------------------------------


def test_build_raw_request_shape():
    raw = pb.build_raw_request(_ex(), redact=True)
    assert raw.splitlines()[0] == "GET /v1/users/1?admin=true HTTP/1.1"
    assert "Host: api.acme.com" in raw


def test_build_raw_response_truncation_note():
    big = "A" * (pb.MAX_BODY_BYTES + 100)
    ex = _ex(response_body=big, response_body_bytes=big.encode())
    out = pb.build_raw_response(ex, redact=True)
    assert "truncated" in out


def test_raw_response_when_not_captured():
    ex = _ex(response_status=None)
    assert "[response not captured]" in pb.build_raw_response(ex, redact=True)


# ---------------------------------------------------------------------------
# HAR
# ---------------------------------------------------------------------------


def test_har_is_valid_1_2_structure():
    har = pb.build_har(_ex(), redact=True)
    log = har["log"]
    assert log["version"] == "1.2"
    entry = log["entries"][0]
    assert entry["request"]["method"] == "GET"
    assert entry["response"]["status"] == 200
    # query string parsed out of the URL
    names = {q["name"] for q in entry["request"]["queryString"]}
    assert "admin" in names


def test_har_content_hashable_and_sized():
    har = pb.build_har(_ex(), redact=True)
    content = har["log"]["entries"][0]["response"]["content"]
    assert content["size"] == len(_ex().response_body_bytes)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def test_manifest_hashes_full_response_body():
    m = pb.build_manifest(pb.Meta(target="acme.com", vuln_class="idor"), _ex(),
                          ["request.http"], redact=True)
    assert m["schema"] == "poc-bundle/1"
    assert m["exchange"]["response_sha256"] == pb.sha256_hex(_ex().response_body_bytes)
    assert m["finding"]["target"] == "acme.com"


# ---------------------------------------------------------------------------
# raw HTTP parsers (from-request)
# ---------------------------------------------------------------------------


def test_parse_raw_request_origin_form_builds_url():
    raw = "GET /account?id=7 HTTP/1.1\r\nHost: app.acme.com\r\nAccept: */*\r\n\r\n"
    ex = pb.parse_raw_request(raw, scheme="https")
    assert ex.method == "GET"
    assert ex.url == "https://app.acme.com/account?id=7"
    assert ("Host", "app.acme.com") in ex.request_headers


def test_parse_raw_request_absolute_uri():
    raw = "POST https://api.acme.com/pay HTTP/1.1\nContent-Type: application/json\n\n{\"amt\":1}"
    ex = pb.parse_raw_request(raw)
    assert ex.url == "https://api.acme.com/pay"
    assert ex.method == "POST"
    assert ex.request_body == '{"amt":1}'


def test_parse_raw_request_requires_url_source():
    with pytest.raises(ValueError):
        pb.parse_raw_request("GET /x HTTP/1.1\nAccept: */*\n\n")  # no Host, not absolute


def test_parse_raw_response():
    raw = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>nope</h1>"
    status, reason, headers, body = pb.parse_raw_response(raw)
    assert status == 403
    assert reason == "Forbidden"
    assert ("Content-Type", "text/html") in headers
    assert body == "<h1>nope</h1>"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_slugify():
    assert pb.slugify("Acme Corp!!") == "acme-corp"
    assert pb.slugify("") == "target"
    assert pb.slugify("", default="finding") == "finding"


def test_env_var_for():
    assert pb.env_var_for("X-Api-Key") == "X_API_KEY"
    assert pb.env_var_for("Authorization") == "AUTHORIZATION"


# ---------------------------------------------------------------------------
# CLI — offline from-request path writes a complete bundle.
# ---------------------------------------------------------------------------


def test_cli_from_request_writes_full_bundle(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text("GET /users/1 HTTP/1.1\nHost: api.acme.com\n"
                   "Authorization: Bearer LEAKME\n\n", encoding="utf-8")
    resp = tmp_path / "resp.txt"
    resp.write_text("HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
                    '{"id":1,"role":"admin"}', encoding="utf-8")
    out = tmp_path / "bundle"
    rc = pb.main(["from-request", str(req), "--response", str(resp),
                  "--target", "acme.com", "--vuln-class", "idor",
                  "--severity", "high", "--finding-id", "F-1", "-o", str(out)])
    assert rc == 0
    for name in ("request.http", "response.http", "repro.sh", "evidence.har",
                 "evidence.md", "bundle.json"):
        assert (out / name).exists(), f"missing {name}"
    # redaction held through the whole pipeline
    assert "LEAKME" not in (out / "evidence.md").read_text(encoding="utf-8")
    assert "LEAKME" not in (out / "request.http").read_text(encoding="utf-8")
    manifest = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert manifest["finding"]["severity"] == "high"
    assert manifest["exchange"]["response_status"] == 200


def test_bundle_file_list_has_no_duplicates(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text("GET / HTTP/1.1\nHost: acme.com\n\n", encoding="utf-8")
    out = tmp_path / "b"
    pb.main(["from-request", str(req), "-o", str(out)])
    files = json.loads((out / "bundle.json").read_text(encoding="utf-8"))["files"]
    assert files == sorted(set(files), key=files.index)  # no dupes, order preserved
    assert set(files) == {"request.http", "response.http", "repro.sh",
                          "evidence.har", "evidence.md", "bundle.json"}


def test_cli_rejects_bad_severity(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text("GET / HTTP/1.1\nHost: acme.com\n\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        pb.main(["from-request", str(req), "--severity", "spicy", "-o", str(tmp_path / "b")])


def test_cli_capture_blocks_unsafe_method_without_flag(capsys):
    rc = pb.main(["capture", "https://acme.com/x", "-X", "DELETE"])
    assert rc == 2
    assert "confirm-unsafe" in capsys.readouterr().err


def test_no_redact_keeps_secret_in_bundle(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text("GET /x HTTP/1.1\nHost: acme.com\nAuthorization: Bearer KEEPME\n\n",
                   encoding="utf-8")
    out = tmp_path / "b"
    pb.main(["from-request", str(req), "--no-redact", "-o", str(out)])
    assert "KEEPME" in (out / "request.http").read_text(encoding="utf-8")
