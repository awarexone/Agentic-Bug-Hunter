"""Deterministic redaction. Secrets go away; ordinary text stays."""

from memory.redaction import redact_obj, redact_text


SECRET = "sk-abcdefghijklmnopqrstuvwxyz"
BEARER = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature12"
COOKIE = "session=SUPERSECRETCOOKIEVALUE"


def test_bearer_and_cookie_headers_removed():
    text = f"Authorization: {BEARER}\nCookie: {COOKIE}\n"
    out = redact_text(text)
    assert "eyJhbGciOiJub25lIn0" not in out
    assert "SUPERSECRETCOOKIEVALUE" not in out
    assert "REDACTED" in out


def test_json_quoted_password_removed():
    raw = '{"password": "hunter2secret", "user": "ada"}'
    out = redact_text(raw)
    assert "hunter2secret" not in out
    assert "ada" in out


def test_dict_key_and_nested_header_removed():
    obj = {
        "headers": {"Authorization": BEARER, "X-Auth-Token": SECRET, "Accept": "application/json"},
        "body": {"password": "p@ssword", "note": "hello"},
    }
    out = redact_obj(obj)
    assert SECRET not in str(out)
    assert "p@ssword" not in str(out)
    assert "eyJ" not in str(out)
    assert out["headers"]["Accept"] == "application/json"
    assert out["body"]["note"] == "hello"


def test_url_userinfo_and_query_token_removed():
    url = "https://alice:s3cret@example.com/a?token=abcdef123456&page=1"
    out = redact_text(url)
    assert "s3cret" not in out
    assert "abcdef123456" not in out
    assert "page=1" in out
    assert "example.com" in out


def test_pem_and_github_token_removed():
    pem = "-----BEGIN PRIVATE KEY-----\nMIISECRETDATA\n-----END PRIVATE KEY-----"
    gh = "ghp_" + "A" * 36
    out = redact_text(pem + " " + gh)
    assert "MIISECRETDATA" not in out
    assert gh not in out


def test_deterministic_and_idempotent():
    raw = f"api_key={SECRET} and password=hunter2"
    once = redact_text(raw)
    twice = redact_text(once)
    assert once == twice
    assert redact_text(raw) == once


def test_benign_content_preserved():
    url = "https://example.com/api/users/42"
    sentence = "The login form is on the homepage."
    assert redact_text(url) == url
    assert redact_text(sentence) == sentence


def test_email_key_redacted_prose_email_kept():
    """Object keys that are personal data are masked. A sentence that
    mentions an address is left alone — it may be the finding itself."""
    assert redact_obj({"email": "ada@example.com"})["email"] == "[REDACTED]"
    prose = "user ada@example.com was returned by the IDOR endpoint"
    assert redact_text(prose) == prose
