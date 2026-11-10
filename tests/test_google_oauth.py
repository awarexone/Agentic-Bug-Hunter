"""Tests for Google OAuth 2.0 and Antigravity (Gemini AI) integration."""

import json
from pathlib import Path
from types import SimpleNamespace

from tools.google_oauth import (
    ANTIGRAVITY_MODEL_LABELS,
    DEFAULT_ANTIGRAVITY_MODELS,
    _extract_code_from_input,
    _generate_pkce_pair,
    clear_oauth_credentials,
    list_antigravity_models,
    load_oauth_credentials,
    resolve_antigravity_model,
    save_oauth_credentials,
)


def test_pkce_generation():
    verifier, challenge = _generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43
    assert "=" not in verifier
    assert "=" not in challenge


def test_extract_code_from_raw_code():
    code = "4/0Axxxxxxxxxxxxxx"
    assert _extract_code_from_input(code) == code
    assert _extract_code_from_input(f"  {code}  ") == code


def test_extract_code_from_redirected_url():
    url = "http://127.0.0.1:45123/oauth2callback?code=4%2F0Atestcode123&state=xyz123"
    assert _extract_code_from_input(url) == "4/0Atestcode123"

    url_localhost = "http://localhost:8080/auth/callback?state=abc&code=auth_code_999"
    assert _extract_code_from_input(url_localhost) == "auth_code_999"


def test_resolve_antigravity_model_defaults():
    assert resolve_antigravity_model(None) == "gemini-4-argon-high"
    assert resolve_antigravity_model("gemini-2.5-pro") == "gemini-4-argon-high"
    assert resolve_antigravity_model("gemini-2.5-flash") == "gemini-3.8-flash-high"
    assert resolve_antigravity_model("claude-sonnet-4-6") == "claude-sonnet-4-6"


def test_credentials_lifecycle(tmp_path, monkeypatch):
    test_file = tmp_path / "google_oauth.json"
    gemini_file = tmp_path / "gemini_oauth.json"

    import tools.google_oauth as oauth_mod
    monkeypatch.setattr(oauth_mod, "BUGHUNTER_OAUTH_FILE", test_file)
    monkeypatch.setattr(oauth_mod, "GEMINI_CLI_OAUTH_FILE", gemini_file)

    assert load_oauth_credentials() is None

    sample_creds = {
        "access_token": "ya29.sample",
        "refresh_token": "1//sample",
        "email": "test@example.com",
    }
    save_oauth_credentials(sample_creds, also_sync_gemini_cli=True)

    loaded = load_oauth_credentials()
    assert loaded is not None
    assert loaded["email"] == "test@example.com"
    assert loaded["access_token"] == "ya29.sample"

    assert test_file.exists()
    assert gemini_file.exists()

    assert clear_oauth_credentials() is True
    assert not test_file.exists()


def test_list_antigravity_models_fallback(monkeypatch):
    import tools.google_oauth as oauth_mod
    monkeypatch.setattr(oauth_mod, "find_agy_binary", lambda: None)

    models = list_antigravity_models()
    assert "gemini-3.8-flash-high" in models
    assert "claude-sonnet-4-6" in models
    assert "claude-sonnet-5-5-medium" in models
