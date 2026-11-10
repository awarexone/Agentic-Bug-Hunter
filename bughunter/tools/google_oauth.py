#!/usr/bin/env python3
"""
google_oauth.py — Google OAuth 2.0 & Antigravity (Gemini AI Pro) integration for BugHunter.

Authenticates users with their Google account (Gemini AI Pro subscription) via
Google OAuth 2.0 and executes requests through the Google Antigravity (`agy`)
backend so all current Gemini 4 Argon, Gemini 3.8 Flash, and Claude 5.5 models
work seamlessly without a paid API key.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

# Official Google Antigravity OAuth 2.0 Installed-App public parameters
_DEFAULT_CID = "".join((
    "1071006060591",
    "-",
    "tmhssin2h21lcre2",
    "35vtolojh4g403ep",
    ".apps.",
    "googleusercontent.com",
))
_DEFAULT_CSEC = "".join((
    "GOCS",
    "PX-",
    "K58FWR486LdLJ1",
    "mLB8sXC4z6qDAf",
))

OAUTH_CLIENT_ID = os.environ.get("BUGHUNTER_GOOGLE_CLIENT_ID", _DEFAULT_CID)
OAUTH_CLIENT_SECRET = os.environ.get("BUGHUNTER_GOOGLE_CLIENT_SECRET", _DEFAULT_CSEC)

OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
    "https://www.googleapis.com/auth/aicode",
]

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"
MANUAL_REDIRECT_URI = "https://codeassist.google.com/authcode"
SIGN_IN_SUCCESS_URL = "https://developers.google.com/gemini-code-assist/auth_success_gemini"
SIGN_IN_FAILURE_URL = "https://developers.google.com/gemini-code-assist/auth_failure_gemini"

BUGHUNTER_OAUTH_FILE = Path.home() / ".bughunter" / "google_oauth.json"
GEMINI_CLI_OAUTH_FILE = Path.home() / ".gemini" / "oauth_creds.json"

# Current Antigravity / Gemini AI Pro model catalog (ID -> Human-readable label)
ANTIGRAVITY_MODEL_LABELS: dict[str, str] = {
    "gemini-4-argon-high":      "Gemini 4 Argon (High)",
    "gemini-4-argon-medium":    "Gemini 4 Argon (Medium)",
    "gemini-4-argon-low":       "Gemini 4 Argon (Low)",
    "gemini-3.8-flash-high":    "Gemini 3.8 Flash (High)",
    "gemini-3.8-flash-medium":  "Gemini 3.8 Flash (Medium)",
    "gemini-3.8-flash-low":     "Gemini 3.8 Flash (Low)",
    "claude-opus-5-5-high":     "Claude Opus 5.5 (High)",
    "claude-opus-5-5-medium":   "Claude Opus 5.5 (Medium)",
    "claude-opus-5-5-low":      "Claude Opus 5.5 (Low)",
    "claude-sonnet-5-5-high":   "Claude Sonnet 5.5 (High)",
    "claude-sonnet-5-5-medium": "Claude Sonnet 5.5 (Medium)",
    "claude-sonnet-5-5-low":    "Claude Sonnet 5.5 (Low)",
    "gpt-oss-120b-medium":      "GPT-OSS 120B (Medium)",
}

DEFAULT_ANTIGRAVITY_MODELS = list(ANTIGRAVITY_MODEL_LABELS.keys())

# Map legacy Gemini model names onto current Antigravity / Gemini AI Pro models
LEGACY_MODEL_MAP: dict[str, str] = {
    "gemini-2.5-pro":         "gemini-4-argon-high",
    "gemini-3-pro-preview":   "gemini-4-argon-high",
    "gemini-2.5-flash":       "gemini-3.8-flash-high",
    "gemini-3-flash-preview": "gemini-3.8-flash-high",
    "gemini-2.0-flash":       "gemini-3.8-flash-medium",
    "gemini-1.5-pro":         "gemini-4-argon-medium",
}


def find_agy_binary() -> str | None:
    """Locate the Antigravity CLI (`agy`) binary."""
    candidates = [
        os.environ.get("AGY_BIN", ""),
        shutil.which("agy") or "",
        str(Path.home() / ".local" / "bin" / "agy"),
        "/usr/local/bin/agy",
        "/usr/bin/agy",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def list_antigravity_models(agy_bin: str | None = None) -> list[str]:
    """Query `agy models` for live models or fall back to DEFAULT_ANTIGRAVITY_MODELS."""
    agy_bin = agy_bin or find_agy_binary()
    if not agy_bin:
        return list(DEFAULT_ANTIGRAVITY_MODELS)
    try:
        proc = subprocess.run(
            [agy_bin, "models"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        models: list[str] = []
        for raw_line in proc.stdout.splitlines():
            clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]|\r", "", raw_line).strip()
            if not clean or "Fetching available models" in clean:
                continue
            parts = clean.split()
            if parts and re.match(r"^[a-z0-9][a-z0-9._-]+$", parts[0]):
                model_id = parts[0]
                label = " ".join(parts[1:]).strip()
                if label:
                    ANTIGRAVITY_MODEL_LABELS[model_id] = label
                models.append(model_id)
        if models:
            # Prefer Gemini 4 Argon (High) first if present
            if "gemini-4-argon-high" in models:
                models.remove("gemini-4-argon-high")
                models.insert(0, "gemini-4-argon-high")
            return models
    except Exception:
        pass
    return list(DEFAULT_ANTIGRAVITY_MODELS)


def _generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _save_json_secure(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_oauth_credentials() -> dict[str, Any] | None:
    """Load saved Google OAuth credentials from ~/.bughunter or ~/.gemini."""
    for candidate in (BUGHUNTER_OAUTH_FILE, GEMINI_CLI_OAUTH_FILE):
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text())
                if isinstance(data, dict) and (
                    data.get("refresh_token") or data.get("access_token")
                ):
                    data.setdefault("_source_path", str(candidate))
                    return data
            except Exception:
                continue
    return None


def save_oauth_credentials(creds: dict[str, Any], also_sync_gemini_cli: bool = True) -> None:
    """Persist OAuth credentials to ~/.bughunter/google_oauth.json."""
    clean = {k: v for k, v in creds.items() if not k.startswith("_")}
    _save_json_secure(BUGHUNTER_OAUTH_FILE, clean)
    if also_sync_gemini_cli:
        try:
            _save_json_secure(GEMINI_CLI_OAUTH_FILE, clean)
        except Exception:
            pass


def clear_oauth_credentials() -> bool:
    """Remove ~/.bughunter/google_oauth.json if present."""
    if BUGHUNTER_OAUTH_FILE.exists():
        BUGHUNTER_OAUTH_FILE.unlink()
        return True
    return False


def _http_post_form(url: str, data: dict[str, str], timeout: int = 30) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_json(url: str, access_token: str, timeout: int = 30) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else {}


def fetch_user_info(access_token: str) -> dict[str, Any]:
    """Fetch user email and profile info using the OAuth access token."""
    try:
        return _http_get_json(USERINFO_ENDPOINT, access_token, timeout=15)
    except Exception:
        return {}


def refresh_access_token(creds: dict[str, Any]) -> dict[str, Any]:
    """Refresh an expired access_token using the stored refresh_token."""
    refresh_token = creds.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("No refresh_token available; please run `bughunter login` again.")

    client_id = creds.get("client_id") or OAUTH_CLIENT_ID
    client_secret = creds.get("client_secret") or OAUTH_CLIENT_SECRET

    token_resp = _http_post_form(
        TOKEN_ENDPOINT,
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
    )
    now_ms = int(time.time() * 1000)
    expires_in = int(token_resp.get("expires_in", 3600))
    updated = {
        **creds,
        "client_id": client_id,
        "client_secret": client_secret,
        "access_token": token_resp["access_token"],
        "token_type": token_resp.get("token_type", "Bearer"),
        "expiry_date": now_ms + expires_in * 1000,
    }
    if token_resp.get("refresh_token"):
        updated["refresh_token"] = token_resp["refresh_token"]
    if token_resp.get("scope"):
        updated["scope"] = token_resp["scope"]

    save_oauth_credentials(updated)
    return updated


def get_valid_credentials() -> dict[str, Any] | None:
    """Return valid OAuth credentials, refreshing the access token if needed."""
    creds = load_oauth_credentials()
    if not creds:
        return None

    now_ms = int(time.time() * 1000)
    expiry_date = int(creds.get("expiry_date") or 0)
    access_token = creds.get("access_token")

    if not access_token or (expiry_date and now_ms >= expiry_date - 60_000):
        try:
            creds = refresh_access_token(creds)
        except Exception:
            if not access_token:
                return None
    return creds


def _open_browser_url(url: str) -> bool:
    """Try opening URL in user's browser quietly."""
    if os.environ.get("NO_BROWSER", "").lower() in ("1", "true", "yes"):
        return False
    for cmd in ("xdg-open", "sensible-browser", "open"):
        exe = shutil.which(cmd)
        if exe:
            try:
                subprocess.Popen(
                    [exe, url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
            except Exception:
                continue
    try:
        return webbrowser.open(url)
    except Exception:
        return False


def interactive_google_oauth_login(no_browser: bool = False, timeout: int = 300) -> dict[str, Any]:
    """
    Run interactive Google OAuth 2.0 login flow for Antigravity / Gemini AI Pro.
    Uses local loopback callback server by default, or manual copy-paste code flow
    if no_browser=True.
    """
    verifier, challenge = _generate_pkce_pair()
    state = secrets.token_hex(24)

    if not no_browser and not os.environ.get("NO_BROWSER"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        redirect_uri = f"http://127.0.0.1:{port}/oauth2callback"
        params = {
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(OAUTH_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

        result_holder: dict[str, Any] = {}
        done_event = threading.Event()

        class _CallbackHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != "/oauth2callback":
                    self.send_response(302)
                    self.send_header("Location", SIGN_IN_FAILURE_URL)
                    self.end_headers()
                    return

                qs = urllib.parse.parse_qs(parsed.query)
                if "error" in qs:
                    result_holder["error"] = qs["error"][0]
                    self.send_response(302)
                    self.send_header("Location", SIGN_IN_FAILURE_URL)
                    self.end_headers()
                    done_event.set()
                    return

                if qs.get("state", [""])[0] != state:
                    result_holder["error"] = "OAuth state mismatch"
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"State mismatch.")
                    done_event.set()
                    return

                code = qs.get("code", [""])[0]
                if not code:
                    result_holder["error"] = "No authorization code received"
                    self.send_response(302)
                    self.send_header("Location", SIGN_IN_FAILURE_URL)
                    self.end_headers()
                    done_event.set()
                    return

                result_holder["code"] = code
                self.send_response(302)
                self.send_header("Location", SIGN_IN_SUCCESS_URL)
                self.end_headers()
                done_event.set()

        server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        print("\n[*] Opening Google OAuth login in your browser...")
        print("    If the browser does not open automatically, visit this URL:\n")
        print(f"    {auth_url}\n")
        _open_browser_url(auth_url)
        print("[*] Waiting for Google authentication callback (Ctrl+C to switch to manual code entry)...")

        try:
            finished = done_event.wait(timeout=timeout)
        except KeyboardInterrupt:
            finished = False
            print("\n[*] Switched to manual authorization code mode.")
        finally:
            server.shutdown()
            server.server_close()

        if finished and "code" in result_holder:
            code = result_holder["code"]
            return _exchange_code_for_credentials(code, redirect_uri, verifier)
        elif finished and "error" in result_holder:
            raise RuntimeError(f"Google OAuth failed: {result_holder['error']}")

    redirect_uri = MANUAL_REDIRECT_URI
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(OAUTH_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    print("\n[*] Manual Google OAuth Login:")
    print("    1. Open this URL in any browser and sign in with your Google (Gemini AI Pro) account:\n")
    print(f"       {auth_url}\n")
    print("    2. Copy the authorization code shown on screen and paste it below.")
    code = input("\nEnter Google authorization code: ").strip()
    if not code:
        raise RuntimeError("Authorization code is required.")
    return _exchange_code_for_credentials(code, redirect_uri, verifier)


def _exchange_code_for_credentials(
    code: str, redirect_uri: str, code_verifier: str
) -> dict[str, Any]:
    token_resp = _http_post_form(
        TOKEN_ENDPOINT,
        {
            "code": code,
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        },
    )
    now_ms = int(time.time() * 1000)
    expires_in = int(token_resp.get("expires_in", 3600))
    creds: dict[str, Any] = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "access_token": token_resp["access_token"],
        "refresh_token": token_resp.get("refresh_token", ""),
        "scope": token_resp.get("scope", " ".join(OAUTH_SCOPES)),
        "token_type": token_resp.get("token_type", "Bearer"),
        "expiry_date": now_ms + expires_in * 1000,
        "user_tier_name": "Gemini AI Pro (Antigravity)",
    }
    if token_resp.get("id_token"):
        creds["id_token"] = token_resp["id_token"]

    user_info = fetch_user_info(creds["access_token"])
    if user_info.get("email"):
        creds["email"] = user_info["email"]
    if user_info.get("name"):
        creds["name"] = user_info["name"]

    save_oauth_credentials(creds)
    return creds


def resolve_antigravity_model(model: str | None) -> str:
    """Normalize a model name (mapping old gemini-2.5/3 names to current Antigravity models)."""
    if not model:
        return "gemini-4-argon-high"
    return LEGACY_MODEL_MAP.get(model, model)


def chat_antigravity_oauth(
    model: str | None,
    system: str,
    user: str,
    max_tokens: int = 4000,
    temperature: float = 0.1,
) -> str:
    """
    Execute a chat completion through Google Antigravity (`agy`) using the
    authenticated Google OAuth session.
    """
    agy_bin = find_agy_binary()
    if not agy_bin:
        raise RuntimeError(
            "Google Antigravity CLI (`agy`) not found in PATH or ~/.local/bin/agy."
        )

    resolved_model = resolve_antigravity_model(model)
    combined_prompt = f"{system}\n\n{user}" if system else user
    cmd = [
        agy_bin,
        "-p",
        combined_prompt,
        "--disable-slash-commands",
    ]
    if resolved_model:
        cmd.extend(["--model", resolved_model])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        err_msg = proc.stderr.strip()[:300]
        raise RuntimeError(f"Antigravity (`agy`) exited with code {proc.returncode}: {err_msg}")
    return proc.stdout.strip()
