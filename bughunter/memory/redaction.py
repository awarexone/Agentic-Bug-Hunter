"""Centralized deterministic secret redaction.

This is the ONE authoritative redactor for the whole project. Every durable
persistence path (evidence store, agent trace, session file, memory JSONL,
export bundles, replay representations) must route data through here *before*
writing to disk. The safety boundary is:

    captured data -> redact_obj() -> durable persistence

never "persist first, redact later".

Design guarantees:
  - Deterministic: no timestamps, no randomness. Identical input -> identical
    output, so JSONL dedup keys and hash-chain digests stay stable.
  - Idempotent: redact(redact(x)) == redact(x). Placeholders never re-match a
    rule, so re-running the redactor over already-redacted data is a no-op.
  - Key-aware AND content-aware: masks by sensitive key name (recursively,
    case-insensitive) and by known secret content formats (JWTs, cloud keys,
    bearer/basic auth, cookies, credentials in URLs, secret query params).
  - Benign content is preserved: rules are specific to secret shapes, so
    ordinary prose / URLs / JSON pass through unchanged.

Honest limit: this catches *known* secret shapes and sensitive keys. A novel
high-entropy secret embedded in a free-text body with no surrounding keyword,
key name, or recognizable prefix is NOT guaranteed to be caught. We deliberately
avoid a blanket high-entropy scrubber because it corrupts legitimate hashes,
IDs, and payloads (and would break benign-preservation + determinism guarantees
callers rely on). See docs/phase3-evidence-provenance.md.
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER = "[REDACTED]"

# Keys whose *value* is always masked, regardless of the value's content.
# Compared case-insensitively; hyphens/underscores are normalized so
# "x-api-key", "x_api_key", "API KEY" all match.
SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pwd",
    "secret", "clientsecret", "client_secret",
    "apikey", "api_key", "xapikey", "x_api_key",
    "token", "accesstoken", "access_token", "refreshtoken", "refresh_token",
    "idtoken", "id_token",
    "authorization", "auth", "bearer",
    "cookie", "cookies", "setcookie", "set_cookie",
    "session", "sessionid", "session_id", "sessiontoken", "session_token",
    "credential", "credentials",
    "privatekey", "private_key",
    "awssecretaccesskey", "aws_secret_access_key", "secretaccesskey",
    "clientkey", "signingkey", "signing_key",
    "email", "phone", "ssn",
})


def _norm_key(key: str) -> str:
    return re.sub(r"[\s\-]", "_", key).strip().lower()


# A key is sensitive if it is in SENSITIVE_KEYS, or one of its underscore
# components is a secret word. This catches X-Auth-Token / proxy-authorization
# without treating ordinary keys like "content_type" as secrets.
_SENSITIVE_COMPONENTS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "apikey",
    "authorization", "cookie", "cookies", "credential", "credentials",
    "email", "phone", "ssn",
})


def _key_is_sensitive(key: str) -> bool:
    norm = _norm_key(key)
    if norm in SENSITIVE_KEYS:
        return True
    return any(part in _SENSITIVE_COMPONENTS for part in norm.split("_"))


# Content patterns. Each entry is (compiled_regex, replacement). Replacement may
# be a string (with backrefs) or a callable. Order matters: most specific first.
# Every replacement is a fixed token that cannot re-match its own or any other
# rule, which is what makes the whole pass idempotent.
_PATTERNS: list[tuple[re.Pattern, Any]] = [
    # PEM private key blocks (multi-line).
    (re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "[REDACTED:private_key]"),
    # JWT (three base64url segments).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
     "[REDACTED:jwt]"),
    # AWS access key id.
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,}\b"),
     "[REDACTED:aws_key]"),
    # Google API key.
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED:google_key]"),
    # Google OAuth access token.
    (re.compile(r"\bya29\.[0-9A-Za-z_\-]+"), "[REDACTED:token]"),
    # Slack tokens.
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "[REDACTED:slack_token]"),
    # GitHub tokens (classic + fine-grained + app).
    (re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}"), "[REDACTED:github_token]"),
    (re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}"), "[REDACTED:github_token]"),
    # OpenAI / Stripe style sk- keys.
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "[REDACTED:api_key]"),
    (re.compile(r"\b[rsp]k_live_[0-9A-Za-z]{10,}"), "[REDACTED:stripe_key]"),
    # SendGrid.
    (re.compile(r"\bSG\.[\w-]{16,}\.[\w-]{16,}"), "[REDACTED:sendgrid_key]"),
    # Authorization: Basic <b64>  (before generic bearer / header rules).
    (re.compile(r"(?i)(authorization\s*:\s*basic)\s+[A-Za-z0-9+/=]+"),
     lambda m: f"{m.group(1)} {PLACEHOLDER}"),
    # Authorization: Bearer <token> / bare "bearer <token>".
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), f"Bearer {PLACEHOLDER}"),
    # Cookie: / Set-Cookie: header lines (whole value).
    (re.compile(r"(?i)(set-cookie|cookie)\s*:\s*[^\r\n]+"),
     lambda m: f"{m.group(1)}: {PLACEHOLDER}"),
    # Credentials embedded in a URL authority: scheme://user:pass@host
    (re.compile(r"://[^/@\s:]+:[^/@\s]+@"), "://[REDACTED]@"),
    # Secret-bearing URL query parameters (keep the param name, mask value).
    (re.compile(
        r"(?i)([?&](?:access_?token|api_?key|apikey|token|key|sig|signature|"
        r"auth|password|passwd|pwd|session_?id|secret|x-amz-signature)=)"
        r"[^&#\s\"']+"),
     lambda m: f"{m.group(1)}{PLACEHOLDER}"),
    # Quoted JSON / form values: "password": "hunter2" or 'token':'abc'.
    # The unquoted rule below does not cross a quote, so this must come first.
    (re.compile(
        r"""(?i)(["']?)(api[_-]?key|apikey|client_secret|secret|password|passwd|pwd|"""
        r"""access_token|refresh_token|authorization|token)\1(\s*[:=]\s*)"""
        r"""(["'])([^"']*)\4"""),
     lambda m: f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}{m.group(4)}{PLACEHOLDER}{m.group(4)}"),
    # Inline key=value / key: value for sensitive names in free text/blobs.
    (re.compile(
        r"(?i)\b(api[_-]?key|apikey|client_secret|secret|password|passwd|pwd|"
        r"access_token|refresh_token|authorization|token)\b(\s*[:=]\s*)"
        r"[^\s,;&\"']+"),
     lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}"),
]


def redact_text(text: str) -> str:
    """Apply every content pattern to a string. Deterministic + idempotent."""
    if not text:
        return text
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_obj(obj: Any) -> Any:
    """Recursively redact a JSON-like structure.

    - dict: any key in SENSITIVE_KEYS -> value replaced by the placeholder
      wholesale; other values are redacted recursively.
    - list/tuple: each element redacted.
    - str: content patterns applied.
    - other scalars: returned unchanged.
    """
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _key_is_sensitive(k):
                out[k] = PLACEHOLDER
            else:
                out[k] = redact_obj(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_obj(x) for x in obj]
    return obj


def redact_kv(key: str, value: Any) -> Any:
    """Redact a single value given its key name (key-aware then content-aware)."""
    if isinstance(key, str) and _key_is_sensitive(key):
        return PLACEHOLDER
    return redact_obj(value)
