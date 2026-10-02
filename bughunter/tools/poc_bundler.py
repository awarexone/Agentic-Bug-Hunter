#!/usr/bin/env python3
"""
poc_bundler.py — turn a finding into a reproducible, shareable evidence bundle.

The gap this closes (docs/CAPABILITY-GAPS.md → "No automatic PoC capture
(screenshot/HAR/video) for reports"): the toolkit can *find* bugs but leaves the
hunter to hand-assemble proof. A report is only as strong as its evidence — the
exact request, the exact response, a copy-paste reproduction, and (when possible)
a screenshot. This produces all of that as one folder, laid out exactly the way
skills/report-writing and commands/report.md expect:

    findings/<target>-<vuln-class>/evidence/<finding-id>/
    ├── request.http      raw HTTP request (what you sent)
    ├── response.http     raw HTTP response (what proves impact)
    ├── repro.sh          copy-paste curl that reproduces it
    ├── evidence.har      HAR 1.2 — import into Burp / browser devtools
    ├── screenshot.png    optional, best-effort via httpx/visual_triage
    ├── evidence.md       report-ready evidence section (paste into /report)
    └── bundle.json       manifest: metadata, file list, response-body SHA-256

Two modes:

  capture <url>            perform the request live (SSRF-guarded) and bundle it
  from-request <req.txt>   build a bundle from a saved raw request (e.g. a Burp
                           request), no network — pair with --response resp.txt

Secrets safety (on by default — bug bounty evidence carries live auth):
  Sensitive headers (Authorization, Cookie, Set-Cookie, API keys, …) are
  REDACTED in every artifact so the bundle is safe to paste into a report.
  repro.sh keeps the request runnable by referencing the secret via an
  environment variable ($AUTHORIZATION, $COOKIE, …) instead of hardcoding it.
  Pass --no-redact to keep raw values (personal/local use only).

Design: everything that shapes an artifact (curl/HAR/markdown/manifest builders,
raw-HTTP parsers, redaction) is a pure function and unit-tested without a socket;
only capture() and the screenshot helper touch the outside world.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen  # noqa: E402

USER_AGENT = "agentic-bug-hunter/poc_bundler"
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "none"}
# HTTP methods that can mutate/destroy production state — refuse without opt-in.
UNSAFE_METHODS = {"PUT", "DELETE", "PATCH"}
MAX_BODY_BYTES = 64 * 1024  # cap what we write into text artifacts (full body is still hashed)

# Header names (lowercased) whose values are secret and must never leak into a
# shareable bundle. Matches the spirit of tools/credential_store.py.
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "auth-token", "x-access-token",
    "x-amz-security-token", "x-goog-api-key", "x-functions-key",
    "x-session-token", "x-csrf-token", "x-xsrf-token",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Exchange:
    """One request/response pair. `response_status is None` when only the
    request was captured (from-request with no --response)."""
    method: str
    url: str
    http_version: str = "HTTP/1.1"
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_body: str = ""
    response_status: int | None = None
    response_reason: str = ""
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    response_body: str = ""
    response_body_bytes: bytes = b""
    started_at: str = ""
    elapsed_ms: int = 0


@dataclass
class Meta:
    target: str = ""
    vuln_class: str = ""
    severity: str = ""
    title: str = ""
    finding_id: str = ""


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify(text: str, default: str = "target") -> str:
    s = re.sub(r"[^\w.-]+", "-", (text or "").strip().lower()).strip("-.")
    return s[:60] or default


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sensitive(name: str) -> bool:
    return name.strip().lower() in SENSITIVE_HEADERS


def env_var_for(name: str) -> str:
    """Environment-variable name a redacted header value is referenced by in
    repro.sh, e.g. 'X-Api-Key' -> 'X_API_KEY'."""
    return re.sub(r"[^A-Z0-9]", "_", name.strip().upper()).strip("_") or "SECRET"


def truncate_note(body: str, raw_len: int) -> str:
    if raw_len > len(body.encode("utf-8", "replace")):
        return f"\n\n[... truncated: {raw_len} bytes total, showing first {len(body)} chars ...]"
    return ""


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def collect_secrets(headers: list[tuple[str, str]]) -> dict[str, str]:
    """Map ENV_VAR -> real value for every sensitive request header, so repro.sh
    can reference them without hardcoding. Deterministic; unit-tested."""
    secrets: dict[str, str] = {}
    for name, value in headers:
        if is_sensitive(name) and value:
            secrets[env_var_for(name)] = value
    return secrets


def display_headers(headers: list[tuple[str, str]], redact: bool) -> list[tuple[str, str]]:
    """Header list for display artifacts: sensitive values masked when redacting."""
    out = []
    for name, value in headers:
        if redact and is_sensitive(name) and value:
            out.append((name, f"‹redacted:${env_var_for(name)}›"))
        else:
            out.append((name, value))
    return out


# ---------------------------------------------------------------------------
# Artifact builders (pure)
# ---------------------------------------------------------------------------


def build_raw_request(ex: Exchange, redact: bool) -> str:
    parsed = urlparse(ex.url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [f"{ex.method} {target} {ex.http_version}"]
    have_host = any(n.lower() == "host" for n, _ in ex.request_headers)
    if not have_host and parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")
    for name, value in display_headers(ex.request_headers, redact):
        lines.append(f"{name}: {value}")
    text = "\n".join(lines) + "\n"
    if ex.request_body:
        text += "\n" + ex.request_body
    return text


def build_raw_response(ex: Exchange, redact: bool) -> str:
    if ex.response_status is None:
        return "[response not captured]\n"
    lines = [f"{ex.http_version} {ex.response_status} {ex.response_reason}".rstrip()]
    for name, value in display_headers(ex.response_headers, redact):
        lines.append(f"{name}: {value}")
    text = "\n".join(lines) + "\n"
    body = ex.response_body[:MAX_BODY_BYTES] if ex.response_body else ""
    if body:
        text += "\n" + body + truncate_note(body, len(ex.response_body_bytes))
    return text


def _sh_squote(s: str) -> str:
    """POSIX single-quote a string for safe shell embedding."""
    return "'" + s.replace("'", "'\\''") + "'"


def build_curl(ex: Exchange, redact: bool) -> str:
    """A copy-paste curl reproduction. Sensitive headers are referenced via
    environment variables when redacting, so the command runs without pasting a
    live token into the report; a header block up top shows what to export."""
    secrets = collect_secrets(ex.request_headers) if redact else {}
    header_flags = []
    for name, value in ex.request_headers:
        if name.lower() == "host":
            continue  # curl derives Host from the URL
        if redact and is_sensitive(name) and value:
            header_flags.append(f'-H "{name}: ${env_var_for(name)}"')
        else:
            header_flags.append("-H " + _sh_squote(f"{name}: {value}"))

    parts = ["curl -i -sS"]
    if ex.method != "GET":
        parts.append("-X " + ex.method)
    parts += header_flags
    if ex.request_body:
        parts.append("--data-raw " + _sh_squote(ex.request_body))
    parts.append(_sh_squote(ex.url))

    lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    if secrets:
        lines.append("# This PoC references secrets via env vars so they stay out of the report.")
        lines.append("# Export the real values before running (they were redacted from this bundle):")
        for var in secrets:
            lines.append(f"#   export {var}='<paste real value>'")
        lines.append("")
    lines.append(" \\\n  ".join(parts))
    return "\n".join(lines) + "\n"


def _har_headers(headers: list[tuple[str, str]], redact: bool) -> list[dict]:
    return [{"name": n, "value": v} for n, v in display_headers(headers, redact)]


def build_har(ex: Exchange, redact: bool) -> dict:
    """A valid HAR 1.2 log with this single exchange — importable into Burp,
    browser devtools, and most HTTP tooling."""
    parsed = urlparse(ex.url)
    query = [{"name": k, "value": v} for k, v in
             (kv.split("=", 1) if "=" in kv else (kv, "")
              for kv in (parsed.query.split("&") if parsed.query else []))]
    request = {
        "method": ex.method,
        "url": ex.url,
        "httpVersion": ex.http_version,
        "headers": _har_headers(ex.request_headers, redact),
        "queryString": query,
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(ex.request_body.encode("utf-8", "replace")) if ex.request_body else 0,
    }
    if ex.request_body:
        request["postData"] = {"mimeType": "application/octet-stream", "text": ex.request_body}

    entry = {
        "startedDateTime": ex.started_at or now_iso(),
        "time": ex.elapsed_ms,
        "request": request,
        "response": {
            "status": ex.response_status or 0,
            "statusText": ex.response_reason,
            "httpVersion": ex.http_version,
            "headers": _har_headers(ex.response_headers, redact),
            "cookies": [],
            "content": {
                "size": len(ex.response_body_bytes),
                "mimeType": next((v for n, v in ex.response_headers
                                  if n.lower() == "content-type"), "text/plain"),
                "text": ex.response_body[:MAX_BODY_BYTES],
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(ex.response_body_bytes),
        },
        "cache": {},
        "timings": {"send": 0, "wait": ex.elapsed_ms, "receive": 0},
    }
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "agentic-bug-hunter", "version": "poc_bundler"},
            "entries": [entry],
        }
    }


def render_evidence_md(meta: Meta, ex: Exchange, files: list[str], redact: bool) -> str:
    sev = (meta.severity or "").upper()
    title = meta.title or f"{meta.vuln_class or 'Finding'} on {meta.target or urlparse(ex.url).netloc}"
    status = f"{ex.response_status} {ex.response_reason}".strip() if ex.response_status else "—"
    md = [f"## Evidence — {title}", ""]
    facts = [
        ("Target", meta.target or urlparse(ex.url).netloc),
        ("URL", ex.url),
        ("Vuln class", meta.vuln_class or "—"),
        ("Severity", sev or "—"),
        ("Finding ID", meta.finding_id or "—"),
        ("Captured", ex.started_at or "—"),
        ("Response", status),
    ]
    md += ["| Field | Value |", "|---|---|"]
    md += [f"| {k} | {v} |" for k, v in facts]
    md += ["", "### Request", "```http", build_raw_request(ex, redact).rstrip(), "```", ""]
    md += ["### Response", "```http", build_raw_response(ex, redact).rstrip(), "```", ""]
    md += ["### Reproduce", "```bash", build_curl(ex, redact).rstrip(), "```", ""]
    if any(f == "screenshot.png" for f in files):
        md += ["### Screenshot", "![screenshot](screenshot.png)", ""]
    if redact:
        md += ["> Secrets (auth headers, cookies) are redacted; `repro.sh` references "
               "them via environment variables. See `bundle.json` for the file manifest "
               "and response-body SHA-256.", ""]
    md += ["_Bundle files: " + ", ".join(f"`{f}`" for f in files) + "_"]
    return "\n".join(md) + "\n"


def build_manifest(meta: Meta, ex: Exchange, files: list[str], redact: bool) -> dict:
    return {
        "schema": "poc-bundle/1",
        "generated": now_iso(),
        "redacted": redact,
        "finding": {
            "finding_id": meta.finding_id,
            "target": meta.target or urlparse(ex.url).netloc,
            "vuln_class": meta.vuln_class,
            "severity": meta.severity,
            "title": meta.title,
        },
        "exchange": {
            "method": ex.method,
            "url": ex.url,
            "captured_at": ex.started_at,
            "elapsed_ms": ex.elapsed_ms,
            "response_status": ex.response_status,
            "response_bytes": len(ex.response_body_bytes),
            "response_sha256": sha256_hex(ex.response_body_bytes) if ex.response_body_bytes else None,
        },
        "files": files,
    }


# ---------------------------------------------------------------------------
# Raw-HTTP parsers (pure) — for `from-request` (e.g. a Burp request/response).
# ---------------------------------------------------------------------------


def _split_head_body(text: str) -> tuple[list[str], str]:
    normalized = text.replace("\r\n", "\n")
    if "\n\n" in normalized:
        head, body = normalized.split("\n\n", 1)
    else:
        head, body = normalized, ""
    return head.split("\n"), body


def parse_raw_request(text: str, scheme: str = "https") -> Exchange:
    """Parse a raw HTTP request (origin-form or absolute-URI) into an Exchange."""
    lines, body = _split_head_body(text)
    if not lines or not lines[0].strip():
        raise ValueError("empty request")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, target = parts[0].upper(), parts[1]
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers = []
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    host = next((v for n, v in headers if n.lower() == "host"), "")
    if target.lower().startswith(("http://", "https://")):
        url = target
    elif host:
        url = f"{scheme}://{host}{target}"
    else:
        raise ValueError("cannot build URL: no absolute target and no Host header")
    return Exchange(method=method, url=url, http_version=http_version,
                    request_headers=headers, request_body=body.rstrip("\n"))


def parse_raw_response(text: str) -> tuple[int, str, list[tuple[str, str]], str]:
    """Parse a raw HTTP response into (status, reason, headers, body)."""
    lines, body = _split_head_body(text)
    status, reason = 0, ""
    if lines and lines[0].strip():
        parts = lines[0].split(None, 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
            reason = parts[2] if len(parts) > 2 else ""
    headers = []
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return status, reason, headers, body


# ---------------------------------------------------------------------------
# Side-effecting layer — network + screenshot + disk.
# ---------------------------------------------------------------------------


def capture(url: str, method: str, headers: list[tuple[str, str]],
            body: str | None, timeout: float) -> Exchange:
    """Perform the request via the repo's SSRF-guarded opener and record the
    exact exchange."""
    send_headers = list(headers)
    if not any(n.lower() == "user-agent" for n, _ in send_headers):
        send_headers.append(("User-Agent", USER_AGENT))
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data,
                                 headers={n: v for n, v in send_headers}, method=method)
    started = now_iso()
    t0 = time.perf_counter()
    status = reason = None
    resp_headers: list[tuple[str, str]] = []
    raw = b""
    try:
        resp = safe_urlopen(req, timeout=timeout)
        raw = resp.read(MAX_BODY_BYTES * 4)  # bounded read; huge bodies are truncated
        status = getattr(resp, "status", None) or getattr(resp, "code", None)
        reason = getattr(resp, "reason", "") or ""
        resp_headers = list(resp.headers.items()) if resp.headers else []
        version = getattr(resp, "version", 11)
    except urllib.error.HTTPError as e:  # non-3xx errors still carry a response
        raw = e.read() if hasattr(e, "read") else b""
        status, reason = e.code, (e.reason or "")
        resp_headers = list(e.headers.items()) if e.headers else []
        version = 11
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    return Exchange(
        method=method, url=url,
        http_version="HTTP/1.1" if version == 11 else "HTTP/1.0",
        request_headers=send_headers, request_body=body or "",
        response_status=status, response_reason=reason or "",
        response_headers=resp_headers,
        response_body=raw.decode("utf-8", "replace"),
        response_body_bytes=raw, started_at=started, elapsed_ms=elapsed_ms,
    )


def try_screenshot(url: str, outdir: str) -> str | None:
    """Best-effort screenshot via httpx. Returns 'screenshot.png' on success,
    None otherwise — never fatal (evidence is still valid without it)."""
    if not shutil.which("httpx"):
        return None
    try:
        subprocess.run(["httpx", "-u", url, "-screenshot", "-srd", outdir,
                        "-silent", "-timeout", "20"],
                       capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    for root, _dirs, files in os.walk(outdir):
        for f in files:
            if f.lower().endswith(".png"):
                src = os.path.join(root, f)
                dst = os.path.join(outdir, "screenshot.png")
                if os.path.abspath(src) != os.path.abspath(dst):
                    try:
                        shutil.move(src, dst)
                    except OSError:
                        return None
                return "screenshot.png"
    return None


def default_outdir(meta: Meta, ex: Exchange) -> str:
    target = slugify(meta.target or urlparse(ex.url).netloc, "target")
    cls = slugify(meta.vuln_class, "finding")
    fid = slugify(meta.finding_id, "") or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return os.path.join(_REPO, "findings", f"{target}-{cls}", "evidence", fid)


def _write(outdir: str, name: str, content: str, executable: bool = False):
    path = os.path.join(outdir, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    if executable:
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass


def write_bundle(outdir: str, meta: Meta, ex: Exchange, redact: bool,
                 want_screenshot: bool) -> dict:
    os.makedirs(outdir, exist_ok=True)

    # Screenshot first (best-effort) so the final file list is accurate and
    # every downstream artifact references the same, deduplicated set of files.
    shot = try_screenshot(ex.url, outdir) if want_screenshot else None

    files = ["request.http", "response.http", "repro.sh", "evidence.har"]
    if shot:
        files.append(shot)
    files += ["evidence.md", "bundle.json"]

    _write(outdir, "request.http", build_raw_request(ex, redact))
    _write(outdir, "response.http", build_raw_response(ex, redact))
    _write(outdir, "repro.sh", build_curl(ex, redact), executable=True)
    _write(outdir, "evidence.har", json.dumps(build_har(ex, redact), indent=2))
    _write(outdir, "evidence.md", render_evidence_md(meta, ex, files, redact))
    manifest = build_manifest(meta, ex, files, redact)
    _write(outdir, "bundle.json", json.dumps(manifest, indent=2))
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _headers_from_args(header_args: list[str] | None, cookie: str | None) -> list[tuple[str, str]]:
    headers = []
    for h in header_args or []:
        if ":" not in h:
            raise ValueError(f"bad header (want 'Name: value'): {h!r}")
        name, value = h.split(":", 1)
        headers.append((name.strip(), value.strip()))
    if cookie:
        headers.append(("Cookie", cookie))
    return headers


def _meta_from_args(args) -> Meta:
    sev = (getattr(args, "severity", "") or "").lower()
    if sev and sev not in VALID_SEVERITIES:
        raise SystemExit(f"[!] --severity must be one of {sorted(VALID_SEVERITIES)}")
    return Meta(target=getattr(args, "target", "") or "",
                vuln_class=getattr(args, "vuln_class", "") or "",
                severity=sev, title=getattr(args, "title", "") or "",
                finding_id=getattr(args, "finding_id", "") or "")


def _finish(outdir: str, meta: Meta, ex: Exchange, redact: bool, want_shot: bool,
            as_json: bool) -> int:
    manifest = write_bundle(outdir, meta, ex, redact, want_shot)
    if as_json:
        print(json.dumps({"bundle_dir": outdir, "manifest": manifest}, indent=2))
    else:
        print(f"[+] evidence bundle: {outdir}")
        for f in manifest["files"]:
            print(f"      - {f}")
        status = ex.response_status if ex.response_status is not None else "n/a"
        print(f"[+] {ex.method} {ex.url}  ->  {status}")
        if redact:
            print("[+] secrets redacted; repro.sh references them via env vars")
        print("[*] paste evidence.md into /report, or attach via "
              f"lead_board.py touch <target> <lead_id> --finding-id {meta.finding_id or '<id>'}")
    return 0


def _add_meta_args(p):
    p.add_argument("--target", help="target/program (folder + report field)")
    p.add_argument("--vuln-class", dest="vuln_class", help="e.g. idor, ssrf, xss")
    p.add_argument("--severity", help="one of: " + ", ".join(sorted(VALID_SEVERITIES)))
    p.add_argument("--title", help="short finding title")
    p.add_argument("--finding-id", dest="finding_id", help="stable id (also names the bundle folder)")
    p.add_argument("-o", "--out", help="output dir (default: findings/<target>-<class>/evidence/<id>)")
    p.add_argument("--no-redact", dest="redact", action="store_false",
                   help="keep raw secret values (local use only)")
    p.add_argument("--json", dest="as_json", action="store_true", help="print JSON result")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="PoC evidence bundler — reproducible proof for a finding.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("capture", help="perform the request live and bundle it")
    pc.add_argument("url")
    pc.add_argument("-X", "--method", default="GET")
    pc.add_argument("-H", "--header", action="append", help="repeatable 'Name: value'")
    pc.add_argument("-d", "--data", help="request body")
    pc.add_argument("--data-file", help="read request body from file")
    pc.add_argument("--cookie", help="Cookie header value")
    pc.add_argument("--timeout", type=float, default=15)
    pc.add_argument("--screenshot", action="store_true", help="best-effort httpx screenshot")
    pc.add_argument("--confirm-unsafe", action="store_true",
                    help="allow PUT/DELETE/PATCH (can mutate production state)")
    _add_meta_args(pc)

    pf = sub.add_parser("from-request", help="build a bundle from a saved raw request (no network)")
    pf.add_argument("request_file", help="raw HTTP request file (e.g. a Burp request)")
    pf.add_argument("--response", help="raw HTTP response file to pair with it")
    pf.add_argument("--scheme", default="https", choices=["http", "https"],
                    help="scheme when the request target is origin-form (default https)")
    pf.add_argument("--screenshot", action="store_true", help="best-effort httpx screenshot")
    _add_meta_args(pf)

    args = ap.parse_args(argv)
    meta = _meta_from_args(args)

    if args.cmd == "capture":
        method = args.method.upper()
        if method in UNSAFE_METHODS and not args.confirm_unsafe:
            print(f"[!] {method} can mutate production state. Re-run with --confirm-unsafe "
                  "if you are certain this is safe and in scope.", file=sys.stderr)
            return 2
        body = args.data
        if args.data_file:
            with open(args.data_file, encoding="utf-8", errors="replace") as fh:
                body = fh.read()
        try:
            headers = _headers_from_args(args.header, args.cookie)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 2
        ex = capture(args.url, method, headers, body, args.timeout)
        outdir = args.out or default_outdir(meta, ex)
        return _finish(outdir, meta, ex, args.redact, args.screenshot, args.as_json)

    if args.cmd == "from-request":
        with open(args.request_file, encoding="utf-8", errors="replace") as fh:
            ex = parse_raw_request(fh.read(), scheme=args.scheme)
        if args.response:
            with open(args.response, encoding="utf-8", errors="replace") as fh:
                status, reason, rheaders, rbody = parse_raw_response(fh.read())
            ex.response_status = status
            ex.response_reason = reason
            ex.response_headers = rheaders
            ex.response_body = rbody
            ex.response_body_bytes = rbody.encode("utf-8", "replace")
        ex.started_at = now_iso()
        outdir = args.out or default_outdir(meta, ex)
        return _finish(outdir, meta, ex, args.redact, args.screenshot, args.as_json)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
