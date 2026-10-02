#!/usr/bin/env python3
"""Intentionally-vulnerable benchmark target with a per-run canary flag.

Ground truth for the RECALL half of the benchmark. Each run plants a unique
FLAG{random} (XBOW's canary pattern): a verifier only "solves" a bug when it
exfiltrates that exact flag over the network, so a solve cannot be fabricated.

Bugs (all deterministically confirmable with NO creds/browser/OOB, so CI is
self-contained):
  /go?url=         open redirect  — honors any Location
  /.env            sensitive file — leaks the flag + an AWS-style secret
  /search?q=       SQLi           — time-based (SLEEP(n)) + error-based ("near")
  /api/account?id= IDOR           — X-User header reads any tenant; anon = 401
  /admin           auth bypass    — serves the flag with no auth

DO NOT DEPLOY. Binds 127.0.0.1 only.
"""
from __future__ import annotations

import os
import re
import secrets
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("BENCH_HOST", "127.0.0.1")
PORT = int(os.environ.get("BENCH_PORT", "8097"))
FLAG = os.environ.get("BENCH_FLAG") or f"FLAG{{{secrets.token_hex(8)}}}"

_SLEEP_RE = re.compile(r"sleep\(\s*(\d+)\s*\)", re.I)


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: A003 - keep output quiet
        pass

    def _send(self, status, body, ctype="text/plain; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)

        if p.path == "/go":  # open redirect — honors arbitrary Location
            target = q.get("url", ["/"])[0]
            return self._send(302, "", extra={"Location": target})

        if p.path == "/.env":  # sensitive file — leaks flag + secret
            body = (
                "APP_NAME=bench\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                f"CANARY={FLAG}\n"
            )
            return self._send(200, body)

        if p.path == "/search":  # SQLi — time-based + error-based
            payload = q.get("q", [""])[0]
            if "'" in payload:
                return self._send(200, "SQL syntax error near '' at line 1")
            m = _SLEEP_RE.search(payload)
            if m:
                time.sleep(min(int(m.group(1)), 5))
            return self._send(200, "<h2>0 results</h2>")

        if p.path == "/api/account":  # IDOR — any X-User reads any id
            if not self.headers.get("X-User"):
                return self._send(401, "auth required")
            acct = q.get("id", ["1"])[0]
            return self._send(
                200,
                f'{{"account":{acct},"owner_secret":"{FLAG}"}}',
                ctype="application/json",
            )

        if p.path == "/admin":  # auth bypass — no auth required
            return self._send(200, f"<h1>Admin Panel</h1> owner token: {FLAG}")

        return self._send(404, "not found")


def main() -> int:
    print(f"[bench] vulnerable target on http://{HOST}:{PORT}  flag={FLAG}")
    ThreadingHTTPServer((HOST, PORT), VulnHandler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
