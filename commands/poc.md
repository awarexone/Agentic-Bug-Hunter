---
description: Capture reproducible PoC evidence for a finding — raw request/response, copy-paste curl, HAR, optional screenshot, and a report-ready evidence.md. Secrets redacted by default. Usage: /poc capture <url> [-H ...] | /poc from-request req.txt [--response resp.txt]
---

# /poc

Turn a finding into a **reproducible evidence bundle** — the exact request, the
exact response, a copy-paste `curl`, a HAR you can import into Burp, an optional
screenshot, and a `evidence.md` section ready to paste into `/report`. This is
the proof layer the report pipeline expects (`skills/report-writing`,
`commands/report.md`).

## Usage

```
/poc capture https://api.target.com/v1/users/1 -H "Authorization: Bearer $TOK" \
     --target target.com --vuln-class idor --severity high --finding-id F-12

/poc from-request req.txt --response resp.txt --target target.com --vuln-class idor
```

Run directly:

```bash
# live: send the request (SSRF-guarded) and bundle it
tools/poc_bundler.py capture <url> -X GET -H "Cookie: session=..." \
    --target t.com --vuln-class idor --severity high --finding-id F-12 --screenshot

# offline: bundle a saved raw request (e.g. copied out of Burp)
tools/poc_bundler.py from-request request.txt --response response.txt \
    --target t.com --vuln-class idor
```

## Output

A folder laid out exactly as `commands/report.md` expects:

```text
findings/<target>-<vuln-class>/evidence/<finding-id>/
├── request.http      raw request you sent
├── response.http     raw response that proves impact
├── repro.sh          copy-paste curl reproduction
├── evidence.har      HAR 1.2 — import into Burp / devtools
├── screenshot.png    optional (best-effort via httpx)
├── evidence.md       paste this into /report
└── bundle.json       manifest + response-body SHA-256
```

## Secrets safety (on by default)

Bug bounty evidence carries **live auth** — session cookies, bearer tokens, API
keys. By default every sensitive header (`Authorization`, `Cookie`, `Set-Cookie`,
`X-Api-Key`, …) is **redacted** in all artifacts so the bundle is safe to paste
into a report. `repro.sh` stays runnable by referencing each secret through an
environment variable (`$AUTHORIZATION`, `$COOKIE`, …) instead of hardcoding it.
Pass `--no-redact` only for local/personal use.

## Safety rails

- `capture` uses the repo's SSRF-guarded opener (`tools/safe_http.py`) — a target
  can't 302 the capture into cloud metadata or an internal host.
- `PUT`/`DELETE`/`PATCH` are refused unless you pass `--confirm-unsafe` (they can
  mutate production state), mirroring the autopilot `SafeMethodPolicy`.
- The full response body is SHA-256'd in `bundle.json` so the evidence is
  tamper-evident; large bodies are truncated in the text artifacts but hashed in
  full.

## Wiring it in

Attach the bundle to its lead so nothing is lost:

```bash
lead_board.py touch <target> <lead_id> --status reported --finding-id F-12
```

The bundle's `evidence.md` and screenshots also surface automatically in the
`/dashboard` findings view.
