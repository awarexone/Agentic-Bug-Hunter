# Phase 6 — Validate & Triage (before any report)

Every candidate finding runs this gauntlet. One wrong answer = KILL IT and move on. N/A hurts your
validity ratio; informational is neutral; only submit what passes. This is the full validate + triage
gate, inlined — johnwick needs no external command or skill for it.

## THE 7-QUESTION GATE (ask in order; one wrong answer = STOP)
- **Q1 — Usable right now?** Fill the template or kill it:
  ```
  1. Setup:   [own account / another user's id / no account]
  2. Request: [exact method, URL, headers, body — copy-paste ready]
  3. Result:  I can [read/modify/delete] [exact data in response]
  4. Impact:  real-world = [ATO / PII read / money stolen]
  5. Cost:    time [X min], capital [$0 / $X]
  ```
  If you can't write step 2 as a real HTTP request → KILL.
- **Q2 — On the program's accepted-impact list?** Maps to a listed exclusion → KILL.
- **Q3 — Root cause in an in-scope, production asset?** Not staging/third-party (Stripe/Salesforce/Google) → else KILL.
- **Q4 — Needs unrealistic privileged access?** "Admin can do X" = KILL. "Non-admin does admin-only X" = valid.
- **Q5 — Already known / accepted behavior?** Search disclosed reports, GH issues, changelog, API docs → if documented, KILL.
- **Q6 — Impact proven beyond "technically possible"?** XSS→real cookie theft (not `alert(1)`); SSRF→internal
  data returned (not DNS ping); SQLi→real rows (not error string); IDOR→foreign user's data (not 200). Else DOWNGRADE.
- **Q7 — Known-invalid class?** On the NEVER-SUBMIT list without a chain → KILL.
- **Q8 — Identity check (auth findings):** record Session, Identity, anon-repro, cross-identity, stale-cred.
  IDOR must work as A-reading-B (not just no-auth); priv-esc must work low→high; auth-bypass must work
  logged-out. A finding that reproduces under only one identity is often a real, scoped permission boundary,
  not a vuln. Blank answers auto-fail auth findings.

## 4 PRE-SUBMISSION GATES (all must PASS)
- **Gate 0 Reality:** real (confirmed with HTTP, not code-reading) · in scope (checked page) · reproducible
  from a fresh session · evidence captured.
- **Gate 1 Impact:** can state "what can the attacker DO that they couldn't before"; more than "see
  non-sensitive data"; a real victim (other user's/company's data, financial loss); not reliant on unlikely victim action.
- **Gate 2 Dedup:** searched Hacktivity + GH issues for this program + endpoint/bug; read last 5 disclosed
  reports; not in changelog; googled "TARGET ENDPOINT bug bounty".
- **Gate 3 Quality:** title = `[Bug] in [Endpoint] allows [actor] to [impact]`; copy-pasteable repro;
  evidence of impact (not just 200); CVSS matches program severity; 1–2 sentence fix; NEVER "could potentially".

## NEVER SUBMIT (destroys validity ratio)
Missing CSP/HSTS/headers · missing SPF/DKIM/DMARC · GraphQL introspection alone · banner/version w/o
CVE · clickjacking on non-sensitive pages · tabnabbing · CSV injection (no code exec) · CORS `*` w/o
credential exfil PoC · logout CSRF · self-XSS · open redirect alone · OAuth client_secret in mobile app ·
SSRF DNS-callback only · host-header injection alone · rate limit on non-critical forms · session not
invalidated on logout · concurrent sessions · internal IP in error · mixed content · weak SSL ciphers ·
missing HttpOnly/Secure alone · autocomplete on password fields · pre-ATO (usually).

## COMMON N/A KILL SIGNALS (stop before writing)
Reflected XSS + `Content-Security-Policy` header present, no cookie in response · SSRF DNS ping, no HTTP
body with internal data · IDOR where response id == your own account · SQLi error string, no rows · CORS
`*` without `Allow-Credentials: true` · rate-limit on search/contact/behind-Cloudflare · nuclei `info`
match · MFA rate-limit but no OTP accepted · open redirect with no OAuth `redirect_uri`/token · "admin can
do X" · `alert(document.domain)` only · SAML metadata (publicly documented). Match → mark INFORMATIONAL, move on.

## CONDITIONALLY VALID — chain required (prove end-to-end first)
| Standalone | + Chain | Valid |
|---|---|---|
| Open redirect | OAuth `redirect_uri` → code theft | ATO (Crit) |
| CORS `*` | credentialed request exfils PII | High |
| CSRF | sensitive action (transfer/email/delete) | High |
| Rate-limit bypass | OTP/reset brute succeeds | Med/High |
| SSRF DNS-only | internal service + data returned | Med |
| Host-header injection | reset email uses injected host | High |
| S3 listing | JS bundles contain live keys/OAuth secrets | Med/High |
| Subdomain takeover | registered as OAuth `redirect_uri` host | Critical |
| GraphQL introspection | + auth-bypass mutation or node() IDOR | High |

## CVSS 3.1 quick anchors
IDOR read PII (auth) 6.5 M · IDOR write/delete any user 7.5 H · auth bypass→admin 9.8 C · stored XSS→cookie
8.8 H · SQLi full dump 8.6 H · SSRF→metadata 9.1 C · race double-spend 7.5 H · JWT alg:none 9.1 C.
`PR:N` no login · `PR:L` free account · `PR:H` admin · `UI:N` no victim action · `S:C` escapes to cloud/browser/OS.

## KILL FAST
5-min rule (can't fill Q1 in 5 min → move on) · >2 simultaneous preconditions → kill · "what does the
attacker walk away with?" nothing → kill · "admin can do X" is never a bug · documented behavior → kill ·
30+ min on Q6 with no repro → kill. **Never chain two separate bugs into one report — that's two payouts.**
Record each survivor's verdict + repro + impact in `findings/`.
