# Exploit Chaining — turn primitives into ceilings

A lone primitive is low-value; the same primitive chained is Critical. **After every finding, ask: what's
the ceiling?** Never report a single read/redirect/leak until you've pushed it as far as it goes. This is
the difference between a $150 info-leak and a $20k account/cloud takeover.

## The forward questions (run on every finding)
1. Does this expose an **identifier** I can enumerate? → how many records / whole platform?
2. Does this expose a **secret** (key, token, source)? → what does the secret unlock?
3. Does this give **read** on something? → is there a matching **write**?
4. Does this touch **auth** (session, code, token, reset)? → can I become another user / admin?
5. Does this reach **internal/cloud**? → metadata → IAM creds → account/RCE?
6. Can I make a victim trigger it (CSRF/redirect/XSS) → **no-interaction or 1-click** impact?

## Canonical chains (steps → ceiling)
| Start | Chain | Ceiling |
|---|---|---|
| IDOR read | enumerate ids → PII at scale → probe matching write/delete | mass PII dump / data tamper (P1) |
| Predictable id + weak authz | sequential sweep → every tenant's records | platform-wide breach |
| **SSRF** | → `169.254.169.254` → IAM creds → AWS API → S3/EC2 | **cloud account takeover / RCE** |
| SSRF (internal) | → Redis/Jenkins/Consul/k8s → command exec | internal RCE |
| **Open redirect** | → OAuth `redirect_uri` → steal `code`/`token` | ATO (see [auth-attacks.md](auth-attacks.md)) |
| **Info leak** (.git / sourcemap / JS) | → hardcoded key/OAuth secret → issuer API | cloud/API/app takeover |
| S3 bucket listing | → JS bundle inside → live key/secret → OAuth | Med → Critical |
| **XSS** (stored/reflected) | → steal session/localStorage token/CSRF token → act as victim; on admin panel → admin | ATO / admin takeover |
| **Subdomain takeover** | → register as OAuth `redirect_uri` host / parent-cookie scope | ATO |
| **CORS** `*`+creds | → cross-origin credentialed read | mass PII read (High) |
| **Request smuggling** | → capture other users' requests / poison shared cache | mass credential theft / mass XSS |
| **Mass assignment** `role/isAdmin` | → become admin | full priv-esc → everything |
| **Dependency confusion** | → CI/build RCE → CI secrets → prod deploy keys | supply-chain compromise |
| **LFI** | → source disclosure → secret → RCE; or log/`.user.ini` poisoning → RCE | RCE |
| **Reset-token leak** (host-header/Referer) | → set victim's password | ATO |
| **File upload** | → SVG XXE → SSRF → cloud; or webshell → RCE; or path-overwrite | RCE / cloud |

## Rules for chaining
- **Prove each hop** with a real request/response — a chain is only as valid as its weakest unproven link
  (see [validation.md](validation.md) Q6). Don't assume "SSRF probably reaches metadata" — show the creds.
- **Report the chain as one finding** at ceiling severity — but keep genuinely separate bugs as separate
  reports (two payouts). A chain = one attack path to one impact; two unrelated bugs = two reports.
- Stop chaining when you hit a real ceiling (ATO, RCE, mass PII, cloud). Then write it up ([reporting.md](reporting.md)).
