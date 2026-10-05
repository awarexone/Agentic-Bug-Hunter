# Backend / Server-Side Bug Classes — taxonomy hub

We hunt backend/server-side bugs that chain to ceiling impact — not frontend-only primitives. Every
finding is grounded in a real request/response (no hallucination). This file is the **index**: the
high-payout classes each have a deep playbook; the rest are inline below. Payload strings →
[payloads.md](payloads.md).

## Deep playbooks (open the file for the class you're hunting)
| Class | Playbook | Top paid signal |
|---|---|---|
| SSRF | [ssrf.md](ssrf.md) | Dropbox full-response SSRF $17.5k, GitLab $10k |
| RCE (deserialization, dep-confusion, injection, media, archive, upload) | [rce.md](rce.md) | GitLab archive RCE $33.5k, PayPal dep-confusion $30k |
| SSTI | [ssti.md](ssti.md) | Uber Jinja2 → RCE $10k |
| XXE | [xxe.md](xxe.md) | Mail.ru blind XXE $6k |
| HTTP request smuggling / desync | [request-smuggling.md](request-smuggling.md) | Basecamp H/2 $7.5k, New Relic cred theft $3k |
| Web cache poisoning / deception | [cache-attacks.md](cache-attacks.md) | PayPal cache-poison DoS $9.7k |
| Race conditions / TOCTOU | [race-conditions.md](race-conditions.md) | Cosmos faucet $5k |
| ATO — OAuth/OIDC/SAML/JWT/reset | [auth-attacks.md](auth-attacks.md) | Coinbase $5k, GitLab OAuth SSRF $4k |
| IDOR / BOLA / BFLA | [authz-idor.md](authz-idor.md) | destructive-ID & cross-tenant patterns |
| SQL / NoSQL injection | [sqli.md](sqli.md) | data exfil / auth bypass / →RCE |
| GraphQL | [graphql.md](graphql.md) | introspection→admin-mutation, batching→ATO |
| 401/403 bypass | [bypass-403.md](bypass-403.md) | X-Original-URL / path-encoding to admin |
| CORS / open-redirect / CSRF / XSS→ATO | [web-misc.md](web-misc.md) | chain fodder → ATO / PII |
| Mobile (APK/IPA) | [mobile.md](mobile.md) | hidden internal base-URLs + hardcoded keys |

**Cross-cutting:** every request is gated by [scope-guard.md](scope-guard.md); escalate every finding to
its ceiling via [chaining.md](chaining.md); write survivors up via [reporting.md](reporting.md).

## Kill list (instant reject, never report alone)
Missing security headers · self-XSS · reflected XSS on logged-out marketing pages · stored XSS w/o
ATO/admin impact · clickjacking w/o sensitive action · CSRF on low-impact actions · rate-limit absence
w/o lockout/financial impact · SPF/DKIM/DMARC · version banners · stack traces alone · open redirect
alone (valid only chained to OAuth/SSO token theft) · default creds on dev with no prod link ·
directory listing w/o sensitive files · "potential/possible" anything.

## Inline classes (no separate file)

### SQLi / NoSQLi
Full playbook (detection ladder per DBMS, WAF bypass, NoSQL operators, →RCE) → [sqli.md](sqli.md).
Fingerprint DBMS manually before sqlmap/ghauri; **prove data exfil** (real rows), not an error string.

### Mass assignment / parameter pollution
Add privileged fields to any create/update body: `role`, `isAdmin`, `isOwner`, `permissions`, `plan`,
`credit`, `balance`, `verified`, `email_verified`, `approved`, `status`. Also try array/object type
confusion and duplicate params (`a=1&a=2`). #1 quiet priv-esc.

### Prototype pollution (Node)
`__proto__` / `constructor.prototype` in JSON merge, query string, form, or deep-clone paths. Detect:
`{"__proto__":{"polluted":"yes"}}` then check a reflected/derived property. Chain to RCE via gadgets
(child_process, lodash, `ejs`/template options) or to authz bypass (pollute `isAdmin`).

### Business logic
Negative/overflow quantities, price/amount tampering, currency swap, step-skipping, coupon/refund/
chargeback abuse, replay of signed requests, workflow state-machine abuse, quantity vs price desync.
Follow the money. Chain with [race-conditions.md](race-conditions.md) for limit-overrun.

### Infra & cloud
Cloud ATO via SSRF→IMDS ([ssrf.md](ssrf.md)); S3/GCS/Azure hijack (dangling CNAME, predictable naming) &
subdomain takeover with cookie/SSO scope ([params-takeover.md](params-takeover.md),
[unauth-p1.md](unauth-p1.md)); leaked cloud keys verified live ([js-mining.md](js-mining.md)).

### Secrets & disclosure
Live secrets in JS/git (verify vs issuer API; live=P1, dead=trash), sourcemap-recovered source, `.git`
exposure, leaked Swagger/OpenAPI (full API surface → reverse it), GraphQL introspection enabled.

## Method (per endpoint)
`baseline capture → stable replay → smallest single mutation → compare status/body/timing/side-effect →
expand by bug class`. Never mutate many fields at once (a signer/stateful check hides the real blocker).
Detect with a polyglot/probe, then escalate to the engine-specific exploit and **prove impact** (data out,
command run, foreign record changed, account taken) before it counts.
