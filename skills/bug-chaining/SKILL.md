---
name: bug-chaining
description: >
  Standalone bug chaining skill — synthesized from omni-killchain, omni-references/chaining-impact, triage-validation, apex-hunter, web2-vuln-classes, bug-bounty, and bb-methodology. Covers the complete chaining mindset: 10-question filter, 15 proven chain patterns (A–O) with payout data, escalation ladders per vuln class, conditional-chain table (when a standalone bug needs a gadget), impact-writing rules, CVSS chain multipliers, and 30-minute chain-or-move decision clock. Use when you have a low/medium finding and want to know how to chain it to Critical, or when strategizing what to hunt for maximum payout. Authorized testing only — bug bounty in-scope, pentest engagement, or CTF.
---

# BUG CHAINING — Low → Critical Playbook

> Single-bug reports get triaged. Chained reports get paid.
> $10K+ reports are almost always chains.

---

## THE ONLY QUESTION THAT MATTERS

**"Can I connect finding A to finding B so that an attacker walks away with real harm — account takeover, stolen money, PII exfil, RCE — that they couldn't achieve with either bug alone?"**

If you can't answer YES with a working PoC → keep escalating or move on.

---

## THE 10-QUESTION CHAIN FILTER

Run for every candidate finding before spending more than 30 minutes on it.

```
Q1.  Cross-user impact?           → IDOR/BOLA family
Q2.  Cross-tenant impact?         → massive multiplier on SaaS
Q3.  Leaks credentials/tokens?    → secret family (esp. cloud/admin)
Q4.  Pre-auth?                    → eliminates social-engineering need
Q5.  0-click?                     → eliminates user-interaction cost
Q6.  Persistent (stored)?         → keeps paying after report
Q7.  Internal/cloud-metadata?     → SSRF chain
Q8.  Source code / config read?   → feeds future bugs
Q9.  Leads to RCE/SQLi/admin?     → critical
Q10. Mass-exploitable?            → dramatic multiplier
```

- **3+ YES → ready to report** (check payout tier below)
- **1-2 YES → keep escalating** (find the connector gadget)
- **0 YES → kill it, move on**

---

## THE 15 PROVEN CHAIN PATTERNS

### Pattern A — Recon → Source disclosure → Bug class flood
**Payout range: $5K–$50K**
```
1. .git exposed / source map present / public S3 with code
2. Pull source
3. Grep for: SQL strings, command runners, deserialization, hardcoded secrets,
   weak JWT keys, internal endpoints
4. Test discovered endpoints/sinks against live target
5. Multiple critical bugs in one report
```
**Signal**: `.git/HEAD` returns `ref: refs/heads/main`; `.js.map` in wayback URLs; S3 bucket named `target-frontend-assets`

---

### Pattern B — Subdomain takeover → Cookie/CSP/OAuth bypass → ATO
**Payout range: $5K–$25K** (takeover alone: ~$200)
```
1. Find dangling CNAME pointing to expired provider
   (GitHub Pages, Heroku, Fastly, Zendesk, Shopify, S3, Azure, etc.)
2. Register a resource at that provider for the vulnerable CNAME
3. Domain now responds under target's subdomain
4. Check: does target set cookies with domain=.target.com?
   → If yes: your takeover page receives those cookies
5. Check: does target's CSP allowlist this subdomain?
   → If yes: XSS on main app bypasses CSP
6. Check: is this subdomain an OAuth redirect_uri?
   → If yes: register it and steal auth codes
```
**Kill if**: subdomain has no cookie scope, no CSP mention, no OAuth registration.

---

### Pattern C — Open redirect → OAuth code theft → ATO
**Payout range: $5K–$15K** (redirect alone: $0–$200)
```
1. Find any open redirect on target.com
   (redirect=, return_to=, next=, url=, r=, continue=)
2. Check if target.com is an OAuth redirect_uri allowlisted provider
3. Craft: /oauth/authorize?redirect_uri=https://target.com/redirect?to=https://evil.com
4. Victim clicks → auth code arrives at evil.com via Referer or fragment
5. Exchange code for access token → ATO
```
**Variants**:
- Wildcard `*.target.com` → takeover a subdomain and register it as redirect_uri
- `redirect_uri=https://target.com.evil.com` (suffix bypass on startsWith check)
- `redirect_uri=https://target.com/oauth/../../redirect?to=evil.com` (path traversal)

---

### Pattern D — SSRF → Cloud metadata → Cloud creds → S3 source → harder bugs
**Payout range: $10K–$50K** (blind SSRF alone: $200–$500)
```
Escalation ladder:
1. Detect SSRF (blind ping to OOB listener) → $200–500
2. Hit http://169.254.169.254/latest/meta-data/ → confirm cloud environment
3. Extract IAM role: /latest/meta-data/iam/security-credentials/
4. Read access_key, secret_key, session_token from credentials endpoint
5. Use creds: aws s3 ls → find source code buckets
6. Download JS bundles → extract API keys / admin secrets
7. Find more critical bugs using extracted source
```
**IMDSv2 (AWS)**: requires a PUT first for a token. If SSRF only allows GET, try:
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` + `Metadata-Flavor: Google`
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + `Metadata: true`

**Internal pivot targets**:
```
127.0.0.1:6379   → Redis → RCE via cron/SSH
127.0.0.1:8080   → Internal admin
127.0.0.1:9200   → Elasticsearch → data exfil
127.0.0.1:8200   → Vault → secret dump
10.x.x.x         → internal services (often no auth)
```

---

### Pattern E — IDOR + mass assignment → Self-promote to admin
**Payout range: $5K–$20K**
```
1. IDOR: request targeting another user's object works
2. Mass assignment: PUT/PATCH accepts role/isAdmin/permissions in body
3. Combine: PATCH /api/users/{victim_id} {"role":"admin"}
4. Your account or victim's account → admin
```
**Test mass assignment params**: `role`, `isAdmin`, `isOwner`, `plan`, `credit`, `verified`, `email_verified`, `balance`, `permissions`, `group_id`, `subscription_tier`

---

### Pattern F — File upload → Stored XSS in admin view → CSRF to admin → Plugin install → RCE
**Payout range: $15K–$50K**
```
1. Upload SVG/HTML file that renders in admin view
2. Blind XSS payload steals admin's CSRF token + session cookie
3. Use token to POST to plugin install or webhook endpoint
4. Plugin executes on server-side → RCE
```
**Simpler variant**: Upload → XSS in admin email notification → admin clicks → session stolen → use admin session for further privesc.

**File types to try**: `.svg`, `.html`, `.xml` (XXE), `.pdf` (SSRF via annotation), `.docx`/`.pptx` (XXE in rels), polyglot GIF+PHP, CSV injection.

---

### Pattern G — Cache poisoning → Stored XSS → Mass session theft
**Payout: PayPal paid $18,900**
```
1. Find unkeyed header that reflects in response (X-Forwarded-Host, X-Forwarded-For, X-Original-URL)
2. Inject XSS payload via unkeyed header
3. Cache stores the poisoned response
4. All subsequent visitors receive XSS payload → mass session theft
```
**Variations**: fat GET (add body to GET request, CDN ignores body but origin uses it), query string stripping discrepancy.

---

### Pattern H — Request smuggling → Cache poisoning → ATO
**Payout: Slack-class, $5K–$15K**
```
1. Detect CL.TE or TE.CL desync between frontend proxy and backend
2. Smuggle a prefix that poisons the next user's response
3. Poisoned response contains redirect to attacker or reflects session cookie
4. Mass session theft or ATO
```
**Test**: Send `Transfer-Encoding: chunked` with a malformed body. Watch for 400 errors from backend only.

---

### Pattern I — JWT alg confusion → Cross-tenant ATO
**Payout range: $5K–$20K**
```
1. Target uses RS256 JWT
2. Test: change alg to HS256 in header, sign with the server's PUBLIC key as HMAC secret
3. Modify payload: change user_id, tenant_id, role, aud
4. If server accepts → cross-tenant or admin ATO
```
**Variants**: `alg=none` (some libraries), kid path traversal (`kid=../../../../dev/null`), weak secret brute force (hashcat -a 0 -m 16500).

---

### Pattern J — GraphQL node bypass → IDOR on admin types
**Payout range: $3K–$15K**
```
1. REST /admin/users is properly protected
2. GraphQL node(id: "AdminUser:123") resolves the same object
3. Authorization check only on the REST layer → bypassed via GraphQL
4. Read/update admin records, other users' data
```
**Also**: GraphQL batch = rate limit bypass for OTP brute force. Alias = same for field-level rate limits.

---

### Pattern K — Race on coupon → Negative price → Free purchase
**Payout range: $3K–$10K**
```
1. Find coupon, refund, credit, or subscription change endpoint
2. Send N parallel requests (HTTP/2 single-packet for best timing)
3. Observe duplicate application (both requests succeed)
4. If coupon stacks: negative price → refund as credit → spend on real items
```
**Tools**: Turbo Intruder (single-packet), Python asyncio with simultaneous send, Burp Pro parallel.

---

### Pattern L — XXE in SAML → File read → AWS keys → S3 source → all the bugs
**Payout range: $10K–$50K**
```
1. Target accepts SAML assertions (SSO login)
2. Inject XXE in SAML response XML
3. Read /etc/passwd, /proc/self/environ, AWS credentials at ~/.aws/credentials
4. Use extracted cloud keys → full Pattern D chain
```
**Also test**: SVG upload with DOCTYPE, DOCX/PPTX (word/_rels/document.xml.rels), SOAP endpoints, REST endpoints with Content-Type: application/xml.

---

### Pattern M — Self-XSS → CSRF → Stored XSS on victim
**Payout range: $2K–$8K** (self-XSS alone: $0)
```
1. XSS payload in profile field only affects own account view
2. Find CSRF that can set that profile field for any user
3. Chain: CSRF sets victim's field to your XSS payload
4. Victim views their own profile → payload fires on their session
```
**Upgrade**: Stored XSS on victim page → steal session cookie → ATO.

---

### Pattern N — CVE on subdomain → Lateral to main app via shared session cookie
**Payout range: $3K–$15K**
```
1. Old marketing/blog subdomain runs vulnerable WordPress/Drupal/Jira
2. Exploit public CVE for RCE on that host
3. Check Set-Cookie headers: domain=.target.com → main app cookies readable
4. Forge/steal main app session → ATO on production
```
**Stop at**: confirming cookie scope access. Do NOT exfil real user sessions — just demonstrate the attack path with your own test accounts.

---

### Pattern O — Dependency confusion → Build agent RCE → Deploy key → Production
**Payout range: $5K–$25K**
```
1. Find internal package names (GitHub source, error messages, npm lock file)
2. Register those names on public npm/pip/RubyGems/Maven
3. Build agent installs your package → runs your code
4. Exfil build agent env (has SSH deploy key or IAM role)
5. STOP HERE — demonstrate RCE, do not push to production
```
**Evidence needed**: screenshot of env vars / id / hostname from your package's install script. Never push backdoored code.

---

## CONDITIONAL CHAIN TABLE

Standalone findings that need a connector gadget before submitting:

| Standalone Finding | Gadget Needed | Valid Result | Tier |
|---|---|---|---|
| Open redirect | + OAuth redirect_uri → code theft | ATO | Critical |
| Clickjacking | + sensitive action PoC | Action performed | Medium |
| CORS wildcard | + credentialed request exfils PII | PII exfil | High |
| CSRF | + funds transfer / email change / delete | State change | High |
| Rate limit bypass | + OTP/reset token brute success | Auth bypass | Medium/High |
| SSRF (DNS only) | + internal service access + data returned | Info/RCE | Medium |
| Host header injection | + password reset email uses injected host | ATO | High |
| Prompt injection | + reads other user's data | IDOR | High |
| S3 bucket listing | + JS bundles contain live API keys | Secret leak | Medium/High |
| Self-XSS | + CSRF to trigger on victim | Stored XSS | Medium |
| Subdomain takeover | + OAuth redirect_uri registered | ATO | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR node() | Data access | High |
| Reflected XSS on logout page | + CSRF on victim's active session | XSS → ATO | High |

---

## ESCALATION LADDER BY VULN CLASS

### XSS escalation
```
alert(1)         → Proof only (Low/Medium)
document.cookie  → Show cookie is readable (High if HttpOnly absent)
Steal session    → Send cookie to attacker (High → Critical if cross-user)
Force action     → XHR to change email/password while victim is online (Critical ATO)
Blind XSS        → Admin panel hit → exfil admin session (Critical)
```

### SSRF escalation
```
DNS ping         → Blind (Low $200)
HTTP to OOB      → Full SSRF confirmed (Medium $500)
Internal port    → Internal service access (High $1K-$3K)
Cloud metadata   → IAM creds extracted (Critical $5K-$15K)
Cloud creds used → S3 read / cross-account / SSM secrets (Critical $15K-$50K)
```

### IDOR escalation
```
Read own data    → Not a bug
Read other user  → Valid IDOR (Medium/High)
Read all users   → Automate scrape, show scale (High)
Write other user → Update email/password/role (Critical)
Delete other user→ DoS or account destruction (High/Critical)
Tenant pivot     → Cross-tenant access (Critical on SaaS)
```

### SQLi escalation
```
Error message    → Stack trace (Low)
Boolean diff     → Confirmed injection (Medium)
Data extraction  → Dump hashes/emails/keys (High)
Auth bypass      → Login as any user (Critical)
File write       → INTO OUTFILE web shell (Critical RCE)
OS commands      → xp_cmdshell / LOAD_FILE (Critical RCE)
```

### Auth flaw escalation
```
Rate limit miss  → Brute-force OTP/password (Medium)
Token reuse      → Account persistence past logout (Medium)
Token leak       → Via Referer/log exfil (High)
Host header      → Token delivered to attacker (Critical ATO)
0-click ATO      → No victim interaction needed (Critical)
Mass ATO         → All users affected simultaneously (Critical)
```

---

## PAYOUT TIERS — WHERE TO AIM

### Tier S ($20K–$50K)
1. Pre-auth RCE on production / VPN / SSO host
2. Dependency confusion on internal package → build agent RCE
3. 0-click ATO via password reset / email confirmation / SAML flaw
4. GraphQL auth bypass exposing all tenant data
5. SSRF → cloud metadata → IAM creds → cross-account / S3 takeover
6. HTTP request smuggling → mass session theft
7. Supply chain: build agent → deploy key → prod

### Tier A ($10K–$20K)
8. Cache poisoning → stored XSS or mass session theft
9. SSTI → RCE (Jinja2/Twig/Freemarker/ERB/Spring)
10. File upload → RCE (ImageMagick MSL, GhostScript, polyglot, ZIP slip)
11. XXE → file read → cloud creds
12. JWT alg confusion → cross-tenant ATO
13. Race condition on payment → financial loss at scale

### Tier B ($1K–$10K)
14. IDOR → mass PII exfil (show scale)
15. Subdomain takeover → cookie/OAuth → ATO chain
16. Mass assignment → privilege escalation
17. Open redirect → OAuth code theft → ATO
18. Self-XSS → CSRF → stored XSS → ATO
19. CORS misconfig → credentialed PII exfil

---

## CHAIN-FINDING WORKFLOW

### Step 1 — Classify your candidate
```
What did you find?
├─ Low-impact finding (redirect, self-XSS, CORS, rate limit, host header)
│   → Go to Conditional Chain Table above
│   → Find the gadget needed, hunt 20 min
│   → If no gadget found: park it, move on
│
├─ Medium finding (SSRF-dns, IDOR on non-sensitive, blind injection)
│   → Run the Escalation Ladder for that class
│   → Spend max 45 min trying to escalate one level
│   → If stuck: 10-question filter — which Q can you make YES?
│
└─ High/Critical confirmed → write the report NOW
```

### Step 2 — Find the connector gadget

A gadget is the missing piece that turns A into B. Common gadgets:

| You have | Gadget to find | Result |
|---|---|---|
| XSS on low-sensitivity page | Endpoint that loads it in admin context | Blind XSS → admin ATO |
| SSRF (blind) | Redirect chain on internal service | Full-response SSRF |
| Open redirect | OAuth flow that allows that redirect_uri | ATO |
| IDOR (read) | API that accepts the exposed ID to write | Write IDOR → ATO |
| Mass assignment | Endpoint that respects the role field | Privesc |
| Subdomain takeover | Cookie with domain=.target.com | ATO chain |
| Self-XSS | CSRF on the field that stores it | Stored XSS |

### Step 3 — Prove the full chain end-to-end

Write out the complete attack as step-by-step HTTP requests BEFORE writing the report:
```
1. Setup: [accounts needed, preconditions]
2. Step 1: [exact request → response showing vulnerability A]
3. Step 2: [use A's output as input to vulnerability B]
4. Step 3: [B's output used to achieve final impact]
5. Impact: [what attacker has now that they didn't before]
```

If you cannot write Step 2 as a real HTTP request → the chain isn't proven. Do not submit.

### Step 4 — Maximize before reporting

Run the 10-question filter again on the chain as a whole.
Each additional YES raises your payout tier.

---

## IMPACT-WRITING RULES

When writing the chain's impact section:

**Do this:**
- Specific numbers: "All ~12M users are affected via this endpoint"
- Worst-case demonstrated: "I was able to read account #12345's API key, billing info, and 2FA recovery codes"
- CIA classification: Confidentiality (data read) / Integrity (data changed) / Availability (service disrupted)
- Demonstrated vs theoretical: show the worst you can without harming prod users

**Never write:**
- "Could potentially allow..."
- "An attacker might be able to..."
- "Under certain conditions..."

**Template:**
```
An attacker can [EXACT IMPACT] via [ENDPOINT] by [METHOD],
demonstrated against test account [ACCOUNT_ID].
[N] users are affected.
This requires [no auth / free account / paid account only].
```

---

## CVSS CHAIN MULTIPLIERS

When chaining, the final CVSS score reflects the chain, not the individual primitives:

| Chain outcome | Score range | Key vectors |
|---|---|---|
| ATO, 0-click, any user | 9.0–9.8 | AV:N AC:L PR:N UI:N S:U C:H I:H A:N |
| ATO, victim click, any user | 8.0–8.8 | AV:N AC:L PR:N UI:R S:U C:H I:H A:N |
| Tenant pivot → all tenant data | 9.1 | AV:N AC:L PR:L UI:N S:C C:H I:H A:N |
| RCE pre-auth | 9.8 | AV:N AC:L PR:N UI:N S:U C:H I:H A:H |
| Cloud creds → cross-account | 9.1–9.8 | AV:N AC:L PR:N UI:N S:C C:H I:H A:H |
| Admin bypass via chain | 9.0 | AV:N AC:L PR:N UI:N S:U C:H I:H A:N |
| Mass PII (IDOR iteration) | 7.5–8.5 | AV:N AC:L PR:L UI:N S:U C:H I:N A:N |

**Scope changed (S:C)**: if your chain pivots out of the vulnerable component (XSS grabs main-app cookie from subdomain, SSRF reaches cloud control plane) → S:C, big payout multiplier.

---

## THE 30-MINUTE CHAIN CLOCK

```
0:00  — Identify candidate finding
0:05  — Run 10-question filter
0:10  — Look up relevant chain pattern (A–O)
0:20  — Try to find the connector gadget
0:25  — If chain confirmed: write PoC steps
0:30  — DECISION: chain proven → write report | chain not proven → park + move on
```

**Rule**: If you can't prove the chain in 30 minutes of active testing → park the primitive in your notes and move to a new surface. Return only if you find the missing gadget elsewhere.

---

## RED FLAGS — CHAINS THAT WON'T PAY

- Self-XSS + "if attacker could trick the user..." → not a chain, not payable
- CORS wildcard + "with credentials=true it would leak data" → prove it or kill it
- SSRF DNS + "could be used to access internal services" → show the data or kill it
- Open redirect + "could be used in a phishing attack" → not a chain, P5 noise
- "Rate limit bypass that could allow brute force" → demonstrate a cracked account or kill it
- Admin can do X + "this is a security risk" → not a bug, kill it
- Chain that requires victim to run a local binary → not realistic, kill it
- Chain with 4+ required preconditions simultaneously → kill it

---

## CHAIN ANTI-PATTERNS THAT LOSE MONEY

```
Reporting A and B as a chain when they're actually separate (two separate payouts, not one)
Submitting a chain report without end-to-end PoC (triager marks it theoretical)
Overclaiming: chain that requires social engineering as "0-click"
Underdescribing: listing steps without showing actual response bodies
Writing the report before the chain works end-to-end (most common mistake)
```

---

## QUICK REFERENCE — CHAIN STARTERS BY SURFACE

| You're testing... | Hunt for chains via... |
|---|---|
| Password reset flow | Host header injection → ATO (Pattern auth-tier-S) |
| OAuth callback | Open redirect on any page → code theft (Pattern C) |
| File upload | SVG XSS → admin blind XSS → session (Pattern F) |
| URL/webhook parameter | SSRF → metadata → cloud creds (Pattern D) |
| ID parameter | IDOR + mass assignment → privesc (Pattern E) |
| XML/SAML input | XXE → file read → cloud creds (Pattern L) |
| Subdomain CNAME | Takeover → cookie/OAuth (Pattern B) |
| JWT | Alg confusion → tenant pivot (Pattern I) |
| GraphQL | node() auth bypass → IDOR (Pattern J) |
| Coupon/payment | Race condition → double spend (Pattern K) |
| Any JS-heavy app | Source map → Pattern A |
| npm/pip/Maven pkgs | Internal pkg name → Pattern O |
| Cache behavior | Unkeyed headers → Pattern G |
| HTTP frontend proxy | Smuggling → Pattern H |
| Self-XSS | + CSRF → Pattern M |
| Old subdomain CVE | + cookie scope → Pattern N |
