---
name: omni-killchain
description: >
  Elite end-to-end offensive bug-bounty hunting orchestrator. ALWAYS activate for: full-scope recon, killchain, bug hunting strategy, target triage, attack surface mapping, "find me a bug", "hunt on $target", high-payout vuln hunting, P1/P2 bug discovery, $10K+ bounty hunting, account takeover (ATO), authentication bypass, IDOR/BOLA, SSRF→cloud-metadata, RCE chains, file upload to RCE, dependency confusion, request smuggling, cache poisoning, OAuth/SAML/JWT abuse, GraphQL abuse, exposed services (Jenkins/Kubernetes/Spring/Actuator), secrets leaks (GitHub/Postman), subdomain takeover, race conditions, web cache deception, XXE chains, unsafe deserialization, SSTI, prototype pollution, mass assignment, CORS abuse, postMessage abuse, business logic, privilege escalation, chaining low → critical, exploit PoC writing, HackerOne/Bugcrowd/Intigriti report writing. Built from analysis of HackerOne TOP100PAID, TOP100UPVOTED, TOPRCE, TOPSSRF, TOPUPLOAD, TOPOAUTH, TOPOPENID, TOPINFODISCLOSURE, TOPXXE plus Awesome-Bugbounty-Writeups. Routes to specialist hunters (sqli, xss, blf, js-recon, prompt-injection) when applicable. Authorized testing only — bug bounty in-scope, pentest engagement, or CTF. Token-efficient. Never assumes — always verifies. 20+ year red-team mindset.
---

# OMNI-KILLCHAIN — Elite Bug Hunting Orchestrator

> **Scope reminder**: Authorization gate first. Confirm target is in-scope for an active bounty program / pentest / CTF before any active probing. If unclear, ask.

---

## PHILOSOPHY (read once, internalize forever)

1. **High payouts come from impact, not novelty.** A boring IDOR that exposes 10M users beats a clever XSS on a marketing page. Always ask: *who else does this affect, and what's the worst they can do?*
2. **Chains > single bugs.** $10K+ reports are almost always chains: `subdomain takeover → cookie scoping → ATO`, `SSRF → metadata → cloud creds → S3 read → source code → harder bugs`, `low IDOR → mass assignment → admin role → tenant pivot`.
3. **Boring features hide gold.** Import/export, bulk actions, integrations, webhooks, password reset, email confirmation, billing, file upload, OAuth callbacks, GraphQL, admin migration tools — these are where the real bugs live. Don't waste hours on the homepage search box.
4. **Verify, don't assume.** Memory of past programs ≠ current state. Re-recon before re-reporting.
5. **Document like a Tier-1 hunter.** Reproducible PoC, video/curl, impact statement, suggested fix, CVSS — see `references/report-writing.md`.

---

## PHASE 0 — TARGET TRIAGE (do this first, every time)

Classify the target before touching it. Different classes get different killchain routes.

```
SaaS multi-tenant web app   → IDOR/BOLA, mass assignment, tenant pivot, GraphQL, OAuth, billing logic
Devtool / SCM (GitLab-like) → import features, template injection, file read, git flag injection, plugin RCE
Marketplace / Two-sided     → seller<->buyer auth boundary, marketplace IDOR, escrow logic, payment flows
API-first / mobile-backend  → BOLA, mass assignment, JWT, GraphQL introspection, rate limit bypass
Identity provider / OAuth   → redirect_uri, state, PKCE, scope creep, account linking, SAML signature
File processor (PDF/img/AV) → ImageMagick, FFmpeg, Ghostscript, ExifTool, parser confusion, SSRF, XXE
E-commerce / payments       → race conditions, coupon stacking, refund logic, currency mismatch, IDOR on orders
Internal/admin panel exposed→ default creds, SSRF pivot, exposed actuators, debug endpoints
Self-hosted/on-prem         → version disclosure, supply chain, dependency confusion
Cloud infra (S3/IAM)        → public buckets, IAM misconfig, presigned URL leaks, metadata SSRF
```

If you can't classify in 60 seconds, you haven't done enough recon. Go to Phase 1.

---

## PHASE 1 — RECON KILLCHAIN

Read `references/recon-killchain.md` for full one-liners. Summary flow:

```
SCOPE -> SUBDOMAINS -> ASSETS -> HTTP PROBE -> SCREENSHOT -> JS HARVEST -> ENDPOINTS -> PARAMS -> SECRETS -> DECISION
```

**Passive (no traffic to target)**
- `subfinder -d $T -all -silent`, `amass enum -passive`, `chaos -d $T`
- `crt.sh`, `github-subdomains -d $T -t $GH_TOKEN`, `cero -c 1000 $T`
- `waybackurls $T`, `gau --threads 10 $T`, `katana -passive -list ...`
- `trufflehog github --org=$T --only-verified`, `gitleaks`, `noseyparker`

**Active**
- `httpx -silent -status-code -title -tech-detect -ip -cname`
- `naabu -top-ports 1000` then `nmap -sV -sC -p $PORTS`
- `katana -d 5 -jc -kf all -aff -fs fqdn`
- `gospider -d 5 -c 10 --js`
- `ffuf -w $WL -u https://$T/FUZZ -mc all -fc 404 -ac` (auto-calibrate)

**Decision criteria (move to Phase 2 only when):**
- >=10 live hosts mapped with tech stack
- >=1 admin/staging/dev subdomain identified
- JS bundles harvested + parsed for endpoints
- Auth flow understood (cookies, JWT, session, OAuth?)
- Existing CVEs for the stack catalogued

---

## PHASE 2 — ATTACK SURFACE MAPPING

Read `references/recon-killchain.md` § "Surface Mapping". Build this table for each target before attacking:

```
| Surface              | Examples                                      | Top bug classes                          |
| -------------------- | --------------------------------------------- | ---------------------------------------- |
| Auth                 | /login, /reset, /verify, /oauth/callback      | ATO, OAuth, password reset, SAML, JWT    |
| User-controlled IDs  | /user/{id}, /order/{id}, GraphQL node(id:...) | IDOR, BOLA, mass assignment              |
| Status/state siblings| /invitations/{challenged,unchallenged}, pending/accepted, active/archived | BOLA (per-variant authz gap → token+PII leak) |
| Import/Export        | /import, /migration, /backup, /clone          | File read, SSRF, RCE, data exfil         |
| File upload          | avatar, attachment, csv import, doc           | RCE, XSS, SSRF, XXE, polyglot            |
| Integrations         | webhooks, OAuth apps, slack/jira              | SSRF, OAuth scope, secret leak           |
| Billing              | checkout, refund, coupon, plan change         | Race, business logic, IDOR               |
| Admin/internal       | /admin, /staff, /internal, X-Forwarded-For    | Auth bypass, header smuggling            |
| GraphQL              | /graphql, /api/graphql                        | Introspection, batch, alias, IDOR        |
| Search/filter/sort   | ?q=, ?orderBy=, ?filter=                      | SQLi, NoSQLi, SSTI, sort injection       |
| URL fetchers         | url=, image=, callback=, return_to=           | SSRF, open redirect -> OAuth ATO         |
| Templating           | email templates, invoice PDF, markdown        | SSTI -> RCE, XSS                         |
| Crypto/JWT           | Authorization: Bearer ...                     | alg=none, kid traversal, weak secret     |
```

---

## PHASE 3 — PAYOUT-PRIORITY ROUTING

Hunt highest-EV first. From HackerOne data, these archetypes consistently pay $10K+ when impact is shown. Each links to a deep reference.

### TIER S ($20K–$50K) — Shoot for these
1. **Pre-auth RCE on production / VPN / SSO host** → `references/rce-archetypes.md` § "Pre-auth"
2. **Dependency confusion on internal package names** → `references/dependency-confusion.md`
3. **Account takeover via password reset / email confirmation flaw** — incl. username/identifier reuse: delete or rename account A, claim A's freed username/handle/email/org-slug, inherit A's orphaned resources/membership/links (ownership keyed on a mutable identifier instead of immutable user ID)
4. **GraphQL authorization bypass exposing private program/tenant data** → `references/graphql-deep.md`
5. **Exposed Kubernetes API / Jenkins / Zeppelin / Spring Actuator with creds** → `references/exposed-services.md`
6. **GitHub/GitLab/CI secrets leak with verified credentials** → `references/secrets-recon.md`
7. **SSRF → cloud metadata → IAM credentials → cross-account / S3 takeover** → `references/ssrf-killchain.md`
8. **HTTP request smuggling → mass session/cookie theft** → `references/request-smuggling.md`
9. **Supply chain: malicious PR / compromised release / build agent** → `references/dependency-confusion.md` § "Build pipeline"
10. **OAuth/SAML response_type or signature bypass → ATO across IdP**

### TIER A ($10K–$20K)
11. **Cache poisoning → stored XSS / session / DoS** → `references/cache-poisoning-deception.md`
12. **Web cache deception leaking auth tokens** → same file
13. **Server-side template injection (Kramdown, Jinja, Smarty, Velocity, Twig, FreeMarker)** → `references/ssti-rce.md`
14. **Java/PHP/Python/.NET unsafe deserialization** → `references/deserialization.md`
15. **File upload to RCE (polyglot, parser confusion, magic bytes, ZIP slip, GhostScript, ImageMagick MSL)** → `references/file-upload-rce.md`
16. **XXE in SOAP/SAML/SVG/DOCX/JPEG XMP/SVG-on-PDF** → `references/xxe-deep.md`
17. **GraphQL batch/alias/depth → DoS, brute-force, info disclosure** → `references/graphql-deep.md`
18. **Race condition on payment / coupon / refund / 2FA / rate limit** → `references/race-conditions.md`
19. **Privilege escalation via role/permission abuse on multi-tenant** → `references/idor-bola-mass-assignment.md`
20. **Subdomain takeover → cookie scope → ATO chain** → `references/subdomain-takeover.md`

### TIER B ($1K–$10K) — Bread and butter
21. IDOR / BOLA on /api/v\*/\*/{id}, GraphQL node(id:...)
22. Mass assignment on PUT/PATCH user/profile/account
23. Open redirect → OAuth code theft
24. Self-XSS → CSRF → stored XSS
25. CORS misconfig leaking auth tokens
26. Session fixation / cookie scoping on sibling subdomain
27. 2FA bypass (race, response manipulation, backup code reuse)
28. SSRF (blind, DNS rebinding, IPv6, URL parser confusion)
29. Reflected XSS in legacy/marketing site → cookie steal on main
30. Path traversal in export/download/zip features

---

## PHASE 4 — EXECUTION RULES

For every candidate vuln:

1. **Reproduce twice.** Different account, different IP, different browser. False positives kill credibility.
2. **Maximize impact before reporting.** A blind SSRF is $500. SSRF→metadata→cloud keys→S3 read→PII is $10K+. Always escalate.
3. **Chain across surfaces.** Subdomain X has reflected XSS. Domain Y sets cookies on `*.target.com`. Combine.
4. **Test rate limits and quotas with care.** Don't break prod. Use minimal payloads to confirm — then stop.
5. **Never exfil real data.** Use marker files / your own accounts / test buckets. Read enough to prove impact, no more.
6. **Capture everything.** Store HTTP requests/responses, screenshots, video. Use Burp Logger/Pro.
7. **Write the report when impact is provable, not before.** Half-impact reports get triaged as low.

---

## PHASE 5 — IMPACT MAXIMIZATION (the $10K multiplier)

Read `references/chaining-impact.md`. Quick mental checklist for every finding:

```
Q1. Can this affect another user (cross-user)?           -> IDOR/BOLA family
Q2. Can this affect another tenant (cross-tenant)?       -> Privilege escalation, big multiplier
Q3. Can this leak credentials/tokens/keys?               -> Secret exposure, big multiplier
Q4. Can this be triggered without auth?                  -> Pre-auth, big multiplier
Q5. Can this be triggered without user interaction?      -> 0-click, big multiplier
Q6. Can this persist (stored)?                           -> Stored XSS, persistent IDOR
Q7. Can this read internal services/cloud metadata?      -> SSRF chain
Q8. Can this read source code or config?                 -> Source disclosure -> harder bugs
Q9. Can this lead to RCE or SQLi?                        -> Critical
Q10. Can this be mass-exploited (batch/race/automation)? -> Mass-impact, big multiplier
```

Each "yes" raises payout tier. Aim for >=3 yeses before submitting.

---

## ROUTING — when to delegate

| Trigger | Delegate to |
|---|---|
| SQL injection signal (errors, time delay, ORDER BY) | `sqli-hunter-agent` |
| XSS sink in DOM/markdown/HTML reflection | `xss-hunter-agent` |
| Heavy JS bundles, source maps, big SPA | `js-recon-agent` |
| Broken Logic / business-logic / authz check pattern | `blf-hunter-agent` |
| LLM/agent target, system prompt, AI feature | `prompt-injection-hunter-agent` |

For everything else — RCE, SSRF, ATO, OAuth, IDOR, upload, XXE, race, smuggling, cache, subdomain takeover, dependency confusion, exposed services, secrets — stay here and use the references below.

---

## REFERENCE INDEX

**Recon & surface**
- `references/recon-killchain.md` — full passive+active recon flow with one-liners
- `references/secrets-recon.md` — GitHub/GitLab/Postman/Docker/CI secret hunting
- `references/subdomain-takeover.md` — full dangling-CNAME provider catalog
- `references/exposed-services.md` — Jenkins, Kubernetes, Zeppelin, Spring Actuator, Drupal, Airflow, Grafana

**Server-side execution**
- `references/rce-archetypes.md` — every RCE archetype seen on H1 ($10K+ ones first)
- `references/ssti-rce.md` — Jinja2, Kramdown, Smarty, Twig, Velocity, FreeMarker, Handlebars, Pug, Mako
- `references/deserialization.md` — Java, PHP (phar/wakeup), .NET, Python, Node (node-serialize), Ruby
- `references/file-upload-rce.md` — polyglot, parser confusion, ImageMagick, GhostScript, ZIP slip, XSLT, ExifTool
- `references/dependency-confusion.md` — npm/pip/RubyGems/Maven/Go substitution, build pipeline RCE

**Server-side request abuse**
- `references/ssrf-killchain.md` — cloud metadata (AWS/GCP/Azure/Alibaba/DO), DNS rebinding, IPv6, parser tricks
- `references/xxe-deep.md` — SOAP, SAML, SVG, DOCX, OOXML, JPEG XMP, blind/OOB extraction

**HTTP layer**
- `references/request-smuggling.md` — CL.TE, TE.CL, TE.TE, h2c, response queue desync
- `references/cache-poisoning-deception.md` — unkeyed input, fat GET, web cache deception
- `references/cors-postmessage.md` — CORS misconfig, postMessage origin abuse

**Authorization & logic**
- `references/idor-bola-mass-assignment.md` — IDOR, BOLA, mass assignment, prototype pollution sinks
- `references/race-conditions.md` — Turbo Intruder, single-packet attack, financial logic
- `references/graphql-deep.md` — introspection, batch, alias, depth, suggestions, IDOR

**Maximization**
- `references/chaining-impact.md` — low->critical recipes from $10K+ H1 reports
- `references/report-writing.md` — H1/Bugcrowd/Intigriti templates, CVSS, impact statements

**Payloads & cheatsheets**
- `payloads/rce-payloads.md`
- `payloads/ssrf-payloads.md`
- `payloads/ssti-payloads.md`
- `payloads/cmd-injection.md`
- `cheatsheets/waf-bypass.md`
- `cheatsheets/oneliners.md` — copy-paste commands per phase
- `cheatsheets/encoding-tricks.md`

---

## QUICK START — when the user says "hunt $TARGET"

1. Confirm scope authorization.
2. Run Phase 1 recon (passive first; ask before going active).
3. Triage findings into the Phase 2 surface table.
4. Prioritize by Phase 3 tier (TIER S → A → B).
5. Pick the top 3 candidates, dig deep with the relevant `references/*.md`.
6. For each candidate, run the Phase 5 impact checklist.
7. Only write the report when >=3 impact answers are "yes".
8. Use `references/report-writing.md` for the submission.

Stay paranoid. Stay scoped. Stack chains. Hunt the $10K+ tier first.
