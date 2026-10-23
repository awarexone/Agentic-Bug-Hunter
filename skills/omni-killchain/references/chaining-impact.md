# Chaining + Impact Maximization — the $10K multiplier

> Single-bug reports get triaged. Chained reports get paid. This file is the playbook for turning low/medium findings into critical chains.

---

## THE 10-QUESTION FILTER

For every candidate finding, run through:

```
Q1.  Cross-user impact?           - IDOR/BOLA family
Q2.  Cross-tenant impact?         - massive multiplier on SaaS
Q3.  Leaks credentials/tokens?    - secret family (esp. cloud/admin)
Q4.  Pre-auth?                    - eliminates social-engineering need
Q5.  0-click?                     - eliminates user-interaction cost
Q6.  Persistent (stored)?         - keeps paying after report
Q7.  Internal/cloud-metadata?     - SSRF chain
Q8.  Source code / config read?   - feeds future bugs
Q9.  Leads to RCE/SQLi/admin?     - critical
Q10. Mass-exploitable (race/auto)?- dramatic multiplier
```

3+ yeses -> ready to write report. 0-2 -> keep escalating.

---

## CHAIN PATTERNS THAT WORK

### Pattern A — Recon → Source disclosure → Bug class flood
1. .git exposed / source map present / public S3 with code
2. Pull source
3. Read for: SQL strings, command runners, deserialization, hardcoded secrets, weak JWT keys, internal endpoints
4. Test discovered endpoints/sinks against live target
5. Multiple critical bugs in one report

### Pattern B — Subdomain takeover → Cookie/CSP/OAuth bypass → ATO
See `subdomain-takeover.md`. Sub-takeover alone $200; chained ATO $5K-$15K.

### Pattern C — Open redirect → OAuth code theft → ATO
1. Find any open redirect on `target.com`
2. Use as `redirect_uri` (or via wildcard allowlist)
3. Code arrives at attacker
4. Exchange for tokens

### Pattern D — SSRF → Cloud metadata → Cloud creds → S3 source → harder bugs
See `ssrf-killchain.md`. The escalation ladder is the value.

### Pattern E — IDOR + mass assignment → Self-promote to admin
1. IDOR allows targeting another user
2. Mass assignment allows setting admin role
3. Combined: promote yourself or anyone

### Pattern F — File upload → Stored XSS in admin view → CSRF admin → Plugin install → RCE
1. SVG/HTML upload returns admin-rendered URL
2. Blind XSS payload sends admin's CSRF token
3. CSRF used to install plugin
4. Plugin runs as part of build/deploy -> RCE

### Pattern G — Cache poisoning → Stored XSS → Mass session theft
PayPal $18.9K. Detailed in `cache-poisoning-deception.md`.

### Pattern H — Request smuggling → Cache poisoning → ATO
Slack pattern. `request-smuggling.md` + `cache-poisoning-deception.md`.

### Pattern I — JWT alg confusion → Cross-tenant ATO
1. JWT signed RS256 verification accepts HS256 (lib bug)
2. Sign with the public key as HMAC secret
3. Modify `aud`/`tenant_id` to victim tenant
4. Cross-tenant ATO

### Pattern J — GraphQL node bypass → IDOR on admin types
1. Authz on REST admin endpoints
2. GraphQL `node(id:"AdminUser:...")` skips authz
3. Read/update admin records

### Pattern K — Race on coupon → Negative price → Free purchase
1. Coupon stacking via race
2. Negative price refunded as account credit
3. Spend credit on real items

### Pattern L — XXE in SAML → File read → AWS keys → S3 source → all the bugs
SAML response XXE on IdP/SP -> file read -> repeat Pattern A.

### Pattern M — Self-XSS → CSRF → Stored XSS
1. Self-XSS in profile field (only victim's view)
2. CSRF that sets that field on victim's account
3. Result: stored XSS in victim's view of their own profile -> ATO

### Pattern N — CVE on subdomain → Lateral to main app via shared session
1. Old marketing/blog subdomain runs vulnerable WordPress
2. Take over via plugin RCE
3. Blog cookie scope is `.target.com` -> can read/set main-app cookies
4. Forge admin session

### Pattern O — Dependency confusion → Build agent RCE → Deploy key → Production
1. Internal package name available on public registry
2. Publish + build agent runs your code
3. Build agent has SSH deploy key
4. Push backdoored code (DON'T — stop at confirming RCE)

---

## IMPACT-WRITING RULES

When writing the impact section of a report:
- Specific numbers (number of users affected, dollar value, data classes)
- Worst-case if exploited (list, don't bury)
- Distinguish theoretical vs demonstrated — *demonstrate* the worst you can without harming production
- Tie to CIA: Confidentiality / Integrity / Availability

Bad: "An attacker could potentially access user data."
Good: "An attacker can read any user's email, phone, address, and 2FA secrets via the GraphQL `node()` resolver, demonstrated against test account `tester+poc@gmail.com` (id `User:abc123`). All ~12M users are affected."

---

## RED FLAGS THAT KILL VALUE

- "Self-XSS" -> low; needs CSRF/postMessage/cache to escalate
- "Theoretical CSRF on logout" -> P5 unless chained
- "No rate limit on login" -> P5 unless creds enumeration via timing
- "Missing security headers" -> P5 noise unless they enable a real bug
- "Best practice violation" without exploitable impact -> noise
- "Unauthenticated endpoint returns errors" -> not a bug

Don't submit these alone. Chain them.

---

## BUDGET HEURISTICS

- 2 hours on a target with no chain candidate -> move on
- 1 hour on a finding before deciding chain potential -> escalate or shelve
- 30 minutes max on report-writing once impact is proven
- Re-verify the bug 24-48h before submitting (state may have changed)
