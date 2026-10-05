# Scope Guard — the counterweight to zero-skip

Rule 1 says **hit every in-scope asset**. This file says **never touch an out-of-scope one**. Both are
absolute. "Zero-skip" is bounded strictly by the scope: a single out-of-scope request can void an
engagement, get you banned, or break the law. When the two rules seem to conflict, scope wins — and the
answer is always "verify scope," never "skip the asset."

## Build the allow/deny model (Phase 0, before any request)
From `scope.txt`:
- **Allow:** in-scope apex domains + wildcard roots (`*.target.com`), explicit hosts, IP ranges, mobile
  packages, API hosts. Every enrolled ledger row must be inside this set.
- **Deny:** explicit out-of-scope hosts/paths, plus everything not in Allow.

## Match rules (get these exactly right)
- `*.target.com` matches `a.target.com`, `a.b.target.com` — **not** `target.com.evil.com`,
  **not** `nottarget.com`, **not** `target.com` itself unless the apex is separately listed.
- Suffix-match on a dot boundary only. Reject look-alikes (`target-cdn.com`, `targetusercontent.com`)
  unless explicitly listed.
- **Third-party services are out of scope even when reachable:** Stripe, PayPal, Salesforce, Auth0,
  Okta, Google/FB OAuth, Cloudflare, Zendesk, Intercom, S3/GCS buckets you don't own, analytics/ads/CDN.
  A bug in *their* product is theirs, not the target's (unless the program says otherwise).
- **Ownership check for acquisitions/apex:** before hitting a root you inferred (not explicitly listed),
  confirm it's the target's via WHOIS/ASN/cert SANs/`security.txt`. If unverified → treat as out-of-scope.

## Gate every outbound request
```python
# scope_check(host) -> "in" | "out"  — run before EVERY request; deny by default
import re
def scope_check(host, allow_wildcards, allow_exact, deny):
    h=host.lower().strip().rstrip('.')
    if h in deny: return "out"
    if h in allow_exact: return "in"
    for w in allow_wildcards:                 # w like "target.com" for *.target.com
        if h==w or h.endswith("."+w): return "in"
    return "out"                               # default-deny
```
Log every host you touch to `audit.jsonl` (`{ts, host, url, method, verdict}`) so coverage and safety are
both auditable. If a hunt step wants to reach a host that returns `out` → **do not send it**; note it and move on.

## Politeness / not-a-DoS
Respect program rate limits; pace enumeration (the IDOR/recon files already pace ~1/sec under WAF). The
zero-skip mandate is about *completeness of coverage*, never about volume/DoS. No stress testing, no
automated scanners against fragile endpoints unless the program allows it.

## When unsure
Ambiguous asset (is this subdomain in scope? is this the target's bucket?) → **default to out-of-scope and
ask the user.** This is one of the few reasons to surface a question mid-run; getting it wrong is far
costlier than pausing.
