# IDOR / BOLA / BFLA — Authorization Bypass Hunting

Hunt only resource-level authorization bugs that chain to PII-at-scale, ATO, or financial impact.

## Kill list (instant reject)
- Self-IDOR (reading your own data) is not IDOR.
- "Possible IDOR — needs confirmation" is not a finding. Confirm or kill.
- Reading a public-by-design resource is not IDOR.
- ID disclosure in a URL with no read/write follow-on is not P-class.
- Org-admin reading their own org's data is not IDOR.

## Valid classes (what we hunt)
- **Cross-tenant read/write** — Tenant A reads/modifies Tenant B's records (orders, invoices, KYC, tickets).
- **Horizontal IDOR** — User A reads User B's data, same tenant, no shared scope.
- **Vertical IDOR / BFLA** — low-priv role calls admin-only function/mutation.
- **Sub-route auth skip** — `/orders/{id}` 403s but `/orders/{id}/edit|refund|notes|export` is unscoped.
- **Per-verb authz gap (CRUD split)** — GET/PUT scoped, but `DELETE`/`archive`/`clone`/`export` isn't.
  **Test every verb/action on the same object independently.** Delete is the classic unguarded sibling.
- **Status-sibling gap** — swap the lifecycle word (`challenged`↔`unchallenged`, `pending`↔`accepted`,
  `active`↔`archived`, `draft`↔`published`) with a foreign `org_id`; authz is wired per-variant, one
  sibling returns 200 while the other 4xx. A status-code diff between siblings is the tell.
- **JWT claim IDOR** — `sub`/`uid` is mutable and used as the model key, or trusted across service hops.
- **GraphQL nested/field IDOR** — top resolver checks auth, nested resolver or deprecated field doesn't.
- **Predictable-ID enumeration** — sequential/short-token IDs make every class enumerable platform-wide.

## No-hallucination rule — every IDOR needs all 3
1. Request A from Account 1 returns **Account 1's** record.
2. Same request shape with Account 2's id, still authed as Account 1, returns **Account 2's** record
   (not 403, not an empty form).
3. Body-level proof of the foreign record (different email/name/amount/order_id in the response).
If you can't show all three, it isn't IDOR.

## The loop
1. **Intel** — tenant model (subdomain / JWT claim / header / path)? ID scheme per resource? auth stack?
2. **Surface map** — every endpoint taking a resource id (path/query/body/JWT). Sources: authed HTML/JS
   (`wire:snapshot`, `data-id`, `fetch(`), proxy history, OpenAPI/GraphQL introspection, JS bundles
   (`jsluice urls`), wayback. Decode Filament/Livewire `wire:snapshot` → model class + key.
3. **ID scheme** — sequential numeric = enumerable (whole platform sweeps even if route authz is right);
   UUIDv4 = needs cross-tenant access; UUIDv1/ULID/Snowflake = time-ordered, partly predictable;
   base62 ≤8 = brute-forceable; HMAC-signed = only if secret leaks (check JS/sourcemaps).
4. **Actor model** — get 2 accounts in different tenants (cross), same tenant diff role (vertical),
   same tenant same role (horizontal), plus an anon session (auth-skip). Record each account's ids.
5. **Hypotheses** — one row per id-endpoint: `endpoint | sub-id | observation that proves the bug`.
   Rank by (scope-cross-severity × ID-enumerability). Cross-tenant + sequential first.
6. **Test** — Baseline (own) → Cross probe (foreign id, own session) → Reverse (B reads A) → Negative
   control (a sibling that *should* 403) → **Body diff** (foreign identifiers present). Pace ~1 probe/
   min; WAFs escalate to CAPTCHA after ~10 fast requests. If WAF/captcha hard-locks the IP, switch to
   Playwright `channel="chrome"` + stealth, or ask the user to re-export a fresh WAF token.
7. **Escalate (mandatory)** — one cross-tenant read ≠ P1. Chain: one read → enumerate id range →
   quantify PII at scale → probe the matching write endpoint → ceiling.
   ```
   read IDOR   → enumerate → full PII dump           (P1 if PII)
   write IDOR  → modify foreign resource             (P1 if money/auth)
   admin BFLA  → low-priv calls admin fn             (P1 if user-data scope)
   JWT sub     → forge token → ATO                   (P1 always)
   ```

## Extra hypotheses (highest-yield disclosed patterns)
- Replay every nameable GraphQL/REST op from a **no-permission / lowest-role** session (undocumented
  mutations with no authz = #1 payer). "Not found" ≠ safe — retry with a valid foreign id.
- Any resource that 403s in UI/GET → retry API, `DELETE`, `PUT`, `/edit`, older `/v1` siblings.
- Add a privilege field (`admin:true`, `role`, `is_admin`) to update requests (mass assignment).
- Capture an owner-only request, replay verbatim as low-priv (forced request).
- Flip approval/status params to skip moderation; inject `email` to accept invites you don't own → ATO.
- Feed wayback/gau UUIDs back into current endpoints.

## Anti-slop checklist (run silently)
- [ ] Own baseline captured before cross probe. [ ] Every verb tested separately (read+update+delete/export).
- [ ] Both directions (A→B and B→A). [ ] Body diff shows foreign identifiers. [ ] Negative control 403s.
- [ ] Ruled out "Account 1 is secretly superadmin." [ ] Enumeration quantified. [ ] Phase-7 chain done.
- [ ] No "potential/possible" language. [ ] Switched to real-Chrome if WAF blocked.
