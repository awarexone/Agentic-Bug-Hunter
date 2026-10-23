# IDOR / BOLA / Mass Assignment — bread and butter -> $10K+ when chained

> H1 hits: HackerOne $25K (GraphQL private program data), HackerOne $12.5K (delete licenses via cert mutation), countless $1K-$5K ones.

---

## IDOR / BOLA — Surface

Anywhere user-controlled IDs hit data:
```
/api/v1/users/{id}                        REST
/api/v1/orders/{order_id}/items/{item_id} REST nested
/graphql with node(id: "...")             GraphQL global ID
/api?file=42                               legacy
?invoiceId=                                pagination + filter
WebSocket frames with id field
JWT claims with user_id (server should ignore, sometimes trusts)
```

Identifier types — each has a different testing approach:
- **Sequential int**: just decrement/increment
- **UUID v4**: random — need to find another UUID via signup, invite, share, public listing
- **UUID v1**: time-based — derivable
- **base64-encoded JSON** (`eyJp...`): decode, swap, re-encode
- **Hashids / shortlinks**: try the salt; sometimes leaks via JS bundle
- **Encrypted IDs**: try IV reuse / padding oracle (rare but devastating)

---

## STAGE 1 — Detection

1. Sign up two accounts (A and B). Always.
2. As A, do everything. Capture all requests with Burp.
3. As B, take A's request, replace A's ID with B's resource ID, replay with B's session.
4. Observe: 200/200? 403/200? Different content?

Tools:
- **Autorize** Burp ext — replays with second user's session automatically
- **AuthMatrix** — multi-role testing
- **AuthAnalyzer** — token swapping

---

## STAGE 2 — Bypass tricks

### HTTP method
Endpoint forbids GET but allows POST, or vice versa.
```
GET /api/users/123     -> 403
POST /api/users/123    -> 200
PUT /api/users/123     -> 200
HEAD /api/users/123    -> 200 (returns headers without body check)
```

### Verb override
```
X-HTTP-Method-Override: GET
X-Method-Override: PUT
X-HTTP-Method: DELETE
```
Or `_method=DELETE` in body.

### Path / param tricks
- `/api/users/123` -> `/api/users/123/` -> `/api/users/123/.json` -> `/api/users/123;` -> `/api/Users/123`
- URL encode part: `/api/users/12%33`
- Double slash: `/api//users/123`
- Param pollution: `?id=victim&id=mine` (and vice versa)
- Array: `id[]=victim`
- Wildcard: `id=*` or `id=%`
- Negative: `id=-1`, `id=null`, `id=0`

### IDOR via separate API gateway
The web UI calls `/api/v1/users/{id}` (authz enforced) but legacy `/internal/users/{id}` or `/v0/users/{id}` skips authz. Mine for legacy paths in JS / wayback.

### JWT user_id trust
JWT has `user_id` claim. App also accepts `user_id` in body/query. Server uses query value. Swap query value -> IDOR.

### GraphQL node() global ID
```graphql
{ node(id: "User:victimUUID") { ... on User { email phone privateField } } }
```
Many GraphQL servers expose every type via `node()` even when the explicit query is locked down.

### WebSocket frames
WebSocket auth often happens at handshake; subsequent frames are trusted. Sniff frames, modify IDs.

---

## MASS ASSIGNMENT — the under-tested cousin

App accepts JSON, copies fields straight to model:
```js
user.update(req.body)  // node
User.update(params)    // rails strong_parameters not used
```

Inject extra fields:
```json
{
  "name":"foo",
  "email":"foo@x.com",
  "is_admin":true,
  "role":"admin",
  "permissions":["*"],
  "verified":true,
  "tenant_id":"victim_org",
  "owner_id":1,
  "balance":99999,
  "credits":99999,
  "subscription_tier":"enterprise",
  "trial_ends_at":"2099-01-01",
  "feature_flags":{"all":true},
  "stripe_customer_id":"cus_VICTIM"
}
```

Where: `PUT /me`, `PATCH /account`, signup `POST /users`, profile updates, settings, team/org create.

**Signal of a sink:**
- Response echoes back the field you injected
- DB error mentioning a column you didn't expect
- `200 OK` with empty body when you sent nonsense (assume merged blindly)

---

## PRIVILEGE ESCALATION via field injection

- `role: admin`, `roles: ["admin"]`, `is_staff: true`, `superuser: true`
- `permissions: ["*", "users:write", "billing:read"]`
- `tenant_id: <other tenant>` -> cross-tenant
- `org_id`, `workspace_id`, `team_id`
- `acl_grants: [{user:me, level:owner}]`
- `_acl`, `_owner`, `_meta` (Mongo / generic)

---

## PROTOTYPE POLLUTION (server-side)

Body parsers (qs, lodash<=4.17.20, mergee, defaults-deep) + `__proto__` -> pollute global Object.prototype.

```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
{"a.__proto__.b":"c"}    // qs allow-prototypes
```

Sinks:
- `if (user.isAdmin)` -> after pollution, every object has `isAdmin=true`
- Template engines (Pug, Handlebars) -> RCE via gadget chains
- Express render lookups
- Mongoose schema bypass

Server-side PP often yields RCE through gadget chains in popular frameworks:
- Express + Pug: `__proto__` with `block` / `extend` -> RCE
- Express + EJS: `outputFunctionName` injection -> RCE
- ssrf, command, RCE gadgets in cves

Tools: `ppfuzz`, `ppmap`, `pp-finder`.

---

## TENANT PIVOT (massive multiplier)

Multi-tenant SaaS. Every IDOR is potentially cross-tenant.
- API expects `tenant_id` in JWT but also accepts `?tenant_id=` query (server uses query)
- Subdomain-based tenants (`tenant1.app.com`, `tenant2.app.com`) -> Host header smuggling
- Resource IDs not scoped: `team:42` exists across all tenants, IDOR works without tenant header
- Webhook delivery into wrong tenant
- Slack/JIRA/SAML integration linked to wrong workspace

Cross-tenant impact = $10K+ even on otherwise small orgs.

---

## CHAIN RECIPES

### Recipe 1 — IDOR -> mass assignment -> admin
1. IDOR on `PUT /api/users/me` allows passing arbitrary `id`
2. Set `id` to admin's ID, body sets fields you want
3. Or set your own role to admin

### Recipe 2 — IDOR on invitation -> tenant pivot
1. Invitation token URL is `/invite/{token}`
2. Token base64-decodes to `{org:42, email:victim@x.com}`
3. Modify org -> accept invitation into target org

### Recipe 3 — GraphQL node() bypass -> private data
1. Find any `id` value (own user, own resource)
2. Try `node(id: "BASE64-encoded ResourceType:victim_uuid")`
3. Most authz checks don't fire on `node()` resolver

### Recipe 4 — Mass assignment on Stripe customer field
1. PATCH /account accepts `stripe_customer_id`
2. Set to victim's Stripe customer ID
3. Their card now charges your account, or your invoices route to them

---

## VALIDATION CHECKLIST

- Reproduce with two clean accounts (different emails, different tenants if applicable)
- Show victim's data clearly visible to attacker (or attacker action affecting victim)
- Note exact endpoint, exact field, exact response
- For mass assignment: capture before/after state of the modified object
- For tenant pivot: show data from another tenant in attacker's view

---

## SCAN AUTOMATION

Once you find the pattern:
- Use Burp Intruder to walk the ID space (don't go nuts on prod)
- For UUIDs, brute is hopeless — focus on chains that leak UUIDs (search APIs, public listings, OG previews)
- For sequential, try a small range; reporting at 5-10 confirmed records is sufficient impact
