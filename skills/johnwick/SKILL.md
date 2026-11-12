---
name: johnwick
description: Use when the user says "run johnwick" / "/johnwick", hands you a bug-bounty target or scope and wants the full manual+recon+automated hunt run end-to-end, or asks to hunt a target with total coverage (every in-scope domain/subdomain, all JS, signup+login, then exploit and validate). Self-contained long-running orchestrator — recon, JS mining, auto-signup, and hunting for IDOR, SSRF, RCE, SSTI, XXE, SQLi, request smuggling, cache poisoning, race conditions, OAuth/JWT/SAML ATO, GraphQL, 403-bypass, and mobile are all built in via internal reference files (each grounded in disclosed paid HackerOne reports), with a zero-skip coverage ledger and a superpowers verification gate between every phase.
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

**Grep is a triage pass to prioritize — NEVER the analysis itself.** Grep finds `apikey` and
`fetch(`. It does not tell you a URL-upload feature silently proxies server-side (SSRF), or that
a role flag is set client-side and never re-checked. **Every beautified/deobfuscated file gets
read end to end.** No exception for hundreds of files across dozens of hosts — budget the time;
this step is supposed to be slow.

---

## RULE 3 — Hunt these in every file (the money list)

Static-scan to triage, then READ to confirm. Scanners: `trufflehog filesystem js_files/` (verifies
live keys), `jsluice urls|secrets js_files/*.js`, `mantra -f js.txt`, `SecretFinder -i <f> -o cli`,
`LinkFinder -i beautified/ -o cli`, `xnLinkFinder`, `nuclei -t http/exposures/ -l js.txt`, `retire.js --js`.

- **Secrets / tokens** — AWS `AKIA…`, GCP `AIza…`, Stripe `sk_live_`, GitHub `ghp_`/`github_pat_`,
  Slack `xox…`, SendGrid `SG.`, Twilio `AC…`, JWTs `eyJ…`, `Authorization: Basic` blobs,
  `client_id`+`client_secret`, Firebase config, Algolia **admin** key, Mapbox `sk.`, private PEM keys.
- **Hidden / internal / staging endpoints** — every endpoint in JS is an UNTESTED endpoint. Grep
  `/api/`, `/internal/`, `/admin/`, `/graphql`, `v1|v2|v3`, `*-dev|staging|uat|sandbox`. Real payout
  pattern: `/api/v2/internal/users` recovered from obfuscated JS → full user DB → $25k.
- **Client-side auth & roles** — `isAdmin`, `role === 'admin'`, `hasPermission`, `parseJwt`,
  `atob(token)`, `localStorage.setItem('admin',…)`. Any UI/route gated ONLY client-side is a
  BAC/BFLA lead — call the endpoint directly with a low-priv token.
- **Hidden routes & feature flags** — dump the SPA router table (React Router / Vue Router / Angular
  route config) from the bundle → visit admin/beta/internal routes the nav never links. **Flip
  feature flags** (`localStorage`, `?feature=`, cookie, JSON config) to unlock ungated functionality.
- **Hardcoded IDs / IDOR seeds** — UUIDs and numeric `userId/orgId/accountId` belonging to other
  tenants → cross-tenant test material.
- **DOM XSS sinks** — `innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`,
  `setTimeout("…")`, jQuery `$()`, `.html()`; sources `location.hash/search/href`, `postMessage`,
  `document.referrer` → trace source→sink.
- **Prototype pollution** — `__proto__`, unsafe `merge/extend/Object.assign(x.prototype…)`,
  query-string parsers → gadget chain to XSS/RCE.
- **Cloud & 3rd-party refs** — `*.amazonaws.com`/`s3://`, `firebaseio.com`, `storage.googleapis.com`,
  `*.blob.core.windows.net`, `cloudfront.net` → test bucket/Firebase/Firestore misconfig + takeover.
- **postMessage** — `addEventListener('message',…)` with no origin check → cross-origin data theft / DOM XSS.
- **Dependency CVEs** — map bundled lib versions to OSV/Snyk (`retire.js`, `nuclei` tech-detect).
  One bundled vulnerable lodash / axios / DOMPurify / jQuery = your bug.
- **Historical / version diffing** — pull OLD JS from Wayback and **diff vs live**. Secrets and
  endpoints "removed" from current JS are frequently STILL LIVE server-side; forgotten APIs survive
  in old bundles.

---

## RULE 4 — Confirm dynamically, THEN it's a finding (kill false positives)

Nothing gets reported on a regex hit alone. Prove it live:
- **OAuth client creds** → mint a real token:
  `curl -sX POST https://apigw.$T/token -H "Authorization: Basic <BLOB>" -d grant_type=client_credentials`
  → `access_token` returned = confirmed High/Crit (can't rotate without breaking prod).
- **"Internal" endpoint** → hit it unauth / cross-tenant and diff the response.
- **Params from JS** → fuzz `debug=true`, `admin=1`, `callback=`, `redirect=` and JS-seeded names
  (`x8` / `Arjun` from bundle var names) against the endpoints they belong to.
- **DOM XSS** → drive source→sink in real headless Chrome; screenshot the alert/exfil.
- Feed confirmed secret keys to the **jsmax** skill for exploitation; DOM-XSS / prototype-pollution
  gadgets to the **xss-hunter-agent** skill for payload crafting.

**Only then write the report.** No "could potentially" — prove it or drop it.

---


# johnwick — Full-Spectrum Hunt Orchestrator (standalone)

One command that takes an authorized target from raw scope → understood → fully mapped (unauth + authed)
→ hunted → validated. **Everything is built in** — this skill depends on no other skill. All techniques
(recon commands, JS mining, temp-mail signup, IDOR/backend/GraphQL/403/mobile hunting, validation gates)
live in this skill's own `references/` files. It runs autonomously and **takes its time**, pausing for a
human only at the auth gate. Its defining trait: **it does not skip anything** — a written coverage
ledger makes skipping structurally impossible, and a superpowers verification gate blocks every phase
boundary until the current phase is provably complete.

Authorized testing only. The user supplies in-scope targets — assume authorization is granted.

---

## Rule 0 — The Prime Directive

**Violating the letter of the no-skip rules is violating the spirit of johnwick.**

The entire value of this skill is *total coverage*. An agent that samples, prioritizes, or "reasonably"
trims is running a different, worse skill. If you catch yourself about to narrow the surface, STOP —
that instinct is the exact failure this skill exists to prevent.

## Rule 1 — The Nine Hard Rules (never negotiable)

1. **Zero-skip scope.** Every **in-scope** domain and subdomain enters the ledger and must reach `covered`. None is ever dropped. (Bounded by Rule 9 — never touch out-of-scope.)
2. **No prioritization.** All assets are equally important. The run is not done while any asset is `untested`.
3. **Read ALL JavaScript.** Collect JS from live crawl **and `waybackurls`/`gau`** **and `katana`** — dedup the union — then read every file. Vendor/minified/hashed: all of them. MANDATORY. ([js-mining.md](references/js-mining.md))
4. **Never curl-only.** When `curl`/`httpx` is blocked (WAF/captcha/403/JS-rendered), fall back to **Playwright real-Chrome**. A block is a tool-switch, not a stop.
5. **Self-refresh tokens.** When auth expires, refresh it yourself (refresh-token flow, re-login, cookie renewal) before asking the human.
6. **Reverse APIs yourself.** If API docs, OpenAPI/Swagger, GraphQL introspection, or discovery documents exist, reconstruct the full API surface from them.
7. **APK/IPA present → run the mobile workflow** ([mobile.md](references/mobile.md)); its recovered endpoints/secrets feed back into the ledger.
8. **No step skipped, at all cost. Take your time.** Thoroughness beats speed. No deadline justifies cutting a phase.
9. **Scope-bounded — never touch out-of-scope.** "Hit everything" means everything *in scope*. Gate every outbound request through the scope guard; default-deny; exclude third-party services; verify ownership before hitting inferred/acquisition assets. This **overrides** zero-skip when they seem to conflict — the answer is always "verify scope," never "hit it anyway." ([scope-guard.md](references/scope-guard.md))

## Rule 2 — Rationalizations that mean STOP

If you think any of these, you are about to break Rule 1. Do not.

| Rationalization | Reality |
|---|---|
| "This subdomain is clearly parked/dead, skip it." | Enroll it, probe it, record the *evidence*. "Looks dead" ≠ "verified dead." |
| "These JS files are just vendor/minified bundles." | Vendor bundles leak endpoints, keys, internal hostnames. Read them. |
| "Wayback has 4,000 JS URLs, I'll sample the interesting ones." | Dedup the union and read all. Sampling = Rule 3 violation. |
| "Let me focus on the high-value host first." | No prioritization (Rule 2). Equal coverage or it isn't johnwick. |
| "curl got 403, this asset is protected, move on." | 403 → switch to Playwright real-Chrome (Rule 4), not skip. |
| "I'll just ask the user to log in / give a token." | Try auto-signup with temp-mail first, then self-refresh, THEN ask (Phase 3). |
| "This is taking forever, I'll wrap up early." | Take your time (Rule 8). Partial coverage is a failed run. |
| "I'll note it as untested and come back." | The run does not complete while any row is `untested`. Come back now. |

## Rule 3 — Red flags (self-check)

- You reduced a list "to save time." · You wrote "skip", "sample", "subset", or "most important" about
  in-scope assets or JS. · A phase ended with `untested` rows still in the ledger. · You asked the human
  for creds before attempting auto-signup. · You stopped at a WAF/403/captcha instead of switching to Playwright.

**Any red flag → return to the ledger and finish the coverage.**

---

## The Coverage Ledger (how no-skip is enforced)

At the start of every run, create a per-target run folder and a `coverage.jsonl` ledger. This is the
mechanism that makes "skip nothing" real. Schema, init/enroll, mark-done, and the completion-invariant
queries are in **[coverage-ledger.md](references/coverage-ledger.md)**. Mirror the ledger into the task
list (one task per asset) so progress is gated and visible — steady tracked execution, never flailing.

**Completion invariant:** the run is complete only when
`jq -s '[.[]|select(.in_scope and .status!="covered")]|length' coverage.jsonl` prints `0` and no field is `untested`.

---

## Internal reference map (this skill only — no external skills)

| Phase / topic | Built-in reference |
|---|---|
| Phase gates (superpowers verification between phases) | [phase-gates.md](references/phase-gates.md) |
| Coverage ledger schema + checks | [coverage-ledger.md](references/coverage-ledger.md) |
| **Scope safety guard** (bounds zero-skip) | [scope-guard.md](references/scope-guard.md) |
| Mindset + threat model | [mindset.md](references/mindset.md) |
| Recon pipeline (subs/live/urls) | [recon-pipeline.md](references/recon-pipeline.md) |
| JS mining — read ALL JS | [js-mining.md](references/js-mining.md) |
| Unauth P1/P2 surface | [unauth-p1.md](references/unauth-p1.md) |
| Hidden params + takeover | [params-takeover.md](references/params-takeover.md) |
| Access acquisition + temp-mail signup | [access-tempmail.md](references/access-tempmail.md) |
| Backend classes — **taxonomy hub** | [backend-classes.md](references/backend-classes.md) |
| IDOR / BOLA / BFLA | [authz-idor.md](references/authz-idor.md) |
| SSRF (deep) | [ssrf.md](references/ssrf.md) |
| RCE — deser/dep-confusion/injection/media/upload (deep) | [rce.md](references/rce.md) |
| SSTI (deep) | [ssti.md](references/ssti.md) |
| XXE (deep) | [xxe.md](references/xxe.md) |
| HTTP request smuggling / desync (deep) | [request-smuggling.md](references/request-smuggling.md) |
| Web cache poisoning / deception (deep) | [cache-attacks.md](references/cache-attacks.md) |
| Race conditions / TOCTOU (deep) | [race-conditions.md](references/race-conditions.md) |
| ATO — OAuth/OIDC/SAML/JWT/reset (deep) | [auth-attacks.md](references/auth-attacks.md) |
| SQL / NoSQL injection (deep) | [sqli.md](references/sqli.md) |
| CORS / open-redirect / CSRF / XSS→ATO | [web-misc.md](references/web-misc.md) |
| GraphQL audit | [graphql.md](references/graphql.md) |
| 403/401 bypass matrix | [bypass-403.md](references/bypass-403.md) |
| Mobile (APK/IPA) | [mobile.md](references/mobile.md) |
| Payload arsenal (raw strings) | [payloads.md](references/payloads.md) |
| Exploit chaining — low→critical | [chaining.md](references/chaining.md) |
| Validate & triage gates | [validation.md](references/validation.md) |
| Report writing | [reporting.md](references/reporting.md) |

---

## Start Protocol (first moves when invoked)

1. Ask for / read the **scope** (in + out) and any creds/cookies the user already has. Nothing else blocks.
2. Create the run folder + `coverage.jsonl`; build the **scope guard** allow/deny model ([scope-guard.md](references/scope-guard.md)).
3. Enroll every in-scope asset as an `untested` row. Mirror to the task list (one task per asset).
4. Announce the plan in one line, then run Phase 1→6 autonomously, pausing **only** at the Phase-3 auth gate
   (or a genuine scope ambiguity). Take your time; skip nothing in scope.
5. Between each phase, run the verification gate ([phase-gates.md](references/phase-gates.md)) before advancing.

## The Pipeline (7 phases, in order, skip none)

> **Between every phase:** run the `superpowers:verification-before-completion` gate against that phase's
> exit criteria before starting the next — a phase is "done" only on fresh ledger evidence, never a claim.
> Full per-phase exit criteria are in [phase-gates.md](references/phase-gates.md). Parallelize the fan-out
> phases (2 and 5) with `superpowers:dispatching-parallel-agents`, one agent per asset slice.

### Phase 0 — Intake & Scope Lock
Write the user's in-scope + out-of-scope lists verbatim to `scope.txt`, then **build the scope guard's
allow/deny model** ([scope-guard.md](references/scope-guard.md)) — every later request is gated through it
(default-deny; third-parties excluded; ownership verified). Enroll **every** in-scope asset as an
`untested` row in `coverage.jsonl` ([coverage-ledger.md](references/coverage-ledger.md)). Save any
creds/cookies the user already provided to `auth/`. Do not advance until every asset is enrolled.

### Phase 1 — Understand the target
Build the threat model, read developer psychology, choose an impact goal per major asset →
[mindset.md](references/mindset.md). Record it in `notes.md`. It shapes every later phase.

### Phase 2 — Unauth full-surface recon & app map
Run against **all** enrolled assets: subdomains/live hosts/URL corpus ([recon-pipeline.md](references/recon-pipeline.md));
**JS union read in full** ([js-mining.md](references/js-mining.md), Rule 3); hidden params + subdomain
takeover ([params-takeover.md](references/params-takeover.md)); unauth P1/P2 surface
([unauth-p1.md](references/unauth-p1.md)). Blocked anywhere → Playwright (Rule 4). Set each row's
`recon` and `js_read` to `done`.

### Phase 3 — Access acquisition (the ONLY human gate)
In strict order: use provided creds → **auto-signup via temp-mail** (rotate a provider fallback chain,
confirm the email, log in) → only if both fail, ask the human. Set up self-refresh.
→ [access-tempmail.md](references/access-tempmail.md). This is the sole mandatory pause.

### Phase 4 — Authenticated app mapping (MAP FIRST, then attack)
Log in and walk the **entire** application before exploitation: every feature, route, role, workflow,
state, API call. Reverse the API from docs/OpenAPI/introspection into `api/` (Rule 6). Enroll newly
discovered authed endpoints/subdomains as fresh ledger rows. Set `authed_mapped:"done"` per asset.

### Phase 5 — Hunt (manual + automated)
For **each** asset, drive the mapped surface through **every applicable class**, starting from the
taxonomy hub [backend-classes.md](references/backend-classes.md), and record each run in the row's
`hunted[]`. The per-class checklist (apply the ones the surface exposes — do not pre-decide a class is
absent without checking):

- `idor` — every id-bearing endpoint → [authz-idor.md](references/authz-idor.md)
- `ssrf` — every URL-fetch/webhook/import/preview/media feature → [ssrf.md](references/ssrf.md)
- `rce` — deserialization blobs, dep-confusion, injection, media/archive/upload → [rce.md](references/rce.md)
- `ssti` — every template-rendered field (email, name, profile, report) → [ssti.md](references/ssti.md)
- `xxe` — every XML/SVG/DOCX/SAML intake → [xxe.md](references/xxe.md)
- `sqli` — every query/filter/sort/id param, logged headers (2nd-order) → [sqli.md](references/sqli.md)
- `smuggling` — front-end/back-end pairs, H/2 → [request-smuggling.md](references/request-smuggling.md)
- `cache` — CDN-fronted paths + unkeyed inputs → [cache-attacks.md](references/cache-attacks.md)
- `race` — every "once-only"/limit/financial flow → [race-conditions.md](references/race-conditions.md)
- `auth` — every OAuth/OIDC/SAML/JWT/reset flow → [auth-attacks.md](references/auth-attacks.md)
- `graphql` — every GQL endpoint → [graphql.md](references/graphql.md)
- `bypass-403` — every 401/403 → [bypass-403.md](references/bypass-403.md)
- `web-misc` — CORS, open-redirect, CSRF, XSS→ATO (chain fodder) → [web-misc.md](references/web-misc.md)
- `mass-assign` / `logic` — create/update bodies, money flows → [backend-classes.md](references/backend-classes.md)
- `mobile` — any APK/IPA → [mobile.md](references/mobile.md)

A row reaches `status:"covered"` only when every applicable class has run against it. No asset skipped for
another (Rule 2). Ground hypotheses in the paid-report patterns cited in each deep file. **After every
finding, push it to its ceiling** via [chaining.md](references/chaining.md) (IDOR→ATO, SSRF→cloud→RCE,
open-redirect→OAuth) before moving on — a chained finding is worth an order of magnitude more.

### Phase 6 — Validate & report
Run every candidate through the 7-Question Gate + 4 pre-submission gates ([validation.md](references/validation.md)).
Kill theoretical/N-A findings; only proven, reproduced findings survive. Then **write each survivor up**
([reporting.md](references/reporting.md)) — impact-first title, copy-paste repro, evidence of real impact,
CVSS, one bug per report — saved with its evidence in `findings/<asset>/`.

---

## Completion criteria (do not declare done until ALL are true)
- `jq -s '[.[]|select(.in_scope and .status!="covered")]|length' coverage.jsonl` prints `0`; no field is `untested`.
- All JS (live ∪ wayback ∪ gau ∪ katana) was read (files mined == `wc -l js/js-urls.txt`).
- Every applicable class ran on every asset: id-endpoints→IDOR; URL-fetch features→SSRF; XML/upload intake→XXE;
  template-rendered fields→SSTI; query/filter params→SQLi; deser/dep-confusion/media/upload→RCE; every 401/403→bypass;
  every GraphQL→audit; front/back-end pairs→smuggling; CDN paths→cache; once-only/money flows→race; auth flows→ATO.
- Any APK/IPA went through the mobile workflow.
- Every surviving finding passed the full validation gate.

If any is false, the run is not complete — return to the ledger and finish it.
