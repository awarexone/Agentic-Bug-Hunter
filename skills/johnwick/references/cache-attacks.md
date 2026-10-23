# Web Cache Poisoning & Deception (deep)

Two distinct bugs that share the cache. Paid patterns (H1): PayPal *DoS via web cache poisoning* **$9.7k**;
Shopify *host-header cache poisoning → DoS* **$2.9k**; Shopify *web cache deception → PII + CSRF-token
leak* **$800**; Glassdoor *poisoning → stored XSS*; GSA *poisoning → stored DOM-XSS defacement* **$750**;
OLX/Tradus *deception → user_id enumeration*.

## A. Cache POISONING — you inject, everyone else is served it
Find an **unkeyed** input (not part of the cache key) that still influences the response.

**Detect (Param Miner / manual):**
```bash
# add a cache buster, vary one unkeyed header, look for reflection + a cache HIT on the poisoned value
curl -s "https://target/path?cb=1" -H "X-Forwarded-Host: evil.com" | grep -i evil.com
curl -s "https://target/path?cb=1"        # second request: is evil.com served without the header? → poisoned
```
Watch `X-Cache: hit/miss`, `Age`, `CF-Cache-Status`, `Cache-Control`.

**High-value unkeyed inputs:** `X-Forwarded-Host`, `X-Forwarded-Scheme`/`-Proto`, `X-Host`,
`X-Forwarded-Server`, `X-Original-URL`, `X-Rewrite-URL`, custom `X-*` the app reflects, and **fat GET**
(a body/param on a cached GET). Also cookies that are reflected but unkeyed.

**Escalate:** reflected unkeyed header into an HTML/script context → **stored XSS to all users**; into a
redirect/`<base href>`/import URL → traffic hijack; into a broken resource → **DoS** (PayPal $9.7k,
Shopify $2.9k). Chain with request smuggling for cache poisoning without an unkeyed input.

## B. Cache DECEPTION — victim's private page gets cached as "static", you read it
The CDN caches by extension/path pattern; the app serves dynamic content at a path that *looks* static.
```
https://target/account/settings          → dynamic, private (your PII, CSRF token, session data)
https://target/account/settings/foo.css  → app still returns your settings, CDN caches it as CSS
```
**Path-confusion variants to try:** `/account.css`, `/account/x.css`, `/account%2f..%2fx.js`,
`/account;foo.css`, `/account/foo.js?x=1`, `/account#.css`, encoded `%2e`/`%2f` delimiters.

**Exploit flow:** lure the victim to `…/foo.css` (or the CDN caches it after any visit) → then **you** fetch
the same URL unauthenticated → you receive the victim's cached private response (PII, CSRF token, gdtoken —
Shopify $800). Confirm the response is cached (`Age`/`X-Cache: hit`) and contains *their* data, not yours.

## Proof-of-impact bar
Poisoning: show the injected payload/broken response served to a **different** session from cache.
Deception: show a **victim's** private data returned to an unauthenticated fetch of the static-looking URL.
A `Vary`/`Cache-Control: private` that already prevents caching = no bug. Impact ranges Medium (info
leak) → High/Critical (stored XSS to all users, CSRF-token theft → ATO, site-wide DoS).
