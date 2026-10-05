# Unauth P1/P2 Surface — Pre-Auth Critical Bugs

Run against every live host before authentication. These are the highest-severity findings reachable
with no account. Enroll every hit in the ledger.

## 1. Cloud storage (buckets)
```bash
# guess bucket names from org/target keywords
for n in $TARGET ${TARGET%%.*} ${TARGET%%.*}-prod ${TARGET%%.*}-dev ${TARGET%%.*}-backup ${TARGET%%.*}-assets ${TARGET%%.*}-static; do
  curl -s -o /dev/null -w "%{http_code} $n\n" "https://$n.s3.amazonaws.com/"
done
# S3Scanner for enumeration + permission check (list/read/write)
s3scanner scan -f assets/subs.txt 2>/dev/null
# GCS / Azure equivalents
curl -s "https://storage.googleapis.com/${TARGET%%.*}/"
curl -s "https://${TARGET%%.*}.blob.core.windows.net/?comp=list"
```
Report only with proven read (sensitive object) or write. Listing alone → chain with what's inside.

## 2. Exposed services / admin panels (unauth)
```
Redis        :6379   RESP ping / INFO with no auth
Elasticsearch:9200   GET /_cat/indices
MongoDB      :27017  unauth connect / listDatabases
Kubernetes   :10250/:6443  /pods, anonymous API
Jenkins      /script  Groovy console → RCE
Spring Boot  /actuator/{env,heapdump,mappings}  creds in env / heapdump
Grafana/Kibana  default creds, /api/datasources
Docker API   :2375   GET /containers/json → RCE
```
```bash
nuclei -l assets/live.txt -tags exposure,misconfig,default-login -severity high,critical -o findings/nuclei-unauth.txt
```

## 3. Source / secret exposure
```bash
# .git, .env, .DS_Store, backups
for h in $(awk '{print $1}' assets/live-200.txt); do
  for p in /.git/config /.env /.DS_Store /backup.zip /config.php.bak /.git/HEAD; do
    curl -s -o /dev/null -w "%{http_code} $h$p\n" "$h$p"
  done
done
# leaked secrets in JS/history — verify LIVE against issuer API (dead key = trash)
trufflehog filesystem js/files/ --only-verified 2>/dev/null
```

## 4. Pre-auth CVEs (fingerprint → match → PoC)
Prioritise these high-yield unauth RCE/authz CVEs when the stack matches:
```
Confluence CVE-2022-26134 / CVE-2023-22515   Spring4Shell CVE-2022-22965
Log4Shell CVE-2021-44228                     MOVEit CVE-2023-34362
Citrix Bleed CVE-2023-4966                   GitLab CVE-2023-7028
Ivanti CVE-2025-0282                         PAN-OS CVE-2024-3400
SharePoint ToolShell CVE-2025-53770          PHP-CGI CVE-2024-4577
```
```bash
nuclei -l assets/live.txt -tags cve -severity critical,high -o findings/nuclei-cve.txt
```

## 5. Subdomain takeover
See [params-takeover.md](params-takeover.md) §takeover — dangling CNAME to unclaimed GitHub Pages/
S3/Heroku/Shopify/Fastly/etc. Critical when it lands on an SSO/OAuth `redirect_uri` domain.

## 6. Origin-IP / WAF bypass (reach the real server behind CDN)
```bash
# historical A records (pre-CDN), favicon hash pivot, crt.sh SANs
curl -s "https://crt.sh/?q=$TARGET&output=json" | jq -r '.[].name_value' | sort -u
# shodan/censys favicon-hash + http.title pivot to find the naked origin, then Host-header it:
curl -s -H "Host: $TARGET" https://<origin-ip>/ -k
```

## Exit
Every host probed for the above; hits enrolled with evidence. No host skipped because another looked
juicier (Rule 2).
