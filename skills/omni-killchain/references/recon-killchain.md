# Recon Killchain — Full Methodology

> Goal: in 4 hours, know the target better than half their engineers do.

---

## STAGE 1 — SCOPE INTAKE

```bash
# Build a clean scope file
echo "*.target.com" > scope.txt
echo "target.io" >> scope.txt
# Out of scope (skip these aggressively)
echo "blog.target.com" > out_of_scope.txt
```

Confirm: bounty program URL, payout table, in-scope/out-of-scope list, allowed test types (e.g. is DoS allowed? is account creation allowed? is SQLi safe to PoC live?).

---

## STAGE 2 — PASSIVE SUBDOMAIN ENUMERATION

```bash
# Aggregate from multiple sources, dedup
subfinder -d $T -all -silent          > subs_subfinder.txt
amass enum -passive -d $T -silent     > subs_amass.txt
chaos -d $T -silent                   > subs_chaos.txt
github-subdomains -d $T -t $GH_TOKEN  > subs_gh.txt
cero -c 1000 $T                       > subs_cero.txt
crt.sh? -> jq -r '.[].name_value'     > subs_crt.txt
findomain -t $T -q                    > subs_findomain.txt

cat subs_*.txt | sort -u | tee all_subs.txt
```

Pull from: `crt.sh`, `securitytrails`, `virustotal`, `urlscan.io`, `chaos.projectdiscovery.io`, `bevigil`, `dnsdumpster`, `bufferover.run`, `wayback`, `commoncrawl`, `alienvault otx`, `riddler.io`, `passivetotal`, `binaryedge`, `shodan`, `censys`, `zoomeye`, `fofa`, `quake`.

**Brute force when passive is thin:**
```bash
puredns bruteforce best-dns-wordlist.txt $T -r resolvers.txt -w bf_subs.txt
# Then permutations
gotator -sub all_subs.txt -perm permutations.txt -depth 2 -numbers 5 \
  | puredns resolve -r resolvers.txt
```

---

## STAGE 3 — DNS / WHOIS / IP INTEL

```bash
dnsx -l all_subs.txt -a -aaaa -cname -ns -mx -txt -resp -silent > dns.json
# Map subs -> IPs -> ASN
mapcidr -silent -aslookup $T
asnmap -d $T -silent
```

Reverse-DNS the ASN ranges; you often find unbranded staging/admin hosts that recon-by-domain misses.

---

## STAGE 4 — HTTP PROBE & TECH FINGERPRINT

```bash
httpx -l all_subs.txt -silent -status-code -title -tech-detect -ip -cname \
  -follow-redirects -web-server -tls-probe -favicon -hash sha256 \
  -timeout 10 -threads 200 -o httpx.json -j

# Cluster by favicon hash to find sibling/related hosts
httpx -l all_subs.txt -favicon -silent | sort -u
# Use favicon hash on shodan: http.favicon.hash:-1234567890
```

**Tech fingerprint sources:**
- `httpx -tech-detect`, `wappalyzer-cli`, `webanalyze`, `whatweb -a 3`
- HTTP response headers: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`
- Cookie names: `JSESSIONID` (Java), `PHPSESSID`, `connect.sid` (Express), `_session_id` (Rails), `laravel_session`, `csrftoken` (Django), `ai-session` (.NET)
- Default 404 pages, error stack traces (force a 500 with `?[]=1` or `/%c0%2e/`)

---

## STAGE 5 — VISUAL TRIAGE

```bash
gowitness scan file -f httpx.txt --no-http
# OR
aquatone -threads 10 < httpx.txt
nuclei -t exposures/ -l httpx.txt -o nuclei_quick.txt
```

Eyeball the screenshots. Look for: login pages on weird hosts, default installer pages, unauthenticated dashboards, "Index of /" listings, error pages with stack traces.

---

## STAGE 6 — PORT / SERVICE SCAN

```bash
naabu -l live_hosts.txt -top-ports 1000 -rate 5000 -silent -o ports.txt
nmap -sV -sC -Pn -iL ports.txt -oA nmap_full
# Specific:
masscan -p1-65535 $IP --rate=10000
```

Notable ports: 22, 25, 80, 443, 1099 (RMI), 1433, 1521, 2375 (Docker), 2376, 3000 (Grafana/Node), 3306, 4040 (Spring), 5000, 5432, 5601 (Kibana), 5984 (Couch), 6379 (Redis), 7001 (WebLogic), 7474 (Neo4j), 8000-8090, 8161 (ActiveMQ), 8443, 8500 (Consul), 8888 (Jupyter), 9000 (SonarQube), 9090 (Prometheus), 9200 (Elastic), 9300, 11211 (Memcache), 15672 (RabbitMQ), 27017 (Mongo), 50070 (Hadoop).

---

## STAGE 7 — CONTENT DISCOVERY

```bash
# Per-host wordlist tuning
ffuf -w raft-large-words.txt -u https://$T/FUZZ -mc all -fc 404 -ac \
  -recursion -recursion-depth 2 -e .php,.bak,.old,.zip,.tar,.gz,.json,.xml,.yml \
  -H "User-Agent: Mozilla/5.0" -o ffuf.json -of json

# Common high-value paths
feroxbuster -u https://$T -w content_discovery_all.txt -x php,asp,aspx,json,bak,zip \
  --auto-tune --rate-limit 50

# API-specific
ffuf -w api-words.txt -u https://$T/api/v1/FUZZ -mc all -fc 404
# Backup files
ffuf -w bak-extensions.txt -u https://$T/index.FUZZ
```

**Wordlists worth their weight:**
- SecLists/Discovery/Web-Content/raft-large-words.txt
- SecLists/Discovery/Web-Content/api/objects.txt
- SecLists/Discovery/Web-Content/quickhits.txt
- assetnote/wordlists (httparchive_directories, httparchive_subdomains)

---

## STAGE 8 — URL HARVEST (history mining)

```bash
gau --threads 10 $T              > gau.txt
waybackurls $T                   > wayback.txt
katana -d 5 -jc -kf all -aff -fs fqdn -list live_hosts.txt > katana.txt
hakrawler -depth 3               < live_hosts.txt > hakrawler.txt

cat gau.txt wayback.txt katana.txt hakrawler.txt | sort -u > all_urls.txt

# Filter for interesting
grep -E "\.(json|js|env|bak|zip|tar|gz|sql|pem|key|p12|pfx|log|config|yml|yaml)$" all_urls.txt
grep -E "(api|admin|internal|debug|test|graphql|swagger|openapi)" all_urls.txt
gf xss          < all_urls.txt > params_xss.txt
gf ssrf         < all_urls.txt > params_ssrf.txt
gf sqli         < all_urls.txt > params_sqli.txt
gf redirect     < all_urls.txt > params_redirect.txt
gf rce          < all_urls.txt > params_rce.txt
qsreplace FUZZ  < all_urls.txt > all_urls_fuzz.txt
```

---

## STAGE 9 — JS HARVEST & ENDPOINT EXTRACTION

```bash
# Find every JS file referenced
grep -oE 'https?://[^"]+\.js' all_urls.txt | sort -u > js_urls.txt
# Download
xargs -I{} -a js_urls.txt -P 10 curl -sk -o js/{}.tmp {}

# Mine for endpoints + secrets
linkfinder -i 'js/*' -o js_endpoints.html
jsluice urls js/*.js > jsluice_urls.txt
jsluice secrets js/*.js > jsluice_secrets.txt
trufflehog filesystem js/ --only-verified

# Sourcemaps?
for u in $(cat js_urls.txt); do
  curl -sI "$u.map" -o /dev/null -w "%{http_code} $u.map\n" | grep ^200
done
shujisan -u $T   # auto sourcemap fetcher
```

Read `references/js-recon-agent` for deep JS analysis (delegate when bundles > 1MB).

---

## STAGE 10 — PARAMETER DISCOVERY

```bash
# From wayback
arjun -u https://$T/api/endpoint -m GET,POST -t 50
paramspider -d $T --level high -o params.txt
x8 -u https://$T/path -w params.txt -X GET,POST,PUT
# Hidden/legacy
ffuf -w burp-parameter-names.txt -u "https://$T/?FUZZ=test" -fs $RESP_SIZE
```

Look especially for: `debug=1`, `admin=1`, `verbose=1`, `next=`, `return_to=`, `redirect=`, `callback=`, `url=`, `image=`, `xml=`, `template=`, `template_url=`, `mode=`, `feature_flag=`.

---

## STAGE 11 — SECRETS & EXTERNAL ARTIFACTS

```bash
# GitHub recon
gh-secret-scanner $T
trufflehog github --org=$T --only-verified
gitleaks dir ~/code/$T-fork
gitdorks_go -gd ~/dorks.txt -tf ~/.gh_token -target $T
github-search "$T" "api_key"
github-search "$T" "BEGIN RSA PRIVATE KEY"

# Postman
google: site:postman.com "$T"
# JSFiddle, Pastebin, GitLab snippets, NPM registry, Docker Hub
# S3 buckets
cloud_enum -k $T
s3scanner scan -bucket $T
```

See `references/secrets-recon.md`.

---

## STAGE 12 — VULN SCANNING (NUCLEI BASELINE)

```bash
# Templates: keep current (nuclei -update-templates)
nuclei -l live_hosts.txt -t cves/ -t exposures/ -t misconfiguration/ \
  -t default-logins/ -t takeovers/ -severity critical,high,medium \
  -rate-limit 50 -bulk-size 25 -o nuclei.txt

# Subdomain takeover
nuclei -l all_subs.txt -t takeovers/ -silent
subzy run --targets all_subs.txt --concurrency 100
```

---

## SURFACE MAPPING — output of recon

For each live host, fill in:

```
host:                target.example.com
tech:                Rails 7.0, nginx, PostgreSQL (cookie hint)
auth:                cookie session + JWT for /api/v2/*
roles:               anonymous, user, staff, admin
interesting paths:   /admin, /api/v1, /graphql, /import, /webhook
parameters of note:  url=, image=, callback=, template=
secrets seen:        none / API key in JS bundle / .env exposed
known CVEs for stack: CVE-XXXX-YYYY
```

This table is the input to Phase 3 (payout-priority routing) in `SKILL.md`.

---

## CADENCE / RE-RECON

- New subdomains spawn weekly. Re-run subfinder + httpx every 7-14 days.
- Set up `notify` + cron: any new live host = a candidate for fresh testing.
- Diff `ffuf` output across runs to find new endpoints.
- Watch RSS/changelog/blog for product updates that hint at new features.
