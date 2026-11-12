# Phase 2 — Recon Pipeline (self-contained)

Full-surface discovery for every in-scope root. Shard across roots for speed (see
[phase-gates.md](phase-gates.md), parallel section). When any step is blocked (WAF/403/captcha/
JS-rendered), switch to **Playwright real-Chrome** — a block is a tool-switch, never a skip (Rule 4).
All output lands in the run folder and updates `coverage.jsonl`.

## 1. Subdomains — enumerate every root, drop nothing

```bash
TARGET=example.com
subfinder -d $TARGET -all -silent > assets/subs.txt
assetfinder --subs-only $TARGET >> assets/subs.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | tr ',' '\n' >> assets/subs.txt
chaos -d $TARGET -silent >> assets/subs.txt 2>/dev/null      # set PDCP_API_KEY
sort -u assets/subs.txt -o assets/subs.txt
```
Enroll **every** discovered subdomain as a `coverage.jsonl` row. No parked/dead filtering — probe and
record evidence instead (Rule 2, no prioritization).

## 2. Live hosts + fingerprint + CNAME chains

```bash
dnsx -l assets/subs.txt -cname -resp -a -silent -o assets/dns-full.txt
httpx -l assets/subs.txt -silent -title -status-code -tech-detect -ip -cname \
  -websocket -web-server -content-type -favicon-mmh3 -o assets/live.txt
grep -E '\[200\]' assets/live.txt > assets/live-200.txt
grep -E '\[401\]|\[403\]' assets/live.txt > assets/live-auth.txt   # auth-gated = feed bypass-403.md
```

## 3. URL corpus — crawl + historical (both mandatory)

```bash
katana -list assets/live-200.txt -jc -kf all -d 4 -silent -o assets/katana-urls.txt
gau --subs $TARGET > assets/gau-urls.txt
echo $TARGET | waybackurls > assets/wayback-urls.txt
cat assets/katana-urls.txt assets/gau-urls.txt assets/wayback-urls.txt | sort -u > assets/all-urls.txt
# high-value + sensitive files
grep -Ei 'admin|internal|dashboard|panel|manage|api/v[0-9]|graphql|playground|swagger|actuator|debug|console|backup|old|dev|staging|test|beta' assets/all-urls.txt | sort -u > assets/high-value-urls.txt
grep -Ei '\.(json|xml|ya?ml|env|config|bak|old|swp)$|~$' assets/all-urls.txt | sort -u > assets/sensitive-files.txt
grep -E '\.git/' assets/all-urls.txt | sort -u > assets/git-exposed.txt
```

## 3b. Content discovery (find what crawling missed)
Brute unlinked endpoints/dirs on every live host — admin panels, API routes, backups, debug endpoints
the crawler never saw.
```bash
# per host — rattle common + API wordlists; match interesting codes, filter noise
ffuf -u "https://HOST/FUZZ" -w raft-large-directories.txt:FUZZ -mc 200,201,204,301,302,307,401,403,405 \
     -ac -recursion -recursion-depth 2 -o assets/ffuf-HOST.json
ffuf -u "https://HOST/api/FUZZ" -w api-endpoints.txt:FUZZ -mc all -fc 404 -ac
# extensions for backups/config leaks
ffuf -u "https://HOST/FUZZ" -w wordlist.txt:FUZZ -e .bak,.old,.zip,.json,.config,.env,.git -mc 200,403
```
Feed hits back into the URL corpus + ledger; 401/403 hits go to [bypass-403.md](bypass-403.md).

## 4. Hand off to the other Phase-2 references (all internal, no external skills)

- **JS union → read ALL of it:** [js-mining.md](js-mining.md) (Rule 3, MANDATORY).
- **Hidden params + subdomain takeover:** [params-takeover.md](params-takeover.md).
- **Unauth P1/P2 surface** (buckets, exposed DBs/services, pre-auth CVEs, secrets, `.git`/`.env`,
  origin-IP/WAF bypass): [unauth-p1.md](unauth-p1.md).

## Exit gate
`jq -c 'select(.in_scope and (.recon!="done" or .js_read!="done"))' coverage.jsonl` must return
**no rows** before Phase 3. Run the `superpowers:verification-before-completion` gate — see
[phase-gates.md](phase-gates.md).
