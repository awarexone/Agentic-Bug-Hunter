# JS Mining — Read ALL JavaScript (Rule 3, MANDATORY)

Every JS file from the **union of live-crawl ∪ waybackurls ∪ gau ∪ katana, run independently
against every live subdomain** (not just the apex/main app) gets downloaded and mined.
Sampling, "vendor bundle" skipping, "this subdomain probably shares the main app's bundle so
skip it", or "min.js is noise" reasoning are Rule 3 violations. The count of files mined must
equal `wc -l js/js-urls.txt` summed across every subdomain.

**"Mined" in this file means regex/jsluice extraction — that is a fast first pass, not the
whole job.** Regex finds secrets and known-shape endpoint strings; it cannot find a logic bug
(a client-side role check that's never re-verified server-side, a URL-upload field that
silently proxies through an SSRF-able server endpoint) because those don't match any keyword
pattern. After steps 1-5 below, every downloaded file must ALSO be beautified
(`js-beautify`/`jsbeautifier`, not just left as one giant minified line) and **read completely,
end to end**, before the file counts as done. This has no file-count exception — hundreds of
files across dozens of subdomains all still get the full read.

## 1. Collect the JS URL union

```bash
# from the URL corpus (recon-pipeline.md step 3)
grep -Ei '\.js(\?|$)' assets/all-urls.txt | sed 's/\\//g' | cut -d'?' -f1 | sort -u > js/js-urls.txt
# plus JS referenced directly by live pages (SPA bundles wayback never saw)
cat assets/live-200.txt | awk '{print $1}' | while read url; do
  curl -sL --max-time 15 "$url" | grep -oP '(?:src|href)=["'\''][^"'\'' ]*\.js[^"'\'' ]*' \
    | sed 's/.*=["'\'']//' >> js/js-urls-discovered.txt
done
# plus a katana JS-only crawl to catch dynamically loaded chunks
cat assets/live-200.txt | awk '{print $1}' | katana -d 3 -jc -silent | grep -Ei '\.js(\?|$)' >> js/js-urls-discovered.txt
sort -u js/js-urls-discovered.txt >> js/js-urls.txt && sort -u js/js-urls.txt -o js/js-urls.txt
wc -l js/js-urls.txt      # THIS is the number of files that must be mined
```

## 2. Download everything (20 concurrent)

```bash
mkdir -p js/files
cat js/js-urls.txt | xargs -P 20 -I{} sh -c \
  'h=$(echo "{}" | md5sum | cut -d" " -f1); curl -sL --max-time 15 "{}" -o "js/files/${h}.js" 2>/dev/null'
```

## 3. Extract endpoints + secrets

```bash
jsluice urls    js/files/*.js > js/endpoints.txt 2>/dev/null
jsluice secrets js/files/*.js > js/secrets.txt   2>/dev/null
# backend-critical greps
grep -rniE '(secret|token|api[_-]?key|bearer|authorization|password|credential)' js/files/ | sort -u > js/credentials.txt
grep -rnE  'isAdmin|isOwner|role|permission|canAccess|hasRole|requireAdmin'      js/files/ | sort -u > js/authz-checks.txt
grep -rniE 'graphql|gql|apollo|hasura|urql'                                       js/files/ | sort -u > js/graphql.txt
grep -rniE 'admin|internal|dashboard|manage|super|/debug'                         js/files/ | sort -u > js/admin-refs.txt
grep -rnE  'sourceMappingURL|\.map'                                               js/files/ > js/sourcemap-refs.txt
```

## 4. High-value secret regex (tiered — check most valuable first)

**TIER 1 — cloud/infra (≈$5K–$25K):**
```
AKIA[0-9A-Z]{16}                         # AWS access key id
"type": "service_account"|private_key    # GCP service account
AccountKey=|SharedAccessSignature        # Azure storage
firebaseConfig|apiKey.*AIza              # Firebase
SUPABASE_URL|supabaseKey                 # Supabase
```
**TIER 2 — API keys / auth tokens (≈$1K–$10K):**
```
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}   # JWT
client_secret|clientSecret|refresh_token
x-api-key|bearer_token|access_token
-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----
```

## 5. Sourcemap recovery (reconstruct original source)

```bash
mkdir -p js/sourcemaps
cat js/js-urls.txt | while read url; do
  curl -sL --max-time 15 "${url}.map" -o "js/sourcemaps/$(echo "${url}.map"|md5sum|cut -d' ' -f1).map" 2>/dev/null
done
for f in js/sourcemaps/*.map; do [ -s "$f" ] && jq -r '.sourcesContent[]?' "$f" 2>/dev/null >> js/sourcemap-src.txt; done
grep -Ei 'api|endpoint|fetch\(|axios|admin|internal|secret|token|password' js/sourcemap-src.txt | sort -u > js/sourcemap-hits.txt
```

## 6. What to do with hits (impact-first)
| Hit | Action — prove impact now |
|---|---|
| Live cloud key (AWS/GCP/Firebase/Algolia/Mapbox/SendGrid) | Verify against issuer API. Live=P1; dead=trash. |
| Internal/staging base URL web recon missed | `httpx` it → new host → enroll in ledger, recon it. |
| Admin/internal endpoint the app never calls | Hit from an authed session (Phase 5) → IDOR/BFLA candidate. |
| Hardcoded backend password / basic-auth | Verify it authenticates against the live host. |

**Only mark `js_read:"done"` when files mined == `wc -l js/js-urls.txt`.** Verify with a count, per
`superpowers:verification-before-completion`.
