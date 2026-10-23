# Hidden Params + Subdomain Takeover

## A. Hidden parameter discovery
Hidden params are gold for IDOR, SSRF, LFI, open-redirect, and authz bypass — scanners miss them.

```bash
# Arjun (primary) — mine params per URL, GET+POST+JSON
arjun -i assets/high-value-urls.txt -oT assets/params.txt -m GET,POST,JSON
arjun -u "https://$TARGET/api/endpoint" -m JSON        # single endpoint
# x8 (fallback) with a param wordlist
x8 -u "https://$TARGET/api/endpoint" -w params-wordlist.txt
```
Also harvest param names from JS (`js/endpoints.txt`) and wayback (`assets/all-urls.txt` query strings):
```bash
grep -oP '[?&]\K[a-zA-Z0-9_]+(?==)' assets/all-urls.txt | sort -u > assets/param-names.txt
```
Feed discovered params into Phase 4/5 as extra IDOR/SSRF/mass-assignment surface.

## B. Subdomain takeover
Every subdomain with a dangling CNAME to an unclaimed third-party service is a takeover candidate.

```bash
# dnsReaper (best signal) or subjack (fast Go)
dnsreaper file --filename assets/subs.txt 2>/dev/null
subjack -w assets/subs.txt -t 50 -ssl -o findings/takeover.txt 2>/dev/null
# manual: resolve CNAMEs, match the fingerprint below
dnsx -l assets/subs.txt -cname -resp -silent
```

**Fingerprints (CNAME target → claim it):**
```
GitHub Pages   *.github.io        "There isn't a GitHub Pages site here"
AWS S3         *.s3.amazonaws.com "NoSuchBucket"
Heroku         *.herokuapp.com    "No such app"
Shopify        *.myshopify.com    "Sorry, this shop is currently unavailable"
Fastly         *.fastly.net       "Fastly error: unknown domain"
Netlify        *.netlify.app      "Not Found" / default page
Azure          *.azurewebsites.net / *.cloudapp.net / *.trafficmanager.net
Zendesk        *.zendesk.com      "Help Center Closed"
Unbounce/Tumblr/WordPress/Surge/Ghost/Cargo/Webflow — check dangling default page
```

**Severity:** a bare takeover of a marketing sub is Low/Medium. It becomes **Critical** when the
subdomain is an SSO/OAuth `redirect_uri` host, holds a parent-domain cookie scope, or serves JS the
main app loads. Always chase that chain before reporting (see [validation.md](validation.md)
conditionally-valid table).
