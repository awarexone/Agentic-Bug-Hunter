# Secrets Recon — $50K Shopify GitHub-token pattern

> H1 #1 paid: Shopify GitHub access token exposure $50K. Snapchat JFrog Artifactory creds $15K. Uber phabricator cert in repo $40K.

---

## SOURCES (in order of yield)

1. **GitHub** (public + org-related repos)
2. **GitLab** (less crawled, often more secrets)
3. **Bitbucket** (forgotten orgs)
4. **Postman public workspaces** (massive: API keys, internal endpoints)
5. **Pastebin / Pastes mirrors**
6. **JS bundles + sourcemaps** (target's own site)
7. **Public Docker images** (Docker Hub, GHCR, ECR public)
8. **NPM / PyPI / RubyGems** packages with secrets in tarballs
9. **JSFiddle / CodePen / CodeSandbox**
10. **archive.org** wayback / commoncrawl
11. **Shodan / Censys** (env files in HTTP)
12. **Trello / Notion / Confluence public pages**
13. **Mobile app reverse engineering** (APK strings, plist)
14. **Third-party SaaS metadata** (Slack, Zendesk, Statuspage)
15. **Recruitment tasks** (devs upload solutions to GitHub)

---

## TOOLING

### GitHub
```bash
# Org enumeration
trufflehog github --org=$ORG --only-verified --concurrency=10

# Specific repo
trufflehog git https://github.com/$ORG/$REPO --since-commit HEAD~1000

# All repos in org (forks too)
gh repo list $ORG --limit 1000 --json nameWithOwner -q '.[].nameWithOwner' | \
  xargs -I{} -P 5 trufflehog github --repo=https://github.com/{} --only-verified

# Dorking via gh search
gh search code "AKIA" "$ORG"
gh search code "BEGIN RSA PRIVATE KEY" "$ORG"
gh search code "client_secret" filename:.env "$ORG"

# gitleaks
gitleaks detect --source=. --report-path=gl.json
gitleaks dir ~/code/$ORG

# Noseyparker (very fast, good signal)
noseyparker scan ./code -d data
noseyparker report -d data

# git-secrets
git-secrets --scan-history
```

### Postman
```
# Public workspace search
https://www.postman.com/search?q=$ORG&type=public-workspace
https://www.postman.com/search?q=$DOMAIN&type=request

# Tools:
postman-leaks (denis-hemraj)
porchpirate
```

### JS / sourcemaps
```bash
shujisan -u $T              # auto sourcemap fetcher
linkfinder -i 'js/*.js'
jsluice secrets js/*.js     # very good
trufflehog filesystem ./js
```

### Docker images
```bash
# whaler - extract secrets from Docker images
whaler $ORG/image:tag

# trufflehog docker
trufflehog docker --image=$IMAGE --only-verified

# dive - inspect layers
dive $IMAGE
```

### NPM / PyPI / etc
```bash
# git history + published-but-not-in-git secrets
trufflehog --regex --entropy=False git ./node_modules

# npm-leak
npm-leak  # scan packages

# Pypi
pip download $PKG -d . --no-deps; tar -xzf *.tar.gz; trufflehog filesystem .
```

### Mobile (APK/IPA)
- `apktool d app.apk` -> grep `AKIA`, `client_secret`, `firebase`
- `MobSF` for full static analysis
- `frida` for runtime extraction

---

## HIGH-VALUE PATTERNS

| Token | Pattern | Context |
|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | + Secret -> verify with `aws sts get-caller-identity` |
| AWS Secret | `[A-Za-z0-9/+=]{40}` | with AKIA |
| GCP service account JSON | `"type": "service_account"` | use with `gcloud auth activate-service-account` |
| Azure | `AccountKey=`, `SharedAccessSignature=` | |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | `gh auth login` |
| GitHub fine-grained | `github_pat_[A-Za-z0-9_]{82}` | |
| GitLab PAT | `glpat-[0-9a-zA-Z\-]{20}` | |
| Slack | `xox[baprs]-[A-Za-z0-9-]+` | `curl -H "Authorization: Bearer X" slack.com/api/auth.test` |
| Stripe live | `sk_live_[A-Za-z0-9]{24,99}` | very high impact |
| Stripe restricted | `rk_live_...` | |
| Twilio | `SK[a-f0-9]{32}` | |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | |
| Mailgun | `key-[a-z0-9]{32}` | |
| Square | `sq0atp-[A-Za-z0-9_-]{22}` | |
| Heroku | `[hH]eroku.*[0-9a-f]{8}-[0-9a-f]{4}` | |
| Datadog | `[a-f0-9]{32}` API key | |
| New Relic | `NRAK-[A-Z0-9]{27}` | |
| PagerDuty | `[a-zA-Z0-9_-]{20}` | |
| OpenAI | `sk-[A-Za-z0-9]{20,99}` | |
| Anthropic | `sk-ant-api03-[A-Za-z0-9_-]{93}AA` | |
| Postman | `PMAK-[a-f0-9]{24}-[a-f0-9]{34}` | |
| NPM token | `npm_[A-Za-z0-9]{36}` | |
| PyPI token | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{70,150}` | |
| RSA private key | `-----BEGIN RSA PRIVATE KEY-----` | SSH/Cert |
| Generic JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | |

---

## STAGE 1 — Verification (critical for $10K+)

Programs only pay for **verified, in-scope** secrets. False positives kill credibility.

For each potential secret:
1. Run trufflehog with `--only-verified`
2. Manually verify with the service's own auth check endpoint
3. Confirm scope: does this token belong to the target's org? (read user/account info, check email domain, check org list)
4. Note privilege level: read-only? deploy? admin?
5. **Stop**. Don't pivot. Don't read other people's data. The screenshot of `aws sts get-caller-identity` showing target's account ID is enough.

---

## STAGE 2 — Source attribution

Critical: prove the leak was caused by *target's* engineering, not a generic third-party. Look at:
- Repo owner / org / contributor email
- Commit author email matches target's email domain
- Code clearly references target's internal services
- File path / context indicates target's project

---

## CHAIN RECIPE — From GitHub to S3 source code

1. trufflehog $ORG -> AKIA + secret
2. `aws sts get-caller-identity` -> confirm target's account
3. `aws iam list-attached-user-policies --user-name $name` -> scope
4. If S3 read: `aws s3 ls` (list buckets only, do not download)
5. Screenshot. Report. Suggest rotation.

---

## VALIDATION CHECKLIST

- Verified token (proven via service auth)
- Source clearly attributable to target
- Privilege level documented
- Did NOT exfil any data — only proved access
- Recommend: rotate immediately, audit usage logs

---

## REPORT TEMPLATE (paste-ready)

```
Title: Verified <SERVICE> credentials exposed in <SOURCE>

Summary:
A live <service> credential belonging to <target> was found exposed at <URL>.
The credential was verified to be active and grants <privilege level>.

Reproduction:
1. Visit <SOURCE_URL>
2. Observe <pattern> at line <N>
3. Verified via:
   curl -H "Authorization: Bearer ..." <verification endpoint>
   Returns <evidence of validity>

Impact:
- <list specific actions the credential allows>
- <data accessible>
- <privilege boundary crossed>

Suggested fix:
- Rotate the credential immediately
- Audit access logs for unauthorized usage
- Add <pre-commit hook / CI scanner> to prevent future leaks
- Use <secrets manager / env vars / ephemeral tokens>
```
