# HTTP Request Smuggling / Desync (deep)

Front-end and back-end disagree on where a request ends → you prepend bytes to the **next** user's
request. Paid patterns (H1): Basecamp *HTTP/2 request smuggling* **$7.5k**; Cloudflare *Transform Rules
hex-escape smuggling* **$6k**; Mail.ru **$5k**; Internet Bug Bounty *Tomcat client-side desync
CVE-2024-21733* and *CVE-2023-45648* **$4.66k** each; New Relic *password theft via request smuggling* **$3k**.

## Variants
| Variant | Cause |
|---|---|
| **CL.TE** | front-end uses `Content-Length`, back-end uses `Transfer-Encoding` |
| **TE.CL** | reverse of above |
| **TE.TE** | both support TE but one is tricked into ignoring it (obfuscated header) |
| **H2.CL / H2.TE** | HTTP/2 downgraded to HTTP/1.1 with a smuggled CL/TE (the modern high-payer) |
| **CSD (client-side desync)** | browser-triggerable; no back-end TE needed (Tomcat CVE-2024-21733) |
| **0.CL / CL.0** | back-end ignores the body entirely |

## Detect (safely)
Use **timing** first (a delayed response reveals the parser split) — Burp *HTTP Request Smuggler* +
*Turbo Intruder* single-packet. Confirm with a differential: smuggle a request that changes the *next*
response.
```http
# CL.TE probe (front-end reads CL=..., back-end reads chunked and hangs waiting for the next chunk)
POST / HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
```http
# TE header obfuscation for TE.TE (one proxy ignores the malformed TE)
Transfer-Encoding: chunked
Transfer-Encoding : chunked        # space before colon
Transfer-Encoding:\tchunked        # tab
X-Foo: bar\r\nTransfer-Encoding: chunked
```
For **H2**: send via HTTP/2 and smuggle a CL/TE in the downgraded request (Basecamp $7.5k pattern) — Burp's
"HTTP/2" tab + `Content-Length`/`Transfer-Encoding` in the h2 body.

## Escalate (what pays)
- **Capture other users' requests → credential/session theft** (New Relic password theft $3k): smuggle a
  prefix that stores the victim's full request (incl. cookies/creds) to an endpoint you can read back.
- **Cache poisoning** (persistent XSS/redirect to all users) — chain with [cache-attacks.md](cache-attacks.md).
- **Auth bypass / internal-header injection:** smuggle `X-Forwarded-For`/internal auth headers to reach
  admin routes past the edge.
- **WAF/edge bypass:** the back-end sees a request the WAF never inspected.

## Proof-of-impact bar
A single delayed/odd response is only a *signal*. Prove it by **capturing another request** or **poisoning
a response served to a different session**. Do this carefully on production — smuggling can affect other
users; use your own second session as the "victim" to demonstrate. Full desync → ATO/cache-poison = Critical.
