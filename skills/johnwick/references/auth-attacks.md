# Auth / OAuth / OIDC / SAML / JWT / Reset — ATO (deep)

Account takeover is the top-value non-RCE class. Paid patterns (H1): Coinbase *OAuth consent clickjacking*
**$5k**; GitLab *unauthenticated blind SSRF in OAuth Jira controller* **$4k**; GitLab *email-verification
bypass for OAuth grants → ATO on 3rd parties* **$3k**; pixiv *steal OAuth code via `redirect_uri`* **$2k**;
LY/page.line.me *open redirect → OAuth code exposure* **$1k**; Rockstar *smuggle Facebook OAuth code via
Referer leakage* **$750**; Twitter/xAI *steal OAuth tokens*.

## OAuth 2.0 / OIDC
- **`redirect_uri` theft (the #1 payer):** try suffix/prefix/substring matches, added path, subdomain,
  `@`-userinfo, path-traversal, and **open-redirect chains** on an allowed host:
  ```
  redirect_uri=https://evil.com                 redirect_uri=https://target.com.evil.com
  redirect_uri=https://evil.com?x=target.com    redirect_uri=https://target.com@evil.com
  redirect_uri=https://target.com/cb/../../evil  redirect_uri=https://sub.target.com/openredirect?to=evil.com
  ```
  Landing the `code`/`token` on your host = ATO.
- **Code/token leak via Referer** (Rockstar $750): if the auth code lands on a page that loads third-party
  resources or has an outbound link, it leaks in the `Referer` header. Look for an injectable image/link.
- **`state` missing/reused → login CSRF / forced account-linking:** no `state` lets you stitch the victim's
  session to your social account (or vice-versa) → ATO.
- **Account pre-hijack:** pre-register the victim's email (unverified) → victim later "Sign in with
  Google/…" links into your account, or your pre-set password survives. Also *email-verification bypass*
  (GitLab $3k): if the IdP grant trusts an unverified email, claim any email.
- **`response_type`/`response_mode` switch** (`code`→`token`, query→fragment), **scope upgrade**, **PKCE
  downgrade** (drop `code_challenge`), **consent clickjacking** (Coinbase $5k — frameable authorize page).

## SAML
- **XML Signature Wrapping (XSW):** inject a forged `Assertion`/`Response` alongside the signed one so the
  validator checks the signed copy but consumes the forged (change `NameID` to victim/admin).
- **Signature stripping** (accepts unsigned assertion), **comment injection** in `NameID`
  (`admin@target.com<!---->.evil.com` → some parsers read `admin@target.com`), **key confusion / self-signed
  cert accepted**. Tools: SAML Raider (Burp).

## JWT
```
alg:none            → header {"alg":"none"}, drop signature
RS256 → HS256       → sign with the server's PUBLIC key as the HMAC secret (alg confusion)
kid injection       → kid:"../../dev/null" (empty key), or SQLi/path in kid
jku / jwks injection→ point jku/x5u to attacker-hosted JWKS you control
weak secret         → brute with hashcat (-m 16500) / jwt_tool
claim tamper        → change sub/uid/email/role/isAdmin; re-sign if key known
```

## Password reset / verification
- **Host-header poisoning** (reset link built from `Host`/`X-Forwarded-Host` → attacker domain gets the
  token when victim clicks).
- **Token leak via Referer**, predictable/short token, **token not invalidated** after use/email-change,
  reuse, token/`email` in the response body, **email-parameter injection** (`email=victim@x.com&email=
  attacker@x.com`, or CC via `%0a`).
- **Response/OTP manipulation** (change `"verified":false`→`true`, brute OTP via GraphQL alias batching).

## Identifier reuse
Rename/delete account A → claim A's freed username/handle/email/slug → inherit A's orphaned resources.
Root cause: ownership keyed on a **mutable** identifier. Cross-ref [authz-idor.md](authz-idor.md).

## Proof-of-impact bar
Demonstrate **full control of another account** (log in as them, read their data, act as them) or capture
a token that grants it. A theoretical redirect_uri accept with no code/token captured is downgraded. Any-user
ATO w/o interaction = Critical (9.8); with interaction = High.
