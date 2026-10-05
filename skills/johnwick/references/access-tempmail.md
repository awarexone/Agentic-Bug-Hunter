# Phase 3 — Access Acquisition (auto-signup + temp-mail, the only human gate)

Attempt in strict order; escalate only when the prior option fails. Store working session material in
`auth/` and set up self-refresh (Rule 5) so you never re-prompt mid-hunt.

```
1. USE provided creds/cookies        → if the user already gave them (auth/)
2. AUTO-SIGNUP yourself via temp-mail → rotate providers until one works, confirm email, log in
3. ASK the human                     → ONLY if 1 and 2 both fail. Sole mandatory pause.
```

## Temp-mail fallback chain

Try providers in order; if create-inbox / poll / captcha fails, move to the next. Never give up after
one provider (Rule 8).

| Provider | Type | Notes |
|---|---|---|
| mail.tm / mail.gw | JSON API | best default — real inbox, no key |
| 1secmail | JSON API | simplest polling, but sometimes blocklisted |
| dropmail.me | GraphQL | good when 1secmail is blocked |
| guerrillamail | JSON API | long-lived, api_email flow |
| maildrop.cc | GraphQL | UI + API |
| emailnator | web (Playwright) | Google-friendly addresses, beats naive blocklists |
| temp-mail.io | web/API | fallback |

### mail.tm (recommended API)
```bash
# 1. get a domain
DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.["hydra:member"][0].domain')
ADDR="jw$(date +%s)@$DOMAIN"; PASS="Jw!$(openssl rand -hex 6)"
# 2. create account + token
curl -s -X POST https://api.mail.tm/accounts -H 'Content-Type: application/json' \
  -d "{\"address\":\"$ADDR\",\"password\":\"$PASS\"}" >/dev/null
TOKEN=$(curl -s -X POST https://api.mail.tm/token -H 'Content-Type: application/json' \
  -d "{\"address\":\"$ADDR\",\"password\":\"$PASS\"}" | jq -r .token)
# 3. (register on target with $ADDR) then poll inbox for the confirmation link
for i in $(seq 1 30); do
  ID=$(curl -s https://api.mail.tm/messages -H "Authorization: Bearer $TOKEN" | jq -r '.["hydra:member"][0].id')
  [ "$ID" != "null" ] && break; sleep 5
done
curl -s "https://api.mail.tm/messages/$ID" -H "Authorization: Bearer $TOKEN" \
  | jq -r '.text, .html[]?' | grep -oP 'https?://[^\s"'\''<>]+(verify|confirm|activate|token)[^\s"'\''<>]*'
```

### 1secmail (no account needed)
```bash
LOGIN="jw$(date +%s)"; DOMAIN=$(curl -s "https://www.1secmail.com/api/v1/?action=getDomainList" | jq -r '.[0]')
ADDR="$LOGIN@$DOMAIN"     # register on target with $ADDR
# poll
for i in $(seq 1 30); do
  MID=$(curl -s "https://www.1secmail.com/api/v1/?action=getMessages&login=$LOGIN&domain=$DOMAIN" | jq -r '.[0].id')
  [ "$MID" != "null" ] && break; sleep 5
done
curl -s "https://www.1secmail.com/api/v1/?action=readMessage&login=$LOGIN&domain=$DOMAIN&id=$MID" \
  | jq -r .body | grep -oP 'https?://[^\s"'\''<>]+'
```

## Registration mechanics
- Simple form → `curl`/httpx the signup POST directly.
- JS-guarded form, hCaptcha/turnstile, SPA flow → drive it with **Playwright real-Chrome** (`channel="chrome"`
  + stealth init) — same engine used to beat WAF JS-challenges elsewhere.
- After the confirmation link, log in and capture the session (cookie jar / bearer token) to `auth/`.

## Self-refresh (Rule 5)
Prefer, in order: refresh-token endpoint → re-login with stored `auth/creds.json` → cookie renewal.
Wire this before Phase 5 so long hunts don't stall on an expired session.

## Exit gate
`auth/` holds working session material **and** a live authenticated request succeeds right now (prove
it — `superpowers:verification-before-completion`). Only then start Phase 4.
