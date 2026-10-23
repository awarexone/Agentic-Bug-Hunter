# Race Conditions / TOCTOU (deep)

A check and its use aren't atomic → fire N requests in parallel and slip past a "once only" guard. Paid
patterns (H1): Cosmos *faucet race via starport* **$5k**; Tools-for-Humanity *race bypasses verification
check* **$3k**; InnoGames *race in email activation → infinite diamonds* **$2k**; Shopify *race on create
Location* **$500**; Razer *race in OAuth 2.0 flow* **$250**; Helium *transfer credits race*; HackerOne
*race joining CTF group*.

## Where it pays (follow the money / the "once" guard)
- **Limit-overrun:** redeem a coupon/gift-card/referral/faucet **N times**; apply one discount many times;
  withdraw/transfer the same balance twice (double-spend); vote/like/rate past the cap.
- **Verification / 2FA bypass:** race the "mark verified" step (Tools-for-Humanity $3k); confirm email/phone
  to grant a reward repeatedly (InnoGames $2k).
- **Quota/resource creation:** create more objects/seats/invites than the plan allows (Shopify $500).
- **State-machine collisions:** cancel + use, approve + edit, redeem + refund at the same instant.

## Technique
- **HTTP/2 single-packet attack** — the modern, jitter-free method: put 20–50 requests in one TCP packet so
  they hit the server simultaneously. Burp Repeater → add to group → **"Send group in parallel (single
  packet)"**; or **Turbo Intruder** with `engine=Engine.BURP2` and `gate`-synced requests.
- **HTTP/1.1 last-byte sync** — send all requests holding back the final byte, then release together.
- Warm the connection first; strip anti-CSRF only if the endpoint needs it once (reuse a fresh token per).

```python
# Turbo Intruder skeleton — release 30 gated requests at once
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

## Detect
Send 20–50 identical "should-succeed-once" requests in parallel. **More than one success** (two redemptions,
balance credited twice, quota exceeded) = race. Compare to a sequential baseline that correctly allows one.

## Proof-of-impact bar
Show the **over-limit result**: two gift-card redemptions, doubled balance, N verification rewards, quota
exceeded. Financial/asset impact = High (CVSS ~7.5, `AC:H`). A race with no tangible over-limit gain is N/A.
