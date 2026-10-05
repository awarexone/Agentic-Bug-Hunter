# Race Conditions — single-packet attack & financial logic

> H1 / Bugcrowd: race-conditions on payment, refund, coupon, 2FA bypass, withdrawal, in-app credit. James Kettle's "single-packet attack" (2023) made these much easier to detect.

---

## CONCEPT

Time-of-check vs time-of-use (TOCTOU). Two requests in flight overlap with shared state mutation -> outcome no longer atomic. Common shapes:
- Buy 1 unit but app charges 0 because race
- Use coupon twice
- Refund issued twice
- 2FA enabled with one device, disabled with another simultaneously
- Withdrawal twice from same balance
- Account creation collision

---

## STAGE 1 — Identify candidates

State-changing endpoints that depend on a check + write:
- `POST /coupon/redeem`
- `POST /refund`
- `POST /withdraw`
- `POST /transfer`
- `POST /accept-invitation`
- `PATCH /2fa/disable`
- `POST /password/reset/use-token`
- `POST /comment/like`
- `POST /vote`
- `POST /signup` (with email uniqueness check)
- `POST /follow` (Twitter/Instagram-style)

---

## STAGE 2 — Single-packet attack

Browsers normally space requests by 1-100ms even on parallel HTTP/2. Single-packet attack uses HTTP/2's last-byte-sync trick to deliver many requests within microseconds:

1. Open many HTTP/2 streams to target
2. Hold the last byte of each header back
3. Release all "last bytes" in one TCP packet
4. Server receives near-simultaneously

Tool: **Turbo Intruder** with `engine=Engine.BURP2` and `concurrentConnections=1` + `requests-per-connection=20`.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=30, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req)
    engine.start()
def handleResponse(req, interesting):
    table.add(req)
```

In Burp Repeater (modern): "Send group in parallel (single-packet attack)".

---

## STAGE 3 — Detect race-on-state

Run 30-50 concurrent requests of the same operation. Look for:
- Multiple "success" responses where there should be one
- Resources created with same unique field
- Counters incrementing more than expected
- Two transactions appearing in audit log when one was sent

---

## STAGE 4 — Common race recipes

### Coupon stacking
```
POST /redeem-coupon { code: "SAVE10" }
```
20 parallel requests -> 20 stacks of 10% off -> negative price.

### Withdraw race
```
POST /withdraw { amount: 100 }
```
Account balance 100. Send 5 parallel -> sometimes 5 withdrawals succeed before balance check sees zero.

### Limit-once feature reuse
- Free trial extension: `POST /trial/extend`
- Loyalty points redemption
- Daily reward claim

### Email uniqueness
```
POST /signup { email: "victim@target.com" }
```
N parallel signups with same email -> uniqueness check skipped, multiple accounts created with same email -> collision attacks.

### 2FA bypass via race
- Submit OTP and `disable-2FA` request concurrently
- One reads "2FA enabled" -> rejects login; other finishes disable; retry passes

### Invitation acceptance race
- Accept invite + decline invite simultaneously
- Land in inconsistent state (member of group but not in members list, or vice versa)

### Order placement race
- Place order while inventory check happens
- Reserve item that doesn't exist -> oversell

---

## STAGE 5 — Higher-impact: state-collision RCE

Some apps have "create resource if not exists" + "execute resource hook on create" patterns. Race two creates:
- One creates a webhook with attacker-controlled URL
- Second triggers an event that fires the webhook before authz check completes

Or upload race: file uploaded, virus scan started; before scan completes, second request renames/moves the file to a public location.

---

## CHAIN RECIPE — Refund race -> infinite credit

1. Identify `/refund` endpoint
2. Make legit purchase ($10)
3. Send 30 parallel `/refund` requests
4. If race exists: 5 succeed -> $50 refund credited
5. Repeat until program-acceptable PoC ($100-1000), then stop

---

## VALIDATION CHECKLIST

- Reproduce 3+ times
- Capture HAR / Burp project file
- Show before/after balance, count, or state
- Note exact race window (hold time, concurrency level)
- Use small dollar amounts; never accept real refunds

---

## TOOLING

- **Turbo Intruder** (Burp ext, James Kettle)
- **Burp Repeater** "Send in parallel (single-packet attack)"
- **race-the-web** (CLI)
- **smuggler** for h2 frame races
