# Reporting — write the survivor up (Phase 6)

Only findings that passed [validation.md](validation.md) reach here. One finding per report (separate
bugs = separate payouts). Impact-first, human tone, proven — never "could potentially / may allow".

## Title formula
`[Bug class] in [endpoint/asset] allows [attacker role] to [concrete impact]`
- ✅ "IDOR in `/api/v2/orders/{id}` allows any authenticated user to read every customer's order + PII"
- ✅ "SSRF in the URL-preview feature allows an unauthenticated attacker to steal AWS IAM credentials"
- ❌ "Possible SSRF" · "Security issue in API" · "Information disclosure"

## Structure
```
## Summary            (impact-first — 2 sentences: what an attacker can do RIGHT NOW + why it matters)
## Steps to Reproduce (copy-pasteable HTTP requests / exact clicks, from a fresh session)
## Impact             (the real-world consequence at the ceiling — data, money, accounts, hosts)
## Evidence           (response bodies / screenshots / video showing the actual data or command output)
## CVSS               (3.1 vector + score, matched to the program's severity tiers)
## Remediation        (1–2 concrete sentences — the specific fix, not "add validation")
```

## Impact statement formula
`An attacker with [precondition] can [action] resulting in [business consequence], affecting [scope/scale].`
Quantify: "any of the ~2.4M sequential order IDs", "all users", "$X per redemption". Numbers beat adjectives.

## Human tone (what triagers trust)
- Active voice, short sentences. State what you did and what happened.
- **Prove, don't hedge.** If you can't prove it, it doesn't go in the report — it goes back to hunting.
- No filler ("As we all know…"), no theoretical padding, no severity inflation (it erodes trust for next time).
- Under-describing impact is as costly as over-claiming — make the triager understand *why it matters*.

## CVSS anchors (full table in [validation.md](validation.md))
IDOR read PII 6.5 · IDOR write/delete 7.5 · auth bypass→admin 9.8 · SSRF→metadata 9.1 · SQLi dump 8.6 ·
stored XSS→cookie 8.8 · JWT alg:none 9.1 · race double-spend 7.5. `PR:N` no login · `S:C` escapes host.

## 60-second pre-submit checklist
```
[ ] Title = class + endpoint + actor + impact
[ ] Repro is copy-pasteable and works from a fresh session
[ ] Evidence shows real impact (data/command/foreign record), not a 200 or alert(1)
[ ] Root cause named; in-scope, production asset confirmed
[ ] Deduped (Hacktivity + changelog + GH issues)
[ ] CVSS matches the program's severity definition
[ ] Zero "could potentially / may allow"; one bug per report
```
Save the final report next to its evidence in `findings/<asset>/<finding>.md`.
