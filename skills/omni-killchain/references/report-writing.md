# Report Writing — H1 / Bugcrowd / Intigriti templates

> A great PoC with a bad report gets paid less than a mediocre PoC with a great report. Triage teams skim. Write to be skimmed.

---

## STRUCTURE THAT WINS

```
1. Title (precise, scannable)
2. Summary (3-5 sentences, lead with impact)
3. Steps to reproduce (numbered, copy-pasteable)
4. Proof of concept (curl / video / screenshot)
5. Impact (specific numbers, real worst-case)
6. Suggested fix (concrete, testable)
7. References (CWE, OWASP, prior art)
8. Severity / CVSS (with vector string)
```

---

## TITLE FORMULA

`[<bug class>] <specific symptom> in <specific endpoint/feature> leading to <impact>`

Examples:
- `[Account Takeover] Password reset token reflected in Host header leading to mass ATO of any user`
- `[Pre-auth RCE] Unsafe deserialization in /api/v1/legacy/upload allowing remote command run as www-data`
- `[Stored XSS] HTML write sink in postMessage receiver of /widgets/sso.html leading to ATO via cookie theft`

Avoid: "Vulnerability in target.com", "Multiple bugs found", "Critical issue please respond".

---

## SUMMARY (lead with impact)

Bad:
> "I found that the application accepts a Host header with attacker-controlled value when a user requests a password reset email."

Good:
> "Any unauthenticated attacker can take over any user account by manipulating the Host header on the password reset endpoint. The reset email link points to attacker-controlled host, leaking the reset token to the attacker. Demonstrated against tester+poc@gmail.com — full session obtained in under 60 seconds."

---

## STEPS TO REPRODUCE — copy-pasteable curl

Triagers want to verify in 30 seconds:
```
1. Sign up two accounts: 
   - Attacker: poc-attacker+1@gmail.com
   - Victim: poc-victim+1@gmail.com  
2. Run:
   curl -X POST https://target.com/api/password/reset \
     -H "Host: attacker.com" \
     -d "email=poc-victim+1@gmail.com"
3. Check inbox of poc-victim+1@gmail.com — link points to https://attacker.com/reset?token=XXXX
4. Open the same path on the real domain:
   curl -i https://target.com/reset?token=XXXX
   -> 200 with new session cookie
```

Provide every value (don't say "X" — say `Bearer eyJhbGc...`). Mark the parts the triager must vary.

---

## IMPACT — be specific

Each line is a different sentence pattern. Use the ones that fit:
- "Any unauthenticated attacker can {action} for any of the ~12M users."
- "An attacker who knows a victim's email can {action} without their interaction."
- "Confidentiality: attacker reads {data classes}."
- "Integrity: attacker modifies {state}."  
- "Availability: attacker {DoS scope}."
- "Demonstrated by {evidence} — see PoC video at minute 1:23."
- "Cross-tenant: attacker in tenant A reads tenant B's data."

For RCE: "The attacker has command execution as user `<user>` on host `<host>` and can read `/etc/passwd`. Cloud metadata is reachable from this host (proof: HTTP 200 from 169.254.169.254/latest/...)."

---

## SUGGESTED FIX

Be concrete, programmer-actionable:
- "Validate Host header against an allowlist of canonical domains before constructing reset URLs."
- "Use a secrets manager for {token type} instead of committing to git; rotate immediately."
- "Set `SameSite=Strict` on the auth cookie."
- "Remove `Domain=.target.com` from the cookie unless it must be shared with subdomains; if so, audit every subdomain for content controls."

Don't write "follow OWASP guidelines" — that's noise.

---

## CVSS

Use [CVSS calculator](https://www.first.org/cvss/calculator/3.1).

For ATO (typical pattern):
```
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  -> 9.1 Critical
```

For SSRF + cloud metadata:
```
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N -> 9.0 Critical
```

For stored XSS in admin context:
```
AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N -> 8.7 High
```

Match the program's expected scoring system. Some prefer impact tier (P1-P5).

---

## ATTACHMENTS

- Burp project file (.burp) for full request/response capture
- Video <2 min showing exact reproduction
- Screenshots for response viewer / DB / cloud console
- File samples (the polyglot, the XXE doc) — encrypted ZIP if program permits

---

## TONE

- Neutral, factual, technical.
- No hyperbole ("catastrophic", "devastating") — let CVSS speak.
- No threats, no time pressure (unless responsibly disclosing a 0day with public risk).
- Don't accuse the team ("this should never happen") — be a partner.
- Don't pad with disclaimers.

---

## DUPLICATE HANDLING

If marked dup:
- Don't argue the merits of your bug; argue the *difference* if real
- "My report demonstrates additional impact via Y not in the original" — link the original ticket if visible
- Accept dups gracefully — they happen

---

## TRIAGE TIMING

- Submit during program-team's business hours
- Critical / 0day-style: notify on Twitter / email simultaneously if program has a public urgent channel
- Track SLA: most programs commit to first-response in N business days

---

## TEMPLATE — copy and fill

```markdown
## Title
[<bug class>] <symptom> in <endpoint/feature> leading to <impact>

## Summary
<2-4 sentences>. Demonstrates impact against <test artifacts>. Reproducible in under <N> minutes.

## Severity
CVSS:3.1/<vector> = <score> (<rating>)

## Steps to Reproduce
1. ...
2. ...
3. ...

## Proof of Concept
```bash
curl ...
```
Or attached: video.mp4, burp-project.burp, screenshot1.png

## Impact
- <numbered list of concrete impacts>
- <demonstrated artifacts>
- <scope: cross-user / cross-tenant / pre-auth / 0-click>

## Suggested Fix
<concrete technical fix>

## References
- CWE-<N>: <name>
- OWASP <category>
- <prior art / similar bug if any>

## Disclosure / Coordination
<note program rules; you commit to N-day private window if applicable>
```
