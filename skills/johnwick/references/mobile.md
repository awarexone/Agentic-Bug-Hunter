# Mobile Pentest (Android APK / iOS IPA)

If an APK/IPA is in scope, run this (Rule 7). Mobile ships a **less-hunted surface**: base URLs, API
endpoints, header schemes, and hardcoded secrets the web app never exposes. Recovered endpoints/secrets
feed back into the ledger as fresh assets.

## Runtime-first — the one rule
**Do NOT start by decompiling.** Order:
```
1. Install app on device/emulator   2. Point it at Burp/mitmproxy
3. Drive real flows by hand (login, pay, edit, share)
4. Traffic visible + replayable → STOP reversing, test the API like a web target
5. Traffic pinned/encrypted/absent → THEN escalate to apktool/jadx/Frida
```
Most paid mobile bugs (IDOR, auth bypass, business logic) come from replaying plain HTTP in Burp.
Reversing is a support step to get traffic flowing, not the goal.

## Scope traps
Is the **app package** (`com.target.app`) in scope, or only web domains? If only `*.target.com`, the
**API endpoints** the app calls are usually in scope but the binary analysis may not be — check.
Third-party SDKs (Firebase/Sentry/AppsFlyer/ads) are out of scope. Don't report "debuggable" /
"no root detection" / "no obfuscation" — N/A on almost every program.

## Setup
```bash
adb install target.apk                 # or pull a live install
# Route device through Burp: Wi-Fi proxy = <laptop-ip>:8080, install Burp CA as a *system* cert
# (apps targeting API 24+ ignore user certs — push to /system/etc/security/cacerts on root,
#  or objection patchapk to inject a network_security_config trusting user certs)
mitmproxy --listen-port 8080
apktool d target.apk -o target_src     # smali + manifest (recompilable)
jadx -d target_jadx target.apk         # DEX → readable Java
pip install frida-tools objection      # Frida 16.7.x = stable bug-bounty pick
```

## Static sweep — highest-ROI 5 minutes 🔑
```bash
apktool d target.apk -o target_src
grep -rn "api_key\|secret\|password\|token\|Authorization\|Bearer\|client_secret\|private_key" \
  target_src/ --include="*.smali" --include="*.xml"
grep -rn "https://" target_src/ | grep -viE "schema|xmlns|android|google|w3.org|apache" | sort -u
grep -rniE "firebaseio\.com|amazonaws\.com|s3\.|googleapis|cloudfront|\.blob\.core" target_src/
apkleaks -f target.apk -o target_apkleaks.txt      # endpoints + secrets in one pass
```
| Found | Action — prove impact now |
|---|---|
| `internal-/staging.target.com` base URL not in web recon | httpx + recon it → fresh, often weak-auth surface |
| Live API key (Maps/AWS/Algolia/Mapbox/SendGrid) | call the API as the key; unkeyed billing = $$ |
| Endpoint web app never calls (`/api/internal/`, `/admin/`, `/debug/`) | hit from Burp with your session → IDOR/admin |
| Hardcoded backend password / basic-auth | verify it authenticates against the live host |

## Network-layer testing (treat like web)
`baseline → stable replay → smallest mutation → compare status/body/timing/side-effect → expand by class`.
Mobile apps love `X-User-Id`/`deviceId` headers the server trusts → horizontal IDOR. Diff the app's
endpoints against the web app's — the app frequently hits older, less-reviewed `/v1/` routes directly.
Then apply [authz-idor.md](authz-idor.md), [backend-classes.md](backend-classes.md), [graphql.md](graphql.md).

## SSL pinning bypass (when traffic is blank)
```bash
objection patchapk -s target.apk --ignore-nativelibs --gadget-version 16.7.19
adb install target.objection.apk
objection -g com.target.app explore     # then: android sslpinning disable
```
Custom/obfuscated pinning → Frida hook `okhttp3.CertificatePinner.check()` (no-op) and the
`X509TrustManager.checkServerTrusted()` chain. iOS (jailbroken): `ios sslpinning disable`.
Pinning bypass is a support step, not a finding.
