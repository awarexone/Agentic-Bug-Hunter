#!/bin/bash
# =============================================================================
# Bug Bounty Vulnerability Scanner v5 — Verified PoC Generation
#
# Usage: ./scanner.sh <recon_dir> [--quick] [--full] [--skip xss,sqli,...]
#
# UPDATED IN V5:
#   • Bash 3.2 compatible (macOS)
#   • Improved RCE Execution PoC (PHP/JSP/ASPX)
#   • Linear-Scaling SQLi Verifier
#   • Race Condition detection (xargs -P20)
#   • SSTI math-canary probes (Jinja2/Freemarker/Thymeleaf/ERB)
#   • dalfox XSS pipeline integration
# =============================================================================

set -o pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[$(ts)] [+]${NC} $1"; }
log_err()   { echo -e "${RED}[$(ts)] [-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[$(ts)] [!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[$(ts)] [*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[$(ts)] [>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[$(ts)] [✓]${NC} $1"; }
log_vuln()  { echo -e "    ${RED}${BOLD}[$(ts)] [VULN]${NC} $1"; }
log_crit()  { echo -e "    ${MAGENTA}${BOLD}[$(ts)] [CRITICAL]${NC} $1"; }
ts()        { date '+%Y-%m-%d %H:%M:%S'; }

# Portable nanosecond clock. BSD `date` (macOS) has no %N and emits a literal
# 'N', which corrupts the `/ 1000000` millisecond math used by the timing-based
# checks below. Prefer GNU date, then gdate, then python3, then fall back to
# second precision (×1e9) so the arithmetic still works everywhere.
_now_ns() {
    local n
    n=$(date +%s%N 2>/dev/null)
    case "$n" in
        ''|*[!0-9]*) : ;;          # empty or contains non-digit (BSD 'N')
        *) printf '%s\n' "$n"; return ;;
    esac
    if command -v gdate >/dev/null 2>&1; then gdate +%s%N; return; fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import time; print(int(time.time()*1000000000))'; return
    fi
    printf '%s\n' "$(( $(date +%s) * 1000000000 ))"
}

# ── Config ────────────────────────────────────────────────────────────────────
RECON_DIR=""
QUICK_MODE=""
FULL_MODE=""
SKIP_CHECKS=""

while [ "$#" -gt 0 ]; do
    arg="$1"
    case "$arg" in
        --quick) QUICK_MODE="--quick" ;;
        --full) FULL_MODE="--full" ;;
        --skip) shift; SKIP_CHECKS="${SKIP_CHECKS:-}${SKIP_CHECKS:+,}$1" ;;
        *) RECON_DIR="$arg" ;;
    esac
    shift
done

if [ -z "$RECON_DIR" ] || [ ! -d "$RECON_DIR" ]; then
    echo "Usage: $0 <recon_dir> [--quick] [--full] [--skip xss,sqli,...]" >&2
    exit 1
fi

RECON_DIR="$(cd "$RECON_DIR" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Auth-aware hunting: load BBHUNT_AUTH_HEADERS into BB_AUTH_ARGS.
# shellcheck source=tools/_auth_helper.sh
. "$SCRIPT_DIR/_auth_helper.sh"
bb_auth_active && bb_auth_banner

# macOS compatibility: GNU timeout may not exist
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
        export -f timeout
    else
        timeout() { shift; "$@"; }
        export -f timeout
    fi
fi

if [ "$(basename "$(dirname "$RECON_DIR")")" = "sessions" ]; then
    SESSION_ID=$(basename "$RECON_DIR")
    TARGET=$(basename "$(dirname "$(dirname "$RECON_DIR")")")
    DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET/sessions/$SESSION_ID"
else
    SESSION_ID=""
    TARGET=$(basename "$RECON_DIR")
    DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET"
fi

FINDINGS_DIR="${FINDINGS_OUT_DIR:-$DEFAULT_FINDINGS_DIR}"

export PATH="$HOME/go/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PRIORITY_DIR="$RECON_DIR/priority"
export FINDINGS_DIR

CURL_TIMEOUT=60
mkdir -p "$FINDINGS_DIR"/{upload,cms,mfa,saml,cmdi,xss,sqli,takeover,misconfig,exposure,ssrf,cves,redirects,idor,auth_bypass,lfi,ssti,graphql,cors,jwt,smuggling,cloud,manual_review,metasploit,.tmp}

# ── Helpers ───────────────────────────────────────────────────────────────────
file_lines()  { [ -f "${1:-}" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
tool_ok()     { command -v "$1" &>/dev/null; }
count_vuln() { local file="$1"; [ -f "$file" ] && [ -s "$file" ] && wc -l < "$file" | tr -d ' ' || echo 0; }

_has_skip() {
    local source="${1:-}"
    local want="${2:-}"
    [[ ",$source," == *",$want,"* ]] || [[ ",$source," == *",all,"* ]]
}

skip_has() { _has_skip "${SKIP_CHECKS:-}" "$1" || { [ "$FULL_MODE" != "--full" ] && _has_skip "xss,lfi,ssti,ssrf,cors,takeover,misconfig,jwt,graphql,smuggling,redirects,idor,auth_bypass,host_header,exposure,cloud,race" "$1"; }; }

unsafe_method_guard() {
    local method="$1"
    local url="$2"
    local label="$3"
    local guard_output decision reason

    guard_output=$(PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$method" "$url" <<'PY'
import sys
from memory.audit_log import SafeMethodPolicy

result = SafeMethodPolicy().check(sys.argv[1], sys.argv[2])
print(result["decision"])
print(result.get("reason", ""))
PY
) || {
        log_warn "Unable to evaluate safe-method policy for $label; skipping"
        return 1
    }

    decision=$(printf '%s\n' "$guard_output" | sed -n '1p')
    reason=$(printf '%s\n' "$guard_output" | sed -n '2p')

    if [ "$decision" = "require_approval" ] && [ "${ALLOW_UNSAFE_HTTP_TESTS:-0}" != "1" ]; then
        log_warn "Skipping $label: $reason. Set ALLOW_UNSAFE_HTTP_TESTS=1 to opt in."
        return 1
    fi

    if [ "$decision" = "require_approval" ]; then
        log_warn "$label uses unsafe HTTP method $method. Proceeding because ALLOW_UNSAFE_HTTP_TESTS=1 is set."
    fi

    return 0
}

# ── Maturity Module: Advanced Verification Logic ─────────────────────────────

verify_sqli_poc() {
    local url="$1"; local p_idx="$2"; local dialect="$3"
    log_warn "Timing anomaly is not proof of SQLi; manual evidence required: $url"
    return 1
}

verify_upload_poc() {
    log_warn "Executable upload tests disabled; manual safe validation required: $1"
    return 1
}

# ── Resolve scan targets ──────────────────────────────────────────────────────
ORDERED_SCAN="$FINDINGS_DIR/ordered_scan_targets.txt"
: > "$ORDERED_SCAN"
for f in "$PRIORITY_DIR/critical_hosts.txt" "$PRIORITY_DIR/high_hosts.txt" "$PRIORITY_DIR/prioritized_hosts.txt" "$RECON_DIR/live/urls.txt"; do
    [ -s "$f" ] && cat "$f" >> "$ORDERED_SCAN"
done
# Clean and uniqify
awk '!seen[$0]++' "$ORDERED_SCAN" > "${ORDERED_SCAN}.tmp" && mv "${ORDERED_SCAN}.tmp" "$ORDERED_SCAN"
[ ! -s "$ORDERED_SCAN" ] && log_err "No scan targets found" && exit 1

# ── Check 0: Upload Surface Discovery ──────────────────────────────────
if ! skip_has upload; then
    log_info "Check 0: Upload Surface Discovery"
    CATCHALL_HOSTS=""
    log_step "Detecting catchall behavior..."
    # NB: no pipe into `while` here. `head ... | while read` runs the loop body in
    # a subshell, so CATCHALL_HOSTS assignments are discarded on exit and the skip
    # below can never fire — every probe path then reports as a hit on any host
    # that answers 200 for unknown paths (i.e. most SPAs).
    while read -r host; do
        [ -z "$host" ] && continue
        # Baseline must go through the same session as the real probes, else an
        # authenticated run compares authed responses against an anonymous 401.
        if [ "$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} "${host}/non_existent_$(date +%s)")" -eq 200 ]; then
            log_warn "Catchall detected: $host"
            CATCHALL_HOSTS="${CATCHALL_HOSTS},${host},"
        fi
    done < <(head -10 "$ORDERED_SCAN")
    PROBE_PATHS=("/upload.php" "/uploader.php" "/upload/index.php" "/filemanager/index.php" "/ckfinder/core/connector/php/connector.php" "/fckeditor/editor/filemanager/connectors/php/connector.php" "/elfinder.php" "/admin/upload")
    while read -r host; do
        [ -z "$host" ] && continue
        # Comma-anchored: an unanchored *"$host"* match is substring, not host
        # equality, so e.g. a recorded "https://api.t.com:8443" would suppress
        # the probed "https://api.t.com". Entries are stored ",host," above.
        case "$CATCHALL_HOSTS" in *",${host},"*) continue ;; esac
        for path in "${PROBE_PATHS[@]}"; do
            U="${host%/}${path}"
            if [ "$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} "$U")" -eq 200 ]; then
                log_info "HTTP 200 only; upload functionality not verified: $U"
                echo "[INFORMATIONAL] [HTTP-200-ONLY-UNVERIFIED] $U" >> "$FINDINGS_DIR/upload/active_upload_probe.txt"
            fi
        done
    done < <(head -30 "$ORDERED_SCAN")
fi


# ── Optional active inert upload validation ─────────────────────────────
# Opt in explicitly: ALLOW_INERT_UPLOAD_TESTS=1
# A text file may persist on the target; no executable file is used.
if [ "${ALLOW_INERT_UPLOAD_TESTS:-0}" = "1" ] && ! skip_has upload; then
    log_warn "Inert upload POST testing enabled; uploaded text files may persist."
    mkdir -p "$FINDINGS_DIR/upload"
    CANARY_FILE=$(mktemp "${TMPDIR:-/tmp}/bughunter-canary.XXXXXX") || exit 1
    printf 'BugHunter inert upload verification marker\n' > "$CANARY_FILE"

    if [ -s "$FINDINGS_DIR/upload/active_upload_probe.txt" ]; then
        awk '{print $3}' "$FINDINGS_DIR/upload/active_upload_probe.txt" |
        sort -u | head -3 |
        while IFS= read -r endpoint; do
            [ -z "$endpoint" ] && continue
            if unsafe_method_guard POST "$endpoint" "inert upload validation"; then
                code=$(curl -sk -o "$FINDINGS_DIR/upload/upload_response.tmp" \
                    -w "%{http_code}" --max-time 10 \
                    ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
                    -F "file=@${CANARY_FILE};filename=bughunter-canary.txt" \
                    "$endpoint" 2>/dev/null || echo 000)

                echo "[POSSIBLE] [INERT-UPLOAD-RESPONSE] $endpoint | HTTP $code | inspect response and storage manually" >> "$FINDINGS_DIR/upload/active_upload_probe.txt"
            fi
        done
    fi
    rm -f "$CANARY_FILE"
fi

# ── Check 2: SQL Injection ──────────────────────────────────────────────
if ! skip_has sqli; then
    log_info "Check 2: SQL Injection"
    # 2a. Nuclei
    if tool_ok nuclei; then
        log_step "nuclei SQLi templates..."
        nuclei -l "$ORDERED_SCAN" -tags sqli -severity medium,high,critical -silent ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} -o "$FINDINGS_DIR/sqli/nuclei_sqli.txt" || true
    fi
    # 2b. Manual timing probes are opt-in because they deliberately delay
    # server-side processing. Nuclei SQLi checks remain a separate check.
    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    if [ "${ALLOW_SQLI_TIMING_TESTS:-0}" = "1" ] && [ -s "$PARAMS_FILE" ]; then
        log_warn "SQLi timing probes explicitly enabled; requests may cause server delays."
        log_step "Bounded SQLi timing-candidate probes on top 10 parameterised URLs..."
    elif [ -s "$PARAMS_FILE" ]; then
        log_info "Skipping manual SQLi timing probes; set ALLOW_SQLI_TIMING_TESTS=1 to opt in."
    fi
    if [ "${ALLOW_SQLI_TIMING_TESTS:-0}" = "1" ] && [ -s "$PARAMS_FILE" ]; then
        head -10 "$PARAMS_FILE" | while read -r url; do
            [ -z "$url" ] && continue
            case "$url" in
                *"/cdn-cgi/"*)
                    log_info "Skipping Cloudflare infrastructure URL in SQLi checks: $url"
                    continue
                    ;;
            esac
            T_START=$(_now_ns); curl -sk -o /dev/null --max-time 10 ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} "$url"; BASE_MS=$(( ($(_now_ns) - T_START) / 1000000 ))
            P_COUNT=$(echo "$url" | grep -o "=" | wc -l | tr -d ' ')
            [ "$P_COUNT" -eq 0 ] && continue
            for i in $(seq 1 "$P_COUNT"); do
                for dialect in "mysql" "postgres"; do
                    p="'%20AND%20SLEEP(2)--%20"; [ "$dialect" = "postgres" ] && p="'||pg_sleep(2)--%20"
                    # Fixed sed: use alternate delimiter and correct numeric occurrence
                    SU=$(echo "$url" | sed "s/=\([^&]*\)/=$p/$i")
                    TS=$(_now_ns); curl -sk -o /dev/null --max-time 20 ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} "$SU" >/dev/null 2>&1; RC=$?; TE=$(( ($(_now_ns) - TS) / 1000000 ))
                    if [ "$RC" -eq 0 ] && [ "$((TE - BASE_MS))" -gt 1800 ]; then
                        if verify_sqli_poc "$url" "$i" "$dialect"; then
                            log_crit "EMPIRICAL SQLI POC: $url"
                            echo "[CONFIRMED] [SQLI-POC-VERIFIED] dialect=$dialect param=$i url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                            break 2
                        else
                            log_warn "SQLi timing candidate only; not independently verified: $url"
                            echo "[POSSIBLE] [SQLI-CANDIDATE] dialect=$dialect param=$i url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                        fi
                    elif [ "$RC" -eq 28 ] && [ "$TE" -gt 18000 ]; then
                        log_warn "Potential SQLi (Timeout Multiplier): $url"
                        echo "[POSSIBLE] [SQLI-TIMEOUT-CANDIDATE] timeout=${TE}ms param=$i url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                    fi
                done
            done
        done
    fi
fi

# ── Check 3: XSS ────────────────────────────────────────────────────────
if ! skip_has xss; then
    log_info "Check 3: XSS (dalfox + URL dedup + global timeout)"
    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    if tool_ok dalfox && [ -s "$PARAMS_FILE" ]; then
        DAL_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 30 || echo 100)
        DAL_MAX_TIME=$([ "$QUICK_MODE" = "--quick" ] && echo 300 || echo 900)
        # Deduplicate by base-URL + sorted param keys to avoid scanning the same
        # endpoint N times with different random values (e.g. ?rand=1.234 variants)
        DAL_DEDUP_FILE=$(mktemp /tmp/dalfox_dedup_XXXXXX.txt)
        python3 - "$PARAMS_FILE" "$DAL_DEDUP_FILE" <<'PYEOF' 2>/dev/null || cp "$PARAMS_FILE" "$DAL_DEDUP_FILE"
import sys
from urllib.parse import urlparse, parse_qs
seen = set()
with open(sys.argv[1]) as fin, open(sys.argv[2], 'w') as fout:
    for line in fin:
        url = line.strip()
        if not url:
            continue
        try:
            p = urlparse(url)
            key = (p.scheme, p.netloc, p.path, frozenset(parse_qs(p.query).keys()))
        except Exception:
            key = url
        if key not in seen:
            seen.add(key)
            fout.write(url + '\n')
PYEOF
        ORIG_COUNT=$(wc -l < "$PARAMS_FILE" 2>/dev/null || true)
        DEDUP_COUNT=$(wc -l < "$DAL_DEDUP_FILE" 2>/dev/null || true)
        log_step "Running dalfox on $DAL_LIMIT URLs (deduped $ORIG_COUNT -> $DEDUP_COUNT, timeout: ${DAL_MAX_TIME}s)..."
        head -"$DAL_LIMIT" "$DAL_DEDUP_FILE" | \
            timeout "$DAL_MAX_TIME" dalfox pipe \
            --silence \
            --no-color \
            --worker 20 \
            --timeout 10 \
            ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
            --output "$FINDINGS_DIR/xss/dalfox_results.txt" 2>/dev/null || true
        rm -f "$DAL_DEDUP_FILE"

        # Prefix every dalfox line with [POSSIBLE] — dalfox labels its own output;
        # impact is not confirmed until manually verified in-browser.
        if [ -s "$FINDINGS_DIR/xss/dalfox_results.txt" ]; then
            DAL_TMP=$(mktemp /tmp/dalfox_prefixed_XXXXXX.txt)
            while IFS= read -r _dal_line; do
                echo "[POSSIBLE] $_dal_line"
            done < "$FINDINGS_DIR/xss/dalfox_results.txt" > "$DAL_TMP"
            mv "$DAL_TMP" "$FINDINGS_DIR/xss/dalfox_results.txt"
        fi

        DALFOX_COUNT=$(count_vuln "$FINDINGS_DIR/xss/dalfox_results.txt")
        [ "$DALFOX_COUNT" -gt 0 ] && log_vuln "Dalfox found $DALFOX_COUNT potential XSS" || log_done "Dalfox: no XSS found"
    else
        [ -s "$PARAMS_FILE" ] || log_warn "No parameterized URLs found for XSS scan"
        tool_ok dalfox || log_warn "dalfox not installed — skipping XSS scan"
    fi
fi

# ── Check 4: SSTI ───────────────────────────────────────────────────────
if ! skip_has ssti; then
    log_info "Check 4: SSTI (reflected parameter probes)"
    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    SSTI_OUT="$FINDINGS_DIR/ssti/ssti_candidates.txt"
    if [ -s "$PARAMS_FILE" ]; then
        # Removed associative array for Bash 3.2 compatibility
        # engines: jinja2, freemarker, thymeleaf, erb
        SSTI_ENGINES=("jinja2" "freemarker" "thymeleaf" "erb")
        SSTI_PAYLOADS=("{{7*7}}" "\${7*7}" "*{7*7}" "<%= 7*7 %>")
        
        SSTI_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 20 || echo 50)
        log_step "Testing SSTI payloads on up to $SSTI_LIMIT URLs..."
        hit=0
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            for idx in "${!SSTI_ENGINES[@]}"; do
                engine="${SSTI_ENGINES[$idx]}"
                payload="${SSTI_PAYLOADS[$idx]}"
                enc_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null || echo "$payload")
                injected=$(echo "$url" | sed "s/=\([^&]*\)/=${enc_payload}/g")
                body=$(curl -sk --max-time 10 ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} "$injected" 2>/dev/null || true)
                if echo "$body" | grep -qE '(\b49\b|7777777)'; then
                    log_warn "SSTI response candidate [$engine] (reflection/evaluation not distinguished): $injected"
                    echo "[POSSIBLE] [SSTI-RESPONSE-CANDIDATE] engine=$engine url=$injected" >> "$SSTI_OUT"
                    hit=$(( hit + 1 ))
                    break
                fi
            done
        done < <(head -"$SSTI_LIMIT" "$PARAMS_FILE")
        [ "$hit" -eq 0 ] && log_done "SSTI: clean"
    fi
fi


# ── Check 7: CMS Fingerprinting ─────────────────────────────────────────
if ! skip_has cms; then
    log_info "Check 7: Active CMS fingerprinting"
    mkdir -p "$FINDINGS_DIR/cms"
    CMS_OUT="$FINDINGS_DIR/cms/cms_detected.txt"

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        RES=$(curl -sk --max-time 10 \
            ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
            "$url" 2>/dev/null || true)

        CMS=""
        if echo "$RES" | grep -qiE 'wp-content|wordpress'; then
            CMS="WordPress"
        elif echo "$RES" | grep -qiE 'Drupal\.settings|drupal'; then
            CMS="Drupal"
        elif echo "$RES" | grep -qiE 'Joomla|/media/system/js/'; then
            CMS="Joomla"
        fi

        if [ -n "$CMS" ]; then
            log_info "[CMS-DETECTED] $CMS: $url"
            echo "[INFORMATIONAL] [CMS-DETECTED] cms=$CMS url=$url" >> "$CMS_OUT"
        fi
    done < <(head -50 "$ORDERED_SCAN")
fi


# ── Check 8: MFA / 2FA Active Checks ────────────────────────────────────
if ! skip_has mfa; then
    log_info "Check 8: Bounded MFA / 2FA checks"
    mkdir -p "$FINDINGS_DIR/mfa"
    MFA_OUT="$FINDINGS_DIR/mfa/findings.txt"

    MFA_ENDPOINTS=$(grep -iE \
        '/(mfa|otp|2fa|verify|authenticate|totp|sms.code|auth.code)' \
        "$ORDERED_SCAN" 2>/dev/null | head -20 || true)

    if [ -n "$MFA_ENDPOINTS" ]; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            BASE="${url%%\?*}"

            echo "[INFORMATIONAL] [MFA-ENDPOINT] $BASE" >> "$MFA_OUT"

            # MFA POST tests are disabled unless the operator explicitly
            # confirms a dedicated test account and the exact endpoint.
            if [ "${ALLOW_MFA_RATE_LIMIT_TESTS:-0}" = "1" ] &&
               [ "${BUGHUNTER_MFA_TEST_ACCOUNT:-0}" = "1" ] &&
               [ -n "${BUGHUNTER_MFA_TEST_ENDPOINT:-}" ] &&
               [ "$BASE" = "${BUGHUNTER_MFA_TEST_ENDPOINT%\?*}" ]; then
                MFA_POST_APPROVED=1
            else
                MFA_POST_APPROVED=0
                log_info "MFA POST test skipped; explicit endpoint and test-account opt-in required: $BASE"
            fi

            # Maximum three invalid-code attempts, with two-second pauses.
            if [ "$MFA_POST_APPROVED" = "1" ] &&
               unsafe_method_guard POST "$BASE" "bounded MFA rate-limit check"; then
                CODES=""
                for attempt in 1 2 3; do
                    CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
                        --max-time 8 \
                        ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
                        -X POST "$BASE" \
                        -H "Content-Type: application/json" \
                        -d '{"otp":"000000"}' 2>/dev/null || echo "000")

                    CODES="${CODES}${CODE} "
                    [ "$attempt" -lt 3 ] && sleep 2
                done

                if echo "$CODES" | grep -qE '(^| )429( |$)'; then
                    echo "[INFORMATIONAL] [MFA-RATE-LIMIT-OBSERVED] $BASE | $CODES" >> "$MFA_OUT"
                else
                    echo "[POSSIBLE] [MFA-RATE-LIMIT-NOT-OBSERVED] $BASE | bounded_codes=$CODES | manual verification required" >> "$MFA_OUT"
                fi
            fi

            # Anonymous protected-route checks are indicators only.
            HOST=$(echo "$BASE" | grep -oE '^https?://[^/]+')
            for path in dashboard profile account settings; do
                CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --max-time 6 "$HOST/$path" 2>/dev/null || echo "000")
                if [ "$CODE" = "200" ]; then
                    echo "[INFORMATIONAL] [MFA-PROTECTED-ROUTE-CANDIDATE] $HOST/$path | HTTP 200; content/authentication must be verified" >> "$MFA_OUT"
                fi
            done
        done <<< "$MFA_ENDPOINTS"
    else
        log_warn "No MFA endpoints found in recon URL inventory"
    fi
fi


# ── Check 9: SAML / SSO Configuration Checks ────────────────────────────
if ! skip_has saml; then
    log_info "Check 9: Active SAML / SSO configuration checks"
    mkdir -p "$FINDINGS_DIR/saml"

    SAML_ENDPOINTS_FILE="$FINDINGS_DIR/saml/endpoints.txt"
    SAML_OUT="$FINDINGS_DIR/saml/findings.txt"

    LIVE_HOSTS=$(head -20 "$RECON_DIR/live/urls.txt" 2>/dev/null || true)

    while IFS= read -r host; do
        [ -z "$host" ] && continue

        CONTROL=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
            "${host%/}/saml-control-$RANDOM-$$" 2>/dev/null || echo 000)

        case "$CONTROL" in
            200|301|302|403)
                echo "[INFORMATIONAL] [SAML-CATCHALL] $host | HTTP $CONTROL" >> "$SAML_OUT"
                continue
                ;;
        esac

        for path in /saml/login /sso/saml /auth/saml \
                    /api/auth/saml /login/saml /saml/acs \
                    /saml/metadata /metadata /adfs/ls; do

            url="${host%/}${path}"
            code=$(curl -sk -o /dev/null -w "%{http_code}" \
                --max-time 6 \
                ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
                "$url" 2>/dev/null || echo 000)

            case "$code" in
                200|301|302|403)
                    echo "[INFORMATIONAL] [SAML-ENDPOINT] $url | HTTP $code" >> "$SAML_ENDPOINTS_FILE"
                    ;;
            esac
        done
    done <<< "$LIVE_HOSTS"

    # Include SAML-looking URLs already discovered by recon.
    grep -iE '/(saml|sso|acs|adfs)' "$ORDERED_SCAN" 2>/dev/null |
        while IFS= read -r url; do
            [ -z "$url" ] || echo "[INFORMATIONAL] [SAML-RECON-ENDPOINT] $url" >> "$SAML_ENDPOINTS_FILE"
        done

    # GET-only metadata validation. No forged assertions or login attempts.
    if [ -s "$SAML_ENDPOINTS_FILE" ]; then
        awk '{print $3}' "$SAML_ENDPOINTS_FILE" | sort -u |
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            body=$(curl -sk --max-time 8 \
                ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
                "$url" 2>/dev/null || true)

            if echo "$body" | grep -qiE \
                'EntityDescriptor|IDPSSODescriptor|X509Certificate'; then
                echo "[INFORMATIONAL] [SAML-METADATA-EXPOSED] $url" >> "$SAML_OUT"
            fi
        done
    fi
fi


# ── Optional safe command-injection canary ───────────────────────────────
# Opt in explicitly: ALLOW_SAFE_CMDI_PROBES=1
# The only command in the payload is printf of a unique marker.
if [ "${ALLOW_SAFE_CMDI_PROBES:-0}" = "1" ] && ! skip_has cmdi; then
    log_info "Safe command-injection canary checks enabled"
    mkdir -p "$FINDINGS_DIR/cmdi"
    CMDI_OUT="$FINDINGS_DIR/cmdi/cmdi_candidates.txt"

    grep -iE '/cgi-bin/|\.cgi([/?]|$)|\.sh([/?]|$)|/debug|/console' \
        "$ORDERED_SCAN" 2>/dev/null |
        while IFS= read -r url; do
            [ -z "$url" ] || echo "[INFORMATIONAL] [SHELL-RELATED-SURFACE] $url" >> "$CMDI_OUT"
        done

    PARAMS_FILE="$RECON_DIR/urls/with_params.txt"
    if [ -s "$PARAMS_FILE" ]; then
        head -5 "$PARAMS_FILE" |
        while IFS= read -r url; do
            [ -z "$url" ] && continue

            for marker in BH$(date +%s)A BH$(date +%s)B; do
                injected=$(python3 - "$url" "$marker" <<'PYURL'
import sys
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

url, marker = sys.argv[1:3]
parts = urlsplit(url)
params = parse_qsl(parts.query, keep_blank_values=True)
if not params:
    raise SystemExit(0)

key, value = params[0]
params[0] = (key, value + ";printf${IFS}" + marker)
print(urlunsplit((parts.scheme, parts.netloc, parts.path,
                  urlencode(params), parts.fragment)))
PYURL
)
                [ -z "$injected" ] && continue

                body=$(curl -sk --max-time 8 \
                    ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
                    "$injected" 2>/dev/null || true)

                if echo "$body" | grep -Fq "$marker"; then
                    echo "[POSSIBLE] [CMDI-MARKER-CANDIDATE] $url | marker=$marker | reflection must be ruled out" >> "$CMDI_OUT"
                fi
            done
        done
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log_info "Scan Complete. Consolidating..."
CONF_SQLI=0 # No independent SQLi verifier is implemented
CONF_RCE=0 # No safe automatic RCE verifier is implemented
CONF_SSTI=0 # Response matching is not proof of template evaluation
CONF_SAML=0 # HTTP status alone cannot verify SAML authentication bypass
POSS_SQLI=$(grep -c "\[POSSIBLE\].*SQLI-" "$FINDINGS_DIR/sqli/timebased_candidates.txt" 2>/dev/null || true)
POSS_XSS=$(grep -c "\[POSSIBLE\]" "$FINDINGS_DIR/xss/dalfox_results.txt" 2>/dev/null || true)
POSS_MFA_RATE=$(grep -c "\[POSSIBLE\].*MFA-RATE-LIMIT-NOT-OBSERVED" "$FINDINGS_DIR/mfa/findings.txt" 2>/dev/null || true)
POSS_UPLOAD=$(grep -c "\[POSSIBLE\].*INERT-UPLOAD-RESPONSE" "$FINDINGS_DIR/upload/active_upload_probe.txt" 2>/dev/null || true)
POSS_MFA_SKIP=$(grep -c "\[POSSIBLE\].*MFA-WORKFLOW-SKIP" "$FINDINGS_DIR/mfa/findings.txt" 2>/dev/null || true)
INFO_UPLOAD=$(grep -c "\[INFORMATIONAL\].*HTTP-200-ONLY-UNVERIFIED" "$FINDINGS_DIR/upload/active_upload_probe.txt" 2>/dev/null || true)
INFO_SAML_ENDPOINTS=$(grep -c "\[INFORMATIONAL\].*SAML-ENDPOINT" "$FINDINGS_DIR/saml/endpoints.txt" 2>/dev/null || true)
INFO_SAML_META=$(grep -c "\[INFORMATIONAL\].*SAML-METADATA-EXPOSED" "$FINDINGS_DIR/saml/findings.txt" 2>/dev/null || true)
INFO_CMS=$(grep -c "\[CMS-DETECTED\]" "$FINDINGS_DIR/cms/cms_detected.txt" 2>/dev/null || true)
INFO_MFA_MANIP=$(grep -c "\[INFORMATIONAL\].*MFA-RESPONSE-MANIP" "$FINDINGS_DIR/mfa/findings.txt" 2>/dev/null || true)
{
    echo "Scan Date  : $(date)"
    echo "Target     : $TARGET"
    echo ""
    echo "=== AUTOMATIC CONFIRMATION COUNTS (independent verification required) ==="
    printf "  SQLi PoC (not auto-verified): %s\n" "$CONF_SQLI"
    printf "  RCE PoC (not auto-tested)   : %s\n" "$CONF_RCE"
    printf "  SSTI (not auto-verified)    : %s\n" "$CONF_SSTI"
    printf "  SAML bypass (not verified)  : %s\n" "$CONF_SAML"
    echo ""
    echo "=== POSSIBLE (run /validate before submitting) ==="
    printf "  SQLi delay candidates       : %s\n" "$POSS_SQLI"
    printf "  XSS (dalfox, unconfirmed)   : %s\n" "$POSS_XSS"
    printf "  MFA rate-limit              : %s\n" "$POSS_MFA_RATE"
    printf "  Upload (file-only)          : %s\n" "$POSS_UPLOAD"
    printf "  MFA workflow-skip           : %s\n" "$POSS_MFA_SKIP"
    echo ""
    echo "=== INFORMATIONAL (do not submit without chain) ==="
    printf "  Upload paths found          : %s\n" "$INFO_UPLOAD"
    printf "  SAML endpoints              : %s\n" "$INFO_SAML_ENDPOINTS"
    printf "  SAML metadata exposed       : %s\n" "$INFO_SAML_META"
    printf "  CMS detected                : %s\n" "$INFO_CMS"
    printf "  MFA response-manip canary   : %s\n" "$INFO_MFA_MANIP"
} > "$FINDINGS_DIR/summary.txt"
cat "$FINDINGS_DIR/summary.txt"

python3 - "$FINDINGS_DIR" "$TARGET" \
    "$CONF_SQLI" "$CONF_RCE" "$CONF_SSTI" "$CONF_SAML" \
    "$POSS_SQLI" "$POSS_XSS" "$POSS_MFA_RATE" "$POSS_UPLOAD" "$POSS_MFA_SKIP" \
    "$INFO_UPLOAD" "$INFO_SAML_ENDPOINTS" "$INFO_SAML_META" "$INFO_CMS" "$INFO_MFA_MANIP" <<'PY'
import json
import os
import sys
from datetime import datetime

out_dir = sys.argv[1]
target = sys.argv[2]
nums = list(map(int, sys.argv[3:]))

payload = {
    "generated_at": datetime.now().isoformat(timespec="seconds"),
    "target": target,
    "counts": {
        "confirmed": {
            "sqli": nums[0],
            "rce": nums[1],
            "ssti": nums[2],
            "saml_sig_strip": nums[3],
        },
        "possible": {
            "sqli_delay": nums[4],
            "xss_dalfox": nums[5],
            "mfa_rate_limit": nums[6],
            "upload_file_only": nums[7],
            "mfa_workflow_skip": nums[8],
        },
        "informational": {
            "upload_paths": nums[9],
            "saml_endpoints": nums[10],
            "saml_metadata": nums[11],
            "cms_detected": nums[12],
            "mfa_response_manip": nums[13],
        },
    },
    "artifacts": {
        "summary_txt": os.path.join(out_dir, "summary.txt"),
        "sqli_timebased": os.path.join(out_dir, "sqli", "timebased_candidates.txt"),
        "rce": os.path.join(out_dir, "upload", "verified_rce_pocs.txt"),
        "ssti": os.path.join(out_dir, "ssti", "ssti_candidates.txt"),
        "saml": os.path.join(out_dir, "saml", "findings.txt"),
        "xss": os.path.join(out_dir, "xss", "dalfox_results.txt"),
        "mfa": os.path.join(out_dir, "mfa", "findings.txt"),
        "upload": os.path.join(out_dir, "upload", "active_upload_probe.txt"),
    },
}

with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
