"""Regression checks for the PR #7 review fixes in tools/vuln_scanner.sh."""

from pathlib import Path


SCANNER_PATH = Path(__file__).resolve().parents[1] / "bughunter" / "tools" / "vuln_scanner.sh"



def test_unsafe_auth_probes_are_policy_gated_and_saml_forgery_is_absent():
    scanner = SCANNER_PATH.read_text()

    assert "SafeMethodPolicy" in scanner
    assert "ALLOW_UNSAFE_HTTP_TESTS" in scanner
    assert 'unsafe_method_guard POST "$BASE" "bounded MFA rate-limit check"' in scanner

    # The previous response-manipulation and forged-SAML probes were removed.
    assert "MFA response-manipulation canary" not in scanner
    assert "SAML signature-stripping probe" not in scanner
    assert "STRIPPED_SAML" not in scanner
    assert "SAML-SIG-STRIP" not in scanner

def test_scanner_uses_current_repo_paths():
    scanner = SCANNER_PATH.read_text()

    assert 'BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"' in scanner
    assert 'DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET"' in scanner
    assert 'head -20 "$RECON_DIR/live/urls.txt"' in scanner
    assert "httpx_live.txt" not in scanner

def test_manual_sqli_timing_probes_are_opt_in():
    scanner = SCANNER_PATH.read_text()
    assert 'ALLOW_SQLI_TIMING_TESTS:-0' in scanner
    assert 'Skipping manual SQLi timing probes' in scanner


def test_mfa_post_requires_explicit_endpoint_and_test_account():
    scanner = SCANNER_PATH.read_text()
    assert 'ALLOW_MFA_RATE_LIMIT_TESTS:-0' in scanner
    assert 'BUGHUNTER_MFA_TEST_ACCOUNT:-0' in scanner
    assert 'BUGHUNTER_MFA_TEST_ENDPOINT' in scanner
    assert '[ "$BASE" = "${BUGHUNTER_MFA_TEST_ENDPOINT%\\?*}" ]' in scanner
    assert 'for attempt in 1 2 3' in scanner


def test_dalfox_worker_setting_is_preserved():
    scanner = SCANNER_PATH.read_text()
    assert '--worker 20' in scanner


def test_summary_counters_match_actual_markers():
    scanner = SCANNER_PATH.read_text()
    assert 'MFA-RATE-LIMIT-NOT-OBSERVED' in scanner
    assert 'INERT-UPLOAD-RESPONSE' in scanner
    assert 'HTTP-200-ONLY-UNVERIFIED' in scanner
    assert 'verified_upload_pocs.txt' not in scanner
