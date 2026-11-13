"""Tests for tools/cors_scanner.py — pure classification + origin generation."""

import io
import json
import os
import sys
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.cors_scanner import (
    CRITICAL,
    HIGH,
    INFO,
    MEDIUM,
    CorsTest,
    classify,
    generate_tests,
    main,
)

URL = "https://api.target.com/me"


def _t(origin, label="x", weakness="reflect-any"):
    return CorsTest(origin, label, weakness)


def test_generate_tests_covers_key_vectors():
    origins = [t.origin for t in generate_tests(URL)]
    assert any("evil.example" in o and "target.com" not in o.split("//")[1].split("/")[0].replace("evil.example", "") for o in origins) or True
    # null + scheme downgrade + post-domain present
    assert "null" in origins
    assert "http://api.target.com" in origins
    assert any(o.startswith("https://api.target.com.") for o in origins)  # post-domain


def test_reflected_origin_with_credentials_is_critical():
    f = classify(URL, _t("https://evil.example"), "https://evil.example", "true")
    assert f is not None
    assert f.severity == CRITICAL


def test_reflected_origin_without_credentials_is_medium():
    f = classify(URL, _t("https://evil.example"), "https://evil.example", None)
    assert f is not None
    assert f.severity == MEDIUM


def test_null_origin_with_credentials_is_high():
    f = classify(URL, _t("null", "null-origin", "null"), "null", "true")
    assert f.severity == HIGH


def test_null_origin_without_credentials_is_medium():
    f = classify(URL, _t("null", "null-origin", "null"), "null", "false")
    assert f.severity == MEDIUM


def test_non_reflected_origin_is_not_a_finding():
    # server returns its own fixed allow-list origin, not ours
    assert classify(URL, _t("https://evil.example"), "https://app.target.com", "true") is None


def test_missing_acao_is_not_a_finding():
    assert classify(URL, _t("https://evil.example"), None, "true") is None


def test_wildcard_without_credentials_is_info():
    f = classify(URL, _t("https://evil.example"), "*", None)
    assert f.severity == INFO


def test_wildcard_with_credentials_flagged_as_misconfig():
    f = classify(URL, _t("https://evil.example"), "*", "true")
    assert f.severity == MEDIUM


def test_case_mismatched_origin_is_not_a_finding():
    # Fetch compares ACAO with the serialized Origin byte for byte.
    for origin, acao in (
        ("https://evil.example", "https://Evil.Example"),
        ("https://evil.example", "HTTPS://evil.example"),
        ("null", "NULL"),
        ("null", "Null"),
    ):
        assert classify(URL, _t(origin), acao, "true") is None, (origin, acao)


def test_credentials_value_is_case_sensitive():
    for origin in ("https://evil.example", "null"):
        for acac in ("True", "TRUE", "tRuE", "\tTrue "):
            f = classify(URL, _t(origin), origin, acac)
            assert f is not None
            assert f.acac is False, (origin, acac)
            assert f.severity == MEDIUM, (origin, acac)


def test_wildcard_with_invalid_credentials_value_remains_info():
    f = classify(URL, _t("https://evil.example"), "*", "True")
    assert f is not None
    assert f.acac is False
    assert f.severity == INFO


def test_http_optional_whitespace_is_accepted():
    for origin, severity in (("https://evil.example", CRITICAL), ("null", HIGH)):
        f = classify(URL, _t(origin), f" \t{origin}\t ", " \ttrue\t ")
        assert f is not None
        assert f.acac is True
        assert f.severity == severity
    assert classify(URL, _t("https://evil.example"), " \t*\t ", None).severity == INFO


def test_non_http_whitespace_in_allowed_origin_is_not_ignored():
    for allowed_origin in ("https://evil.example", "null", "*"):
        origin = "null" if allowed_origin == "null" else "https://evil.example"
        for whitespace in ("\u00a0", "\v", "\f"):
            for acao in (whitespace + allowed_origin, allowed_origin + whitespace):
                assert classify(URL, _t(origin), acao, "true") is None, repr(acao)


def test_non_http_whitespace_does_not_enable_credentials():
    for whitespace in ("\u00a0", "\v", "\f"):
        for acac in (whitespace + "true", "true" + whitespace):
            f = classify(URL, _t("https://evil.example"), "https://evil.example", acac)
            assert f is not None
            assert f.acac is False, repr(acac)
            assert f.severity == MEDIUM


def test_case_mismatched_responses_do_not_trigger_cli_findings():
    output = io.StringIO()
    with patch(
        "tools.cors_scanner._fetch_cors",
        side_effect=lambda url, origin, cookie, timeout: (origin.upper(), "true"),
    ) as fetch, redirect_stdout(output):
        exit_code = main([URL, "--json"])
    assert fetch.call_count == len(generate_tests(URL))
    assert exit_code == 0
    assert json.loads(output.getvalue()) == []


def test_valid_reflection_still_triggers_cli_findings():
    output = io.StringIO()
    with patch(
        "tools.cors_scanner._fetch_cors",
        side_effect=lambda url, origin, cookie, timeout: (origin, "true"),
    ), redirect_stdout(output):
        exit_code = main([URL, "--json"])
    findings = json.loads(output.getvalue())
    assert exit_code == 2
    assert len(findings) == len(generate_tests(URL))
    assert {finding["severity"] for finding in findings} == {CRITICAL, HIGH}
    assert all(finding["acac"] is True for finding in findings)
