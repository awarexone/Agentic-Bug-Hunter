"""Validation tests for target normalization (URL/host/port parsing).

Covers the cases from the bug report: localhost targets, URLs with a protocol,
URLs without a protocol, bare domains, IPs and private IPs — plus a parity
check that recon_engine.sh's shell normalizer agrees with the Python one, since
the two must produce the same host/type or the output directory splits in two.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RECON_ENGINE = REPO / "bughunter" / "tools" / "recon_engine.sh"


def load_norm():
    path = REPO / "bughunter" / "tools" / "target_normalize.py"
    spec = importlib.util.spec_from_file_location("target_normalize", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# (raw input, expected host, expected port, expected type)
CASES = [
    # localhost, with and without a port
    ("localhost",                 "localhost",  None,  "local"),
    ("localhost:3000",            "localhost",  "3000", "local"),
    ("http://localhost:3000/",    "localhost",  "3000", "local"),
    # URLs WITH protocol
    ("https://9am.io/",           "9am.io",     None,  "domain"),
    ("https://9am.io/path?q=1#f", "9am.io",     None,  "domain"),
    ("http://user:pass@example.com:8080/x", "example.com", "8080", "domain"),
    # URLs WITHOUT protocol
    ("9am.io",                    "9am.io",     None,  "domain"),
    ("example.com:443",           "example.com", "443", "domain"),
    ("www.9am.io/",               "www.9am.io", None,  "domain"),
    # domains — case/trailing-dot canonicalization
    ("HTTPS://Example.COM.",      "example.com", None, "domain"),
    # IPs (public) vs private/local
    ("192.0.2.10",                "192.0.2.10", None,  "ip"),      # RFC-5737 doc net = public stand-in
    ("172.32.0.1",                "172.32.0.1", None,  "ip"),      # just outside RFC-1918
    ("127.0.0.1",                 "127.0.0.1",  None,  "local"),
    ("10.2.77.193",               "10.2.77.193", None, "local"),
    ("192.168.1.10",              "192.168.1.10", None, "local"),
    ("172.16.5.5",                "172.16.5.5", None,  "local"),
    ("http://10.0.0.5:3000/",     "10.0.0.5",   "3000", "local"),
    # CIDR keeps its mask and is a range, not a single local host
    ("10.0.0.0/24",               None,         None,  "cidr"),
    ("192.0.2.0/24",              None,         None,  "cidr"),
]


@pytest.mark.parametrize("raw,host,port,ttype", CASES)
def test_normalize_and_detect(raw, host, port, ttype):
    norm = load_norm()
    if host is not None:  # CIDR host is not meaningful; only assert type
        h, p = norm.normalize_target(raw)
        assert h == host, f"{raw!r} → host {h!r}, expected {host!r}"
        assert p == port, f"{raw!r} → port {p!r}, expected {port!r}"
    assert norm.detect_target_type(raw) == ttype, f"{raw!r} type"


def test_url_never_leaks_scheme_into_host():
    """Regression for `nmap https://9am.io/` / `recon/https:/9am.io`."""
    norm = load_norm()
    host, _ = norm.normalize_target("https://9am.io/")
    assert "://" not in host and "/" not in host and host == "9am.io"


@pytest.mark.parametrize("raw,ttype", [(c[0], c[3]) for c in CASES])
def test_shell_normalizer_matches_python(raw, ttype):
    """recon_engine.sh --normalize-only must agree with the Python module."""
    out = subprocess.run(
        ["bash", str(RECON_ENGINE), raw, "--normalize-only"],
        capture_output=True, text=True, timeout=30,
    ).stdout
    parsed = dict(
        line.split("=", 1) for line in out.strip().splitlines() if "=" in line
    )
    assert parsed.get("type") == ttype, f"{raw!r}: shell type {parsed!r} != {ttype}"
    norm = load_norm()
    py_host, py_port = norm.normalize_target(raw)
    if ttype != "cidr":  # CIDR is passed through unnormalized in the shell
        assert parsed.get("host") == py_host, f"{raw!r}: host mismatch"
        assert parsed.get("port", "") == (py_port or ""), f"{raw!r}: port mismatch"
