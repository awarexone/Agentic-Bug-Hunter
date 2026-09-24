"""Path-traversal defenses for target handling.

A target reaches the recon pipeline from the CLI and, over MCP, from an
untrusted client. Because pathlib does not collapse '..' and resets on an
absolute component, an unvalidated target like '../../etc/x' or '/etc/x' used
to be able to steer recon writes/reads outside the recon/ sandbox. These tests
lock the fixes at every layer: the Python normalizer, the MCP adapters, and
recon_engine.sh.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RECON_ENGINE = REPO / "bughunter" / "tools" / "recon_engine.sh"

TRAVERSAL = [
    "../../../etc/cron.d/x",
    "/etc/cron.d/x",
    "./../../tmp/pwn",
    "..",
    "$(whoami)",   # command-substitution chars must never become a dir name
    "",
]
SAFE = ["9am.io", "localhost", "10.0.0.5", "sub.example.com", "192.0.2.10"]


def load_norm():
    path = REPO / "bughunter" / "tools" / "target_normalize.py"
    spec = importlib.util.spec_from_file_location("target_normalize", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_adapters():
    import sys
    sys.path.insert(0, str(REPO / "bughunter"))
    path = REPO / "bughunter" / "mcp" / "bughunter-mcp" / "adapters.py"
    spec = importlib.util.spec_from_file_location("bh_adapters", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("bad", TRAVERSAL)
def test_safe_target_dirname_rejects(bad):
    norm = load_norm()
    assert norm.safe_target_dirname(bad) is None


@pytest.mark.parametrize("good", SAFE)
def test_safe_target_dirname_accepts(good):
    norm = load_norm()
    assert norm.safe_target_dirname(good) == good


def test_safe_dirname_never_contains_separators():
    norm = load_norm()
    for good in SAFE:
        name = norm.safe_target_dirname(good)
        assert name and "/" not in name and ".." not in name


@pytest.mark.parametrize("bad", ["../../../../etc", "..", "/etc"])
def test_mcp_adapters_reject_traversal(bad):
    a = load_adapters()
    assert a.read_recon_file(bad, "subdomains/all.txt").get("error") == "INVALID_TARGET"
    assert a.attack_surface(bad).get("error") == "INVALID_TARGET"
    assert a.list_findings(bad).get("error") == "INVALID_TARGET"


def test_mcp_read_recon_file_rejects_relative_escape():
    a = load_adapters()
    # even a legit target must not allow the relative part to climb out
    assert a.read_recon_file("example.com", "../../../etc/passwd").get("error") == "INVALID_TARGET"


@pytest.mark.parametrize("bad", ["../../etc", "/etc/passwd/../..", "..%2f..%2fetc"])
def test_recon_engine_refuses_unsafe_target(bad):
    proc = subprocess.run(
        ["bash", str(RECON_ENGINE), bad, "--normalize-only"],
        capture_output=True, text=True, timeout=30,
    )
    # /etc/passwd exists so it may be taken as a host-list basename; the pure
    # traversal strings must be refused (exit 2) — never a 0 that would scan.
    assert proc.returncode == 2, f"{bad!r} not refused: rc={proc.returncode} {proc.stdout}"
