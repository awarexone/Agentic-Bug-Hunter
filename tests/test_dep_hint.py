"""Every scanner the recon pipeline can miss must print macOS AND Linux
install commands, not a bare "not installed — skipping"."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[1] / "bughunter" / "tools" / "_dep_hint.sh"

# The tools named in the bug report.
TOOLS = ["subfinder", "httpx", "nuclei", "gau", "ffuf", "nmap"]


def _hint(tool: str) -> str:
    return subprocess.run(
        ["bash", "-c", f'. "{HELPER}"; dep_install_hint {tool}'],
        capture_output=True, text=True, timeout=30,
    ).stdout


@pytest.mark.parametrize("tool", TOOLS)
def test_hint_has_both_os(tool):
    out = _hint(tool)
    assert "macOS:" in out, f"{tool}: no macOS hint"
    assert "Linux:" in out, f"{tool}: no Linux hint"
    # Each hint line must carry an actual command, not be empty.
    for line in out.splitlines():
        if line.strip().startswith(("macOS:", "Linux:")):
            assert line.split(":", 1)[1].strip(), f"{tool}: empty command line"


def test_httpx_avoids_brew_trap():
    """`brew install httpx` is the wrong (Python) tool — the recommended
    command lines must use `go install`. (The note may still name brew to warn.)"""
    out = _hint("httpx")
    cmd_lines = [
        ln for ln in out.splitlines()
        if ln.strip().startswith(("macOS:", "Linux:"))
    ]
    assert cmd_lines and all("go install" in ln for ln in cmd_lines)
    assert not any("brew install httpx" in ln for ln in cmd_lines)


def test_warn_missing_returns_zero():
    """warn_missing must not leak a non-zero status (it runs under pipefail)."""
    rc = subprocess.run(
        ["bash", "-c", f'log_warn(){{ echo "$1"; }}; . "{HELPER}"; warn_missing nmap x'],
        capture_output=True, text=True, timeout=30,
    ).returncode
    assert rc == 0
