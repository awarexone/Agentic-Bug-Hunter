"""Command-injection regression tests for hunt.py's remaining shell sinks.

run_cve_hunt, run_zero_day_fuzzer, run_vuln_scan and the shared run_cmd all
used to build shell=True command strings with the target/domain interpolated,
so a domain like `x$(touch pwned)` executed. Each must now use an argv list
(shell=False). These tests drive each entry point with a shell-metacharacter
domain and assert the marker file is never created.
"""

from __future__ import annotations

import importlib.util
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_hunt():
    spec = importlib.util.spec_from_file_location(
        "hunt", os.path.join(REPO_ROOT, "bughunter", "tools", "hunt.py")
    )
    hunt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hunt)
    return hunt


def _stub(path: str, body: str = '#!/bin/bash\necho "got: $@"\n'):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)


def test_run_cmd_list_does_not_invoke_shell(tmp_path):
    hunt = load_hunt()
    marker = tmp_path / "pwned_runcmd"
    # As an argv list, the metacharacters are a literal argv[1] to echo.
    ok, out = hunt.run_cmd(["echo", f"x$(touch {marker})"])
    assert not marker.exists()
    assert "$(touch" in out  # printed literally


def test_run_cve_hunt_no_injection(tmp_path, monkeypatch):
    hunt = load_hunt()
    marker = tmp_path / "pwned_cve"
    monkeypatch.setattr(hunt, "TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    os.makedirs(tmp_path / "tools", exist_ok=True)
    _stub(str(tmp_path / "tools" / "cve_scan.sh"))
    hunt.run_cve_hunt(f'target.com$(touch {marker})')
    assert not marker.exists()


def test_run_zero_day_fuzzer_no_injection(tmp_path, monkeypatch):
    hunt = load_hunt()
    marker = tmp_path / "pwned_zd"
    monkeypatch.setattr(hunt, "TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    os.makedirs(tmp_path / "tools", exist_ok=True)
    # python stub: accept any args, do nothing harmful
    _stub(str(tmp_path / "tools" / "zero_day_fuzzer.py"),
          '#!/usr/bin/env python3\nimport sys\nprint("args", sys.argv[1:])\n')
    hunt.run_zero_day_fuzzer(f'target.com$(touch {marker})')
    assert not marker.exists()


def test_run_vuln_scan_no_injection(tmp_path, monkeypatch):
    hunt = load_hunt()
    marker = tmp_path / "pwned_vuln"
    monkeypatch.setattr(hunt, "TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
    os.makedirs(tmp_path / "tools", exist_ok=True)
    _stub(str(tmp_path / "tools" / "vuln_scanner.sh"))
    # run_vuln_scan requires the recon dir for the (malicious) domain to exist.
    domain = f'target.com$(touch {marker})'
    os.makedirs(os.path.join(str(tmp_path / "recon"), domain), exist_ok=True)
    hunt.run_vuln_scan(domain)
    assert not marker.exists()
