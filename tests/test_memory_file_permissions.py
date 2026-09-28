"""Hunt-memory files can contain secret-bearing recon data / request URLs, so
they must be created owner-only (0o600), not world-readable (0o644)."""

from __future__ import annotations

import os
import stat

from memory.audit_log import AuditLog
from memory.pattern_db import PatternDB


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_audit_log_file_and_dir_are_owner_only(tmp_path):
    log = AuditLog(path=tmp_path / "mem" / "audit.jsonl")
    log.log_request(
        url="https://api.target.com/reset?token=secret",
        method="GET",
        scope_check="pass",
    )
    assert _mode(tmp_path / "mem" / "audit.jsonl") == 0o600
    assert _mode(tmp_path / "mem") == 0o700


def test_pattern_db_file_is_owner_only(tmp_path, sample_pattern_entry):
    db = PatternDB(tmp_path / "mem" / "patterns.jsonl")
    assert db.save(sample_pattern_entry) is True
    assert _mode(tmp_path / "mem" / "patterns.jsonl") == 0o600
