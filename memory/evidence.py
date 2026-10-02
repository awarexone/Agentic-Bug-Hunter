"""Evidence / provenance foundation.

An append-only, hash-chained, redacted-before-persistence evidence store. One
JSONL file per session (`evidence.jsonl`, alongside `agent_trace.jsonl`), plus a
small external head anchor (`evidence_head.json`) that makes tail-truncation
detectable.

Core chain like the product requires:

    Action -> Scope decision -> Evidence -> Finding -> Validation -> Report

Every record captures the *observed* security action (what the system actually
did), not an AI narrative, and preserves the scope rules that were active at
capture time so "was this in scope under the rules then?" stays answerable.

Trust boundary (documented honestly): this provides **tamper evidence**, not
tamper-proofing. A local attacker with write access can rewrite both the log and
the head anchor. What integrity verification guarantees is that *unauthorized
modification, reordering, or deletion of interior records is detectable*, and
tail truncation is detectable unless the attacker also rewrites the head anchor.
See docs/phase3-evidence-provenance.md.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory.redaction import redact_obj

EVIDENCE_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
EVIDENCE_FILENAME = "evidence.jsonl"
HEAD_FILENAME = "evidence_head.json"

# Fields that participate in the integrity digest, in the order they are set.
# `digest` itself is excluded (it is the output). `prev_hash` IS included, so
# reordering records changes each digest and breaks verification.
_DIGEST_EXCLUDE = {"digest"}


class EvidenceError(Exception):
    """Raised on unrecoverable evidence-store errors."""


def new_evidence_id() -> str:
    return "ev-" + secrets.token_hex(6)


def new_finding_id() -> str:
    return "fnd-" + secrets.token_hex(6)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(obj: Any) -> str:
    """Deterministic serialization for hashing (stable key order, ASCII)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest_of(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k not in _DIGEST_EXCLUDE}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _parse_line(line: str) -> dict:
    """Parse one evidence line. Rejects non-objects and duplicate keys.

    Duplicate keys are rejected because Python's default parser keeps the last
    value while another reader might keep the first, which would let a forged
    field hide beside the one the digest was computed over.
    """
    def _pairs(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise EvidenceError("duplicate JSON keys")
        return dict(pairs)

    try:
        obj = json.loads(line, object_pairs_hook=_pairs)
    except EvidenceError:
        raise
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"malformed json: {exc}") from exc
    if not isinstance(obj, dict):
        raise EvidenceError("record is not a JSON object")
    return obj


class EvidenceStore:
    """Append-only, hash-chained evidence log for one session directory."""

    def __init__(self, session_dir: str | Path):
        self.session_dir = Path(session_dir)
        self.path = self.session_dir / EVIDENCE_FILENAME
        self.head_path = self.session_dir / HEAD_FILENAME

    # ── internal ────────────────────────────────────────────────────────────
    def _read_lines(self) -> list[str]:
        if not self.path.is_file():
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            return [ln for ln in f.read().splitlines() if ln.strip()]

    def _tail_state(self) -> tuple[str, int]:
        """Return (last digest, record count). Caller must hold the append lock.

        A corrupt or digest-less tail raises. It does not reset the chain to
        genesis — that would let a torn line start a fresh chain that verifies
        after the bad line is deleted.
        """
        lines = self._read_lines()
        if not lines:
            return GENESIS_HASH, 0
        try:
            rec = _parse_line(lines[-1])
        except EvidenceError as exc:
            raise EvidenceError(
                "evidence log tail is corrupt; refusing to append"
            ) from exc
        digest = rec.get("digest")
        if not isinstance(digest, str) or len(digest) != 64:
            raise EvidenceError("evidence log tail has no digest; refusing to append")
        return digest, len(lines)

    def _write_head(self, digest: str, count: int) -> None:
        payload = json.dumps(
            {"head_digest": digest, "count": count, "updated": _utc_now()},
            indent=2,
        ).encode("utf-8")
        tmp = self.head_path.with_suffix(".json.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        os.replace(tmp, self.head_path)

    # ── capture ─────────────────────────────────────────────────────────────
    def capture(
        self,
        *,
        kind: str,
        tool: str | None = None,
        target: str | None = None,
        url: str | None = None,
        method: str | None = None,
        scope: dict | None = None,
        timing: dict | None = None,
        status: str | None = None,
        observation: str | None = None,
        request: dict | None = None,
        response: dict | None = None,
        output_paths: list[str] | None = None,
        finding_id: str | None = None,
        parent_id: str | None = None,
        agent: str | None = None,
        session_id: str | None = None,
        step: int | None = None,
        extra: dict | None = None,
    ) -> dict:
        """Redact -> build record -> chain -> append. Returns the stored record.

        Everything that could carry a secret (observation, request, response,
        url, extra) is passed through the centralized redactor BEFORE the record
        is serialized, so no unredacted artifact is ever written to disk.
        """
        self.session_dir.mkdir(parents=True, exist_ok=True)

        record: dict[str, Any] = {
            "evidence_id": new_evidence_id(),
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "ts": _utc_now(),
            "kind": kind,
            "session_id": session_id,
            "step": step,
            "agent": agent,
            "tool": tool,
            "target": target,
            "url": redact_obj(url) if url is not None else None,
            "method": method,
            "scope": redact_obj(scope) if scope is not None else None,
            "timing": timing,
            "status": status,
            "finding_id": finding_id,
            "parent_id": parent_id,
            "observation": redact_obj(observation) if observation is not None else None,
            "request": redact_obj(request) if request is not None else None,
            "response": redact_obj(response) if response is not None else None,
            "output_paths": output_paths,
            "extra": redact_obj(extra) if extra is not None else None,
        }
        # Hash and append under one lock so two writers cannot share a prev_hash,
        # and the head anchor is written before the lock is released.
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                prev, count = self._tail_state()
                record["prev_hash"] = prev
                record["digest"] = _digest_of(record)
                data = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
                written = 0
                while written < len(data):
                    n = os.write(fd, data[written:])
                    if n <= 0:
                        raise EvidenceError("short write appending evidence record")
                    written += n
                self._write_head(record["digest"], count + 1)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return record

    def link_finding(self, evidence_id: str, finding_id: str,
                     note: str | None = None, session_id: str | None = None) -> dict:
        """Append a provenance link connecting an evidence record to a finding.

        Append-only: we never mutate the original record (that would break the
        chain). A `link` record records the association and is itself chained.
        Unknown evidence ids fail closed — a link cannot point at a record that
        was never captured.
        """
        known = {r.get("evidence_id") for r in self.read_all()}
        if evidence_id not in known:
            raise EvidenceError(f"unknown evidence_id: {evidence_id}")
        return self.capture(
            kind="link",
            finding_id=finding_id,
            parent_id=evidence_id,
            session_id=session_id,
            extra={"note": note} if note else None,
        )

    # ── read / verify ────────────────────────────────────────────────────────
    def read_all(self) -> list[dict]:
        records = []
        for ln in self._read_lines():
            records.append(_parse_line(ln))
        return records

    def verify_chain(self) -> dict:
        """Recompute the hash chain and report any tampering.

        Detects: field modification (digest mismatch), reordering / interior
        deletion (prev_hash linkage break), malformed lines, and tail truncation
        (head anchor mismatch). Returns a structured verdict.
        """
        errors: list[dict] = []
        lines = self._read_lines()
        prev = GENESIS_HASH
        last_digest = GENESIS_HASH
        n = 0

        for idx, ln in enumerate(lines):
            try:
                rec = _parse_line(ln)
            except EvidenceError as exc:
                errors.append({"index": idx, "error": "malformed_record", "detail": str(exc)})
                return {"ok": False, "count": n, "errors": errors, "head": last_digest}

            n += 1
            stored_digest = rec.get("digest")
            recomputed = _digest_of(rec)
            if stored_digest != recomputed:
                errors.append({
                    "index": idx,
                    "evidence_id": rec.get("evidence_id"),
                    "error": "digest_mismatch",
                })
            if rec.get("prev_hash") != prev:
                errors.append({
                    "index": idx,
                    "evidence_id": rec.get("evidence_id"),
                    "error": "prev_hash_mismatch",
                })
            prev = stored_digest or recomputed
            last_digest = prev

        # Tail-truncation check. A missing anchor is itself a failure when any
        # records exist — deleting the anchor must not hide a truncated tail.
        if n == 0 and not self.head_path.is_file():
            pass
        elif not self.head_path.is_file():
            errors.append({"error": "missing_head_anchor", "detail": f"{n} record(s) and no head anchor"})
        else:
            try:
                head = json.loads(self.head_path.read_text())
                if head.get("count") != n or head.get("head_digest") != last_digest:
                    errors.append({
                        "error": "head_anchor_mismatch",
                        "detail": f"anchor count={head.get('count')} digest={head.get('head_digest')} "
                                  f"vs actual count={n} digest={last_digest}",
                    })
            except (json.JSONDecodeError, OSError) as exc:
                errors.append({"error": "head_anchor_unreadable", "detail": str(exc)})

        return {"ok": not errors, "count": n, "errors": errors, "head": last_digest}

    # ── provenance ────────────────────────────────────────────────────────────
    def provenance_for(self, finding_id: str) -> list[dict]:
        """All records tied to a finding: those captured with the finding_id and
        those linked to it afterward (via link records)."""
        records = self.read_all()
        direct = [r for r in records if r.get("finding_id") == finding_id]
        linked_ids = {r.get("parent_id") for r in records
                      if r.get("kind") == "link" and r.get("finding_id") == finding_id}
        linked = [r for r in records if r.get("evidence_id") in linked_ids]
        # Preserve on-disk order, de-duplicate by evidence_id.
        seen = set()
        out = []
        for r in records:
            if r in direct or r in linked:
                eid = r.get("evidence_id")
                if eid not in seen:
                    seen.add(eid)
                    out.append(r)
        return out


def build_replay(record: dict) -> str:
    """Safe, human-readable replay representation for an evidence record.

    Uses ONLY the already-redacted record fields, so secrets that were redacted
    at capture cannot reappear here. Never emits an executable command with live
    credentials.
    """
    lines = [
        "# Replay (redacted — secrets removed, not runnable as-is if auth was required)",
        f"# evidence_id: {record.get('evidence_id')}",
        f"# tool: {record.get('tool')}   kind: {record.get('kind')}",
    ]
    scope = record.get("scope") or {}
    if scope:
        lines.append(f"# scope decision: {scope.get('decision')} "
                     f"(rule: {scope.get('matched_rule')})")
    url = record.get("url")
    method = str(record.get("method") or "GET")
    if not (method.isascii() and method.isalpha() and method.isupper() and 1 <= len(method) <= 10):
        method = "GET"
    req = record.get("request") or {}
    if url:
        cmd = [f"curl -X {method} {json.dumps(url)}"]
        for hk, hv in (req.get("headers") or {}).items():
            cmd.append(f"-H {json.dumps(f'{hk}: {hv}')}")
        body = req.get("body")
        if body:
            cmd.append(f"--data {json.dumps(body)}")
        lines.append(" \\\n  ".join(cmd))
    else:
        lines.append(f"# {method} {record.get('target')} via {record.get('tool')} "
                     f"(subprocess scanner — no raw HTTP request captured in-process)")
    return "\n".join(lines)


# Record fields that may carry captured content (and therefore secrets). Only
# these are redacted on export. Structural/ID fields (evidence_id, session_id,
# digest, prev_hash, ...) are left intact — redacting them would corrupt
# provenance and break the integrity digest.
_REDACTABLE_FIELDS = ("url", "scope", "observation", "request", "response", "extra")


def _export_safe(record: dict) -> tuple[dict, bool]:
    """Return an export-safe copy of a record and whether redaction changed it.

    For an untampered record the content fields were already redacted at
    capture, so this is a no-op (digest stays valid). If a secret was injected
    into the log after capture, it is redacted here so export never leaks it,
    and the change is reported (integrity will also flag the tampering).
    """
    out = dict(record)
    changed = False
    for field in _REDACTABLE_FIELDS:
        if out.get(field) is not None:
            red = redact_obj(out[field])
            if red != out[field]:
                changed = True
                out[field] = red
    return out, changed


def export_bundle(session_dir: str | Path, *, finding_id: str | None = None,
                  out_path: str | Path | None = None, strict: bool = False) -> dict:
    """Build a portable Evidence Bundle from a session directory.

    Contains: evidence records (export-safe), provenance for the finding,
    validation result if present, scope snapshots (embedded in records),
    integrity verification result + head digest. Writes JSON to `out_path` when
    given. The bundle uses ONLY redacted evidence — no hidden credentials.

    Integrity is verified against the RAW on-disk records first, so tampering is
    reported truthfully. Each record is then run through `_export_safe` so that
    even a record whose secret was injected after capture cannot leak through the
    export; such records are flagged in `export_redacted_post_capture`.
    """
    store = EvidenceStore(session_dir)
    integrity = store.verify_chain()
    errors: list[str] = []
    try:
        if finding_id:
            raw_records = store.provenance_for(finding_id)
        else:
            raw_records = store.read_all()
    except EvidenceError as exc:
        raw_records = []
        errors.append(str(exc))

    if finding_id and not raw_records:
        errors.append(f"no evidence linked to finding {finding_id}")

    records: list[dict] = []
    post_capture_flagged: list[str] = []
    for r in raw_records:
        safe, changed = _export_safe(r)
        records.append(safe)
        if changed:
            post_capture_flagged.append(r.get("evidence_id"))

    bundle: dict[str, Any] = {
        "bundle_schema_version": EVIDENCE_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "session_dir": str(session_dir),
        "finding_id": finding_id,
        "integrity": integrity,
        "provenance_ok": not errors,
        "errors": errors,
        "export_redacted_post_capture": post_capture_flagged,
        "evidence": records,
        "replays": [build_replay(r) for r in records
                    if r.get("kind") not in ("link",)],
    }

    # Attach validation only when its finding_id matches (or none was requested).
    # A nearby validation.json for a different finding is not this bundle.
    for cand in (Path(session_dir) / "validation.json",
                 Path(session_dir).parent / "validation.json"):
        if not cand.is_file():
            continue
        try:
            validation = redact_obj(json.loads(cand.read_text()))
        except (json.JSONDecodeError, OSError):
            errors.append(f"unreadable validation file: {cand.name}")
            bundle["errors"] = errors
            bundle["provenance_ok"] = False
            continue
        vid = validation.get("finding_id") if isinstance(validation, dict) else None
        if finding_id and vid not in (None, finding_id):
            errors.append(
                f"validation finding_id {vid!r} does not match requested {finding_id}"
            )
            bundle["errors"] = errors
            bundle["provenance_ok"] = False
            continue
        bundle["validation"] = validation
        break

    if strict and (errors or not integrity.get("ok")):
        raise EvidenceError("; ".join(errors) or "evidence integrity check failed")

    if out_path is not None:
        Path(out_path).write_text(json.dumps(bundle, indent=2))
    return bundle
