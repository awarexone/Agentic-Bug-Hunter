#!/usr/bin/env python3
"""
bench.py — BugBench: measure the toolkit's detection quality.

Reputation in security tooling is trust, and trust is *measured* false positives
and reproducibility. This harness runs the toolkit's detectors against a
ground-truth corpus of known-vulnerable AND known-safe cases and reports
precision / recall / false-positive rate — so the project can make a claim few
AI security tools can: "here is our measured accuracy, reproduce it yourself."

Determinism is the whole point: a benchmark case carries a *recorded* input (the
exact response/data a detector would see), never a live URL. CI, and anyone, get
the identical score every time.

This file is being built step by step.
  STEP 1: the data contract — what a benchmark case is, plus load + validation.
  STEP 2: the metrics — precision / recall / false-positive rate from a
          confusion matrix. FP-rate is the headline: for a security tool, trust
          is "almost never cries wolf", and accuracy alone hides that under
          class imbalance.
  STEP 3: the runner — a detector registry where each detector registers a tiny
          adapter (recorded input -> DetectorResult). Adding a detector is a
          one-function change; the harness core never grows an if/elif tree.
  STEP 4: the scoreboard + `run` CLI + a CI gate (--min-precision / --max-fp-rate)
          so a change that regresses detection quality fails the build.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from dataclasses import dataclass, field

_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../bughunter
_TOOLS = os.path.join(_PKG, "tools")
for _p in (_PKG, _TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)
_CASES_DIR = os.path.join(_PKG, "bench", "cases")


class BenchError(Exception):
    """Raised when a benchmark case is malformed — a bad corpus must fail loud,
    never silently skew the score."""


@dataclass
class Case:
    """One ground-truth benchmark case.

    id        unique identifier, names the case in reports
    detector  which classifier judges this case (wired in a later step)
    input     recorded data the detector sees (kept opaque here; detector-specific)
    expected  ground truth: {"vulnerable": bool, "class": str?, "min_severity": str?}
    note      human-readable provenance / description
    """
    id: str
    detector: str
    expected: dict
    input: dict = field(default_factory=dict)
    note: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.expected.get("vulnerable"))


def _validate_raw(raw: dict, source: str) -> Case:
    """Turn one parsed JSON object into a validated Case, or raise BenchError."""
    if not isinstance(raw, dict):
        raise BenchError(f"{source}: case must be a JSON object")
    for key in ("id", "detector", "expected"):
        if key not in raw:
            raise BenchError(f"{source}: missing required field '{key}'")
    if not isinstance(raw["id"], str) or not raw["id"].strip():
        raise BenchError(f"{source}: 'id' must be a non-empty string")
    if not isinstance(raw["detector"], str) or not raw["detector"].strip():
        raise BenchError(f"{source}: 'detector' must be a non-empty string")
    expected = raw["expected"]
    if not isinstance(expected, dict) or "vulnerable" not in expected:
        raise BenchError(f"{source}: 'expected' must be an object with a 'vulnerable' field")
    if not isinstance(expected["vulnerable"], bool):
        raise BenchError(f"{source}: 'expected.vulnerable' must be true or false")
    inp = raw.get("input", {})
    if not isinstance(inp, dict):
        raise BenchError(f"{source}: 'input' must be an object")
    return Case(id=raw["id"].strip(), detector=raw["detector"].strip(),
                expected=expected, input=inp, note=raw.get("note", ""))


def load_cases(cases_dir: str | None = None) -> list[Case]:
    """Load and validate every *.json case under `cases_dir`. Raises BenchError
    on a malformed case or a duplicate id — a broken corpus must never quietly
    produce a wrong score."""
    cases_dir = cases_dir or _CASES_DIR
    cases: list[Case] = []
    seen: set[str] = set()
    for path in sorted(glob.glob(os.path.join(cases_dir, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            try:
                raw = json.load(fh)
            except ValueError as e:
                raise BenchError(f"{os.path.basename(path)}: invalid JSON — {e}") from e
        records = raw if isinstance(raw, list) else [raw]
        for rec in records:
            case = _validate_raw(rec, os.path.basename(path))
            if case.id in seen:
                raise BenchError(f"duplicate case id: {case.id!r}")
            seen.add(case.id)
            cases.append(case)
    return cases


# ---------------------------------------------------------------------------
# STEP 2 — metrics. Pure: a confusion matrix in, quality numbers out.
# ---------------------------------------------------------------------------


def _safe_div(a: int, b: int) -> float:
    """Divide, treating 0/0 as 0.0 — a metric with no applicable cases is not a
    failure, it's simply undefined; reporting 0 keeps the scoreboard readable."""
    return a / b if b else 0.0


@dataclass
class Metrics:
    """Detection quality from a confusion matrix. tp/fp/tn/fn are the raw counts;
    the rest are derived. Rounding happens only at display time (as_dict)."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        # of everything we flagged, how much was real
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        # of the real bugs present, how many we caught
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def fp_rate(self) -> float:
        # of the safe cases, how many we wrongly flagged — the trust metric
        return _safe_div(self.fp, self.fp + self.tn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return _safe_div(2 * p * r, p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        # included for completeness — but it is misleading under class imbalance
        # (all-safe corpus + a do-nothing detector still scores high), so the
        # scoreboard leads with precision / fp_rate, not this.
        return _safe_div(self.tp + self.tn, self.total)

    def as_dict(self) -> dict:
        return {
            "n": self.total, "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "fp_rate": round(self.fp_rate, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }

    def summary_line(self) -> str:
        return (f"precision {self.precision:.0%}  recall {self.recall:.0%}  "
                f"FP-rate {self.fp_rate:.0%}  F1 {self.f1:.2f}  (n={self.total})")


def score(pairs: list[tuple[bool, bool]]) -> Metrics:
    """Build a Metrics from (predicted_vulnerable, actually_vulnerable) pairs.

    Pure and decoupled from how predictions were produced — the runner (a later
    step) turns cases + detector output into these pairs, and this stays trivial
    to unit-test with synthetic data."""
    m = Metrics()
    for predicted, actual in pairs:
        if predicted and actual:
            m.tp += 1
        elif predicted and not actual:
            m.fp += 1
        elif not predicted and actual:
            m.fn += 1
        else:
            m.tn += 1
    return m


def score_cases(cases: list[Case], predictions: dict[str, bool]) -> Metrics:
    """Convenience: score a run given cases and a {case_id: predicted} map.
    A case with no prediction is treated as 'not flagged' (a miss on a vuln
    case, a correct silence on a safe one) — never dropped, so the denominator
    always reflects the full corpus."""
    return score([(bool(predictions.get(c.id, False)), c.is_vulnerable) for c in cases])


# ---------------------------------------------------------------------------
# STEP 3 — the runner. A registry of detector adapters; the harness stays
# generic (open for new detectors, closed for modification).
# ---------------------------------------------------------------------------


@dataclass
class DetectorResult:
    """What a detector concluded about one case. Reduced to `.vulnerable` at the
    metric boundary; `severity`/`detail` are kept for the human scoreboard."""
    vulnerable: bool
    severity: str | None = None
    detail: str = ""


# name -> callable(input: dict) -> DetectorResult
DETECTORS: dict[str, "callable"] = {}


def detector(name: str):
    """Register a detector adapter under `name` (matches Case.detector)."""
    def deco(fn):
        DETECTORS[name] = fn
        return fn
    return deco


@detector("cors")
def _detect_cors(inp: dict) -> DetectorResult:
    """Adapter for the CORS classifier. Feeds the case's recorded ACAO/ACAC to
    the real, pure cors_scanner.classify — no network. Lazy-imported so bench's
    core stays dependency-free."""
    from cors_scanner import classify, CorsTest  # lazy: keep core import-light
    test = CorsTest(origin=inp.get("sent_origin", ""), label="bench",
                    weakness="reflect-any")
    finding = classify(inp.get("url", ""), test, inp.get("acao"), inp.get("acac"))
    if finding is None:
        return DetectorResult(False, None, "no CORS finding")
    # A public wildcard (INFO) is a misconfig note, not a reportable bug —
    # counting it as a detection would manufacture false positives.
    is_vuln = finding.severity != "INFO"
    return DetectorResult(is_vuln, finding.severity, finding.title)


def run_case(case: Case) -> DetectorResult:
    """Run the case's registered detector on its recorded input."""
    fn = DETECTORS.get(case.detector)
    if fn is None:
        raise BenchError(f"no detector registered for {case.detector!r} "
                         f"(case {case.id!r}); registered: {sorted(DETECTORS)}")
    return fn(case.input)


def run_cases(cases: list[Case]) -> dict[str, DetectorResult]:
    """Run every case, returning {case_id: DetectorResult}."""
    return {c.id: run_case(c) for c in cases}


# ---------------------------------------------------------------------------
# STEP 4 — scoreboard + CI gate.
# ---------------------------------------------------------------------------


def evaluate(cases: list[Case]) -> dict:
    """Run every case and compute overall + per-detector metrics. Returns a
    plain dict so it serializes straight to JSON for CI."""
    results = run_cases(cases)
    preds = {cid: r.vulnerable for cid, r in results.items()}
    overall = score_cases(cases, preds)
    detectors = sorted({c.detector for c in cases})
    per = {det: score_cases([c for c in cases if c.detector == det], preds)
           for det in detectors}
    # Actionable failure rows: what did we get wrong, and how.
    failures = []
    for c in cases:
        pred = preds.get(c.id, False)
        if pred and not c.is_vulnerable:
            kind = "false_positive"   # cried wolf
        elif not pred and c.is_vulnerable:
            kind = "miss"             # missed a real bug
        else:
            continue
        failures.append({"id": c.id, "detector": c.detector, "kind": kind,
                         "detail": results[c.id].detail})
    return {"overall": overall, "per_detector": per,
            "failures": failures, "results": results, "predictions": preds}


def render_report(cases: list[Case]) -> str:
    """A Markdown scoreboard. Leads with precision / FP-rate (the trust metrics);
    accuracy is intentionally not the headline."""
    ev = evaluate(cases)
    o: Metrics = ev["overall"]
    lines = [
        "# BugBench — detection quality", "",
        f"**{o.precision:.0%} precision · {o.fp_rate:.0%} false-positive rate · "
        f"{o.recall:.0%} recall · F1 {o.f1:.2f}**  (n={o.total})", "",
        "| detector | cases | precision | recall | FP-rate | F1 |",
        "|---|---|---|---|---|---|",
    ]
    for det, m in ev["per_detector"].items():
        lines.append(f"| {det} | {m.total} | {m.precision:.0%} | {m.recall:.0%} "
                     f"| {m.fp_rate:.0%} | {m.f1:.2f} |")
    lines += ["", f"| **overall** | **{o.total}** | **{o.precision:.0%}** | "
              f"**{o.recall:.0%}** | **{o.fp_rate:.0%}** | **{o.f1:.2f}** |"]
    if ev["failures"]:
        lines += ["", "## Failures", "", "| case | detector | kind | detail |",
                  "|---|---|---|---|"]
        for f in ev["failures"]:
            lines.append(f"| {f['id']} | {f['detector']} | {f['kind']} | {f['detail']} |")
    else:
        lines += ["", "_No false positives, no misses on the current corpus._"]
    return "\n".join(lines) + "\n"


def gate(overall: Metrics, min_precision: float | None,
         max_fp_rate: float | None) -> list[str]:
    """Return a list of threshold violations (empty = passed). Kept pure so the
    CI decision is testable without spawning a process."""
    violations = []
    if min_precision is not None and overall.precision < min_precision:
        violations.append(f"precision {overall.precision:.2%} < required {min_precision:.2%}")
    if max_fp_rate is not None and overall.fp_rate > max_fp_rate:
        violations.append(f"FP-rate {overall.fp_rate:.2%} > allowed {max_fp_rate:.2%}")
    return violations


def main(argv=None) -> int:
    for _stream in (sys.stdout, sys.stderr):  # non-ASCII marks must not crash a cp1252 console
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description="BugBench — detection-quality benchmark.")
    ap.add_argument("--cases-dir", default=_CASES_DIR, help="corpus directory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list loaded benchmark cases")

    prun = sub.add_parser("run", help="run detectors over the corpus and score them")
    prun.add_argument("--json", dest="as_json", action="store_true")
    prun.add_argument("--report", help="write the Markdown scoreboard to this path")
    prun.add_argument("--min-precision", type=float,
                      help="CI gate: fail (exit 1) if precision falls below this")
    prun.add_argument("--max-fp-rate", type=float,
                      help="CI gate: fail (exit 1) if false-positive rate exceeds this")

    args = ap.parse_args(argv)

    try:
        cases = load_cases(args.cases_dir)
    except BenchError as e:
        print(f"[!] corpus error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "list":
        vuln = sum(1 for c in cases if c.is_vulnerable)
        print(f"{len(cases)} case(s): {vuln} vulnerable, {len(cases) - vuln} safe")
        for c in cases:
            tag = "VULN" if c.is_vulnerable else "safe"
            print(f"  [{tag:>4}] {c.id:<32} detector={c.detector}")
        return 0

    if args.cmd == "run":
        try:
            ev = evaluate(cases)
        except BenchError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 2
        overall: Metrics = ev["overall"]
        report = render_report(cases)
        if args.report:
            with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(report)
        if args.as_json:
            print(json.dumps({"overall": overall.as_dict(),
                              "per_detector": {d: m.as_dict() for d, m in ev["per_detector"].items()},
                              "failures": ev["failures"]}, indent=2))
        else:
            print(report)
        violations = gate(overall, args.min_precision, args.max_fp_rate)
        if violations:
            for v in violations:
                print(f"[✗] BugBench gate failed: {v}", file=sys.stderr)
            return 1
        if args.min_precision is not None or args.max_fp_rate is not None:
            print("[✓] BugBench gate passed.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
