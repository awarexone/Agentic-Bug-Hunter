"""Tests for tools/bench.py — BugBench detection-quality harness.

STEP 1 scope: the data contract — loading + strict validation of benchmark
cases. (Detector running and metrics are added in later steps, with their own
tests.) `bughunter/tools` is on sys.path via conftest.
"""

import json

import pytest

import bench


def _write_case(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _valid_case(**over):
    base = {"id": "c1", "detector": "cors",
            "expected": {"vulnerable": True}, "input": {}}
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_loads_the_shipped_corpus():
    """The corpus that ships with the repo must always be valid — a broken
    case file would poison every score."""
    cases = bench.load_cases()
    assert len(cases) >= 2
    assert any(c.is_vulnerable for c in cases)
    assert any(not c.is_vulnerable for c in cases)  # safe cases exist (for FP measurement)


def test_loads_valid_cases_from_dir(tmp_path):
    _write_case(tmp_path, "a.json", _valid_case(id="a"))
    _write_case(tmp_path, "b.json", _valid_case(id="b", expected={"vulnerable": False}))
    cases = bench.load_cases(str(tmp_path))
    assert {c.id for c in cases} == {"a", "b"}
    assert cases[0].is_vulnerable is True


def test_a_file_may_hold_a_list_of_cases(tmp_path):
    _write_case(tmp_path, "many.json",
                [_valid_case(id="x"), _valid_case(id="y", expected={"vulnerable": False})])
    assert len(bench.load_cases(str(tmp_path))) == 2


# ---------------------------------------------------------------------------
# Validation — a bad corpus must fail loud, never skew the score silently
# ---------------------------------------------------------------------------


def test_missing_required_field_raises(tmp_path):
    _write_case(tmp_path, "bad.json", {"detector": "cors", "expected": {"vulnerable": True}})
    with pytest.raises(bench.BenchError, match="missing required field 'id'"):
        bench.load_cases(str(tmp_path))


def test_expected_must_have_bool_vulnerable(tmp_path):
    _write_case(tmp_path, "bad.json", _valid_case(expected={"vulnerable": "yes"}))
    with pytest.raises(bench.BenchError, match="vulnerable"):
        bench.load_cases(str(tmp_path))


def test_duplicate_ids_raise(tmp_path):
    _write_case(tmp_path, "a.json", _valid_case(id="dup"))
    _write_case(tmp_path, "b.json", _valid_case(id="dup"))
    with pytest.raises(bench.BenchError, match="duplicate case id"):
        bench.load_cases(str(tmp_path))


def test_invalid_json_raises(tmp_path):
    (tmp_path / "broken.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(bench.BenchError, match="invalid JSON"):
        bench.load_cases(str(tmp_path))


def test_input_must_be_object(tmp_path):
    _write_case(tmp_path, "bad.json", _valid_case(input=["not", "an", "object"]))
    with pytest.raises(bench.BenchError, match="'input' must be an object"):
        bench.load_cases(str(tmp_path))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_list(capsys):
    rc = bench.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "vulnerable" in out
    assert "cors-reflect-credentialed" in out


# ---------------------------------------------------------------------------
# STEP 2 — metrics
# ---------------------------------------------------------------------------


def test_confusion_matrix_counts():
    # (predicted, actual): TP, FP, FN, TN
    m = bench.score([(True, True), (True, False), (False, True), (False, False)])
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 1)
    assert m.total == 4


def test_perfect_detector():
    m = bench.score([(True, True), (True, True), (False, False)])
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.fp_rate == 0.0
    assert m.f1 == 1.0


def test_false_positives_drive_precision_and_fp_rate():
    # 1 real bug caught, but 3 safe cases wrongly flagged
    m = bench.score([(True, True), (True, False), (True, False), (True, False)])
    assert m.precision == 0.25          # 1 of 4 flags was real
    assert m.fp_rate == 1.0             # every safe case was flagged — max noise
    assert m.recall == 1.0             # it did catch the one real bug


def test_accuracy_is_misleading_under_imbalance():
    """The core lesson: a do-nothing detector on a mostly-safe corpus scores
    high accuracy while catching zero bugs — which is why the scoreboard leads
    with precision / fp_rate, not accuracy."""
    pairs = [(False, False)] * 19 + [(False, True)]  # 19 safe, 1 missed bug
    m = bench.score(pairs)
    assert m.accuracy == 0.95   # looks great...
    assert m.recall == 0.0      # ...but it caught nothing
    assert m.fp_rate == 0.0


def test_empty_does_not_crash():
    m = bench.score([])
    assert m.total == 0
    assert m.precision == 0.0 and m.recall == 0.0 and m.fp_rate == 0.0


def test_score_cases_missing_prediction_counts_as_not_flagged():
    cases = [
        bench.Case(id="v", detector="d", expected={"vulnerable": True}),   # a real bug
        bench.Case(id="s", detector="d", expected={"vulnerable": False}),  # safe
    ]
    # no prediction for either → vuln case becomes a miss (FN), safe stays TN
    m = bench.score_cases(cases, {})
    assert (m.fn, m.tn, m.tp, m.fp) == (1, 1, 0, 0)
    # now flag only the real bug → perfect
    m2 = bench.score_cases(cases, {"v": True})
    assert m2.precision == 1.0 and m2.recall == 1.0 and m2.fp_rate == 0.0


def test_as_dict_and_summary_line():
    m = bench.score([(True, True), (True, False)])
    d = m.as_dict()
    assert d["tp"] == 1 and d["fp"] == 1 and d["precision"] == 0.5
    assert "FP-rate" in m.summary_line()


# ---------------------------------------------------------------------------
# STEP 3 — the runner (real cors classifier, offline)
# ---------------------------------------------------------------------------


def test_cors_adapter_flags_credentialed_reflection():
    inp = {"url": "https://api.x/me", "sent_origin": "https://evil.example",
           "acao": "https://evil.example", "acac": "true"}
    res = bench._detect_cors(inp)
    assert res.vulnerable is True
    assert res.severity == "CRITICAL"


def test_cors_adapter_clears_fixed_allowlist():
    inp = {"url": "https://api.x/me", "sent_origin": "https://evil.example",
           "acao": "https://app.x", "acac": "true"}
    res = bench._detect_cors(inp)
    assert res.vulnerable is False


def test_cors_adapter_public_wildcard_is_not_a_bug():
    """INFO-level public wildcard must NOT count as a detection (else it's a
    manufactured false positive)."""
    inp = {"url": "https://api.x/data", "sent_origin": "https://evil.example",
           "acao": "*", "acac": "false"}
    res = bench._detect_cors(inp)
    assert res.vulnerable is False
    assert res.severity == "INFO"


def test_run_case_uses_registered_detector():
    case = bench.Case(id="c", detector="cors", expected={"vulnerable": True},
                      input={"url": "https://x/me", "sent_origin": "https://evil.example",
                             "acao": "https://evil.example", "acac": "true"})
    assert bench.run_case(case).vulnerable is True


def test_unknown_detector_raises():
    case = bench.Case(id="c", detector="nope", expected={"vulnerable": True})
    with pytest.raises(bench.BenchError, match="no detector registered"):
        bench.run_case(case)


def test_run_the_shipped_corpus_end_to_end():
    """Run every real detector on the shipped cases and score it — the two cors
    cases should come out perfect (1 caught, 0 false alarms)."""
    cases = bench.load_cases()
    results = bench.run_cases(cases)
    predictions = {cid: r.vulnerable for cid, r in results.items()}
    m = bench.score_cases(cases, predictions)
    assert m.fp == 0          # never cries wolf on the safe case
    assert m.fn == 0          # catches the real bug
    assert m.precision == 1.0


# ---------------------------------------------------------------------------
# STEP 4 — scoreboard + gate
# ---------------------------------------------------------------------------


def test_evaluate_overall_and_per_detector():
    ev = bench.evaluate(bench.load_cases())
    assert ev["overall"].precision == 1.0
    assert "cors" in ev["per_detector"]
    assert ev["failures"] == []


def test_render_report_is_markdown_with_headline():
    md = bench.render_report(bench.load_cases())
    assert "detection quality" in md
    assert "FP-rate" in md or "false-positive" in md
    assert "| cors |" in md
    assert "No false positives" in md


def test_gate_passes_and_fails():
    good = bench.Metrics(tp=5, fp=0, tn=5, fn=0)  # precision 1.0, fp_rate 0
    bad = bench.Metrics(tp=1, fp=4, tn=1, fn=0)   # precision .2, fp_rate .8
    assert bench.gate(good, min_precision=0.9, max_fp_rate=0.0) == []
    viol = bench.gate(bad, min_precision=0.9, max_fp_rate=0.0)
    assert len(viol) == 2  # both thresholds violated


def _register_dummy():
    @bench.detector("dummy_always_flags")
    def _d(inp):
        return bench.DetectorResult(True, "HIGH", "always flags")


def test_cli_run_gate_blocks_a_false_positive(tmp_path, capsys):
    """A detector that flags a SAFE case must fail the --max-fp-rate 0 gate —
    this is the CI mechanism that blocks quality regressions."""
    _register_dummy()
    (tmp_path / "safe.json").write_text(json.dumps({
        "id": "dummy-safe", "detector": "dummy_always_flags",
        "expected": {"vulnerable": False}, "input": {}}), encoding="utf-8")
    rc = bench.main(["--cases-dir", str(tmp_path), "run", "--max-fp-rate", "0.0"])
    assert rc == 1
    assert "gate failed" in capsys.readouterr().err


def test_cli_run_shipped_corpus_passes_strict_gate(capsys):
    rc = bench.main(["run", "--min-precision", "1.0", "--max-fp-rate", "0.0"])
    assert rc == 0
    assert "gate passed" in capsys.readouterr().out


def test_cli_run_writes_report_file(tmp_path):
    out = tmp_path / "score.md"
    rc = bench.main(["run", "--report", str(out)])
    assert rc == 0
    assert "detection quality" in out.read_text(encoding="utf-8")
