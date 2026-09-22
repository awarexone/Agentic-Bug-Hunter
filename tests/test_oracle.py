"""Tests for tools/oracle.py — the self-learning prioritizer.

The whole model/feature/eval layer is pure and tested here without touching the
network or the real hunt-memory. `bughunter/tools` is on sys.path via conftest.
"""

import json
import os

import pytest

import oracle as oc


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------


def test_norm_class_strips_hunt_prefix():
    assert oc.norm_class("hunt-idor") == "idor"
    assert oc.norm_class("IDOR") == "idor"
    assert oc.norm_class(None) == ""


def test_endpoint_tokens():
    toks = oc.endpoint_tokens("https://api.acme.com/v1/users/1?id=5&admin=1")
    assert "ep:has_params" in toks
    assert "ep:numeric_id" in toks
    assert "ep:kw_api" in toks
    assert "ep:kw_user" in toks
    assert any(t.startswith("ep:depth_") for t in toks)


def test_endpoint_tokens_empty():
    assert oc.endpoint_tokens("") == set()
    assert oc.endpoint_tokens(None) == set()


def test_tech_tokens_handles_list_and_string():
    assert oc._tech_tokens("nginx, PHP") == {"tech:nginx", "tech:php"}
    assert oc._tech_tokens(["Next.js", "node"]) == {"tech:next.js", "tech:node"}
    assert oc._tech_tokens(None) == set()


def test_features_from_lead_maps_skill_to_class():
    lead = {"skill": "hunt-idor", "evidence": "https://acme.com/api/order?id=3",
            "target": "acme.com"}
    feats = oc.features_from_lead(lead, {"acme.com": {"tech:nginx"}})
    assert "class:idor" in feats
    assert "ep:numeric_id" in feats
    assert "tech:nginx" in feats


def test_label_from_journal():
    assert oc.label_from_journal({"result": "confirmed"}) == 1
    assert oc.label_from_journal({"result": "rejected"}) == 0
    assert oc.label_from_journal({"result": "false_positive"}) == 0
    assert oc.label_from_journal({"result": "partial"}) is None  # ambiguous → excluded
    assert oc.label_from_journal({"result": "informational"}) is None


# ---------------------------------------------------------------------------
# The model learns a real signal
# ---------------------------------------------------------------------------


def _signal_samples(n=40):
    """idor+numeric_id => confirmed; xss without signal => rejected."""
    samples = []
    for i in range(n):
        if i % 2 == 0:
            samples.append(({"class:idor", "ep:numeric_id", "sev:high"}, 1))
        else:
            samples.append(({"class:xss", "ep:has_params", "sev:low"}, 0))
    return samples


def test_model_learns_positive_signal():
    m = oc.OracleModel().train(_signal_samples())
    good = m.score({"class:idor", "ep:numeric_id", "sev:high"})
    bad = m.score({"class:xss", "ep:has_params", "sev:low"})
    assert good > 0.7
    assert bad < 0.3
    assert good > bad


def test_scores_are_probabilities():
    m = oc.OracleModel().train(_signal_samples())
    for feats in ({"class:idor", "ep:numeric_id"}, {"class:xss"}, set(), {"unknown:feat"}):
        s = m.score(feats)
        assert 0.0 <= s <= 1.0


def test_explanation_points_at_the_learned_feature():
    m = oc.OracleModel().train(_signal_samples())
    top = m.explain({"class:idor", "ep:numeric_id", "sev:high"}, k=3)
    # the strongest positive contributor should be one of the idor-signal features
    best = max(top, key=lambda r: r["logodds"])
    assert best["feature"] in {"class:idor", "ep:numeric_id", "sev:high"}
    assert best["logodds"] > 0


def test_expected_value_uses_mean_payout():
    samples = [({"class:idor", "ep:numeric_id"}, 1)] * 10 + [({"class:xss"}, 0)] * 10
    payouts = [("idor", 500.0)] * 10
    m = oc.OracleModel().train(samples, payouts)
    ev = m.expected_value({"class:idor", "ep:numeric_id"})
    assert 0 < ev <= 500.0


def test_serialization_round_trip():
    m = oc.OracleModel().train(_signal_samples())
    m2 = oc.OracleModel.from_dict(json.loads(json.dumps(m.to_dict())))
    feats = {"class:idor", "ep:numeric_id", "sev:high"}
    assert abs(m.score(feats) - m2.score(feats)) < 1e-9


# ---------------------------------------------------------------------------
# Cold-start prior + blending
# ---------------------------------------------------------------------------


def test_prior_favors_high_value_class():
    assert oc.prior_score({"class:idor"}) > oc.prior_score({"class:misc"})
    assert oc.prior_score({"sev:critical"}) > oc.prior_score({"sev:low"})


def test_empty_model_falls_back_to_prior():
    m = oc.OracleModel()  # untrained
    assert m.confidence() == "prior"
    # with no learned data, score should equal the prior
    feats = {"class:idor", "ep:numeric_id"}
    assert abs(m.score(feats) - oc.prior_score(feats)) < 1e-9


def test_confidence_grows_with_data():
    assert oc.OracleModel().train(_signal_samples(4)).confidence() in ("prior", "blended")
    assert oc.OracleModel().train(_signal_samples(40)).confidence() in ("blended", "learned")
    assert oc.OracleModel().train(_signal_samples(60)).confidence() == "learned"


# ---------------------------------------------------------------------------
# Evaluation: Oracle must beat the baselines on a learnable signal
# ---------------------------------------------------------------------------


def test_loocv_oracle_beats_majority_on_signal():
    ev = oc.loocv(_signal_samples(40))
    assert ev["oracle"]["accuracy"] >= 0.9
    assert ev["oracle"]["accuracy"] >= ev["baseline_majority"]["accuracy"]


def test_loocv_needs_min_samples():
    assert "error" in oc.loocv([({"a"}, 1), ({"b"}, 0)])


# ---------------------------------------------------------------------------
# Data loading + training set
# ---------------------------------------------------------------------------


def _write_memory(tmp_path, journal_rows, pattern_rows=()):
    d = tmp_path / "hunt-memory"
    d.mkdir()
    with open(d / "journal.jsonl", "w", encoding="utf-8") as fh:
        for r in journal_rows:
            fh.write(json.dumps(r) + "\n")
    if pattern_rows:
        with open(d / "patterns.jsonl", "w", encoding="utf-8") as fh:
            for r in pattern_rows:
                fh.write(json.dumps(r) + "\n")
    return str(d)


def test_build_tech_index():
    patterns = [{"target": "acme.com", "tech_stack": "nginx, php"},
                {"target": "acme.com", "tech_stack": ["laravel"]}]
    idx = oc.build_tech_index(patterns)
    assert idx["acme.com"] == {"tech:nginx", "tech:php", "tech:laravel"}


def test_build_training_set_skips_ambiguous_and_featureless():
    journal = [
        {"vuln_class": "idor", "endpoint": "https://a/x?id=1", "result": "confirmed", "payout": 300},
        {"vuln_class": "xss", "endpoint": "https://a/y?q=1", "result": "rejected"},
        {"vuln_class": "ssrf", "endpoint": "https://a/z", "result": "partial"},  # ambiguous
    ]
    samples, payouts = oc.build_training_set(journal, {})
    assert len(samples) == 2
    assert ("idor", 300.0) in payouts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _big_journal(n=30):
    rows = []
    for i in range(n):
        if i % 2 == 0:
            rows.append({"vuln_class": "idor", "endpoint": "https://a/api/o?id=2",
                         "result": "confirmed", "severity": "high", "payout": 400,
                         "target": "a", "action": "hunt", "ts": "t", "schema_version": 2})
        else:
            rows.append({"vuln_class": "xss", "endpoint": "https://a/s?q=1",
                         "result": "rejected", "severity": "low",
                         "target": "a", "action": "hunt", "ts": "t", "schema_version": 2})
    return rows


def test_cli_train_saves_model(tmp_path):
    mem = _write_memory(tmp_path, _big_journal())
    rc = oc.main(["--memory-dir", mem, "train"])
    assert rc == 0
    model = json.loads((tmp_path / "hunt-memory" / "oracle_model.json").read_text(encoding="utf-8"))
    assert model["schema"] == "oracle-model/1"
    assert model["n_pos"] > 0 and model["n_neg"] > 0


def test_cli_train_no_data_is_graceful(tmp_path, capsys):
    mem = _write_memory(tmp_path, [])
    rc = oc.main(["--memory-dir", mem, "train"])
    assert rc == 0
    assert "cold-start" in capsys.readouterr().out


def test_cli_score_json(tmp_path, capsys):
    mem = _write_memory(tmp_path, _big_journal())
    oc.main(["--memory-dir", mem, "train"])
    capsys.readouterr()  # discard training output before capturing JSON
    rc = oc.main(["--memory-dir", mem, "score", "--class", "idor",
                  "--url", "https://a/api/o?id=9", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert 0.0 <= out["score"] <= 1.0
    assert out["confidence"] in ("prior", "blended", "learned")


def test_cli_rank_uses_lead_board(tmp_path, monkeypatch, capsys):
    mem = _write_memory(tmp_path, _big_journal())
    oc.main(["--memory-dir", mem, "train"])
    leads = [
        {"id": "lb-1", "skill": "hunt-idor", "evidence": "https://a/api/o?id=1",
         "target": "a", "status": "new"},
        {"id": "lb-2", "skill": "hunt-xss", "evidence": "https://a/s?q=x",
         "target": "a", "status": "new"},
    ]
    monkeypatch.setattr(oc.lead_board, "load_ledger", lambda t: leads)
    capsys.readouterr()  # discard training output before capturing JSON
    rc = oc.main(["--memory-dir", mem, "rank", "a", "--json"])
    assert rc == 0
    ranked = json.loads(capsys.readouterr().out)
    assert ranked[0]["skill"] == "hunt-idor"  # learned high-value lead ranks first
    assert ranked[0]["score"] >= ranked[1]["score"]
