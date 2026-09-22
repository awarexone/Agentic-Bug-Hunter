#!/usr/bin/env python3
"""
oracle.py — a self-learning lead & finding prioritizer.

The problem: the hunt-memory flywheel records every finding's *outcome*
(confirmed / rejected / false_positive, payout, severity, vuln_class, tech
stack, endpoint) in journal.jsonl — but nothing learns from it. The lead board
still ranks purely by hardcoded regex priority (high/med/low). So the single
richest asset a hunter builds up — their own track record of what actually pays
on which surfaces — never feeds back into deciding what to hunt next
(docs/TODOS.md TODO-6: the memory→hunt loop "never spins up in practice").

Oracle closes that loop. It trains on the hunter's own journal and scores any
lead by P(this turns into a real, valuable finding), replacing the static
regex rank with one that gets sharper every hunt.

Why Naive Bayes and not a heavy ML stack:
  Bug-bounty history is *small* (tens–hundreds of labelled findings). A big
  model overfits that and would drag in a dependency this repo deliberately
  avoids. A smoothed Naive-Bayes log-odds model is the right tool for the data
  regime: it works with little data, produces calibrated-ish probabilities,
  is fully explainable (per-feature log-odds you can read off), pure-stdlib,
  and deterministic. A cold-start PRIOR (mirroring the current high-value skill
  intuition) is blended in and decays as real evidence accumulates, so Oracle
  is useful on day one and data-driven by day thirty.

Commands:
  oracle.py train  [--memory-dir DIR] [--out model.json]   learn from journal, save + report
  oracle.py eval   [--memory-dir DIR]                       leave-one-out CV vs baselines
  oracle.py rank   <target> [--model model.json]            score & rank that target's leads
  oracle.py score  --class idor [--url U] [--tech nginx]    score one hypothetical lead

Everything except file/lead I/O is pure and unit-tested.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../bughunter
_TOOLS = os.path.join(_PKG, "tools")
for _p in (_PKG, _TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import lead_board  # noqa: E402  (reuse load_ledger + high-value skills)

# Outcome → label. Ambiguous results are left out of training entirely.
POSITIVE_RESULTS = {"confirmed"}
NEGATIVE_RESULTS = {"rejected", "false_positive"}

# When history is thin, blend the learned model with a heuristic prior. The
# learned weight is n/(n+SHRINKAGE_K): ~0 with no data, ~0.8 at 80 samples.
SHRINKAGE_K = 20
MIN_TRAIN = 6  # below this, output is prior-dominated and flagged as such

# Endpoint keywords worth a categorical feature (high-signal path/param hints).
_EP_KEYWORDS = ("admin", "api", "graphql", "upload", "login", "oauth", "sso",
                "user", "account", "internal", "debug", "token", "file",
                "redirect", "password", "reset", "payment", "invoice")

# Vuln classes that historically pay well — the cold-start prior leans on these
# (normalized, i.e. lead_board's "hunt-idor" -> "idor").
_HIGH_VALUE_CLASSES = {re.sub(r"^hunt-", "", s) for s in lead_board.HIGH_VALUE}
_SEV_PRIOR = {"critical": 0.22, "high": 0.15, "medium": 0.05, "low": -0.05,
              "informational": -0.15, "none": -0.15}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Feature engineering (pure)
# ---------------------------------------------------------------------------


def norm_class(value: str | None) -> str:
    return re.sub(r"^hunt-", "", (value or "").strip().lower())


def _tech_tokens(tech) -> set[str]:
    if not tech:
        return set()
    if isinstance(tech, (list, tuple, set)):
        parts = tech
    else:
        parts = re.split(r"[,\s/|;]+", str(tech))
    return {f"tech:{re.sub(r'[^a-z0-9.]+', '', p.lower())}"
            for p in parts if p and p.strip()} - {"tech:"}


def endpoint_tokens(url: str | None) -> set[str]:
    """Categorical features describing an endpoint's shape."""
    toks: set[str] = set()
    if not url:
        return toks
    p = urlparse(url if "://" in url else "//" + url)
    query = p.query.lower()
    if query:
        toks.add("ep:has_params")
        if re.search(r"=\d+(?:&|$)", query):
            toks.add("ep:numeric_id")
    path = (p.path or "").lower()
    depth = len([s for s in path.split("/") if s])
    toks.add(f"ep:depth_{min(depth, 4)}")
    # Host matters too: api./admin./internal. subdomains are strong signals.
    hay = (p.netloc or "").lower() + " " + path + " " + query
    for kw in _EP_KEYWORDS:
        if kw in hay:
            toks.add(f"ep:kw_{kw}")
    return toks


def _tag_tokens(tags) -> set[str]:
    if not tags:
        return set()
    if isinstance(tags, str):
        tags = re.split(r"[,\s]+", tags)
    return {f"tag:{re.sub(r'[^a-z0-9]+', '', t.lower())}" for t in tags if t} - {"tag:"}


def features_from_journal(entry: dict, tech_index: dict[str, set[str]]) -> set[str]:
    f: set[str] = set()
    cls = norm_class(entry.get("vuln_class"))
    if cls:
        f.add(f"class:{cls}")
    sev = (entry.get("severity") or "").lower()
    if sev:
        f.add(f"sev:{sev}")
    f |= endpoint_tokens(entry.get("endpoint"))
    f |= _tag_tokens(entry.get("tags"))
    f |= _tech_tokens(entry.get("tech_stack"))
    f |= tech_index.get(entry.get("target", ""), set())
    return f


def features_from_lead(lead: dict, tech_index: dict[str, set[str]]) -> set[str]:
    """Same feature space as journal, derived from a lead_board lead."""
    f: set[str] = set()
    cls = norm_class(lead.get("skill"))
    if cls:
        f.add(f"class:{cls}")
    f |= endpoint_tokens(lead.get("evidence"))
    f |= tech_index.get(lead.get("target", ""), set())
    return f


def label_from_journal(entry: dict) -> int | None:
    r = (entry.get("result") or "").lower()
    if r in POSITIVE_RESULTS:
        return 1
    if r in NEGATIVE_RESULTS:
        return 0
    return None


# ---------------------------------------------------------------------------
# The model (pure) — smoothed Naive-Bayes log-odds + heuristic prior blend.
# ---------------------------------------------------------------------------


def _payout_num(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    m = re.search(r"[\d,]+(?:\.\d+)?", str(value))
    return float(m.group(0).replace(",", "")) if m else 0.0


def prior_score(features: set[str]) -> float:
    """Heuristic cold-start probability from class/severity/endpoint shape —
    the same intuition the regex prioritizer encodes, expressed as a probability
    so it can be blended with the learned model."""
    z = 0.0
    for f in features:
        if f.startswith("class:") and f[6:] in _HIGH_VALUE_CLASSES:
            z += 0.6
        elif f.startswith("sev:"):
            z += _SEV_PRIOR.get(f[4:], 0.0) * 4
        elif f in ("ep:numeric_id", "ep:kw_admin", "ep:kw_graphql",
                   "ep:kw_upload", "ep:kw_oauth", "ep:kw_internal"):
            z += 0.25
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class OracleModel:
    alpha: float = 1.0
    n_pos: int = 0
    n_neg: int = 0
    feat_pos: dict[str, int] = field(default_factory=dict)
    feat_neg: dict[str, int] = field(default_factory=dict)
    mean_payout: dict[str, float] = field(default_factory=dict)  # class -> mean payout (positives)
    trained_at: str = ""

    @property
    def n(self) -> int:
        return self.n_pos + self.n_neg

    def train(self, samples: list[tuple[set[str], int]],
              payouts: list[tuple[str, float]] | None = None) -> "OracleModel":
        for feats, label in samples:
            if label == 1:
                self.n_pos += 1
                dst = self.feat_pos
            else:
                self.n_neg += 1
                dst = self.feat_neg
            for f in feats:
                dst[f] = dst.get(f, 0) + 1
        if payouts:
            acc: dict[str, list[float]] = {}
            for cls, amt in payouts:
                acc.setdefault(cls, []).append(amt)
            self.mean_payout = {c: sum(v) / len(v) for c, v in acc.items() if v}
        self.trained_at = now_iso()
        return self

    def _prior_logodds(self) -> float:
        return math.log((self.n_pos + self.alpha) / (self.n_neg + self.alpha))

    def contributions(self, features: set[str]) -> dict[str, float]:
        """Per-feature log-odds contribution — the model's explanation."""
        out = {}
        for f in features:
            p1 = (self.feat_pos.get(f, 0) + self.alpha) / (self.n_pos + 2 * self.alpha)
            p0 = (self.feat_neg.get(f, 0) + self.alpha) / (self.n_neg + 2 * self.alpha)
            out[f] = math.log(p1 / p0)
        return out

    def _learned_score(self, features: set[str]) -> float:
        z = self._prior_logodds() + sum(self.contributions(features).values())
        z = max(-30.0, min(30.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def score(self, features: set[str]) -> float:
        """Blend the learned score with the cold-start prior by evidence weight."""
        learned = self._learned_score(features)
        w = self.n / (self.n + SHRINKAGE_K)  # 0 with no data → ~1 with lots
        return w * learned + (1 - w) * prior_score(features)

    def confidence(self) -> str:
        if self.n >= MIN_TRAIN * 5:
            return "learned"
        if self.n >= MIN_TRAIN:
            return "blended"
        return "prior"

    def explain(self, features: set[str], k: int = 5) -> list[dict]:
        contribs = self.contributions(features)
        rows = sorted(contribs.items(), key=lambda kv: abs(kv[1]), reverse=True)[:k]
        return [{"feature": f, "logodds": round(c, 3),
                 "pos": self.feat_pos.get(f, 0), "neg": self.feat_neg.get(f, 0)}
                for f, c in rows]

    def expected_value(self, features: set[str]) -> float:
        cls = next((f[6:] for f in features if f.startswith("class:")), "")
        return self.score(features) * self.mean_payout.get(cls, 0.0)

    def to_dict(self) -> dict:
        return {"schema": "oracle-model/1", "alpha": self.alpha,
                "n_pos": self.n_pos, "n_neg": self.n_neg,
                "feat_pos": self.feat_pos, "feat_neg": self.feat_neg,
                "mean_payout": self.mean_payout, "trained_at": self.trained_at}

    @classmethod
    def from_dict(cls, d: dict) -> "OracleModel":
        m = cls(alpha=d.get("alpha", 1.0))
        m.n_pos, m.n_neg = d.get("n_pos", 0), d.get("n_neg", 0)
        m.feat_pos = dict(d.get("feat_pos", {}))
        m.feat_neg = dict(d.get("feat_neg", {}))
        m.mean_payout = dict(d.get("mean_payout", {}))
        m.trained_at = d.get("trained_at", "")
        return m


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def _read_jsonl(path: str) -> list[dict]:
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except ValueError:
                    pass
    return out


def build_tech_index(patterns: list[dict]) -> dict[str, set[str]]:
    idx: dict[str, set[str]] = {}
    for p in patterns:
        tgt = p.get("target")
        if tgt:
            idx.setdefault(tgt, set()).update(_tech_tokens(p.get("tech_stack")))
    return idx


def build_training_set(journal: list[dict], tech_index: dict[str, set[str]]
                       ) -> tuple[list[tuple[set[str], int]], list[tuple[str, float]]]:
    samples, payouts = [], []
    for e in journal:
        label = label_from_journal(e)
        if label is None:
            continue
        feats = features_from_journal(e, tech_index)
        if not feats:
            continue
        samples.append((feats, label))
        if label == 1:
            payouts.append((norm_class(e.get("vuln_class")), _payout_num(e.get("payout"))))
    return samples, payouts


def load_memory(memory_dir: str) -> tuple[list[dict], list[dict]]:
    journal = _read_jsonl(os.path.join(memory_dir, "journal.jsonl"))
    patterns = _read_jsonl(os.path.join(memory_dir, "patterns.jsonl"))
    return journal, patterns


# ---------------------------------------------------------------------------
# Evaluation (pure) — honest metrics + baselines to prove Oracle earns its keep.
# ---------------------------------------------------------------------------


def _metrics(pairs: list[tuple[int, int]]) -> dict:
    """pairs = list of (predicted, actual) in {0,1}."""
    tp = sum(1 for p, a in pairs if p == 1 and a == 1)
    fp = sum(1 for p, a in pairs if p == 1 and a == 0)
    tn = sum(1 for p, a in pairs if p == 0 and a == 0)
    fn = sum(1 for p, a in pairs if p == 0 and a == 1)
    n = len(pairs) or 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"n": len(pairs), "accuracy": round((tp + tn) / n, 3),
            "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3), "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def loocv(samples: list[tuple[set[str], int]], threshold: float = 0.5) -> dict:
    """Leave-one-out cross-validation — the honest way to score a small model.
    Also reports two baselines: majority class, and the heuristic prior alone."""
    if len(samples) < 3:
        return {"error": "need >=3 labelled samples", "n": len(samples)}
    model_pairs, prior_pairs = [], []
    n_pos = sum(1 for _, y in samples if y == 1)
    majority = 1 if n_pos * 2 >= len(samples) else 0
    for i in range(len(samples)):
        train = samples[:i] + samples[i + 1:]
        feats, actual = samples[i]
        m = OracleModel().train(train)
        model_pairs.append((1 if m._learned_score(feats) >= threshold else 0, actual))
        prior_pairs.append((1 if prior_score(feats) >= threshold else 0, actual))
    majority_pairs = [(majority, a) for _, a in samples]
    return {
        "oracle": _metrics(model_pairs),
        "baseline_prior": _metrics(prior_pairs),
        "baseline_majority": _metrics(majority_pairs),
        "positives": n_pos, "negatives": len(samples) - n_pos,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def default_memory_dir() -> str:
    return os.environ.get("BBHUNT_MEMORY_DIR", "hunt-memory")


def _fit(memory_dir: str) -> tuple[OracleModel, list, dict]:
    journal, patterns = load_memory(memory_dir)
    tech_index = build_tech_index(patterns)
    samples, payouts = build_training_set(journal, tech_index)
    model = OracleModel().train(samples, payouts)
    return model, samples, tech_index


def cmd_train(args) -> int:
    model, samples, _ = _fit(args.memory_dir)
    out = args.out or os.path.join(args.memory_dir, "oracle_model.json")
    if not samples:
        print(f"[!] no labelled findings in {args.memory_dir}/journal.jsonl "
              "(need results of 'confirmed' / 'rejected' / 'false_positive').")
        print("[*] Oracle will run on its cold-start prior until you log outcomes.")
    os.makedirs(args.memory_dir, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(model.to_dict(), fh, indent=2)
    print(f"[+] trained on {model.n} labelled findings "
          f"({model.n_pos} confirmed / {model.n_neg} rejected) — confidence: {model.confidence()}")
    print(f"[+] model saved: {out}")
    ev = loocv(samples)
    if "error" not in ev:
        _print_eval(ev)
    return 0


def _print_eval(ev: dict) -> None:
    o, p, mj = ev["oracle"], ev["baseline_prior"], ev["baseline_majority"]
    print(f"\n  leave-one-out CV ({ev['positives']} confirmed / {ev['negatives']} rejected):")
    print(f"    {'model':<18}{'acc':>6}{'prec':>7}{'rec':>7}{'f1':>7}")
    print(f"    {'Oracle (learned)':<18}{o['accuracy']:>6}{o['precision']:>7}{o['recall']:>7}{o['f1']:>7}")
    print(f"    {'prior heuristic':<18}{p['accuracy']:>6}{p['precision']:>7}{p['recall']:>7}{p['f1']:>7}")
    print(f"    {'majority class':<18}{mj['accuracy']:>6}{'—':>7}{'—':>7}{'—':>7}")
    lift = round(o["accuracy"] - p["accuracy"], 3)
    print(f"  → Oracle vs prior heuristic: {'+' if lift >= 0 else ''}{lift} accuracy")


def cmd_eval(args) -> int:
    _, samples, _ = _fit(args.memory_dir)
    ev = loocv(samples)
    if "error" in ev:
        print(f"[!] {ev['error']} (have {ev['n']}). Log more outcomes with /remember.")
        return 0
    _print_eval(ev)
    return 0


def _load_model(args) -> OracleModel:
    path = getattr(args, "model", None) or os.path.join(args.memory_dir, "oracle_model.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            return OracleModel.from_dict(json.load(fh))
    # fall back to training on the fly
    return _fit(args.memory_dir)[0]


def cmd_rank(args) -> int:
    model = _load_model(args)
    _, patterns = load_memory(args.memory_dir)
    tech_index = build_tech_index(patterns)
    leads = [l for l in lead_board.load_ledger(args.target) if l.get("status") == "new"]
    if not leads:
        print(f"[!] no untouched leads for {args.target}. Run lead_board.py ingest first.")
        return 0
    scored = []
    for l in leads:
        feats = features_from_lead(l, tech_index)
        scored.append((model.score(feats), model.expected_value(feats), l, feats))
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)

    if args.as_json:
        print(json.dumps([{"score": round(s, 3), "ev": round(ev, 1),
                           "id": l.get("id"), "skill": l.get("skill"),
                           "evidence": l.get("evidence"),
                           "explain": model.explain(f)} for s, ev, l, f in scored], indent=2))
        return 0

    print(f"\n=== ORACLE RANK: {args.target} — {len(scored)} leads "
          f"(model confidence: {model.confidence()}) ===")
    for s, ev, l, feats in scored[:args.top]:
        evs = f"  ~${ev:,.0f}" if ev else ""
        print(f"  {s*100:5.1f}%{evs}  {l.get('skill',''):<18} {str(l.get('evidence',''))[:56]}")
        top = model.explain(feats, k=3)
        if top and model.confidence() != "prior":
            why = ", ".join(f"{r['feature']}({'+' if r['logodds']>=0 else ''}{r['logodds']})"
                            for r in top)
            print(f"         why: {why}")
    return 0


def cmd_score(args) -> int:
    model = _load_model(args)
    feats = {f"class:{norm_class(args.vuln_class)}"} if args.vuln_class else set()
    feats |= endpoint_tokens(args.url)
    for t in (args.tech or []):
        feats |= _tech_tokens(t)
    if args.severity:
        feats.add(f"sev:{args.severity.lower()}")
    score = model.score(feats)
    result = {"score": round(score, 4), "confidence": model.confidence(),
              "expected_value": round(model.expected_value(feats), 2),
              "features": sorted(feats), "explain": model.explain(feats)}
    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"P(worth pursuing) = {score*100:.1f}%   ({model.confidence()})")
        if result["expected_value"]:
            print(f"expected value    = ~${result['expected_value']:,.0f}")
        for r in result["explain"]:
            print(f"  {r['feature']:<22} {'+' if r['logodds']>=0 else ''}{r['logodds']:>6}"
                  f"   (seen {r['pos']}✓ / {r['neg']}✗)")
    return 0


def main(argv=None) -> int:
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description="Oracle — self-learning lead/finding prioritizer.")
    ap.add_argument("--memory-dir", default=default_memory_dir(),
                    help="hunt-memory dir with journal.jsonl / patterns.jsonl")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("train", help="learn from journal history, save + report")
    pt.add_argument("--out", help="model output path (default: <memory-dir>/oracle_model.json)")

    sub.add_parser("eval", help="leave-one-out CV vs baselines")

    prk = sub.add_parser("rank", help="score & rank a target's untouched leads")
    prk.add_argument("target")
    prk.add_argument("--model", help="model path (default: <memory-dir>/oracle_model.json)")
    prk.add_argument("--top", type=int, default=20)
    prk.add_argument("--json", dest="as_json", action="store_true")

    psc = sub.add_parser("score", help="score one hypothetical lead")
    psc.add_argument("--class", dest="vuln_class", help="vuln class / skill, e.g. idor")
    psc.add_argument("--url", help="candidate endpoint")
    psc.add_argument("--tech", action="append", help="tech token(s), repeatable")
    psc.add_argument("--severity", help="critical/high/medium/low")
    psc.add_argument("--model", help="model path")
    psc.add_argument("--json", dest="as_json", action="store_true")

    args = ap.parse_args(argv)
    return {"train": cmd_train, "eval": cmd_eval,
            "rank": cmd_rank, "score": cmd_score}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
