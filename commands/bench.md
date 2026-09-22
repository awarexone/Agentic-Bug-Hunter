---
description: BugBench — measure the toolkit's detection quality (precision / recall / false-positive rate) against a ground-truth corpus of known-vulnerable AND known-safe cases. Usage: /bench run [--min-precision 1.0 --max-fp-rate 0.0] | /bench list
---

# /bench

Reputation in security tooling is trust, and trust is *measured*. BugBench runs
the toolkit's detectors against a ground-truth corpus — cases that are **known
vulnerable** and cases that are **known safe** — and reports precision, recall,
and **false-positive rate**, so the project can make a claim few AI security
tools can: *"here is our measured accuracy — reproduce it yourself."*

Every case carries a **recorded input** (the exact response a detector would
see), never a live URL, so the score is identical on every machine and in CI.

## Usage

```
/bench list                                   # show the corpus
/bench run                                     # score every detector
/bench run --json                              # machine-readable
/bench run --report bench-score.md             # write the Markdown scoreboard
/bench run --min-precision 1.0 --max-fp-rate 0.0   # CI gate (exit 1 on regression)
```

Run directly:

```bash
tools/bench.py run --min-precision 1.0 --max-fp-rate 0.0
```

## What it reports

- **precision** — of everything flagged, how much was a real bug (noise ↓).
- **recall** — of the real bugs present, how many were caught.
- **false-positive rate** — of the safe cases, how many were wrongly flagged.
  *This is the headline trust metric.* Accuracy is deliberately **not** the
  headline: on a mostly-safe corpus a do-nothing detector scores high accuracy
  while catching zero bugs.
- **failures** — the exact cases that were false positives or misses, so a
  regression is actionable, not just a number.

## The CI gate

`--min-precision` / `--max-fp-rate` make `/bench run` **exit non-zero** when
quality drops below the bar, so CI blocks any change that makes a detector
noisier or less accurate. That turns "we measure quality" into an *enforced*
guarantee over time.

## Adding a case

Drop a JSON file in `bughunter/bench/cases/`:

```json
{
  "id": "cors-reflect-credentialed",
  "detector": "cors",
  "note": "reflects arbitrary origin with credentials",
  "input": { "url": "...", "sent_origin": "https://evil.example",
             "acao": "https://evil.example", "acac": "true" },
  "expected": { "vulnerable": true, "class": "cors", "min_severity": "high" }
}
```

Cases are data — anyone can contribute one without touching Python. Add safe
cases too: they're what let BugBench measure false positives.

## Adding a detector

Register a one-function adapter in `tools/bench.py` (recorded `input` →
`DetectorResult`) with `@detector("name")`. The harness core never changes.
