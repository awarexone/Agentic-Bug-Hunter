---
description: Self-learning lead/finding prioritizer — trains on your own hunt-memory outcomes to predict which leads are worth pursuing, replacing the static regex priority. Usage: /oracle train | /oracle rank <target> | /oracle score --class idor --url <u> | /oracle eval
---

# /oracle

Turn the hunt-memory flywheel into a decision engine. Every finding's outcome
(confirmed / rejected / false_positive, payout, severity, vuln class, endpoint,
tech stack) already lives in `journal.jsonl` — Oracle learns from it and scores
any lead by **P(this becomes a real, valuable finding)**, so you work the leads
your own track record says pay, not the ones a hardcoded regex guesses.

## Usage

```
/oracle train                 # learn from history, save model, print eval
/oracle eval                  # leave-one-out CV vs baselines (no save)
/oracle rank target.com       # score & rank that target's untouched leads
/oracle score --class idor --url https://api.t.com/v1/o?id=9 --severity high
```

Run directly:

```bash
tools/oracle.py train
tools/oracle.py rank target.com --top 20
tools/oracle.py score --class open-redirect --url https://t.com/go?next=/x --json
```

## What it learns

Features per finding: vuln class, severity, endpoint shape (`numeric_id`,
`api`/`admin`/`graphql`/`upload`/`oauth` keywords, path depth, host), tags, and
the target's tech stack (from `patterns.jsonl`). Label: `confirmed` → positive,
`rejected`/`false_positive` → negative; ambiguous results are excluded.

## The model (and why this one)

Bug-bounty history is small, so Oracle uses a **smoothed Naive-Bayes log-odds
model** — the right tool for little data: calibrated, fully explainable
(every score comes with the per-feature log-odds that produced it), pure-stdlib,
deterministic. A **cold-start prior** (the same high-value-class intuition the
regex scorer encodes) is blended in and **decays as real evidence accumulates**
(`prior` → `blended` → `learned`), so Oracle is useful on day one and
data-driven by day thirty.

## Why it beats the static prioritizer

The regex priority is the same for every program. Oracle learns **program-specific
reality** — e.g. that IDOR is always a duplicate on one program (down-rank it) or
that open-redirect chains to ATO and pays on another (up-rank it). `oracle eval`
proves this on *your* data with leave-one-out CV against two baselines (the prior
heuristic and majority class), so you can see the lift before you trust it.

## Output

`rank` prints each lead's probability, expected value (`P × mean historical
payout for that class`), and the top features driving the score. `score` explains
a single hypothetical lead. `train` saves `oracle_model.json` into the memory dir.
Read-only — Oracle never mutates the lead board.
