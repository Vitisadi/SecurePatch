# SecurePatch — Detection Results Log

Running record of detector benchmark runs against the labeled corpus
(`benchmarks/`, 56 cases). Regenerate any row with the commands in the
[How to reproduce](#how-to-reproduce) section. Raw per-case rows live in
`harness/results/*.jsonl` (gitignored); this file is the human-readable summary
we keep in version control.

**Metric:** _detection recall_ — a finding whose location (±2 lines) and
CWE/type matches a ground-truth bug. For AI detectors, `--scans k` reports
**detection@k** (found in *any* of k repeated scans). See
[`RESEARCH_PLAN.md`](RESEARCH_PLAN.md) §3 for metric definitions.

---

## Headline: recall by obscurity tier

| Tier | Cases | Regex | OpenAI `gpt-4.1-mini` @3 | Anthropic `claude-opus-4-8` @3 |
|---|---:|---:|---:|---:|
| syntactic       | 10 | **100%** (10/10) | 80% (8/10)  | **100%** (10/10) |
| local-semantic  | 45 | 20% (9/45)       | 78% (35/45) | **91%** (41/45) |
| cross-function  | 1  | 0% (0/1)         | **100%** (1/1)  | **100%** (1/1) |
| **Overall**     | 56 | 34% (19/56)      | 79% (44/56) | **93%** (52/56) |
| False positives | —  | 3                | 8           | 10 |

## By collection

| Collection | Cases | Regex | OpenAI @3 | Anthropic @3 |
|---|---:|---:|---:|---:|
| cweval     | 44 | 20% (9/44) | 77% (34/44) | **91%** (40/44) |
| literature | 6  | 83% (5/6)  | 83% (5/6)   | **100%** (6/6) |
| seeded     | 6  | 83% (5/6)  | 83% (5/6)   | **100%** (6/6) |

## Run metadata

| Run | Date | Scans | Cost | $/case | Wall latency | Raw rows |
|---|---|---:|---:|---:|---:|---|
| regex baseline      | 2026-07-02 | 1 | $0.00   | $0.00     | <1s      | `results/full_regex.jsonl` |
| OpenAI gpt-4.1-mini | 2026-07-02 | 3 | $0.053  | $0.0009   | ~4.4 min | `results/openai.jsonl` |
| Anthropic opus-4-8  | 2026-07-02 | 3 | $1.380  | $0.0246   | ~9.7 min | `results/claude.jsonl` |

> Cost/latency are also captured **per case** in each JSONL row (`usage`), and the
> `bench` CLI now prints per-case `$cost latency` plus a `wall time` footer.

---

## Observations

1. **AI massively lifts recall; Claude leads** (regex 34% → OpenAI 79% →
   **Claude 93%**), driven by the **local-semantic** tier (20% → 78% → 91%) —
   the exact gap the research plan predicted regex could not close.
2. **Claude dominates the accuracy axis but at a steep cost.** Claude is the only
   detector that keeps **syntactic recall at 100%** (regex-level) *and* leads on
   semantic bugs — but it costs **~26× more** ($1.38 vs $0.053) and runs **~2×
   slower** than OpenAI. `$/bug-found` and latency are the real tradeoff, not
   recall.
3. **OpenAI regresses on trivial bugs; Claude does not.** OpenAI missed two
   *regex-detectable* cases (`cwe-078-cmdi-subprocess`, `py-cmdi-ping`) →
   syntactic recall dropped to 80%. Claude caught both. Still an argument for an
   **ensemble (regex ∪ AI)** as a cheap safety net under the cheaper models.
4. **Obscurity labels validated:** many cases labeled `regex-undetectable` were
   found by both models (the harness flags these as "surprises"), confirming both
   the labels and the AI thesis.
5. **False positives rise with recall** (regex 3 → OpenAI 8 → Claude 10). A
   per-category FP breakdown is a Week 4 analysis-layer task.
6. **Neither model is perfect.** Both still miss `js-cwe_400_0`, `js-cwe_943_0`,
   `py-cwe_400_0`, `py-cwe_943_0` (Claude's 4 misses) — resource-exhaustion (CWE-400)
   and NoSQL-injection (CWE-943) are the hardest categories so far. Candidates for
   the "how many scans" and ensemble analyses.

## How to reproduce

Run from `harness/` (keys loaded from `harness/.env`):

```bash
# regex baseline (no key needed)
python -m securepatch_bench bench --record results/full_regex.jsonl

# AI detectors, 3 scans/case (detection@3)
python -m securepatch_bench bench --detector ai --provider openai \
    --model gpt-4.1-mini --scans 3 --record results/openai.jsonl
python -m securepatch_bench bench --detector ai --provider anthropic \
    --scans 3 --record results/claude.jsonl
```

> Note: entries labeled "@3" are detection@3. Single-scan regex is deterministic,
> so k does not apply. Update this file whenever a run is re-executed — keep the
> date and cost columns current.
