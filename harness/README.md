# SecurePatch research harness (Python)

Headless instrument that drives `@securepatch/core` to gather research data:
detection across repeated scans and multiple AI providers, fixes applied in
isolated sandboxes, automatic verification, and per-run JSONL results.

See `../docs/RESEARCH_PLAN.md` for the full plan and week-by-week timeline.

## Status: Week 2 (benchmark corpus + baseline)

Implemented:
- `core_bridge.py` — shells out to the Node detection CLI (`core/dist/cli.js`),
  so detection logic is single-sourced with the VS Code extension.
- `results.py` — append-only JSONL writer (one row per run).
- `corpus.py` — loads and validates the labeled benchmark corpus
  (`../benchmarks/`), failing loudly on unknown vulnerability types/obscurity
  tiers, missing files, or bad line ranges.
- `matcher.py` — matches detector findings (0-based lines) to ground-truth bugs
  (1-based) by type + line window; yields true positives / misses / false
  positives.
- `bench.py` + the `bench` command — the **baseline**: scans every case with the
  regex detector and scores recall overall, per collection, and per obscurity tier.
- `cweval_import.py` + the `import-cweval` command — vendors the in-scope
  (Python/JS) tasks of the [CWEval](https://github.com/Co1lin/CWEval) benchmark
  into `benchmarks/cweval/` (Apache-2.0, attributed).
- `__main__.py` — `scan`, `bench`, and `import-cweval` commands.

Not yet (later weeks): provider adapters (OpenAI/Claude/Gemini/Ollama), the
sandbox + verify loop, and the full experiment runner (cases x models x scans).

## Prerequisites

1. Build the core CLI once from the repo root:
   ```bash
   npm install
   npm run build:core
   ```
2. Python 3.10+.

## Usage

```bash
# from the repo root
python -m securepatch_bench scan test/test.py

# also append the result as a JSONL row
python -m securepatch_bench scan test/test.py --record harness/results/run.jsonl

# baseline: scan the whole benchmark corpus and score the regex detector
python -m securepatch_bench bench
python -m securepatch_bench bench --record harness/results/baseline.jsonl

# (re)import the CWEval tasks from a local CWEval checkout
python -m securepatch_bench import-cweval /path/to/CWEval
```

`bench` reports the regex detector's recall over `../benchmarks/` (overall, per
collection, per obscurity tier). It clears every syntactic case but misses the
semantic / multi-function ones — the gap the AI providers are meant to close.
Use it as the regression harness when extending the base detector rules.

Run from the `harness/` directory, or add it to `PYTHONPATH`. To override where
the core CLI lives, set `SECUREPATCH_CORE_CLI`.
