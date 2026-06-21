# SecurePatch research harness (Python)

Headless instrument that drives `@securepatch/core` to gather research data:
detection across repeated scans and multiple AI providers, fixes applied in
isolated sandboxes, automatic verification, and per-run JSONL results.

See `../docs/RESEARCH_PLAN.md` for the full plan and week-by-week timeline.

## Status: Week 1 (skeleton)

Implemented:
- `core_bridge.py` — shells out to the Node detection CLI (`core/dist/cli.js`),
  so detection logic is single-sourced with the VS Code extension.
- `results.py` — append-only JSONL writer (one row per run).
- `__main__.py` — `scan` command proving the end-to-end bridge.

Not yet (later weeks): provider adapters (OpenAI/Claude/Gemini/Ollama), the
benchmark corpus loader, the sandbox + verify loop, and the experiment runner.

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
```

Run from the `harness/` directory, or add it to `PYTHONPATH`. To override where
the core CLI lives, set `SECUREPATCH_CORE_CLI`.
