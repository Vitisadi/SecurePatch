# SecurePatch research harness (Python)

Headless instrument that drives `@securepatch/core` to gather research data:
detection across repeated scans and multiple AI providers, fixes applied in
isolated sandboxes, automatic verification, and per-run JSONL results.

See `../docs/RESEARCH_PLAN.md` for the full plan and week-by-week timeline.

## Status: Week 2 (benchmark corpus + baseline + AI detection)

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
- `providers/` — model provider adapters (`base.py` interface + cost table,
  `openai_provider.py`, `anthropic_provider.py`). SDKs are imported lazily, so
  the harness imports fine without them. Each call captures tokens, latency, and
  an estimated USD cost.
- `detectors.py` — the `RegexDetector` (core CLI) and the `AIDetector` (prompts a
  provider, parses its JSON findings into the same shape the matcher consumes).
- `bench.py` + the `bench` command — scores **any** detector against the corpus
  (overall, per collection, per obscurity tier), over repeated scans
  (detection@k) for AI.
- `cweval_import.py` + the `import-cweval` command — vendors the in-scope
  (Python/JS) tasks of the [CWEval](https://github.com/Co1lin/CWEval) benchmark
  into `benchmarks/cweval/` (Apache-2.0, attributed).
- `sandbox.py` — copies a case into a throwaway temp dir (never mutating the
  corpus) and re-validates the copy as a real `BenchmarkCase`.
- `fixer.py` — the `AIFixer`: prompts a provider for a whole-file rewrite that
  removes one vulnerability, applies it in the sandbox, and keeps a unified diff.
- `verify.py` — automatic verification of a patched sandbox: compile/parse check
  → run the case's `tests/` → re-scan for the original vuln → re-scan for new
  findings.
- `fixloop.py` + the `fix` command — the detect → sandbox → fix → verify loop,
  collapsing the verify signals into one verdict per attempt
  (`fixed` / `regressed` / `no-op` / `error`). `regressed` is the automatable
  "did the fix cause a problem?" signal.
- `__main__.py` — `scan`, `detect`, `bench`, `fix`, and `import-cweval` commands.

Not yet (later weeks): Gemini + Ollama adapters, parallel concurrency-limited
queue, retry-on-regression (agentic) loop, and the analysis notebooks.

- `cweval_oracle.py` — runs CWEval's pytest oracles in a Docker container
  (`docker/Dockerfile`). Its `functionality` marker is the "still works" signal
  and its `security` marker is a stronger, exploit-based "vuln gone" signal.

**Verification coverage:**
- `seeded` + `literature` cases ship runnable `tests/` → full native verification
  (compile + unit tests + re-scan for vuln-gone / new-findings).
- `cweval` cases ship a `oracle/` → verified in Docker: `functionality` = tests,
  `security` = a real exploit-based vuln-gone check (stronger than re-scan);
  new-findings still come from a re-scan.
- If Docker is unavailable, `cweval` cases **degrade gracefully** to re-scan-only
  and the attempt records why, rather than failing.

**Building the CWEval verification image (once):**
```bash
# from harness/ — needs Docker Desktop running
docker build -t securepatch-cweval docker/
```
The image bundles Python + Node + the CWEval dependency stack (pycryptodome,
lxml, PyJWT, argon2, sqlite3, jsdom, ...). The harness mounts one sandboxed case
at `/work` and runs `pytest oracle -m <marker> -k "not unsafe"`.

## Prerequisites

1. Build the core CLI once from the repo root:
   ```bash
   npm install
   npm run build:core
   ```
2. Python 3.9+.
3. For AI detection, install the provider SDKs and set the relevant key(s):
   ```bash
   pip install -e .[providers]        # from harness/
   export OPENAI_API_KEY=...          # for --provider openai
   export ANTHROPIC_API_KEY=...       # for --provider anthropic
   ```

## Usage

```bash
# --- regex detector (no key needed) ---
# from the repo root
python -m securepatch_bench scan test/test.py
python -m securepatch_bench scan test/test.py --record harness/results/run.jsonl

# baseline: scan the whole corpus and score the regex detector
python -m securepatch_bench bench
python -m securepatch_bench bench --record harness/results/baseline.jsonl

# --- AI detection (needs SDK + key) ---
# smoke-test one file against a provider (verifies setup)
python -m securepatch_bench detect test/test.py --provider anthropic
python -m securepatch_bench detect test/test.py --provider openai --model gpt-4.1-mini

# score an AI detector over the whole corpus, 5 scans per case (detection@k)
python -m securepatch_bench bench --detector ai --provider anthropic --scans 5 \
    --record harness/results/claude.jsonl
python -m securepatch_bench bench --detector ai --provider openai \
    --model gpt-4.1-mini --scans 5 --record harness/results/openai.jsonl

# --- fix + verify loop (needs SDK + key) ---
# fix one case end-to-end: detect -> sandbox -> fix -> verify -> verdict
python -m securepatch_bench fix --provider anthropic --case py-cmdi-ping

# fix a whole collection (seeded/literature run tests; cweval is re-scan only)
python -m securepatch_bench fix --provider anthropic --collection seeded \
    --record results/fix_claude_seeded.jsonl

# (re)import the CWEval tasks from a local CWEval checkout
python -m securepatch_bench import-cweval /path/to/CWEval
```

The `fix` command records one row per attempt with the applied **unified diff**,
the verify breakdown (compiles / tests_passed / vuln_still_present / new_findings),
the verdict, and per-attempt cost + latency — the reviewable "see how it fixed it
and whether it caused a problem" provenance.

Default models: OpenAI → `gpt-4.1-mini`, Anthropic → `claude-opus-4-8`. Override
with `--model`. Each AI run prints token usage and an estimated USD cost; the
recorded JSONL rows carry per-scan matches (`per_scan_matched`) for discovery
curves plus usage for the `$/bug` axis.

`bench` reports the detector's recall over `../benchmarks/`. The regex detector
clears every syntactic case but misses the semantic / multi-function ones — the
gap the AI providers are meant to close. Use the regex baseline as the regression
harness when extending the base detector rules.

Run from the `harness/` directory, or add it to `PYTHONPATH`. To override where
the core CLI lives, set `SECUREPATCH_CORE_CLI`.
