# SecurePatch — LLM Security Vulnerability Detection and Repair

Empirical evaluation of seven large language models as composable detectors and fixers for source-code security vulnerabilities. The central experiment is a 7×7 matrix: every combination of detector model and fixer model is run over 56 benchmark cases, producing 49 pipeline F1 scores scored by a deterministic oracle.

**Paper:** `paper/main.pdf`  
**Results log:** `docs/RESULTS.md`  
**Raw data:** `harness/results/*.jsonl`

---

## Repository layout

```
benchmarks/          56 labeled vulnerability cases
  cweval/            44 cases from CWEval (Apache-2.0)
  seeded/            6 hand-written cases
  literature/        6 cases from published disclosures

harness/             Python research harness
  securepatch_bench/ importable package (bench, fix, ensemble, …)
  results/           per-run JSONL output files (gitignored)
  docker/            Dockerfile for the CWEval oracle sandbox

paper/               LaTeX source and compiled PDF
docs/                RESULTS.md (human-readable results log)
```

---

## Setup

### 1. Python environment

```bash
cd harness
pip install -e .[providers]
```

This installs the harness package plus provider SDKs (openai, anthropic, google-genai, ollama).

### 2. API keys

Copy the template and fill in your keys:

```bash
cp harness/.env.example harness/.env
# edit harness/.env
```

```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
# Ollama needs no key (runs locally)
```

Keys can also be set as regular environment variables; those take precedence over the `.env` file.

### 3. CWEval Docker oracle (required for fix verification)

```bash
# from repo root — needs Docker Desktop running
docker build -t securepatch-cweval harness/docker/
```

The image bundles the full CWEval dependency stack (pycryptodome, lxml, PyJWT, jsdom, …). Without it, CWEval fix verification degrades to re-scan only instead of exploit-based oracle.

---

## Re-running detection

All commands are run from the repo root. Results are written as append-only JSONL (one row per case).

### Baselines (no API key needed)

```bash
# Regex rule baseline
python -m securepatch_bench bench \
    --record harness/results/full_regex.jsonl

# Semgrep OSS baseline (pip install semgrep first)
python -m securepatch_bench bench --detector sast \
    --record harness/results/sast_semgrep.jsonl
```

### AI detection — single model

```bash
# Sonnet (3 scans per case, matching the paper's detection@3)
python -m securepatch_bench bench --detector ai \
    --provider anthropic --model claude-sonnet-4-6 --scans 3 \
    --record harness/results/sonnet_detect_v2.jsonl

# Opus
python -m securepatch_bench bench --detector ai \
    --provider anthropic --model claude-opus-4-8 --scans 3 \
    --record harness/results/opus_detect_v2.jsonl

# Haiku
python -m securepatch_bench bench --detector ai \
    --provider anthropic --model claude-haiku-4-5 --scans 3 \
    --record harness/results/haiku_detect_v2.jsonl

# GPT-5.5
python -m securepatch_bench bench --detector ai \
    --provider openai --model gpt-5.5 --scans 3 \
    --record harness/results/gpt55_detect_v2.jsonl

# GPT-4.1-mini
python -m securepatch_bench bench --detector ai \
    --provider openai --model gpt-4.1-mini --scans 3 \
    --record harness/results/mini_detect_v2.jsonl

# Gemini 2.5 Flash
python -m securepatch_bench bench --detector ai \
    --provider gemini --model gemini-2.5-flash --scans 3 \
    --record harness/results/gemini_detect_v2.jsonl

# Ollama (local, free — model must already be pulled)
python -m securepatch_bench bench --detector ai \
    --provider ollama --model qwen2.5-coder:7b --scans 3 \
    --record harness/results/ollama_detect_v2.jsonl
```

### Smoke-test a single file

```bash
python -m securepatch_bench detect benchmarks/seeded/js-sqli-concat/source/sqli_concat_js_unsafe.js \
    --provider anthropic --model claude-sonnet-4-6
```

---

## Re-running the fix pipelines

The fix command reads cached detection results (`--detect-jsonl`) so every fixer column in a row receives identical detection output, eliminating detection variance as a confound.

### Self-pipelines (detector = fixer, diagonal)

```bash
python -m securepatch_bench fix \
    --provider anthropic --model claude-sonnet-4-6 \
    --detect-jsonl harness/results/sonnet_detect_v2.jsonl \
    --detect-label cached:sonnet_v2 \
    --record harness/results/fix_sonnet_sonnet_v2.jsonl

python -m securepatch_bench fix \
    --provider anthropic --model claude-opus-4-8 \
    --detect-jsonl harness/results/opus_detect_v2.jsonl \
    --detect-label cached:opus_v2 \
    --record harness/results/fix_opus_opus_v2.jsonl

python -m securepatch_bench fix \
    --provider anthropic --model claude-haiku-4-5 \
    --detect-jsonl harness/results/haiku_detect_v2.jsonl \
    --detect-label cached:haiku_v2 \
    --record harness/results/fix_haiku_haiku_v2.jsonl

python -m securepatch_bench fix \
    --provider openai --model gpt-5.5 \
    --detect-jsonl harness/results/gpt55_detect_v2.jsonl \
    --detect-label cached:gpt55_v2 \
    --record harness/results/fix_gpt55_gpt55_v2.jsonl

python -m securepatch_bench fix \
    --provider openai --model gpt-4.1-mini \
    --detect-jsonl harness/results/mini_detect_v2.jsonl \
    --detect-label cached:mini_v2 \
    --record harness/results/fix_mini_mini_v2.jsonl

python -m securepatch_bench fix \
    --provider gemini --model gemini-2.5-flash \
    --detect-jsonl harness/results/gemini_detect_v2.jsonl \
    --detect-label cached:gemini_v2 \
    --record harness/results/fix_gemini_gemini_v2.jsonl

python -m securepatch_bench fix \
    --provider ollama --model qwen2.5-coder:7b \
    --detect-jsonl harness/results/ollama_detect_v2.jsonl \
    --detect-label cached:ollama_v2 \
    --record harness/results/fix_ollama_ollama_v2.jsonl
```

### Cross-pipeline (example: GPT-5.5 detector → Opus fixer)

Replace `--detect-jsonl` with whichever detector's cache you want, and `--provider`/`--model` with the desired fixer:

```bash
python -m securepatch_bench fix \
    --provider anthropic --model claude-opus-4-8 \
    --detect-jsonl harness/results/gpt55_detect_v2.jsonl \
    --detect-label cached:gpt55_v2 \
    --record harness/results/fix_gpt55_opus_v2.jsonl
```

The naming convention for output files is `fix_<detector>_<fixer>_v2.jsonl`.

### Ground-truth fixer experiment

This gives each fixer a perfect detection (all 56 bugs, zero false positives) to isolate pure repair capability:

```bash
python -m securepatch_bench fix \
    --provider anthropic --model claude-opus-4-8 \
    --detect-jsonl harness/results/ground_truth_detect.jsonl \
    --detect-label ground_truth \
    --record harness/results/fix_gt_opus.jsonl
```

---

## Ensemble detection

Compute majority-vote ensemble F1 from existing detection JSONL files:

```bash
python -m securepatch_bench ensemble \
    harness/results/sonnet_detect_v2.jsonl \
    harness/results/opus_detect_v2.jsonl \
    harness/results/gpt55_detect_v2.jsonl \
    harness/results/gemini_detect_v2.jsonl \
    --out docs/ensemble_f1_results.md
```

---

## Detection discovery curves

Shows recall as a function of scan count (detection@k) from recorded JSONL:

```bash
python -m securepatch_bench discovery \
    harness/results/sonnet_detect_v2.jsonl \
    harness/results/gpt55_detect_v2.jsonl \
    harness/results/gemini_detect_v2.jsonl \
    harness/results/opus_detect_v2.jsonl \
    harness/results/haiku_detect_v2.jsonl \
    harness/results/mini_detect_v2.jsonl \
    harness/results/ollama_detect_v2.jsonl
```

---

## JSONL result format

Detection rows (`bench` phase):

| Field | Description |
|---|---|
| `case_id` | Benchmark case identifier |
| `detected` | 1 if any bug was found across all scans |
| `bug_count` | Ground-truth bugs in this case |
| `false_positives` | Number of spurious findings |
| `matched` | List of matched bug IDs |
| `missed` | List of missed bug IDs |
| `per_scan_matched` | Per-scan match lists (for discovery curves) |
| `usage` | `{input_tokens, output_tokens, cost_usd, latency_ms}` |

Fix rows (`fix` phase):

| Field | Description |
|---|---|
| `case_id` | Benchmark case identifier |
| `verdict` | `fixed` / `regressed` / `no-op` / `error` |
| `diff` | Unified diff of the applied patch |
| `compiles` | Whether the patched file compiles/parses |
| `tests_passed` | Whether behavioral tests passed |
| `vuln_still_present` | Whether the oracle still flags the vulnerability |
| `usage` | Cost and latency for the fix call |

---

## Recompiling the paper

```bash
cd paper
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

Output: `paper/main.pdf`
