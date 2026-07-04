# SecurePatch — Results Log

Running record of harness runs against the labeled corpus (`benchmarks/`, 56
cases). Two independent experiments:

- **Part 1 — Detection** (`bench`): can a detector *find* the bug? → recall.
- **Part 2 — Fix + Verify** (`fix`): can it *fix* the bug, and does the fix break
  anything? → verdicts.

Raw per-case rows live in `harness/results/*.jsonl` (gitignored); this file is the
human-readable summary we keep in version control. See
[`RESEARCH_PLAN.md`](RESEARCH_PLAN.md) §3 for metric definitions.

**Models under test:** regex (baseline), OpenAI `gpt-4.1-mini`, Google Gemini
`2.5-flash`, Anthropic Sonnet `4-6`, Anthropic Opus `4-8`, and a local Ollama
`qwen2.5-coder:7b` (runs on-machine, $0).

---

# Part 1 — Detection

**Metric:** _recall_ — a finding whose location (±2 lines) and CWE/type matches a
ground-truth bug. AI detectors run `--scans 3` → **detection@3** (found in any of
3 scans).

## Recall by obscurity tier

| Tier | Cases | Regex | Ollama 7b | OpenAI mini | Gemini 2.5-flash | Opus 4-8 | Sonnet 4-6 |
|---|---:|---:|---:|---:|---:|---:|---:|
| syntactic       | 10 | **100%** | 80% | 80% | 80% | **100%** | **100%** |
| local-semantic  | 45 | 20% | 58% | 78% | 87% | 91% | **93%** |
| cross-function  | 1  | 0% | **100%** | **100%** | **100%** | **100%** | **100%** |
| **Overall**     | 56 | 34% (19) | 62% (35) | 79% (44) | 86% (48) | 93% (52) | **95% (53)** |
| False positives | —  | 3 | **30** | 8 | 8 | 10 | 13 |

## Recall by collection

| Collection | Cases | Regex | Ollama | OpenAI | Gemini | Opus | Sonnet |
|---|---:|---:|---:|---:|---:|---:|---:|
| cweval     | 44 | 20% | 57% | 77% | 86% | 91% | **93%** |
| literature | 6  | 83% | 83% | 83% | 83% | **100%** | **100%** |
| seeded     | 6  | 83% | 83% | 83% | 83% | **100%** | **100%** |

## Detection cost & time

| Detector | Cost | $/case | Wall | Notes |
|---|---:|---:|---:|---|
| regex        | $0.000 | $0.0000 | <1s      | deterministic |
| Ollama 7b    | $0.000 | $0.0000 | ~57 min  | local; ~4× slower/case |
| OpenAI mini  | $0.053 | $0.0009 | ~4.4 min | |
| Gemini flash | $0.085 | $0.0015 | ~15.7 min| |
| Sonnet       | $0.747 | $0.0133 | ~12.5 min| |
| Opus         | $1.380 | $0.0246 | ~9.7 min | |

## Detection observations

1. **AI massively lifts recall** (regex 34% → 62–95%), driven by the
   **local-semantic** tier (regex 20% → up to 93%).
2. **Sonnet is the best detector** (95%), edging Opus (93%) at ~half the cost, and
   keeping syntactic at 100%.
3. **Free local model beats regex but is noisy and slow.** Ollama 7b reaches 62%
   recall at $0, but with **30 false positives** (2–4× the API models) and ~4×
   the per-case latency. Precision, not recall, is its weakness.
4. **OpenAI + Gemini dip on trivial bugs** (syntactic 80%): both miss two
   *regex-detectable* cases (`cwe-078-cmdi-subprocess`, `py-cmdi-ping`). The
   Claude models don't. Argues for an **ensemble (regex ∪ AI)** safety net.
5. **False positives rise with recall** (3 → 8 → 8 → 10 → 13), and blow up for the
   local model (30). Per-category FP breakdown is a Week 4 task.

---

# Part 2 — Fix + Verify

**Pipeline:** per bug — copy the case into a sandbox → AI rewrites the file →
verify. Verification differs by collection:

- `seeded`/`literature` → native unit tests; "vuln gone" via detector **re-scan**.
- `cweval` → CWEval pytest oracle in **Docker**: `functionality` = "still works",
  `security` = a real **exploit-based** "vuln gone" (stronger than re-scan). 43–44
  of 56 cases used this stronger signal.

**Verdicts:** `fixed` (vuln gone + compiles + tests pass + no new finding) /
`regressed` (test/compile broke, or a new finding appeared) / `no-op` (vuln still
present, nothing broke) / `error`.

> **Ollama fix caveat:** running the local 7b through the Docker oracle is not
> feasible on the test machine (RAM contention between Docker and the resident
> model caused a hang). Ollama fix was therefore run on the **12 Docker-free
> cases** (seeded + literature) only. To compare fairly, the table below also
> shows the API models restricted to those **same 12 cases**.

## Verdict distribution (full 56 cases; Ollama = 12)

| Verdict | OpenAI mini | Gemini flash | Sonnet | Ollama 7b (12) |
|---|---:|---:|---:|---:|
| ✅ fixed      | 27 (48%) | 25 (45%) | 19 (34%) | 2 (17%) |
| ⚠️ regressed  | 23 (41%) | 31 (55%) | 34 (61%) | 10 (83%) |
| ➖ no-op      | 6 (11%)  | 0        | 3 (5%)   | 0 |
| ✗ error      | 0        | 0        | 0        | 0 |

## The `regressed` count is noisy — use functional-fix instead

The strict `fixed` verdict marks a fix regressed if the **AI re-scan flags any new
finding**, and that re-scan is stochastic. Breaking `regressed` down by real cause:

| Regressed cause | OpenAI | Gemini | Sonnet | Ollama(12) |
|---|---:|---:|---:|---:|
| new-finding only (noisy; compiles + tests pass) | 12 | 9 | 18 | 3 |
| test failure (real) | 9 | 7 | 10 | 3 |
| compile failure (real) | 2 | **15** | 6 | 4 |

**Functional-fix rate** (vuln removed **and** compiles **and** tests/oracle pass,
ignoring the new-finding signal) is the fairer measure:

| Metric | OpenAI | Gemini | Sonnet | Ollama(12) |
|---|---:|---:|---:|---:|
| strict `fixed` (full 56 / Ollama 12) | 48% | 45% | 34% | 17% |
| **functional-fix** (full 56 / Ollama 12) | **68%** | 59% | 62% | 25% |
| real breakage (compile+test) | 11 | 22 | 16 | 7 |

### Apples-to-apples: functional-fix on the SAME 12 Docker-free cases

| Model | functional-fix (of 12) |
|---|---:|
| OpenAI mini | **8 / 12 (67%)** |
| Sonnet      | 6 / 12 (50%) |
| Gemini flash| 5 / 12 (42%) |
| Ollama 7b   | 3 / 12 (25%) |

## Fix verdicts by collection (fixed / regressed / no-op)

| Collection | OpenAI | Gemini | Sonnet | Ollama |
|---|---|---|---|---|
| cweval (Docker oracle) | 20 / 18 / 6 | 21 / 23 / 0 | 14 / 27 / 3 | _not run_ |
| literature | 2 / 4 / 0 | 1 / 5 / 0 | 2 / 4 / 0 | 1 / 5 / 0 |
| seeded     | 5 / 1 / 0 | 3 / 3 / 0 | 3 / 3 / 0 | 1 / 5 / 0 |

## Fix cost & time

| Run | Cost | $/attempt | Wall | Rows |
|---|---:|---:|---:|---|
| OpenAI mini | $0.028 | $0.0005 | ~12.3 min | `results/fix_openai.jsonl` |
| Gemini flash| $0.047 | $0.0008 | ~28.7 min | `results/fix_gemini.jsonl` |
| Sonnet      | $0.330 | $0.0059 | ~17.7 min | `results/fix_sonnet.jsonl` |
| Ollama 7b (12) | $0.000 | $0.0000 | ~2 min | `results/fix_ollama.jsonl` |

## Fix observations

1. **Detection skill ≠ fixing skill.** Sonnet is the *best detector* (95%) but the
   *weakest API fixer* by functional-fix (62%); the *cheapest* model, OpenAI
   `gpt-4.1-mini`, is the **best fixer** (68% full, 67% on the shared 12) at ~12×
   lower cost. Fixing and finding are different capabilities.
2. **Gemini breaks compilation the most** — 15 of its 31 regressions are compile
   failures (vs OpenAI 2, Sonnet 6). Its whole-file rewrites more often emit
   code that doesn't parse.
3. **The local 7b is a weak fixer** — 25% functional-fix on the shared 12 vs
   42–67% for the API models, with the most compile/test breakage per case. Free,
   but not yet good enough to fix unsupervised.
4. **`regressed` needs the reason breakdown to mean anything** — roughly half of
   all regressions are noisy "new-finding-only" from the stochastic re-scan. Next
   improvement: gate new-findings with a *deterministic* detector (regex, or the
   oracle's own security check) instead of the AI re-scan.
5. **The Docker oracle scaled cleanly** — 43–44 of 56 cases verified with the
   exploit-based `security` oracle, zero pipeline errors across three full runs.
6. **Best "product" recipe so far:** detect with Sonnet (or an ensemble incl.
   regex), **fix with `gpt-4.1-mini`** — highest fix success at lowest cost.

---

## Setup notes (for reproducing)

- **Gemini:** use `gemini-2.5-flash` (`2.0-flash` is retired / zero free-tier
  quota); requires a billed key. Adapter has 429 retry/backoff.
- **Ollama:** local `qwen2.5-coder:7b` (the 14b OOMs on 8 GB VRAM alongside
  Docker). Models stored on `D:\ollama\models` via `OLLAMA_MODELS`. cweval fix
  needs Docker + resident model simultaneously — infeasible on this hardware.

## How to reproduce

Run from `harness/` (keys in `harness/.env`):

```bash
# --- Part 1: detection (@3) ---
python -m securepatch_bench bench --record results/full_regex.jsonl
for p in "openai --model gpt-4.1-mini" "gemini --model gemini-2.5-flash" \
         "anthropic --model claude-sonnet-4-6" "ollama --model qwen2.5-coder:7b"; do
  python -m securepatch_bench bench --detector ai --provider $p --scans 3 \
      --record results/${p%% *}_detect.jsonl
done

# --- Part 2: fix + verify (cweval needs the Docker image) ---
docker build -t securepatch-cweval docker/
python -m securepatch_bench fix --provider openai --model gpt-4.1-mini --record results/fix_openai.jsonl
python -m securepatch_bench fix --provider gemini --model gemini-2.5-flash --record results/fix_gemini.jsonl
python -m securepatch_bench fix --provider anthropic --model claude-sonnet-4-6 --record results/fix_sonnet.jsonl
# Ollama: Docker-free scopes only (see caveat)
python -m securepatch_bench fix --provider ollama --model qwen2.5-coder:7b --collection seeded --record results/fix_ollama.jsonl
python -m securepatch_bench fix --provider ollama --model qwen2.5-coder:7b --collection literature --record results/fix_ollama.jsonl
```

> Update this file whenever a run is re-executed — keep the date/cost/verdict
> columns current.
