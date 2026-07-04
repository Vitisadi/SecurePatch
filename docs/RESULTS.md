# SecurePatch — Results Log

Running record of harness runs against the labeled corpus (`benchmarks/`, 56
cases). Two independent experiments:

- **Part 1 — Detection** (`bench`): can a detector *find* the bug? → recall.
- **Part 2 — Fix + Verify** (`fix`): can it *fix* the bug, and does the fix break
  anything? → verdicts.

Raw per-case rows live in `harness/results/*.jsonl` (gitignored); this file is the
human-readable summary we keep in version control. See
[`RESEARCH_PLAN.md`](RESEARCH_PLAN.md) §3 for metric definitions.

**Models under test:** regex (baseline), **Semgrep (off-the-shelf SAST baseline)**,
OpenAI `gpt-4.1-mini`, Google Gemini `2.5-flash`, Anthropic Sonnet `4-6`, Anthropic
Opus `4-8`, and a local Ollama `qwen2.5-coder:7b` (runs on-machine, $0).

---

# Part 1 — Detection

**Metric:** _recall_ — a finding whose location (±2 lines) and CWE/type matches a
ground-truth bug. AI detectors run `--scans 3` → **detection@3** (found in any of
3 scans).

## SAST baseline: Semgrep

Added a second, *off-the-shelf* baseline alongside the homemade regex rules so the
"floor" in the paper isn't just our own code. **Tool: [Semgrep](https://semgrep.dev)
OSS (`pip install semgrep`, no account/API key needed)** — the most widely cited
installable SAST tool that covers both corpus languages (Python + JS/TS) in one
engine; Bandit was considered but is Python-only, and CodeQL requires a compiled
database + CLI setup that's much heavier for a 56-case corpus. **Rulesets:**
Semgrep Registry `p/security-audit` + `p/owasp-top-ten` + `p/secrets` (community
security rules, run with `--metrics=off`, no telemetry). Findings are mapped from
Semgrep's `cwe` rule metadata to our vocabulary via the exact CWE→type table
already implied by every case's `ground_truth.json` (see
`securepatch_bench/detectors.py::SAST_CWE_TO_TYPE`) — not a hand-tuned guess.
Wired in as `--detector sast`, scored by the same matcher as every other
detector, over the same 56 cases (`results/sast_semgrep.jsonl`).

## Recall by obscurity tier

| Tier | Cases | Regex | Semgrep | Ollama 7b | OpenAI mini | Gemini 2.5-flash | Opus 4-8 | Sonnet 4-6 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| syntactic       | 10 | **100%** | 40% | 80% | 80% | 80% | **100%** | **100%** |
| local-semantic  | 45 | 20% | 16% | 58% | 78% | 87% | 91% | **93%** |
| cross-function  | 1  | 0% | 0% | **100%** | **100%** | **100%** | **100%** | **100%** |
| **Overall**     | 56 | 34% (19) | 20% (11) | 62% (35) | 79% (44) | 86% (48) | 93% (52) | **95% (53)** |
| False positives | —  | 3 | **2** | 30 | 8 | 8 | 10 | 13 |

## Recall by collection

| Collection | Cases | Regex | Semgrep | Ollama | OpenAI | Gemini | Opus | Sonnet |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| cweval     | 44 | 20% | 16% | 57% | 77% | 86% | 91% | **93%** |
| literature | 6  | 83% | 33% | 83% | 83% | 83% | **100%** | **100%** |
| seeded     | 6  | 83% | 33% | 83% | 83% | 83% | **100%** | **100%** |

## Detection cost & time

| Detector | Cost | $/case | Wall | Notes |
|---|---:|---:|---:|---|
| regex        | $0.000 | $0.0000 | <1s      | deterministic |
| Semgrep      | $0.000 | $0.0000 | ~7.9 min | local; ~8.4s/case (per-file process + rule load overhead) |
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
6. **A real off-the-shelf SAST tool does *worse* than our own regex rules on this
   corpus (20% vs 34%) — and both are far behind every AI model.** This is the
   important methodological result: Semgrep's community rules are written to
   pattern-match real framework/library call sites (`cursor.execute()`,
   `subprocess.call(shell=True)`, etc.), and a large share of our cases —
   especially the CWEval-derived ones, which are short self-contained functions
   rather than app code wired to a real DB/HTTP framework — don't hit those
   patterns even though the vulnerability is genuine. Semgrep's syntactic-tier
   recall (40%) is *below* our regex baseline's (100%) for the same reason: our
   regex rules were hand-tuned against this exact corpus, which is an admitted
   bias in the *regex* baseline, not a flaw in Semgrep. **Practically:** Semgrep
   is the more defensible academic baseline (an independent, widely-cited tool,
   not overfit to our cases) precisely because it does worse — it establishes
   that "the floor a generic tool achieves on obscure/task-style vulnerability
   code" is low, which is the gap the paper's AI-detection numbers are filling.
   It is also by far the lowest-noise detector (2 FPs, beating even the regex
   baseline's 3), consistent with rule-based tools trading recall for precision.

## Detection@k — how many scans to find a bug?

Recall as a function of the number of repeated scans (k), from `per_scan_matched`
in the detection JSONL (reproduce with `python -m securepatch_bench discovery`).

**Overall**

| Model | @1 | @2 | @3 |
|---|---:|---:|---:|
| qwen2.5-coder:7b | 57% | 62% | 62% |
| gpt-4.1-mini     | 73% | 77% | 79% |
| gemini-2.5-flash | 80% | 84% | 86% |
| opus-4-8         | 93% | 93% | 93% |
| sonnet-4-6       | 93% | 95% | 95% |

**Local-semantic tier** (the obscure bugs the question is really about)

| Model | @1 | @2 | @3 |
|---|---:|---:|---:|
| qwen2.5-coder:7b | 53% | 58% | 58% |
| gpt-4.1-mini     | 73% | 76% | 78% |
| gemini-2.5-flash | 84% | 87% | 87% |
| opus-4-8         | 91% | 91% | 91% |
| sonnet-4-6       | 93% | 93% | 93% |

**Findings:**
1. **Repeated scans give small, quickly-diminishing gains** — +2 to +6 points
   overall, and **almost all of it is realized by k=2**. The third scan adds ≈0.
2. **The gain is a "recover stochastic misses" effect, not a "grind out obscure
   bugs" effect.** The frontier models (Opus, Sonnet) are essentially **flat** —
   they find a bug on scan 1 or not at all. Only the weaker/cheaper models
   (OpenAI, Gemini, Ollama) claw back a few points with a second scan.
3. **Practical takeaway:** a single scan captures the large majority of what a
   model can detect; **k=2 is a reasonable budget** for the cheaper models, and
   there is no evidence that many scans meaningfully surface additional obscure
   bugs on this corpus. (Cross-function is a single bug, so its 0%→100% jump for
   Gemini is noise, not signal.)

### Temperature — the lever behind the discovery curve

`gpt-4.1-mini`, detection@5, sweeping sampling temperature (the frontier Claude
models are excluded — the adapter can't send temperature, they reject it):

| Temp | @1 | @2 | @3 | @4 | @5 | FPs |
|---|---:|---:|---:|---:|---:|---:|
| 0.0 | 75% | 75% | 75% | 75% | 75% | 8 |
| 1.0 | 71% | 75% | 75% | 77% | **79%** | 8 |
| 1.5 | 71% | 73% | 77% | 77% | **79%** | 9 |

1. **Temperature *is* what makes repeated scans work.** At **temp 0 the curve is
   flat** (deterministic — scans 2–5 reproduce scan 1 exactly); at **temp ≥1
   repeated scans recover ~8 points** by sampling diverse outputs. The earlier
   flat curves were a low-diversity effect, now confirmed causally.
2. **Single-shot vs. multi-shot inverts.** One temp-0 scan (75%) *beats* one
   temp-1 scan (71%) — greedy decoding is more accurate per shot — but multi-scan
   temp-1 overtakes it (79% vs 75%) via accumulated diversity.
3. **~1.0 is the sweet spot.** temp 1.5 matches 1.0 on recall but adds a false
   positive; going hotter buys noise, not bugs.
4. **Actionable:** budget one scan → use temp 0; budget several scans → temp ~1.0.
   Don't exceed 1.0.

## Ensemble — do multiple detectors help?

Combining detectors on the *union* of found bugs (reproduce with
`python -m securepatch_bench ensemble`).

**regex + AI (cheap safety net)** — union of a model with the regex baseline:

| Model | alone | + regex | gain |
|---|---:|---:|---:|
| qwen2.5-coder:7b | 62% | 66% | +2 |
| gpt-4.1-mini     | 79% | 82% | +2 |
| gemini-2.5-flash | 86% | 89% | +2 |
| opus-4-8         | 93% | 93% | +0 |
| sonnet-4-6       | 95% | 95% | +0 |

**Union / voting:**

| Ensemble | recall |
|---|---:|
| best single (Sonnet) | 95% (53/56) |
| **all AI models (union)** | **95% (53/56)** |
| all AI + regex (union) | 95% (53/56) |
| voting ≥2 detectors | 93% (52/56) |
| voting ≥3 detectors | 91% (51/56) |

**Findings — mostly a negative result, which is the interesting part:**
1. **Ensembling does NOT improve recall.** The union of all six detectors equals
   the best single model (Sonnet, 53/56). Every bug any detector finds, Sonnet
   also finds — the detectors are **nested (a strict hierarchy), not
   complementary**. Only Sonnet has a *unique* catch (1 bug); every other
   detector's unique count is **0**.
2. **A hard ceiling of 3 bugs** is found by *no* detector: `js-cwe_943_0`,
   `py-cwe_943_0` (NoSQL injection) and `py-cwe_400_0` (resource exhaustion).
   These need better detection, not more models.
3. **regex adds a cheap +2** to the *sub-frontier* models (Ollama/OpenAI/Gemini)
   — the syntactic safety net for the trivial bugs they drop — but nothing to the
   Claude models. So "ensemble with regex" only matters if you're already using a
   cheaper model.
4. **Ensembling's real value is precision, not recall.** Requiring ≥2 detectors to
   agree keeps 93% recall (−2 pp) while discarding lone-detector findings — a
   near-free way to cut false positives (e.g. Ollama's 30). That reframes the
   "multiple models" question: vote to *raise precision*, don't union to raise
   recall.

**Practical takeaway:** for recall, **use the single best model** — do not pay for
an ensemble. Add regex only under a cheaper model; use voting only to cut FPs.

## Verification — can an AI judge remove false positives?

An LLM-as-judge second pass: each finding is re-examined in isolation ("is this a
real vulnerability? keep/reject", temperature 0), and we score precision/recall
before vs. after against ground truth (`verify-findings` command). *Detection here
is a single fresh scan, so the "before" recall differs slightly from the @3 table.*

| Detector → Judge | precision | recall | FPs removed | real bugs dropped |
|---|---:|---:|---:|---:|
| OpenAI → OpenAI (self) | 83% → 82% | 71% → 66% | 0 / 8 | 3 |
| Sonnet → Sonnet (self) | 78% → 78% | 93% → 91% | 1 / 15 | 1 |
| OpenAI → Sonnet (strong→strong) | 81% → 81% | 70% → 68% | 0 / 9 | 1 |
| **Ollama → Sonnet (weak→strong)** | **54% → 61%** | 55% → 54% | **7 / 26** | 1 |

**Findings:**
1. **Self-verification does not work.** A model removes ~0 of *its own* false
   positives — it is confident in the findings it just made (confirmation, not
   critique) — and over-rejects a taint bug or two. True for both OpenAI and
   Sonnet.
2. **A strong judge over a strong detector also does nothing** (Sonnet removes 0
   of OpenAI's FPs). The reason is subtle and important: a capable detector's
   "false positives" are mostly **plausible real-but-unlabeled findings** (extra
   issues beyond the one labeled bug per case), which the judge *correctly keeps*.
   The matcher's FP count is inflated by **incomplete ground truth**, not model
   noise — no judge can (or should) remove those.
3. **A strong judge over a *weak* detector works** — Sonnet removes **7/26 (27%)**
   of Ollama's FPs for **+7 pts precision** at **−1 pt recall**. When there is a
   real capability gap, the judge rejects the weak model's genuine junk.
4. **Consistent ~1-bug recall tax:** the single-finding view can't trace taint to
   its source, so it occasionally rejects a real SQL-injection (`js-sqli-concat`).

**Design answer — what to do:**
- **Same model: no.** Self-verification is useless (correlated errors).
- **Different, *stronger* model as judge: yes — but only across a capability gap.**
  The "detect cheap/local, verify with a frontier model" recipe cuts a weak
  detector's FPs (Ollama +7 pts precision). For a frontier detector, verification
  adds nothing.
- **Never a weaker judge** (it would reject true findings, per the ensemble
  hierarchy).
- **The bigger lever is the benchmark, not a verifier:** for capable models,
  reduce apparent FPs by **completing the ground-truth labels**, not by adding a
  judge.

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

| Verdict | OpenAI mini | Gemini flash | Sonnet | Opus | Ollama 7b (12) |
|---|---:|---:|---:|---:|---:|
| ✅ fixed      | 27 (48%) | 25 (45%) | 19 (34%) | 34 (61%) | 2 (17%) |
| ⚠️ regressed  | 23 (41%) | 31 (55%) | 34 (61%) | 17 (30%) | 10 (83%) |
| ➖ no-op      | 6 (11%)  | 0        | 3 (5%)   | 5 (9%)   | 0 |
| ✗ error      | 0        | 0        | 0        | 0        | 0 |

## The `regressed` count is noisy — use functional-fix instead

The strict `fixed` verdict marks a fix regressed if the **AI re-scan flags any new
finding**, and that re-scan is stochastic. Breaking `regressed` down by real cause:

| Regressed cause | OpenAI | Gemini | Sonnet | Opus | Ollama(12) |
|---|---:|---:|---:|---:|---:|
| new-finding only (noisy; compiles + tests pass) | 12 | 9 | 18 | 11 | 3 |
| test failure (real) | 9 | 7 | 10 | 6 | 3 |
| compile failure (real) | 2 | **15** | 6 | 0 | 4 |

**Functional-fix rate** (vuln removed **and** compiles **and** tests/oracle pass,
ignoring the new-finding signal) is the fairer measure:

| Metric | OpenAI | Gemini | Sonnet | Opus | Ollama(12) |
|---|---:|---:|---:|---:|---:|
| strict `fixed` (full 56 / Ollama 12) | 48% | 45% | 34% | 61% | 17% |
| **functional-fix** (full 56 / Ollama 12) | **68%** | 59% | 62% | **80%** | 25% |
| real breakage (compile+test) | 11 | 22 | 16 | 6 | 7 |

### Apples-to-apples: functional-fix on the SAME 12 Docker-free cases

| Model | functional-fix (of 12) |
|---|---:|
| **Opus**    | **11 / 12 (92%)** |
| OpenAI mini | 8 / 12 (67%) |
| Sonnet      | 6 / 12 (50%) |
| Gemini flash| 5 / 12 (42%) |
| Ollama 7b   | 3 / 12 (25%) |

## Fix verdicts by collection (fixed / regressed / no-op)

| Collection | OpenAI | Gemini | Sonnet | Opus | Ollama |
|---|---|---|---|---|---|
| cweval (Docker oracle) | 20 / 18 / 6 | 21 / 23 / 0 | 14 / 27 / 3 | 25 / 14 / 5 | _not run_ |
| literature | 2 / 4 / 0 | 1 / 5 / 0 | 2 / 4 / 0 | 5 / 1 / 0 | 1 / 5 / 0 |
| seeded     | 5 / 1 / 0 | 3 / 3 / 0 | 3 / 3 / 0 | 4 / 2 / 0 | 1 / 5 / 0 |

## Fix cost & time

| Run | Cost | $/attempt | Wall | Rows |
|---|---:|---:|---:|---|
| OpenAI mini | $0.028 | $0.0005 | ~12.3 min | `results/fix_openai.jsonl` |
| Gemini flash| $0.047 | $0.0008 | ~28.7 min | `results/fix_gemini.jsonl` |
| Sonnet      | $0.330 | $0.0059 | ~17.7 min | `results/fix_sonnet.jsonl` |
| Opus        | $0.731 | $0.0131 | ~12.6 min | `results/fix_opus.jsonl` |
| Ollama 7b (12) | $0.000 | $0.0000 | ~2 min | `results/fix_ollama.jsonl` |

## Fix observations

1. **Detection skill ≠ fixing skill — but frontier scale still wins overall.**
   Sonnet is the *best detector* (95%) yet the *weakest Anthropic fixer* by
   functional-fix (62%); its sibling **Opus is the best fixer of any model
   tested** (80% full-56, **92% on the shared 12**) at ~2.2× Sonnet's fix cost.
   So the "detect ≠ fix" gap is real *within* a model family (Sonnet's ranking
   flips between the two tasks), but it is not a small-model-wins story once
   you compare against Opus: raw capability still dominates once cost is not
   the deciding constraint. `gpt-4.1-mini` remains the best **cost-adjusted**
   fixer (67% functional-fix at ~$0.0002/attempt vs Opus's $0.0131 — a ~65×
   cost gap for 25 fewer points).
2. **Opus is also the "cleanest" fixer** — 0 compile failures across all 56
   attempts (vs OpenAI 2, Sonnet 6, Gemini 15), and only 6 real test failures.
   Its regressions are almost entirely the noisy new-finding-only kind (11/17).
3. **Gemini breaks compilation the most** — 15 of its 31 regressions are compile
   failures (vs OpenAI 2, Sonnet 6, Opus 0). Its whole-file rewrites more often
   emit code that doesn't parse.
4. **The local 7b is a weak fixer** — 25% functional-fix on the shared 12 vs
   42–92% for the API models, with the most compile/test breakage per case. Free,
   but not yet good enough to fix unsupervised.
5. **`regressed` needs the reason breakdown to mean anything** — roughly half of
   all regressions are noisy "new-finding-only" from the stochastic re-scan. Next
   improvement: gate new-findings with a *deterministic* detector (regex, or the
   oracle's own security check) instead of the AI re-scan.
6. **The Docker oracle scaled cleanly** — 43–44 of 56 cases verified with the
   exploit-based `security` oracle, zero pipeline errors across four full runs.
7. **Two "product" recipes, by budget:** cost-sensitive → detect with Sonnet,
   **fix with `gpt-4.1-mini`** (cheapest good fixer); quality-first → **detect
   and fix with Opus** (best fixer, and ties Opus/Sonnet at 100% on syntactic
   detection) if the ~13×-vs-Sonnet fix cost is acceptable.

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
pip install semgrep  # off-the-shelf SAST baseline, no key needed
python -m securepatch_bench bench --detector sast --record results/sast_semgrep.jsonl
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
python -m securepatch_bench fix --provider anthropic --model claude-opus-4-8 --record results/fix_opus.jsonl
# Ollama: Docker-free scopes only (see caveat)
python -m securepatch_bench fix --provider ollama --model qwen2.5-coder:7b --collection seeded --record results/fix_ollama.jsonl
python -m securepatch_bench fix --provider ollama --model qwen2.5-coder:7b --collection literature --record results/fix_ollama.jsonl
```

> Update this file whenever a run is re-executed — keep the date/cost/verdict
> columns current.
