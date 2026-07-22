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

## Ground truth correction (2026-07-21)

Three cases imported from CWEval carried incorrect type labels, causing every
model that correctly identified the vulnerability to be scored as a miss + false
positive simultaneously. The labels were fixed after manual review of the CWEval
oracle files and confirmed by live detection spot-checks. All recall numbers
below reflect the corrected labels.

| Case | Old type (wrong) | New type (correct) | Root cause |
|---|---|---|---|
| `js-cwe_943_0` | `nosql-injection` | `sql-injection` | CWEval filed a SQLite string-interpolation task under CWE-943 (parent class); exploit and oracle tests are pure SQL injection (CWE-89). Our importer mechanically mapped 943→nosql-injection. |
| `py-cwe_943_0` | `nosql-injection` | `sql-injection` | Same as above (Python version of the same task). |
| `py-cwe_400_0` | `resource-exhaustion` | `redos` | CWEval task directory is named cwe_400 but oracle file header says "CWE-377: Regular expression injection"; secure fix uses `re.escape()`. Models universally reported `redos`; ground truth said `resource-exhaustion`. |

Every AI model that had `fp=1` on these cases was actually correct — it found the
real vulnerability and reported the right type; the matcher penalised it for not
matching our mislabelled type string. Semgrep and OpenAI did not detect
`py-cwe_400_0` even with the corrected label (genuine miss).

## Recall by obscurity tier

| Tier | Cases | Regex | Semgrep | Ollama 7b | OpenAI mini | Gemini 2.5-flash | Opus 4-8 | Sonnet 4-6 | GPT-5.5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| syntactic       | 10 | **100%** | 40% | 80% | 80% | 80% | **100%** | **100%** | 80% |
| local-semantic  | 45 | 22% | 16% | 62% | 82% | 91% | 96% | **100%** | 93% |
| cross-function  | 1  | 0% | 0% | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** |
| **Overall**     | 56 | 38% (21) | 20% (11) | 68% (38) | 82% (46) | 91% (51) | 98% (55) | **100% (56)** | 95% (53) |
| False positives | —  | 1 | **2** | 27 | 6 | 5 | 7 | 10 | 2 |

## Recall by collection

| Collection | Cases | Regex | Semgrep | Ollama | OpenAI | Gemini | Opus | Sonnet | GPT-5.5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cweval     | 44 | 23% | 16% | 61% | 80% | 91% | 96% | **100%** | 93% |
| literature | 6  | 83% | 33% | 83% | 83% | 83% | **100%** | **100%** | 83% |
| seeded     | 6  | 83% | 33% | 83% | 83% | 83% | **100%** | **100%** | 83% |

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
| GPT-5.5      | $1.995 | $0.0356 | ~17.9 min| `results/openai_gpt55_detect.jsonl` |

## Detection observations

1. **AI massively lifts recall** (regex 38% → 68–100%), driven by the
   **local-semantic** tier (regex 22% → up to 100%).
2. **Sonnet achieves perfect recall (100%)** after ground truth correction —
   it never actually failed on the three previously-missed cases, it was being
   penalised for reporting the correct type against mislabelled ground truth.
   Opus reaches 98% (55/56), missing only one case.
3. **Free local model beats regex but is noisy and slow.** Ollama 7b reaches 68%
   recall at $0, but with **27 false positives** (~4× the API models) and ~4×
   the per-case latency. Precision, not recall, is its weakness.
4. **OpenAI + Gemini dip on trivial bugs** (syntactic 80%): both miss two
   *regex-detectable* cases (`cwe-078-cmdi-subprocess`, `py-cmdi-ping`). The
   Claude models don't. Argues for an **ensemble (regex ∪ AI)** safety net.
5. **False positives are lower across the board** after correction (mislabelled
   cases were generating spurious FPs): Sonnet 13→10, Opus 10→7, GPT-5.5 5→2.
6. **GPT-5.5 reaches 95% recall** (corrected), matching pre-correction Sonnet.
   Its FP count of 2 is the lowest of any AI model — it is the most precise
   detector tested, though it still misses two syntactic cases that regex catches.
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
| qwen2.5-coder:7b | 61% | 66% | 68% |
| gpt-4.1-mini     | 77% | 80% | 82% |
| gemini-2.5-flash | 84% | 89% | 91% |
| gpt-5.5          | 95% | 95% | 95% |
| opus-4-8         | 96% | 96% | 98% |
| sonnet-4-6       | 96% | 98% | 100% |

**Local-semantic tier** (the obscure bugs the question is really about)

| Model | @1 | @2 | @3 |
|---|---:|---:|---:|
| qwen2.5-coder:7b | 56% | 62% | 62% |
| gpt-4.1-mini     | 73% | 78% | 82% |
| gemini-2.5-flash | 87% | 91% | 91% |
| gpt-5.5          | 93% | 93% | 93% |
| opus-4-8         | 96% | 96% | 96% |
| sonnet-4-6       | 96% | 98% | **100%** |

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

### Full cross-model matrix (self + every strong-model pairing)

Original run had 4 pairs (2 self, 1 cross, 1 weak→strong). Filled in the missing
cells of the 3×3 strong-model grid (Sonnet, Opus, gpt-4.1-mini) plus Opus
self-judge, so the "does a second model help" question is answered for every
combination, not just one:

| Detector → Judge | TP kept | FP before→after | precision | recall | FPs removed | cost |
|---|---:|---:|---:|---:|---:|---:|
| OpenAI → OpenAI (self) | 40→37 | 8→8 | 83%→82% | 71%→66% | 0 / 8 | $0.030 |
| Sonnet → Sonnet (self) | 52→51 | 15→14 | 78%→78% | 93%→91% | 1 / 15 | $0.442 |
| **Opus → Opus (self)** | 52→49 | 12→12 | 81%→80% | 93%→88% | **0 / 12** | $0.849 |
| OpenAI → Sonnet | 39→38 | 9→9 | 81%→81% | 70%→68% | 0 / 9 | $0.151 |
| **OpenAI → Opus** | 41→38 | 9→9 | 82%→81% | 73%→68% | **0 / 9** | $0.309 |
| **Sonnet → OpenAI** | 52→50 | 14→14 | 79%→78% | 93%→89% | **0 / 14** | $0.268 |
| **Sonnet → Opus** | 53→51 | 12→12 | 82%→81% | 95%→91% | **0 / 12** | $0.654 |
| **Opus → Sonnet** | 50→49 | 12→12 | 81%→80% | 89%→88% | **0 / 12** | $0.641 |
| **Opus → OpenAI** | 50→47 | 10→10 | 83%→82% | 89%→84% | **0 / 10** | $0.471 |
| **Ollama → Sonnet (weak→strong)** | 31→30 | 26→19 | 54%→61% | 55%→54% | **7 / 26** | $0.172 |

(Bold rows are the 6 combos run for this question; the rest were already on
record.)

**Findings:**
1. **The result generalizes cleanly: no pairing among the three strong models
   (Sonnet, Opus, gpt-4.1-mini) removes false positives — self or cross.** All
   9 strong-model cells remove **0 or at most 1** of 8–15 FPs, regardless of
   which model detects and which judges. This isn't a self-verification quirk;
   it's a property of the *capability tier*, not the specific model pairing.
   Every strong-model combination *does*, however, cost 1–4 real bugs (recall
   drops 2–5 points every time) — so cross-judging among strong models is
   **strictly worse than doing nothing**: zero precision gain, guaranteed
   recall loss.
2. **This reinforces, not contradicts, the earlier explanation:** a capable
   detector's "false positives" are mostly plausible real-but-unlabeled
   findings (extra genuine issues beyond the one labeled bug per case), which
   *any* competent judge correctly keeps — Opus doesn't reject Sonnet's extra
   findings any more than Sonnet rejects its own, because from the judge's
   point of view those findings look real. The matcher's FP count reflects
   **incomplete ground truth**, not model noise, so no judge (of any identity)
   can fix it.
3. **The weak→strong pair remains the only one that works** — Sonnet removes
   7/26 (27%) of Ollama's FPs for +7 pts precision at only −1 pt recall. The
   determining factor is a genuine **capability gap**, not "is it a different
   model": Opus judging Sonnet (both frontier) behaves just like Sonnet judging
   Sonnet (self); only Ollama (a real, weaker tier) has junk a stronger judge
   can actually catch.
4. **Consistent ~1–4-bug recall tax scales with judge activity:** every judged
   pass loses at least one real bug (a single-finding view can't trace taint to
   its source), and the strong-model cross pairs lose *more* (2–5 bugs) than
   self-judging typically did (1–3) — mixing models doesn't buy safety, it just
   adds i.i.d.-ish judgment noise on top of the same "real bug looks rejectable
   in isolation" failure mode.

**Design answer — what to do:**
- **Same model: no.** Self-verification is useless (correlated errors).
- **A *different* strong model: also no.** The cross-model strong pairs (6 new
  runs) confirm this isn't specific to self-judging — Opus, Sonnet, and
  gpt-4.1-mini all fail to filter each other's findings, at a real recall cost.
  There is no "best pairing" among strong models; they're all equally useless.
- **Different, *stronger*-tier model as judge: yes — but only across a genuine
  capability gap.** The "detect cheap/local, verify with a frontier model"
  recipe cuts a weak detector's FPs (Ollama +7 pts precision). For any
  frontier detector, verification by another frontier model adds nothing.
- **Never a weaker judge** (it would reject true findings, per the ensemble
  hierarchy).
- **The bigger lever is the benchmark, not a verifier:** for capable models,
  reduce apparent FPs by **completing the ground-truth labels**, not by adding
  a judge.

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

| Verdict | OpenAI mini | Gemini flash | Sonnet | Opus | Ollama 7b (12) | GPT-5.5 |
|---|---:|---:|---:|---:|---:|---:|
| ✅ fixed      | 27 (48%) | 25 (45%) | 19 (34%) | 34 (61%) | 2 (17%) | 36 (64%) |
| ⚠️ regressed  | 23 (41%) | 31 (55%) | 34 (61%) | 17 (30%) | 10 (83%) | 13 (23%) |
| ➖ no-op      | 6 (11%)  | 0        | 3 (5%)   | 5 (9%)   | 0 | 4 (7%) |
| ✗ error      | 0        | 0        | 0        | 0        | 0 | 3 (5%) |

## The `regressed` count is noisy — use functional-fix instead

The strict `fixed` verdict marks a fix regressed if the **AI re-scan flags any new
finding**, and that re-scan is stochastic. Breaking `regressed` down by real cause:

| Regressed cause | OpenAI | Gemini | Sonnet | Opus | Ollama(12) | GPT-5.5 |
|---|---:|---:|---:|---:|---:|---:|
| new-finding only (noisy; compiles + tests pass) | 12 | 9 | 18 | 11 | 3 | 5 |
| test failure (real) | 9 | 7 | 10 | 6 | 3 | 1 |
| compile failure (real) | 2 | **15** | 6 | 0 | 4 | **0** |

**Functional-fix rate** (vuln removed **and** compiles **and** tests/oracle pass,
ignoring the new-finding signal) is the fairer measure:

| Metric | OpenAI | Gemini | Sonnet | Opus | Ollama(12) | GPT-5.5 |
|---|---:|---:|---:|---:|---:|---:|
| strict `fixed` (full 56 / Ollama 12) | 48% | 45% | 34% | 61% | 17% | 64% |
| **functional-fix** (full 56 / Ollama 12) | **68%** | 59% | 62% | **80%** | 25% | **73%** |
| real breakage (compile+test) | 11 | 22 | 16 | 6 | 7 | 1 |

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
| GPT-5.5     | $1.841 | $0.0329 | ~30.5 min | `results/fix_gpt55.jsonl` |

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
5. **GPT-5.5 is a strong fixer (73% functional-fix) despite being a weak detector
   (89%).** It produces **0 compile failures** (matching Opus) and only 1 real
   test failure — the cleanest fix behavior of any OpenAI model tested. At $1.84
   for 56 attempts it is expensive (~66× gpt-4.1-mini's fix cost, ~2.5× Opus's),
   making it cost-uncompetitive as a fixer unless its 73% rate (between OpenAI
   mini 68% and Opus 80%) is specifically needed. The 3 errors
   (`js-cwe_095_0`, `js-cwe_918_1`, `py-cwe_1333_0`) are the same complex cases
   that stall other models.
6. **`regressed` needs the reason breakdown to mean anything** — roughly half of
   all regressions are noisy "new-finding-only" from the stochastic re-scan. Next
   improvement: gate new-findings with a *deterministic* detector (regex, or the
   oracle's own security check) instead of the AI re-scan.
6. **The Docker oracle scaled cleanly** — 43–44 of 56 cases verified with the
   exploit-based `security` oracle, zero pipeline errors across four full runs.
7. **Two "product" recipes, by budget:** cost-sensitive → detect with Sonnet,
   **fix with `gpt-4.1-mini`** (cheapest good fixer); quality-first → **detect
   and fix with Opus** (best fixer, and ties Opus/Sonnet at 100% on syntactic
   detection) if the ~13×-vs-Sonnet fix cost is acceptable.

## Mixed pipeline — best detector (Sonnet) hands off to a different fixer

**Caveat on what "detector" means in the fix loop first:** `run_fixloop`
(`fixloop.py::_fix_one`) attempts **every ground-truth bug in every case**, not
just the bugs a detector actually found — a missed detection falls back to the
bug's ground-truth metadata for the fix prompt. So every existing self-model fix
run (`fix_sonnet.jsonl`, `fix_opus.jsonl`, `fix_openai.jsonl`) already fixes all
56 bugs regardless of the model's own recall; the detector only supplies a
*richer finding description* (line/type/title/description) when it happens to
catch the bug itself, vs. the bare ground-truth fields on a miss. That makes the
self-vs-mixed comparison **cleaner than it first looks**: the only variable a
mixed pipeline changes is *whose enrichment text* the fixer sees, isolating
exactly the question asked ("does handing the best detector's findings to a
different fixer help") without needing a separate coverage-filtering run.

Added `--detect-provider`/`--detect-model` to the `fix` CLI to decouple the two
roles, then ran: **Sonnet detects (best detector, 95% recall) → Opus fixes**
and **Sonnet detects → gpt-4.1-mini fixes**, both over the full 56 cases.

| Pipeline | fixed | func-fix | real breakage (test+compile) | cost | $/attempt |
|---|---:|---:|---:|---:|---:|
| Sonnet detect + **Sonnet** fix (self) | 19 | 37/56 (66%) | 16 | $0.330 | $0.0059 |
| Opus detect + **Opus** fix (self) | 34 | 45/56 (80%) | 6 | $0.731 | $0.0131 |
| OpenAI detect + **OpenAI** fix (self) | 27 | 39/56 (70%) | 11 | $0.028 | $0.0005 |
| **Sonnet detect → Opus fix** | 28 | **44/56 (79%)** | 8 | $0.735 | $0.0131 |
| **Sonnet detect → gpt-4.1-mini fix** | 24 | **44/56 (79%)** | **7** | **$0.030** | **$0.0005** |

*(Self-model numbers here are recomputed directly from the JSONL with one
consistent rule — `fixed` + regressed-with-new-finding-only — for a clean
apples-to-apples read; they differ by ~1–2 points from the rounded figures
earlier in this doc, which is rounding/methodology drift between passes, not
new data.)*

**Findings:**
1. **The split pipeline is smart, and one pairing is a clear win.** Handing
   Sonnet's findings to `gpt-4.1-mini` for fixing gets **79% functional-fix —
   9 points above solo gpt-4.1-mini (70%) and just 1 point under solo Opus
   (80%) — at gpt-4.1-mini's cost ($0.030 for all 56 cases, ~24× cheaper than
   Opus's $0.735).** That's the best cost/quality point on the whole grid: a
   near-frontier-fixer outcome for cents.
2. **Sonnet detect → Opus fix does *not* beat Opus fixing itself** (79% vs
   80%, within noise) and costs about the same ($0.735 vs $0.731) — pairing two
   frontier models doesn't add anything over just using Opus for both roles.
   The benefit of splitting only shows up when the *fixer* alone is the weak
   link (gpt-4.1-mini), not when it's already strong (Opus).
3. **Sonnet's enrichment measurably improves fix quality for both downstream
   fixers**, and specifically **cleans up compile failures**: mixed
   gpt-4.1-mini fixing goes from 2 compile failures solo to **0** paired with
   Sonnet's findings, and real breakage drops from 11 (solo) to 7 (mixed).
   Mixed Sonnet→Opus also holds Opus's compile failures at 0. A richer,
   correctly-typed finding description (line, CWE, title) gives the fixer a
   more precise target, which shows up as fewer malformed patches — not just
   as noise reduction in the "new-finding-only" bucket.
4. **Practical recipe, sharpened:** the "detect with Sonnet, fix with
   `gpt-4.1-mini`" recipe already recommended above is *confirmed* by this
   controlled comparison (rather than inferred from two separate single-model
   runs) — it beats solo gpt-4.1-mini by 9 points at no extra cost, and nearly
   matches Opus at ~4% of Opus's price. If cost is genuinely no constraint,
   solo Opus (80%) edges out the mixed Opus pipeline (79%, same cost) very
   slightly, so there's no reason to route Opus's fixer through a different
   detector — but there's every reason to route a cheap fixer through Sonnet's
   detector first.

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

# --- Cross-model verification matrix (does a 2nd model cut false positives?) ---
python -m securepatch_bench verify-findings --provider anthropic --model claude-opus-4-8 \
    --verify-provider anthropic --verify-model claude-opus-4-8 --record results/verify_opus_self.jsonl
python -m securepatch_bench verify-findings --provider openai --model gpt-4.1-mini \
    --verify-provider anthropic --verify-model claude-opus-4-8 --record results/verify_openai_by_opus.jsonl
python -m securepatch_bench verify-findings --provider anthropic --model claude-sonnet-4-6 \
    --verify-provider openai --verify-model gpt-4.1-mini --record results/verify_sonnet_by_openai.jsonl
python -m securepatch_bench verify-findings --provider anthropic --model claude-sonnet-4-6 \
    --verify-provider anthropic --verify-model claude-opus-4-8 --record results/verify_sonnet_by_opus.jsonl
python -m securepatch_bench verify-findings --provider anthropic --model claude-opus-4-8 \
    --verify-provider anthropic --verify-model claude-sonnet-4-6 --record results/verify_opus_by_sonnet.jsonl
python -m securepatch_bench verify-findings --provider anthropic --model claude-opus-4-8 \
    --verify-provider openai --verify-model gpt-4.1-mini --record results/verify_opus_by_openai.jsonl

# --- Mixed detect->fix pipeline (best detector Sonnet -> a different fixer) ---
python -m securepatch_bench fix --provider anthropic --model claude-opus-4-8 \
    --detect-provider anthropic --detect-model claude-sonnet-4-6 \
    --record results/fix_mixed_sonnetdetect_opusfix.jsonl
python -m securepatch_bench fix --provider openai --model gpt-4.1-mini \
    --detect-provider anthropic --detect-model claude-sonnet-4-6 \
    --record results/fix_mixed_sonnetdetect_openaifix.jsonl

# --- GPT-5.5 (detection + fix) ---
python -m securepatch_bench bench --detector ai --provider openai --model gpt-5.5 \
    --scans 3 --record results/openai_gpt55_detect.jsonl
python -m securepatch_bench fix --provider openai --model gpt-5.5 \
    --record results/fix_gpt55.jsonl
```

> Update this file whenever a run is re-executed — keep the date/cost/verdict
> columns current.
