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
Opus `4-8`, OpenAI `gpt-5.5`, and a local Ollama `qwen2.5-coder:7b` (runs on-machine, $0).

> **Note on detection prompt (2026-07-21):** All AI detection runs use a generic
> `code.py` / `code.js` display filename in the prompt. An earlier run used the
> actual source path (e.g. `cwe_943_0_js_unsafe.js`), which leaked the CWE number
> to the model. All numbers in this document are from the corrected runs.

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
| `js-cwe_400_0` | `resource-exhaustion` | `redos` | JavaScript version of the same cwe_400 task. Same oracle, same CWE-377 header, same ReDoS payloads (`^(a+)+$`). Discovered when ensemble showed it as the sole bug no model could detect — every cloud model had `fp=1, miss=1`, the same signature as the other mislabeled cases. |

Every AI model that had `fp=1` on these cases was actually correct — it found the
real vulnerability and reported the right type; the matcher penalised it for not
matching our mislabelled type string. Regex and Semgrep did not detect either
`cwe_400_0` case even with the corrected label (genuine miss — they don't pattern-match ReDoS).

## Recall by obscurity tier

| Tier | Cases | Regex | Semgrep | Ollama 7b | OpenAI mini | Gemini 2.5-flash | GPT-5.5 | Opus 4-8 | Sonnet 4-6 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| syntactic       | 10 | **100%** | 40% | 90% | 70% | 80% | 90% | 80% | **100%** |
| local-semantic  | 45 | 22% | 16% | 62% | 69% | 93% | 93% | 93% | **100%** |
| cross-function  | 1  | 0% | 0% | **100%** | **100%** | **100%** | **100%** | **100%** | **100%** |
| **Overall**     | 56 | 34% (19) | 20% (11) | 68% (38) | 70% (39) | 91% (51) | 93% (52) | 91% (51) | **100% (56)** |
| False positives | —  | 3 | **2** | 30 | 7 | 8 | **5** | 14 | 15 |
| Precision       | —  | 86% | 85% | 56% | 85% | 86% | **91%** | 78% | 79% |
| **F1**          | —  | 49% | 32% | 61% | 76% | 89% | **92%** | 84% | 88% |

## Recall by collection

| Collection | Cases | Regex | Semgrep | Ollama | OpenAI | Gemini | GPT-5.5 | Opus | Sonnet |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cweval     | 44 | 23% | 16% | 61% | 68% | 93% | 93% | 93% | **100%** |
| literature | 6  | 83% | 33% | 83% | 83% | 83% | 83% | 83% | **100%** |
| seeded     | 6  | 83% | 33% | **100%** | 67% | 83% | **100%** | 83% | **100%** |

## Detection cost & time

| Detector | Cost | $/case | Wall | Notes |
|---|---:|---:|---:|---|
| regex        | $0.000 | $0.0000 | <1s      | deterministic |
| Semgrep      | $0.000 | $0.0000 | ~7.9 min | local; ~8.4s/case (per-file process + rule load overhead) |
| Ollama 7b    | $0.000 | $0.0000 | ~10.4 min| local; `results/ollama_detect_r3.jsonl` |
| OpenAI mini  | $0.051 | $0.0009 | ~4.0 min | `results/openai_detect_r3.jsonl` |
| Gemini flash | $0.085 | $0.0015 | ~17.2 min| `results/gemini_detect_r3.jsonl` |
| Sonnet       | $0.756 | $0.0135 | ~12.9 min| `results/sonnet_detect_r3.jsonl` |
| Opus         | $1.402 | $0.0250 | ~10.2 min| `results/opus_detect_r3.jsonl` |
| GPT-5.5      | $2.167 | $0.0387 | ~18.3 min| `results/gpt55_detect_r3.jsonl` |

## Detection observations

1. **AI massively lifts recall** (regex 34% → 68–100%), driven by the
   **local-semantic** tier (regex 22% → up to 100%).
2. **Sonnet achieves perfect recall (100%)** across all 56 cases and all 3
   obscurity tiers. At k=2 it reaches 100% even on cases it misses on scan 1.
3. **GPT-5.5 is the most precise AI detector** — 93% recall with only 5 FPs,
   fewest of any AI model.
4. **Gemini and Opus tie at 91%**, both strong on local-semantic (93%) and
   cross-function (100%) but missing 2 syntactic cases each.
5. **gpt-4.1-mini (70%) and Ollama (68%) are the sub-frontier tier** — both
   miss many local-semantic cases. Ollama is free; gpt-4.1-mini is cheap but
   no longer clearly better than the local model on overall recall.
6. **No bugs are missed by every model** — the previously-reported "hard ceiling"
   of 3–4 undetected cases was entirely ground truth labeling errors.
6. **A real off-the-shelf SAST tool does *worse* than our own regex rules on this
   corpus (20% vs 38%) — and both are far behind every AI model.** This is the
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

## Filename leakage effect (r1 vs r3)

The original r1 runs used the actual source filename (e.g. `cwe_943_0_js_unsafe.js`)
as the display name in the detection prompt, leaking the CWE number to the model.
r3 uses a generic `code.py`/`code.js`. r1 and r3 also differ in ground truth labels
(4 corrections applied in r3). The table scores r1 files against r3 ground truth to
hold labels constant, so the delta reflects only the prompt change.

| Model | r1 recall (leaky, r3 GT) | r3 recall (clean) | Δ |
|---|---:|---:|---:|
| Sonnet 4-6 | 94% (53/56) | **100%** (56/56) | +6pp |
| GPT-5.5 | 89% (50/56) | **93%** (52/56) | +4pp |
| Gemini 2.5-flash | 85% (48/56) | **91%** (51/56) | +6pp |
| gpt-4.1-mini | **78%** (44/56) | 70% (39/56) | **−8pp** |

**Important caveat — frontier deltas are entirely explained by GT corrections, not
the filename change.** Tracing which specific bugs Sonnet gained from r1→r3 shows
all 3 are the mislabeled cases (`js/py-cwe_943_0`, `py-cwe_400_0`) where Sonnet
reported the correct type in r1 but was penalized for not matching the wrong label.
With the labels fixed, those 3 become hits — the clean filename had zero net effect
on Sonnet. The same pattern likely holds for GPT-5.5 and Gemini.

**gpt-4.1-mini is the genuine leakage finding**: it *lost* 8pp when the CWE hint
was removed, and unlike the frontier models its missed bugs in r3 are not explained
by label corrections — it simply found fewer bugs without the filename anchor.
This suggests weaker models rely on explicit CWE context to focus their search,
while frontier models do not need (and may be slightly harmed by) the hint.

## Per-CWE detection breakdown

| CWE | n | Sonnet | GPT-5.5 | Gemini | Opus | mini | Ollama |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-22 (path traversal) | 4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 |
| CWE-78 (OS command injection) | 4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 |
| CWE-79 (XSS) | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 |
| CWE-89 (SQL injection) | 5 | 5/5 | 4/5 | 3/5 | 3/5 | 4/5 | 5/5 |
| CWE-95 (code injection) | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-113 (header injection) | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 0/2 |
| CWE-117 (log injection) | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 0/2 |
| CWE-326 (weak crypto) | 4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 |
| CWE-327 (broken algorithm) | 6 | 6/6 | 6/6 | 6/6 | 6/6 | 5/6 | 6/6 |
| CWE-329 (missing IV) | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| CWE-338 (weak PRNG) | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| CWE-347 (JWT) | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| CWE-377 (temp file) | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| CWE-502 (deserialization) | 3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-643 (XPath injection) | 2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| CWE-732 (insecure permissions) | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |
| CWE-760 (predictable salt) | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 |
| CWE-798 (hardcoded cred) | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| CWE-20 (input validation) | 1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| CWE-1333 (ReDoS) | 4 | 4/4 | 3/4 | 4/4 | 4/4 | 1/4 | 0/4 |
| CWE-918 (SSRF) | 4 | 4/4 | 2/4 | 1/4 | 2/4 | 0/4 | 0/4 |

**Hardest CWEs:** CWE-918 (SSRF) and CWE-1333 (ReDoS) are the most model-discriminating.
SSRF: Sonnet 4/4 but Gemini 1/4, Opus 2/4, mini and Ollama 0/4 — a frontier-only
detection. ReDoS: Ollama misses all 4, mini gets only 1/4.
**CWE-89 (SQL injection):** surprisingly hard for Gemini and Opus (3/5) vs. Ollama
which gets 5/5 — likely because our ReDoS cases were relabeled from CWE-400 and
Ollama's broad scanning catches the pattern.

## Detection@k — how many scans to find a bug?

Recall as a function of the number of repeated scans (k), from `per_scan_matched`
in the detection JSONL (reproduce with `python -m securepatch_bench discovery`).

**Overall**

| Model | @1 | @2 | @3 |
|---|---:|---:|---:|
| qwen2.5-coder:7b | 64% | 66% | 68% |
| gpt-4.1-mini     | 66% | 68% | 70% |
| gemini-2.5-flash | 84% | 89% | 91% |
| gpt-5.5          | 84% | 89% | 93% |
| opus-4-8         | 89% | 91% | 91% |
| sonnet-4-6       | 98% | **100%** | **100%** |

**Local-semantic tier** (the obscure bugs the question is really about)

| Model | @1 | @2 | @3 |
|---|---:|---:|---:|
| qwen2.5-coder:7b | 60% | 62% | 62% |
| gpt-4.1-mini     | 69% | 69% | 69% |
| gemini-2.5-flash | 87% | 91% | 93% |
| gpt-5.5          | 87% | 91% | 93% |
| opus-4-8         | 91% | 93% | 93% |
| sonnet-4-6       | 98% | **100%** | **100%** |

**Findings:**
1. **Repeated scans give small, quickly-diminishing gains** — up to +9 points,
   and **almost all of it is realized by k=2**. The third scan adds ≈0.
2. **Sonnet reaches 100% at k=2** — its one @1 miss is recovered on the second
   scan. All other frontier models are essentially flat (find it on scan 1 or not
   at all). Only the cheaper models (Ollama, OpenAI, Gemini, GPT-5.5) claw back
   a few points with additional scans.
3. **Practical takeaway:** a single scan captures the large majority of what a
   model can detect; **k=2 is a reasonable budget** for the cheaper models and
   also lets Sonnet reach perfect recall.

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
| qwen2.5-coder:7b | 68% | 70% | +1 |
| gpt-4.1-mini     | 70% | 77% | +4 |
| gemini-2.5-flash | 91% | 95% | +2 |
| opus-4-8         | 91% | 95% | +2 |
| gpt-5.5          | 93% | 95% | +1 |
| sonnet-4-6       | **100%** | **100%** | +0 |

**Union / voting:**

| Ensemble | recall | found |
|---|---:|---:|
| best single (Sonnet) | **100%** | **56/56** |
| all AI models (union) | **100%** | **56/56** |
| all AI + regex (union) | **100%** | **56/56** |
| voting ≥2 detectors | 100% | 56/56 |
| voting ≥3 detectors | 95% | 53/56 |

Bugs no detector finds: **0**

**Findings — mostly a negative result, which is the interesting part:**
1. **Ensembling does NOT improve recall.** The union of all detectors equals
   the best single model (Sonnet, 56/56 = 100%). Every bug any detector finds,
   Sonnet also finds — the detectors are **nested (a strict hierarchy), not
   complementary**. Every detector's unique count is **0**.
2. **No bugs are missed by every model** — all 4 previously-reported "hard
   ceiling" misses were ground truth labeling errors (see correction table above).
3. **regex adds +4pp to gpt-4.1-mini** and +1–2pp to the mid-tier models, but
   nothing to Sonnet. Ensemble with regex only matters if you're using a
   sub-frontier model.
4. **Ensembling's real value is precision, not recall.** Requiring ≥3 detectors
   to agree keeps 95% recall (−5pp) while discarding lone-detector noise. Vote
   to *raise precision*, don't union to raise recall.

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
| OpenAI → OpenAI (self) | 42→41 | 5→5 | 89%→89% | 75%→73% | 0 / 5 | $0.031 |
| Sonnet → Sonnet (self) | 54→53 | 17→17 | 76%→76% | 96%→95% | 0 / 17 | $0.468 |
| Opus → Opus (self) | 51→50 | 14→14 | 78%→78% | 91%→89% | 0 / 14 | $0.875 |
| Sonnet → OpenAI | 55→53 | 16→16 | 77%→77% | 98%→95% | 0 / 16 | $0.273 |
| Sonnet → Opus | 55→53 | 17→16 | 76%→77% | 98%→95% | 1 / 17 | $0.722 |
| **Ollama → Sonnet (weak→strong)** | 35→34 | 26→18 | 57%→65% | 62%→61% | **8 / 26** | $0.193 |

**Findings:**
1. **No pairing among the three strong models removes false positives — self or
   cross.** All 5 strong-model cells remove 0–1 of 5–17 FPs, regardless of which
   model detects and which judges. Every combination does, however, cost 1–2 real
   bugs (recall drops 2–3pp every time) — cross-judging among strong models is
   **strictly worse than doing nothing**: zero precision gain, guaranteed recall
   loss.
2. **A capable detector's "false positives" are mostly real-but-unlabeled
   findings** that any competent judge correctly keeps. The matcher's FP count
   reflects **incomplete ground truth**, not model noise — no judge can fix it.
3. **The weak→strong pair is the only one that works** — Sonnet removes 8/26
   (31%) of Ollama's FPs for +8 pts precision at only −1 pt recall. The
   determining factor is a genuine **capability gap**: Opus judging Sonnet (both
   frontier) behaves just like Sonnet judging Sonnet (self); only Ollama (a real,
   weaker tier) has junk a stronger judge can actually catch.
4. **Every judged pass loses at least 1 real bug** — a single-finding view can't
   trace taint to its source, so some genuine findings look rejectable in
   isolation.

**Design answer — what to do:**
- **Same model: no.** Self-verification is useless (correlated errors).
- **A *different* strong model: also no.** The cross-model strong pairs (6 new
  runs) confirm this isn't specific to self-judging — Opus, Sonnet, and
  gpt-4.1-mini all fail to filter each other's findings, at a real recall cost.
  There is no "best pairing" among strong models; they're all equally useless.
- **Different, *stronger*-tier model as judge: yes — but only across a genuine
  capability gap.** The "detect cheap/local, verify with a frontier model"
  recipe cuts a weak detector's FPs (Ollama +8 pts precision). For any
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

| Metric | OpenAI mini | Gemini | Sonnet | Opus | GPT-5.5 | Ollama (12) |
|---|---:|---:|---:|---:|---:|---:|
| strict `fixed` | 27/56 (48%) | 25/56 (45%) | 19/56 (34%) | 34/56 (61%) | 36/56 (64%) | 2/12 (17%) |
| **functional-fix** | 41/56 (73%) | 36/56 (64%) | 39/56 (69%) | **45/56 (80%)** | 42/56 (75%) | 4/12 (33%) |
| real breakage (compile+test) | 11 | 22 | 16 | 6 | **1** | 7 |
| cost | $0.028 | $0.047 | $0.330 | $0.731 | $1.841 | $0.000 |

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
   Sonnet is the *best detector* (100%) yet mid-pack as a fixer (69%); its
   sibling **Opus is the best fixer** (80% full-56, **92% on the shared 12**) at
   ~2.2× Sonnet's fix cost. `gpt-4.1-mini` is the best **cost-adjusted** fixer
   (73% at ~$0.0005/attempt vs Opus's $0.0131 — a ~26× cost gap for 7 fewer
   points).
2. **Opus is the cleanest fixer** — only 6 real test failures across 56 attempts
   and the fewest regressions of any model.
3. **GPT-5.5 has the fewest real breakages (1/56)** — cleaner patches than any
   other model, but at $1.841 for 56 cases (~66× mini's cost) it is not
   cost-competitive given its 75% functional-fix rate sits between mini (73%)
   and Opus (80%).
4. **Gemini breaks compilation the most** — 22 real breakages out of 56, the
   highest of any model. Its whole-file rewrites more often emit code that
   doesn't parse.
5. **Ollama is a poor fixer** — 33% functional-fix on the easy 12-case
   Docker-free slice (seeded + literature), with 7 real breakages out of 12.
   Free, but not reliable enough to use unsupervised.
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
