# SecurePatch — Findings Summary

A single, self-contained snapshot of the project: what the benchmark is, what
was tested, and every key result with its exact numbers. This is the source
document for the poster/paper — everything below is pulled from
[`RESULTS.md`](RESULTS.md) (the full run-by-run log); if the two ever disagree,
`RESULTS.md` is authoritative and this file should be refreshed from it.

---

## 1. The benchmark

**56 labeled vulnerability cases** (`benchmarks/`), each self-describing:
`meta.json` (language, category, difficulty, obscurity, provenance) +
`ground_truth.json` (every known bug, its file/line range, CWE, and type) +
`source/` (the only thing a model ever sees) + `tests/`.

### Sources (3 collections, kept separate so results can be reported per-origin)

| Collection | Cases | Origin |
|---|---:|---|
| `cweval/` | 44 | Vendored (Apache-2.0) from **CWEval** (Peng et al., arXiv:2501.08200, LLM4Code 2025; github.com/Co1lin/CWEval) — the in-scope Python + JS tasks of a peer-reviewed benchmark with dual functional+security execution oracles. |
| `literature/` | 6 | Hand-authored, each weakness class drawn from a citable authority (CWE Top 25 / SecurityEval / SALLM) — external grounding for classes CWEval doesn't cover. |
| `seeded/` | 6 | Hand-authored from scratch — a fully-owned control set, used to place bugs anywhere on the obscurity axis deliberately. |

Selection was weighted toward MITRE/CISA's **2024 CWE Top 25 Most Dangerous
Software Weaknesses** list (see `benchmarks/REFERENCES.md`).

### CWE coverage — 22 distinct CWEs across the 56 cases

CWE-20 (Improper Input Validation), CWE-22 (Path Traversal), CWE-78 (OS Command
Injection), CWE-79 (XSS), CWE-89 (SQL Injection), CWE-95 (Code Injection/Eval),
CWE-113 (HTTP Response Splitting), CWE-117 (Log Injection), CWE-326/327/329
(Weak/Broken Crypto), CWE-338 (Weak PRNG), CWE-347 (Improper Signature
Verification), CWE-377 (Insecure Temp File), CWE-502 (Insecure Deserialization),
CWE-643 (XPath Injection), CWE-732 (Incorrect Permissions), CWE-760 (Predictable
Salt), CWE-798 (Hardcoded Credentials), CWE-918 (SSRF), CWE-1333 (ReDoS).

> **Ground truth correction (2026-07-21):** Four cases imported from CWEval
> carried incorrect type labels — `js-cwe_943_0` and `py-cwe_943_0` were filed
> under CWE-943 (NoSQL injection) but the code and exploits are pure SQL injection
> (CWE-89); `py-cwe_400_0` and `js-cwe_400_0` were filed under CWE-400 but the
> oracle header says "CWE-377: Regular expression injection" and the security
> tests use ReDoS payloads (CWE-1333). All recall numbers in this document
> reflect the corrected labels. Every apparent "miss" on these cases was a
> measurement artifact — models were reporting the correct type and being penalised
> for not matching the wrong label. See `RESULTS.md` for the full correction table.

### Difficulty / obscurity axis (not just a CWE label — how hard is it to *see*)

| Tier | Cases | Meaning |
|---|---:|---|
| syntactic | 10 | Pattern-matchable — a regex/rule tool should catch it. |
| local-semantic | 45 | Requires reasoning about data flow within a function/file; the bulk of the corpus. |
| cross-function | 1 | The vulnerable sink and the tainted source are in different functions. |

---

## 2. Models / providers tested

| Model | Provider | Role(s) tested |
|---|---|---|
| `claude-opus-4-8` | Anthropic | detector, fixer, judge |
| `claude-sonnet-4-6` | Anthropic | detector, fixer, judge |
| `gpt-4.1-mini` | OpenAI | detector, fixer, judge |
| `gpt-5.5` | OpenAI | detector, fixer |
| `gemini-2.5-flash` | Google | detector, fixer |
| `qwen2.5-coder:7b` | Ollama (local, $0) | detector, fixer (12 Docker-free cases only — see §7) |
| regex (`securepatch-core` TS engine) | — (rule-based, no model) | detector baseline |
| Semgrep OSS (`p/security-audit`+`p/owasp-top-ten`+`p/secrets`) | — (rule-based, no model) | detector baseline |

---

## 3. Headline findings

### 3.1 AI detection crushes rule-based baselines

| Detector | Recall | Precision | F1 | Syntactic | Local-semantic | Cross-function | FPs |
|---|---:|---:|---:|---:|---:|---:|---:|
| Regex (homemade) | 34% (19/56) | 86% | 49% | 100% | 22% | 0% | 3 |
| **Semgrep (off-the-shelf SAST)** | **20% (11/56)** | 85% | 32% | 40% | 16% | 0% | **2** |
| Ollama 7b | 68% (38/56) | 56% | 61% | 90% | 62% | 100% | 30 |
| OpenAI `gpt-4.1-mini` | 70% (39/56) | 85% | 76% | 70% | 69% | 100% | 7 |
| Gemini `2.5-flash` | 91% (51/56) | 86% | 89% | 80% | 93% | 100% | 8 |
| Opus `4-8` | 91% (51/56) | 78% | 84% | 80% | 93% | 100% | 14 |
| **GPT-5.5 (best F1)** | 93% (52/56) | **91%** | **92%** | 90% | 93% | 100% | **5** |
| **Sonnet `4-6` (best recall)** | **100% (56/56)** | 79% | 88% | 100% | 100% | 100% | 15 |

**A real, independent SAST tool (Semgrep) scores *below* our own hand-tuned
regex rules (20% vs 34%)** — both far behind every AI model. Semgrep's
community rules pattern-match real framework/library call sites
(`cursor.execute()`, `subprocess.call(shell=True)`, …); most of the corpus
(especially the 44 CWEval-derived cases, which are short self-contained
functions, not app code wired to a real DB/HTTP framework) doesn't hit those
shapes even though the vulnerability is genuine. This makes Semgrep the more
defensible academic baseline (not overfit to our cases) precisely because it
does worse — it establishes a believable floor for what a generic tool
achieves on this kind of code, which is the gap the AI numbers are filling.
Semgrep is also the lowest-noise detector (2 FPs).

**Sonnet achieves perfect recall (100%)** across all 56 cases and all 3 tiers,
reaching 100% at k=2 scans. **GPT-5.5 leads on F1 (92%)** — 93% recall with only
5 FPs, giving it the best precision (91%) of any AI model. Sonnet's 15 FPs (mostly
real-but-unlabeled findings) drop its F1 to 88% despite perfect recall. Gemini and Opus tie at 91%.
Repeated scans (`detection@k`) add only a few points and saturate by k=2;
temperature (not scan count) is the actual lever — at temp 0 the discovery
curve is flat, at temp ≥1 it gains ~8 points from sampling diversity, with 1.0
as the sweet spot.

### 3.2 Detection skill ≠ fixing skill (the headline result)

| Model | Functional-fix rate (full 56) | Functional-fix (shared 12 Docker-free) | Cost (56 cases) |
|---|---:|---:|---:|
| Sonnet (best *detector*, **100% recall**) | 62% | 50% | $0.330 |
| OpenAI `gpt-4.1-mini` (best *cost-adjusted* fixer) | 68% | 67% | $0.028 |
| Gemini `2.5-flash` | 59% | 42% | $0.047 |
| GPT-5.5 | 73% | — | $1.841 |
| **Opus (best fixer overall)** | **80%** | **92%** | $0.731 |
| Ollama 7b (local) | 25%* | 25% | $0.000 |

*\*Ollama fix numbers are on the 12 Docker-free cases only — Docker + the
resident local model can't coexist on the test machine (RAM contention).*

**Sonnet — the best detector (98%) — is the *weakest Anthropic fixer*** (62%
functional-fix), while its sibling **Opus is the best fixer of any model
tested** (80% full-56, 92% on the shared 12), at ~2.2× Sonnet's fix cost and
**0 compile failures** across all 56 attempts (vs OpenAI 2, Sonnet 6, Gemini
15). GPT-5.5 lands at 73% functional-fix with 0 compile failures, between
gpt-4.1-mini and Opus, but at ~66× gpt-4.1-mini's cost. So the "detect ≠ fix"
gap is real *within a model family* — but it isn't a small-model-wins story
once Opus is in the comparison: raw capability still dominates when cost isn't
the constraint. `gpt-4.1-mini` remains the best **cost-adjusted** fixer — 68%
at roughly 1/26 of Opus's cost.

### 3.3 Ensembling / voting — a clean negative result

| Ensemble strategy | Recall |
|---|---:|
| Best single model (Sonnet) | **100% (56/56)** |
| All AI models, union | **100% (56/56)** — no gain |
| All AI + regex, union | **100% (56/56)** — no gain |
| Voting ≥2 detectors agree | 100% (56/56) |
| Voting ≥3 detectors agree | 95% (53/56) |

**Union of every detector equals the single best model.** The detectors form a
strict hierarchy (nested, not complementary) — every bug any weaker detector
finds, Sonnet also finds; every other detector's unique count is 0. **No bugs
are missed by every model** — all previously-reported "hard ceiling" misses were
ground truth labeling errors. **Ensembling's real value is precision, not recall**:
requiring ≥3 detectors to agree keeps 95% recall while discarding lone-detector
noise — a near-free way to cut false positives.
**Practical takeaway: use the single best model for recall; don't pay for an ensemble.**

### 3.4 False-positive reduction via a second-model filter — fails for strong models

Full cross-model verification matrix (self + every pairing among the three
strong models, plus the original weak→strong pair).

| Detector → Judge | FPs removed | Recall before→after |
|---|---:|---:|
| OpenAI → OpenAI (self) | 0 / 5 | 75%→73% |
| Sonnet → Sonnet (self) | 0 / 17 | 96%→95% |
| Opus → Opus (self) | 0 / 14 | 91%→89% |
| Sonnet → OpenAI | 0 / 16 | 98%→95% |
| Sonnet → Opus | 1 / 17 | 98%→95% |
| **Ollama → Sonnet (weak→strong)** | **8 / 26** | 62%→61% |

**No pairing among the strong models (Sonnet, Opus, gpt-4.1-mini) removes
false positives — self or cross.** Every strong-model cell removes 0–1 FP,
while still costing 1–2 real bugs of recall every time — cross-judging among
strong models is **strictly worse than doing nothing**. A capable detector's
"false positives" are mostly plausible real-but-unlabeled findings that any
competent judge correctly keeps. The **only pairing that works is a genuine
capability gap**: Sonnet removes 8/26 (31%) of Ollama's FPs for +8 points
precision at only −1 point recall.
**Design rule: never self-verify, never cross-verify among strong models,
only verify a weak/cheap detector with a stronger judge — and never use a
weaker judge.**

### 3.5 Split detect→fix pipeline — smart for the cheap fixer, not for Opus

| Pipeline | Functional-fix | Cost (56 cases) |
|---|---:|---:|
| Sonnet detect + Sonnet fix (self) | 66%* | $0.330 |
| OpenAI detect + OpenAI fix (self) | 70%* | $0.028 |
| Opus detect + Opus fix (self) | 80%* | $0.731 |
| Sonnet detect → Opus fix | 79% | $0.735 |
| **Sonnet detect → gpt-4.1-mini fix** | **79%** | **$0.030** |

*\*Recomputed directly from the JSONL with one consistent rule (`fixed` +
regressed-with-new-finding-only) for a clean apples-to-apples read across this
table; differs by ~1–2 points from the rounded self-fix figures quoted in §3.2
(rounding/methodology drift between analysis passes, not new data).*

**Handing Sonnet's findings to `gpt-4.1-mini` for fixing reaches 79%
functional-fix — 9 points above solo gpt-4.1-mini (70%) and within 1 point of
solo Opus (80%) — at gpt-4.1-mini's cost (~24× cheaper than Opus).** That's the
best cost/quality point found in the whole project. Sonnet's richer, correctly
typed finding descriptions also **eliminate gpt-4.1-mini's compile failures
entirely** (2→0) and cut real breakage from 11 to 7. By contrast, **Sonnet
detect → Opus fix does not beat Opus fixing itself** (79% vs 80%, same cost) —
splitting only helps when the *fixer* alone is the weak link, not when it's
already frontier-grade. (Note: the existing fix loop attempts every
ground-truth bug regardless of detector recall — a miss falls back to the bug's
ground-truth metadata — so what a mixed pipeline actually varies is *whose
finding-enrichment text* the fixer sees, which is exactly the variable this
question asks about.)

**Practical recipe:** cost-sensitive → **detect with Sonnet, fix with
`gpt-4.1-mini`**; quality-first (cost no object) → **detect and fix with
Opus**.

---

## 4. Other results worth keeping

- **Detection@k saturates fast.** Repeated scans give +2 to +4 points overall,
  almost all realized by the 2nd scan; frontier models (Sonnet, Opus) are flat
  (find it on scan 1 or not at all) — only sub-frontier models claw back a few
  points from a 2nd scan.
- **Temperature, not scan count, drives the discovery-curve gain.** At temp 0
  the curve is flat (deterministic); at temp ≥1 repeated scans recover ~8
  points via sampled diversity; ~1.0 is the sweet spot (1.5 matches recall but
  adds a false positive).
- **The Docker-based CWEval oracle scaled cleanly** — 43–44 of 56 cases
  verified with the real exploit-based `security` oracle (not just a re-scan),
  zero pipeline errors across four full fix runs.
- **`regressed` needs a reason breakdown to be meaningful** — roughly half of
  all "regressed" verdicts are the stochastic AI re-scan flagging a
  "new finding" that isn't a real break (compiles + tests still pass); the
  functional-fix metric strips that noise out.

---

## 5. Setup / reproduction caveats

- **Ollama fix** could only run on the 12 Docker-free cases (`seeded` +
  `literature`) — Docker and the resident 7B model can't coexist on the test
  machine (RAM contention causes a hang). All Ollama comparisons in this doc
  use that same 12-case slice for both Ollama and the API models, for a fair
  read.
- **Gemini** requires a billed key (`gemini-2.5-flash`; `2.0-flash` has zero
  free-tier quota).
- Full reproduction commands live at the bottom of `RESULTS.md`.

---

## 6. Poster outline (6 sections)

A working outline for turning this into a poster/short paper. Each section
lists what goes in it and which numbers above it draws on.

1. **Intro / Motivation** — Why AI-based vulnerability detection/fixing is
   worth studying: regex/rule-based tools (including a real off-the-shelf SAST
   tool, Semgrep) have a low, defensible ceiling on realistic/obscure
   vulnerability code (20–38% recall); LLMs promise much higher recall but at
   unknown cost in false positives and fix reliability. State the four research
   questions: how many scans to find a bug, do multiple models help, which
   model is best, and does a fix introduce new problems.
2. **Benchmark / Methods** — The 56-case corpus (§1): 3 collections
   (`cweval`/`literature`/`seeded`), 22 CWEs, 3 obscurity tiers, provenance
   requirements. The two-part harness: `bench` (detection recall via a
   location+type matcher, ±2 lines) and `fix` (sandbox → AI patch → verify via
   native tests or the Docker CWEval exploit-based oracle). List all 8
   detectors/models tested (§2). Note the ground truth correction and its
   methodological implication (§1 correction note).
3. **Detection Results** — Recall table by tier and by model (§3.1): regex 34%
   → Semgrep 20% → Ollama 68% → OpenAI 70% → Gemini 91% = Opus 91% → GPT-5.5
   93% → Sonnet 100%; the Semgrep-below-regex result and why it's the more
   defensible baseline; Sonnet reaches 100% at k=2; detection@k saturating by
   k=2; the temperature-not-scan-count finding.
4. **Fixing Results (headline)** — The detect≠fix split (§3.2): Sonnet best
   detector (98%) but weakest Anthropic fixer (62%); Opus best fixer overall
   (80%, 92% on the shared 12, 0 compile failures); gpt-4.1-mini best
   cost-adjusted fixer (68% at ~1/26 Opus's cost); GPT-5.5 at 73% but
   expensive. This is the paper's central, counterintuitive claim — lead the
   poster with it.
5. **Multi-Model Strategies** — Three negative-leaning results that all point
   the same direction (§3.3, §3.4, §3.5): ensembling/voting doesn't raise
   recall (union = best single model; only helps precision via voting);
   cross-model verification doesn't cut FPs among strong models (only a
   genuine weak→strong capability gap works, e.g. Ollama→Sonnet +7pts
   precision); but a split detect→fix pipeline *does* pay off when the fixer
   is the weak link (Sonnet→gpt-4.1-mini: 79% functional-fix at ~1/24 Opus's
   cost, beating solo gpt-4.1-mini by 9 points).
6. **Conclusions** — Practical recipes: cost-sensitive product = detect with
   Sonnet, fix with gpt-4.1-mini; quality-first = Opus for both. General
   lesson: throwing more models at a problem (ensembling, cross-verification)
   mostly doesn't help — the exception is when you deliberately pair strength
   at one *role* (detection) with strength/cheapness at a *different role*
   (fixing), not just adding more model opinions to the same role. Future
   work: expand beyond 56 cases, add variance bars (current numbers are single
   runs), re-run verify/ensemble experiments to confirm FP-reduction results
   with the updated detection data.
