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
Verification), CWE-377 (Insecure Temp File), CWE-400 (Uncontrolled Resource
Consumption), CWE-502 (Insecure Deserialization), CWE-643 (XPath Injection),
CWE-732 (Incorrect Permissions), CWE-760 (Predictable Salt), CWE-798 (Hardcoded
Credentials), CWE-918 (SSRF), CWE-943 (NoSQL Injection), CWE-1333 (ReDoS).

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
| `gemini-2.5-flash` | Google | detector, fixer |
| `qwen2.5-coder:7b` | Ollama (local, $0) | detector, fixer (12 Docker-free cases only — see §7) |
| regex (`securepatch-core` TS engine) | — (rule-based, no model) | detector baseline |
| Semgrep OSS (`p/security-audit`+`p/owasp-top-ten`+`p/secrets`) | — (rule-based, no model) | detector baseline |

---

## 3. Headline findings

### 3.1 AI detection crushes rule-based baselines

| Detector | Overall recall | Syntactic | Local-semantic | Cross-function | False positives |
|---|---:|---:|---:|---:|---:|
| Regex (homemade) | 34% (19/56) | 100% | 20% | 0% | 3 |
| **Semgrep (off-the-shelf SAST)** | **20% (11/56)** | 40% | 16% | 0% | **2** |
| Ollama 7b | 62% (35/56) | 80% | 58% | 100% | 30 |
| OpenAI `gpt-4.1-mini` | 79% (44/56) | 80% | 78% | 100% | 8 |
| Gemini `2.5-flash` | 86% (48/56) | 80% | 87% | 100% | 8 |
| Opus `4-8` | 93% (52/56) | 100% | 91% | 100% | 10 |
| **Sonnet `4-6` (best detector)** | **95% (53/56)** | 100% | 93% | 100% | 13 |

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
Semgrep is also the lowest-noise detector of all seven (2 FPs).

**Sonnet is the best detector overall** (95%), edging Opus (93%) at about half
the cost ($0.747 vs $1.380 for all 56 cases). Repeated scans (`detection@k`)
add only +2 to +6 points and saturate by k=2; temperature (not scan count) is
the actual lever — at temp 0 the discovery curve is flat, at temp ≥1 it gains
~8 points from sampling diversity, with 1.0 as the sweet spot (1.5 matches
recall but adds an FP).

### 3.2 Detection skill ≠ fixing skill (the headline result)

| Model | Functional-fix rate (full 56) | Functional-fix (shared 12 Docker-free) | Cost (56 cases) |
|---|---:|---:|---:|
| Sonnet (best *detector*, 95% recall) | 62% | 50% | $0.330 |
| OpenAI `gpt-4.1-mini` (best *cost-adjusted* fixer) | 68% | 67% | $0.028 |
| Gemini `2.5-flash` | 59% | 42% | $0.047 |
| **Opus (best fixer overall)** | **80%** | **92%** | $0.731 |
| Ollama 7b (local) | 25%* | 25% | $0.000 |

*\*Ollama fix numbers are on the 12 Docker-free cases only — Docker + the
resident local model can't coexist on the test machine (RAM contention).*

**Sonnet — the best detector — is the *weakest Anthropic fixer*** (62%
functional-fix), while its sibling **Opus is the best fixer of any model
tested** (80% full-56, 92% on the shared 12), at ~2.2× Sonnet's fix cost and
**0 compile failures** across all 56 attempts (vs OpenAI 2, Sonnet 6, Gemini
15). So the "detect ≠ fix" gap is real *within a model family* — but it isn't
a small-model-wins story once Opus is in the comparison: raw capability still
dominates when cost isn't the constraint. `gpt-4.1-mini` remains the best
**cost-adjusted** fixer — 68% at roughly 1/26 of Opus's cost.

### 3.3 Ensembling / voting — a clean negative result

| Ensemble strategy | Recall |
|---|---:|
| Best single model (Sonnet) | 95% (53/56) |
| All 6 detectors, union | 95% (53/56) — **no gain** |
| All 6 + regex, union | 95% (53/56) — **no gain** |
| Voting ≥2 detectors agree | 93% (52/56) |
| Voting ≥3 detectors agree | 91% (51/56) |

**Union of every detector equals the single best model.** The detectors form a
strict hierarchy (nested, not complementary) — every bug any weaker detector
finds, Sonnet also finds; only Sonnet has a unique catch (1 bug), every other
detector's unique count is 0. A hard ceiling of 3 bugs (2 NoSQL-injection, 1
resource-exhaustion) is missed by every detector, AI or not — that needs
better detection, not more models. Regex adds a cheap +2 points when unioned
with a sub-frontier model (Ollama/OpenAI/Gemini), but nothing for the Claude
models. **Ensembling's real value is precision, not recall**: requiring ≥2
detectors to agree keeps 93% recall while discarding lone-detector noise — a
near-free way to cut false positives (e.g. Ollama's 30). **Practical
takeaway: use the single best model for recall; don't pay for an ensemble.**

### 3.4 False-positive reduction via a second-model filter — fails for strong models

Full cross-model verification matrix (self + every pairing among the three
strong models, plus the original weak→strong pair):

| Detector → Judge | FPs removed | Recall before→after |
|---|---:|---:|
| OpenAI → OpenAI (self) | 0 / 8 | 71%→66% |
| Sonnet → Sonnet (self) | 1 / 15 | 93%→91% |
| Opus → Opus (self) | 0 / 12 | 93%→88% |
| OpenAI → Sonnet | 0 / 9 | 70%→68% |
| OpenAI → Opus | 0 / 9 | 73%→68% |
| Sonnet → OpenAI | 0 / 14 | 93%→89% |
| Sonnet → Opus | 0 / 12 | 95%→91% |
| Opus → Sonnet | 0 / 12 | 89%→88% |
| Opus → OpenAI | 0 / 10 | 89%→84% |
| **Ollama → Sonnet (weak→strong)** | **7 / 26** | 55%→54% |

**No pairing among the three strong models (Sonnet, Opus, gpt-4.1-mini)
removes false positives — self or cross.** Every strong-model cell removes 0
or at most 1 of 8–15 FPs, while still costing 1–4 real bugs of recall every
time — cross-judging among strong models is **strictly worse than doing
nothing**. This isn't a self-verification quirk (that was the original,
narrower finding); it's a property of the *capability tier*, not the specific
pairing — Opus judging Sonnet behaves just like Sonnet judging itself, because
a capable detector's "false positives" are mostly plausible real-but-unlabeled
findings that any competent judge correctly keeps. The **only pairing that
works is a genuine capability gap**: Sonnet removes 7/26 (27%) of Ollama's FPs
for +7 points precision at only −1 point recall. **Design rule: never
self-verify, never cross-verify among strong models, only verify a weak/cheap
detector with a stronger judge — and never use a weaker judge.**

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

- **Detection@k saturates fast.** Repeated scans give +2 to +6 points overall,
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
   vulnerability code (20–34% recall); LLMs promise much higher recall but at
   unknown cost in false positives and fix reliability. State the four research
   questions: how many scans to find a bug, do multiple models help, which
   model is best, and does a fix introduce new problems.
2. **Benchmark / Methods** — The 56-case corpus (§1): 3 collections
   (`cweval`/`literature`/`seeded`), 22 CWEs, 3 obscurity tiers, provenance
   requirements. The two-part harness: `bench` (detection recall via a
   location+type matcher, ±2 lines) and `fix` (sandbox → AI patch → verify via
   native tests or the Docker CWEval exploit-based oracle). List all 7
   detectors/models tested (§2).
3. **Detection Results** — Recall table by tier and by model (§3.1): regex 34%
   → Semgrep 20% → Ollama 62% → OpenAI 79% → Gemini 86% → Opus 93% → Sonnet
   95%; the Semgrep-below-regex result and why it's the more defensible
   baseline; detection@k saturating by k=2; the temperature-not-scan-count
   finding.
4. **Fixing Results (headline)** — The detect≠fix split (§3.2): Sonnet best
   detector but weakest Anthropic fixer (62%); Opus best fixer overall (80%,
   92% on the shared 12, 0 compile failures); gpt-4.1-mini best cost-adjusted
   fixer (68% at ~1/26 Opus's cost). This is the paper's central,
   counterintuitive claim — lead the poster with it.
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
   work: complete the 3 undetected-by-anyone bugs' ground truth, expand beyond
   56 cases, add variance bars (current numbers are single runs).
