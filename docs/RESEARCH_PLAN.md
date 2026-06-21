# SecurePatch AI — Research & Implementation Plan

> MS research project. Goal: a VS Code extension that detects (and eventually
> auto-fixes) vulnerabilities/bugs in the background while you code, **plus** a
> research harness to measure *how many scans* are needed to find obscure bugs,
> whether *multiple/different AIs* help, *which model performs best*, and whether
> applied fixes *introduce new problems*.

---

## 1. Where the project is today

- **Detection** = regex rules only (`src/scanners/codeScanner.ts`,
  `src/scanners/dependencyScanner.ts`). Deterministic, single pass, no AI in the
  detection loop.
- **Fixing** = AI, on demand, one finding at a time, **one-line replacements only**
  (`explainFindingWithAi` → `insertSuggestedLine` in `src/extension.ts`). Single
  provider (OpenAI Responses API, `src/ai/openAiSuggestionProvider.ts`).
- **Verification** = a human eyeballs the green/red preview and clicks Apply/Reject
  (`src/ui/pendingFixes.ts`). Nothing checks compile/tests/regressions.
- **Data capture** = none. Findings print to an output channel and are lost.

The missing piece for research is **ground truth + repetition + isolation + a
results database**. The interactive extension cannot produce statistics; a
headless harness against a labeled benchmark can.

---

## 2. Central architecture

```
                 ┌─────────────────────────┐
                 │   securepatch-core (TS)  │  detection + fix engines,
                 │   no vscode imports      │  exposed via a thin CLI
                 └─────────────┬───────────┘
            ┌──────────────────┴──────────────────┐
            │                                      │
   ┌────────▼─────────┐                ┌───────────▼────────────┐
   │  VS Code ext (TS)│                │ Experiment Harness (PY) │
   │  product / demo  │   shells out → │ research instrument      │
   └──────────────────┘                └─────────────────────────┘
```

Decisions locked in:
- **Harness language: Python** (data-science/analysis ecosystem, benchmark
  loaders, provider SDKs).
- **Providers to compare: OpenAI, Anthropic (Claude), Google Gemini, Ollama (local)**.
- Keep the **VS Code extension as the product/demo**; **all research data comes
  from the Python harness**.

### Bridging TS core and Python harness
Detection logic should be **single-sourced**, not duplicated. Two acceptable
options (pick during Phase 0):
1. **Thin Node CLI** (recommended): expose `securepatch-core scan <file> --json`
   from the TS core; the Python harness shells out and parses JSON. Detection
   rules live in one place; the extension and harness both use them.
2. **Port the regex rules to Python.** Simpler dependency-wise, but now you
   maintain two rule sets — avoid unless the CLI bridge proves painful.

The **AI provider calls live in Python** in the harness (using each vendor's SDK),
so the harness owns the model-comparison logic directly. The extension keeps its
own TS provider adapters for the live product.

---

## 3. Research design (define before building)

| Question | Independent variable | Metric |
|---|---|---|
| How many scans to find obscure bugs? | # repeated scans (k) | Detection rate vs k (*discovery curve*); scans-to-first-detection; detection@k |
| Do multiple AIs help? | single model vs ensemble/voting | marginal recall gain; unique bugs per model |
| Which AI is best? | model identity | precision, recall, F1, fix-success rate, regression rate, $/bug, latency |
| Did a fix cause a problem? | per fix | regression rate = % fixes that break tests / fail compile / add new finding |

### Metric definitions (lock these down)
- **Detection** = a finding whose location + type matches a ground-truth bug.
  Needs a matcher: same line ± window AND same CWE/category.
- **Fix success** = original vuln no longer detected **AND** all pre-existing
  tests pass **AND** still compiles/type-checks.
- **Regression** ("did it make a mistake") = fix applied but a previously-passing
  test now fails, OR a new finding appears, OR compile/type-check breaks. Fully
  automatable — this is the core "did it cause a problem" signal.
- Always log **cost + latency + tokens** per call. Report **$/bug-found** as a
  comparison axis even though credits aren't a constraint.

LLMs are stochastic → **every experiment cell is repeated runs**; report
distributions, not single numbers.

---

## 4. Phased roadmap

### Phase 0 — Refactor to a shared core *(1 sprint)*
Extract from the extension into `securepatch-core` (no `vscode` imports):
- `Detector` interface (regex today; AI detector later).
- `Fixer` interface (generalize the current one-line fixer to multi-line/multi-file patches).
- `ModelProvider` interface (extension keeps TS adapters; harness has Python ones).
- Move `SecurityFinding` / `AiFixSuggestion` types here.
- Add the thin **Node CLI** bridge (`scan`, later `fix`) emitting JSON.

Mostly mechanical given the current structure; unblocks everything else.

### Phase 1 — Benchmark corpus *(the real "first deliverable")*
`benchmarks/<case-id>/` — each case self-describing:
```
benchmarks/<case-id>/
  source/            # the (vulnerable) program
  ground_truth.json  # known bugs: file, line range, CWE/type, obscurity rating
  tests/             # functional tests defining "still works"
  meta.json          # language, difficulty, category
```
Source tiers:
1. **Seeded/synthetic** — write programs, inject known bugs (full control over
   "obscurity"). **Start here.**
2. **Established SAST benchmarks** — OWASP Benchmark, NIST SARD/Juliet,
   SecurityEval, CVEfixes/Devign. *(Verify license/suitability before importing.)*
3. **Real CVE fixes** — hardest tier, later.

Add an explicit **"obscurity" axis** (shallow/syntactic → deep/semantic/multi-file)
so "obscure bugs" becomes quantitative.

### Phase 2 — Headless experiment runner (Python)
CLI, e.g. `securepatch-bench run --models openai,claude,gemini,ollama --scans 20 --bench ./benchmarks`:
1. For each (case × model × scan-index): run detection, **in parallel** across
   models/cases (concurrency-limited queue).
2. Copy the case into an **isolated sandbox** (git worktree / temp dir) before any
   fix — never mutate the corpus.
3. Apply the AI fix in the sandbox.
4. **Verify automatically**: compile/type-check → run `tests/` → re-scan for the
   original vuln → re-scan for new vulns.
5. Write **one append-only JSONL row per run** with full provenance.

### Phase 3 — Results store + provenance
Each run row: case id, model, scan index, prompt sent, **raw model response**, the
**unified diff applied**, compile result, test results (before/after), re-scan
results, latency, tokens, cost, verdict (`detected` / `fixed` / `regressed` /
`no-op` / `error`). JSONL (parallel-friendly append) → load into SQLite/pandas.
The stored diff + raw response is the **"see how it fixed it and whether it caused
a problem"** requirement — reviewable per run after the fact.

### Phase 4 — Analysis layer (Python notebooks + small dashboard)
- Discovery curves (detection@k per model and per obscurity tier).
- Model leaderboard (P/R/F1, fix-success, regression rate, $/bug, latency).
- Ensemble analysis: union-of-models vs best single model; voting agreement.
- False-positive breakdown by rule/category.

### Phase 5 — Feed conclusions back into the product
Wire the best scan budget / model mix into the live extension: background scanning
loop, multi-model fixing, auto-apply-with-verification. Extension becomes the
demonstrator of the harness's conclusions.

### Phase 6 (stretch) — Autonomous fix loop
Agentic: detect → fix → verify → on regression, retry with feedback up to N
attempts. The harness already measures this if per-attempt rows are logged;
autonomy is just closing the loop in the product.

---

## 5. Concrete first step (minimal vertical slice)

Phase 0 + a thin slice of Phases 1–3:
- One **seeded benchmark case** with tests + `ground_truth.json`.
- `ModelProvider` adapters in Python for the four providers (start with 2, add the rest).
- A tiny Python runner: N scans × 2 models → apply fixes in temp dirs → run tests
  → write JSONL.

This single slice exercises the **entire pipeline end-to-end** and surfaces the
hard design decisions before scaling the corpus.

---

## 5b. Week-by-week timeline

Target: **development complete by mid-July (~Fri Jul 17)**, then data gathering
through the rest of the term. Today = Sat Jun 20. Four dev weeks, then collection.

### Week 1 — Jun 20–26 · Foundations (Phase 0 + start Phase 1)
- Extract `securepatch-core` (TS, no `vscode`): `Detector`, `Fixer`,
  `ModelProvider` interfaces; move `SecurityFinding` / `AiFixSuggestion` types.
- Verify the extension still builds/runs against the extracted core.
- Add the thin **Node CLI** bridge: `securepatch-core scan <file> --json`.
- Stand up the Python harness skeleton (repo layout, venv/poetry, JSONL writer).
- **Exit check:** `scan` CLI returns JSON; Python can shell out and parse it.

### Week 2 — Jun 27–Jul 3 · Benchmark + provider adapters (Phase 1 + 2 start)
- Build **3–5 seeded benchmark cases** (`source/`, `ground_truth.json`,
  `tests/`, `meta.json`) across the obscurity axis.
- Python `ModelProvider` adapters: **OpenAI + Anthropic first**, then Gemini +
  Ollama. Uniform request/response + cost/latency/token capture.
- Detection **matcher** (line window + CWE/category mapping) — drives all recall numbers.
- **Exit check:** harness runs N detection scans for ≥2 models on 1 case, logs JSONL.

### Week 3 — Jul 4–10 · Fix + verify loop (Phase 2 finish + Phase 3)
- Sandbox isolation (git worktree / temp dir copy) — never mutate the corpus.
- Apply AI fix in sandbox → **auto-verify**: compile/type-check → run `tests/` →
  re-scan original vuln → re-scan for new findings.
- Full provenance rows: prompt, raw response, applied diff, before/after tests,
  verdict (`detected`/`fixed`/`regressed`/`no-op`/`error`).
- Wire in all four providers; parallel concurrency-limited queue.
- **Exit check:** end-to-end run (N scans × 4 models × all cases) writes complete rows.

### Week 4 — Jul 11–17 · Harden + analysis layer (Phase 4) → **dev freeze**
- Analysis notebooks: discovery curves, model leaderboard, ensemble/voting,
  false-positive breakdown.
- Robustness: retries/backoff, error handling, resumable runs, config files.
- Dry-run a full experiment grid end-to-end; fix the rough edges.
- **Exit check (mid-July):** one command produces a complete dataset + the
  notebooks render every planned metric. **Stop building.**

### Jul 18 → end of term · Data gathering (no new dev)
- Run the full grid at scale: many scans per cell, all models, all cases,
  repeated for statistical power.
- Periodically refresh notebooks; expand the corpus only with *more cases of
  existing shape* (no new harness features).
- Reserve the final stretch for analysis, write-up, and conclusions.

> Buffer note: if Week 2 or 3 slips, cut benchmark *quantity* (fewer cases) and
> provider *count* (ship OpenAI + Claude, add Gemini/Ollama during data-gathering)
> rather than cutting the verify loop — the verify loop is the research.

---

## 6. Open items to revisit
- TS↔Python bridge: confirm the Node CLI approach vs porting rules.
- Detection matcher tolerance (line window, CWE mapping) — affects all recall numbers.
- Per-language verification toolchains (JS/TS: tsc + a test runner; Python: pytest).
- Benchmark licensing for external datasets.
