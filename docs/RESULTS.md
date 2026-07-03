# SecurePatch — Results Log

Running record of harness runs against the labeled corpus (`benchmarks/`, 56
cases). Two independent experiments:

- **Part 1 — Detection** (`bench`): can a detector *find* the bug? → recall.
- **Part 2 — Fix + Verify** (`fix`): can it *fix* the bug, and does the fix break
  anything? → verdicts.

Raw per-case rows live in `harness/results/*.jsonl` (gitignored); this file is the
human-readable summary we keep in version control. See
[`RESEARCH_PLAN.md`](RESEARCH_PLAN.md) §3 for metric definitions.

---

# Part 1 — Detection

**Metric:** _recall_ — a finding whose location (±2 lines) and CWE/type matches a
ground-truth bug. AI detectors run `--scans 3`, so numbers are **detection@3**
(found in any of 3 scans).

## Recall by obscurity tier

| Tier | Cases | Regex | OpenAI `gpt-4.1-mini` | Anthropic `sonnet-4-6` | Anthropic `opus-4-8` |
|---|---:|---:|---:|---:|---:|
| syntactic       | 10 | **100%** (10/10) | 80% (8/10)  | **100%** (10/10) | **100%** (10/10) |
| local-semantic  | 45 | 20% (9/45)       | 78% (35/45) | **93%** (42/45)  | 91% (41/45) |
| cross-function  | 1  | 0% (0/1)         | **100%** (1/1) | **100%** (1/1) | **100%** (1/1) |
| **Overall**     | 56 | 34% (19/56)      | 79% (44/56) | **95% (53/56)**  | 93% (52/56) |
| False positives | —  | 3                | 8           | 13               | 10 |

## Recall by collection

| Collection | Cases | Regex | OpenAI | Sonnet | Opus |
|---|---:|---:|---:|---:|---:|
| cweval     | 44 | 20% (9/44) | 77% (34/44) | **93%** (41/44) | 91% (40/44) |
| literature | 6  | 83% (5/6)  | 83% (5/6)   | **100%** (6/6)  | **100%** (6/6) |
| seeded     | 6  | 83% (5/6)  | 83% (5/6)   | **100%** (6/6)  | **100%** (6/6) |

## Detection observations

1. **AI massively lifts recall** (regex 34% → 79–95%), driven by the
   **local-semantic** tier (regex 20% → 78–93%) — the gap the plan predicted
   regex could not close.
2. **Sonnet is the sweet spot.** It edges out Opus on recall (95% vs 93%) at
   **~half the cost** ($0.75 vs $1.38), and unlike OpenAI keeps syntactic recall
   at 100%. Its price is the most false positives (13).
3. **OpenAI regresses on trivial bugs; the Claude models don't.** OpenAI missed
   two *regex-detectable* cases (`cwe-078-cmdi-subprocess`, `py-cmdi-ping`) →
   syntactic recall 80%. Argues for an **ensemble (regex ∪ AI)** safety net under
   the cheaper model.
4. **False positives rise with recall** (3 → 8 → 10 → 13). Per-category FP
   breakdown is a Week 4 task.

---

# Part 2 — Fix + Verify

**Pipeline:** for each bug — copy the case into a sandbox → AI rewrites the file
→ verify. Verification differs by collection:

- `seeded`/`literature` → native unit tests; "vuln gone" via detector **re-scan**.
- `cweval` → CWEval pytest oracle in **Docker**: `functionality` marker = "still
  works", `security` marker = a real **exploit-based** "vuln gone" (stronger than
  re-scan). 43–44 of 56 cases used this stronger oracle signal.

**Verdicts:** `fixed` (vuln gone + compiles + tests pass + no new finding) /
`regressed` (a test/compile broke, or a new finding appeared) / `no-op` (vuln
still present, nothing broke) / `error`.

## Verdict distribution

| Verdict | OpenAI `gpt-4.1-mini` | Anthropic `sonnet-4-6` |
|---|---:|---:|
| ✅ fixed      | 27 (48%) | 19 (34%) |
| ⚠️ regressed  | 23 (41%) | 34 (61%) |
| ➖ no-op      | 6 (11%)  | 3 (5%)   |
| ✗ error      | 0        | 0        |

## Why `regressed` is misleading — read this before the table above

The strict `fixed` verdict counts a fix as regressed if the **AI re-scan flags any
new finding** — and that re-scan is stochastic and noisy. Breaking `regressed`
down by its actual cause:

| Regressed cause | OpenAI | Sonnet |
|---|---:|---:|
| new-finding only (noisy re-scan; compiles + tests pass) | 12 | 18 |
| test failure (real) | 9 | 10 |
| compile failure (real) | 2 | 6 |

So most of the gap between the two models is **measurement noise**: Sonnet is a
more aggressive *detector*, so its post-fix re-scan reports more "new findings,"
inflating its `regressed` count. Controlling for that with a **functional-fix
rate** (vuln removed **and** compiles **and** tests/oracle pass, *ignoring* the
new-finding signal):

| Metric | OpenAI | Sonnet |
|---|---:|---:|
| strict `fixed` | 27/56 (48%) | 19/56 (34%) |
| **functional-fix** | **38/56 (68%)** | **35/56 (63%)** |
| real breakage (compile+test) | 11 | 16 |

The two models are actually close on real fixing (68% vs 63%). Sonnet's
whole-file rewrites break compile/tests a bit more often (16 vs 11) — the honest
downside of a more powerful model making larger edits.

## Fix verdicts by collection

| Collection | OpenAI (fixed/regressed/no-op) | Sonnet (fixed/regressed/no-op) |
|---|---|---|
| cweval (Docker oracle) | 20 / 18 / 6 | 14 / 27 / 3 |
| literature | 2 / 4 / 0 | 2 / 4 / 0 |
| seeded     | 5 / 1 / 0 | 3 / 3 / 0 |

## Run metadata

| Run | Kind | Date | Cost | $/case | Wall | Raw rows |
|---|---|---|---:|---:|---:|---|
| regex baseline      | detect | 2026-07-02 | $0.00   | $0.00   | <1s      | `results/full_regex.jsonl` |
| OpenAI gpt-4.1-mini | detect | 2026-07-02 | $0.053  | $0.0009 | ~4.4 min | `results/openai.jsonl` |
| Anthropic sonnet-4-6| detect | 2026-07-03 | $0.747  | $0.0133 | ~12.5 min| `results/sonnet_detect.jsonl` |
| Anthropic opus-4-8  | detect | 2026-07-02 | $1.380  | $0.0246 | ~9.7 min | `results/claude.jsonl` |
| OpenAI gpt-4.1-mini | fix    | 2026-07-03 | $0.028  | $0.0005 | ~12.3 min| `results/fix_openai.jsonl` |
| Anthropic sonnet-4-6| fix    | 2026-07-03 | $0.330  | $0.0059 | ~17.7 min| `results/fix_sonnet.jsonl` |

> Cost/latency are captured **per case** in each JSONL row (`usage`); the CLI
> prints per-case `$cost latency` plus a `wall time` footer.

## Fix observations

1. **~2/3 of vulnerabilities are functionally fixed** by both models (OpenAI 68%,
   Sonnet 63%) — vuln removed without breaking compile or tests. The headline
   `fixed` verdict (48% / 34%) understates this because of the noisy new-finding
   signal.
2. **The `regressed` signal needs the reason breakdown to be meaningful.** ~half
   of all regressions are "new-finding-only" from a stochastic re-scan. A future
   improvement: use a *deterministic* detector (regex, or the Docker oracle's own
   security check) for the new-finding gate instead of the AI re-scan.
3. **The Docker oracle worked at scale.** 43–44 of 56 cases were verified with the
   exploit-based `security` oracle — a stronger "vuln gone" signal than re-scan —
   with zero pipeline errors across both full runs.
4. **Real breakage is the true cost signal.** Compile+test failures (OpenAI 11,
   Sonnet 16) are the genuine "the fix caused a problem" cases. `py-cmdi-ping`
   regressed for both by changing a function's return contract (list vs string) —
   a valid security fix that breaks the API, exactly the nuanced case the loop is
   built to catch.
5. **Cheaper isn't worse at fixing.** OpenAI `gpt-4.1-mini` matched Sonnet on
   functional-fix at **~12× lower cost** ($0.028 vs $0.330) — a strong argument
   for cheap models in the fix role even where a stronger model detects better.

---

## How to reproduce

Run from `harness/` (keys loaded from `harness/.env`):

```bash
# --- Part 1: detection ---
python -m securepatch_bench bench --record results/full_regex.jsonl
python -m securepatch_bench bench --detector ai --provider openai \
    --model gpt-4.1-mini --scans 3 --record results/openai.jsonl
python -m securepatch_bench bench --detector ai --provider anthropic \
    --model claude-sonnet-4-6 --scans 3 --record results/sonnet_detect.jsonl

# --- Part 2: fix + verify (cweval needs the Docker image built) ---
docker build -t securepatch-cweval docker/
python -m securepatch_bench fix --provider openai --model gpt-4.1-mini \
    --record results/fix_openai.jsonl
python -m securepatch_bench fix --provider anthropic --model claude-sonnet-4-6 \
    --record results/fix_sonnet.jsonl
```

> Update this file whenever a run is re-executed — keep the date/cost/verdict
> columns current. Providers `gemini` and `ollama` are also wired in (add a
> `GEMINI_API_KEY`, or run a local Ollama server) but are not yet in these tables.
