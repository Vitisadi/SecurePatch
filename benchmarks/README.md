# SecurePatch benchmark corpus

Labeled, self-describing vulnerability cases that the research harness scans,
fixes, and verifies. This is the project's first research deliverable
(Phase 1 in `../docs/RESEARCH_PLAN.md`): without ground truth there is nothing
to measure recall, fix-success, or regression against.

The cases are **seeded/synthetic** — small programs with deliberately injected,
known bugs. That gives full control over the *obscurity* axis (see below) and an
unambiguous answer key. Established SAST benchmarks and real CVE fixes are later
tiers.

## Collections

Cases live in a collection (one folder level under `benchmarks/`):

| collection    | cases | purpose |
|---------------|-------|---------|
| `seeded/`     | bugs we authored from scratch | a control set we fully own |
| `literature/` | our authored cases, each weakness class drawn from a citable authority (CWE Top 25) | external grounding + the deep obscurity tiers |
| `cweval/`     | the in-scope Python/JS tasks of the [CWEval](https://github.com/Co1lin/CWEval) benchmark, vendored under Apache-2.0 | a standard external benchmark with functional+security execution oracles |

`seeded/` + `literature/` are our own; `cweval/` is the adopted external
benchmark — those are the **only** sources we use. The **rationale for which
cases exist** is in [`SELECTION.md`](SELECTION.md); the bibliography is in
[`REFERENCES.md`](REFERENCES.md); CWEval-specific attribution is in
[`cweval/ATTRIBUTION.md`](cweval/ATTRIBUTION.md). The harness records a case's
collection on every result row, and refuses to load a `literature/` case that
cites no source.

`cweval/` cases carry an extra `oracle/` directory (CWEval's secure reference +
its dynamic functional/security tests, verbatim) for the container-based verify
step; only `source/` is scanned by the detector.

## Case layout

```
benchmarks/<collection>/<case-id>/
  meta.json          # language, category, difficulty, obscurity, how to test, provenance
  ground_truth.json  # the answer key: every known bug, located and typed
  source/            # the vulnerable program (the only thing a model is shown)
  tests/             # functional tests that define "still works"
```

`<case-id>` must equal the `case_id` field inside both JSON files. Only `source/`
is ever fed to a model — `meta.json` / `ground_truth.json` (which name the CWE
and location) are withheld to avoid security-awareness leakage.

### `meta.json`

| field          | meaning                                                            |
|----------------|--------------------------------------------------------------------|
| `case_id`      | unique id; must match the directory name                           |
| `language`     | `python` \| `javascript` \| `typescript`                           |
| `category`     | dominant vulnerability class (see vocabulary)                      |
| `difficulty`   | `easy` \| `medium` \| `hard` (informal)                            |
| `obscurity`    | hardest obscurity tier present in the case (see axis)              |
| `entrypoint`   | the primary source file, repo-relative to the case                 |
| `test_command` | command (run from the case dir) that exercises `tests/`            |
| `description`  | one or two sentences on the bug and why it is/ isn't pattern-visible |
| `provenance`   | optional; **required for `literature/` cases** — CWE id/name/rank, OWASP mapping, `construction` (`archetypal`/`novel`), `selection_rationale`, and a `sources` list (each with a `title`). See [`SELECTION.md`](SELECTION.md). |

### `ground_truth.json`

```jsonc
{
  "case_id": "py-cmdi-ping",
  "bugs": [
    {
      "id": "py-cmdi-ping-1",      // unique within the case
      "file": "source/app.py",      // case-relative path to the file with the bug
      "line_start": 13,             // 1-BASED, inclusive
      "line_end": 13,               // 1-based, inclusive (== line_start for a point bug)
      "type": "command-injection",  // from the vulnerability vocabulary below
      "cwe": "CWE-78",
      "obscurity": "syntactic",     // this specific bug's tier
      "detectable_by_regex": true,  // expectation for the current regex detector
      "description": "..."
    }
  ]
}
```

> **Line numbering.** Ground truth is authored **1-based** (matches what you see
> in an editor). The core detector emits **0-based** lines, so the matcher
> compares `finding.line + 1` against `[line_start, line_end]` with a small
> window. Keep ground-truth lines 1-based.

## Vulnerability vocabulary

Bug `type` is drawn from the same set the detector emits, plus categories that
the regex rules deliberately do **not** cover (those drive the "obscure bugs"
research question):

`sql-injection`, `command-injection`, `code-injection`, `path-traversal`,
`deserialization`, `ssrf`, `weak-randomness`, `xss`, `weak-cryptography`,
`hardcoded-secret`, `vulnerable-dependency`.

## Obscurity axis

The core research question is *"how many scans / which models are needed to find
**obscure** bugs."* "Obscure" is made quantitative by tiering each bug:

| tier             | what makes it hard                                                  | regex floor |
|------------------|--------------------------------------------------------------------|-------------|
| `syntactic`      | a single line matches a known dangerous pattern                    | should find |
| `local-semantic` | needs to understand what a call *does* (e.g. `eval`), no fixed pattern | misses     |
| `cross-function` | the dangerous data flow is split across functions/lines in one file | misses     |
| `multi-file`     | the flow crosses module boundaries                                 | misses      |

`detectable_by_regex` encodes the expected outcome for the current regex
detector. The baseline `bench` run checks the detector against that expectation:
the syntactic cases establish the detector's floor, and the obscure cases are
where AI models have to earn their keep.

## `tests/` — what "still works" means

Tests assert **functional behaviour**, not the vulnerable implementation, so a
correct fix keeps them green (e.g. "the hash is deterministic", not "the hash
equals this MD5 value"). They are dependency-light on purpose:

- Python: `unittest` (stdlib) — `python -m unittest discover -s tests`
- JavaScript: the built-in test runner — `node --test tests/**/*.js`
  (Node expands the `**` glob itself, so it works without shell globbing)

The Week 3 verify loop runs these before/after a fix to detect regressions.

## Current cases

**`seeded/`** (control set, authored by us):

| case                     | lang | category          | obscurity      | regex |
|--------------------------|------|-------------------|----------------|-------|
| `py-cmdi-ping`           | py   | command-injection | syntactic      | yes   |
| `py-weak-hash-md5`       | py   | weak-cryptography | syntactic      | yes   |
| `js-sqli-concat`         | js   | sql-injection     | syntactic      | yes   |
| `js-weak-random-token`   | js   | weak-randomness   | syntactic      | yes   |
| `py-code-injection-eval` | py   | code-injection    | syntactic      | yes   |
| `js-sqli-crossfn`        | js   | sql-injection     | cross-function | no    |

**`literature/`** (CWE Top 25-grounded, each cited — see [`SELECTION.md`](SELECTION.md)):

| case                            | CWE (rank) | lang | obscurity      | regex |
|---------------------------------|------------|------|----------------|-------|
| `cwe-079-xss-innerhtml`         | CWE-79 (1) | js   | syntactic      | yes   |
| `cwe-089-sqli-python`           | CWE-89 (3) | py   | syntactic      | yes   |
| `cwe-022-path-traversal-python` | CWE-22 (5) | py   | local-semantic | no    |
| `cwe-078-cmdi-subprocess`       | CWE-78 (7) | py   | syntactic      | yes   |
| `cwe-502-deserialization-pickle`| CWE-502 (16)| py  | syntactic      | yes   |
| `cwe-798-hardcoded-credentials` | CWE-798 (22)| py  | syntactic      | yes   |

The remaining `no` (path traversal, cross-function SQL) are genuinely semantic /
multi-function — left for the AI tier on purpose. `cwe-089-sqli-python` once read
`gap` (the detector had a JS SQL rule but none for Python); that gap was closed by
adding a Python SQL rule to the base detector.

**`cweval/`** — 44 imported tasks (23 JS + 21 Python; 4 Python tasks skipped, no
extractable insecure reference). Obscurity is provisional (`needs_review`) on all
of them. The detector flags 9/44 — most CWEval bugs are semantic, span multiple
lines, or are classes the regex rules deliberately don't cover.

Across the whole corpus (56 cases) the regex baseline is **19/56 recall, 3 false
positives** (up from 11/56 before the base detector was extended; see
[base-detector coverage](#base-detector-coverage)). The 3 false positives are
the detector firing off-target on the two CWE-643/943 query-injection tasks
(flagging an incidental secret or a SQL-shaped string). Run
`python -m securepatch_bench bench` for the live per-collection breakdown.

## Base-detector coverage

The non-AI baseline is a rule set in `core/src/scanners/codeScanner.ts`. Using
this corpus as a regression harness, it was extended beyond the original
md5/sha1, `os.system`, `Math.random`, `innerHTML`, and JS-SQL rules to also flag:
`eval`/`exec` and JS `eval` (code injection), `pickle`/`yaml.load`/`unserialize`
(unsafe deserialization), Python SQL string-building, weak crypto (RSA < 2048,
ECB mode, static/zero IV, DES/RC4/Blowfish, SHA-2 used for passwords), and
multi-line `subprocess(..., shell=True)`. Path traversal, SSRF, log injection,
HTTP response splitting, ReDoS, and cross-function data flow are **intentionally
left to the AI tier** — pattern rules for them would be noisy.

## Running the baseline

From the repo root, after `npm run build:core`:

```bash
python -m securepatch_bench bench
```

This scans every case with the regex detector, matches findings against the
answer key, and reports recall overall and per obscurity tier.
