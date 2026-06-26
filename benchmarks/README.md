# SecurePatch benchmark corpus

Labeled, self-describing vulnerability cases that the research harness scans,
fixes, and verifies. This is the project's first research deliverable
(Phase 1 in `../docs/RESEARCH_PLAN.md`): without ground truth there is nothing
to measure recall, fix-success, or regression against.

The corpus is **seeded/synthetic** — small programs with deliberately injected,
known bugs. That gives full control over the *obscurity* axis (see below) and an
unambiguous answer key. Established SAST benchmarks and real CVE fixes are later
tiers.

## Case layout

```
benchmarks/<case-id>/
  meta.json          # language, category, difficulty, obscurity, how to test
  ground_truth.json  # the answer key: every known bug, located and typed
  source/            # the vulnerable program
  tests/             # functional tests that define "still works"
```

`<case-id>` must equal the `case_id` field inside both JSON files.

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

`sql-injection`, `command-injection`, `code-injection`, `weak-randomness`,
`xss`, `weak-cryptography`, `hardcoded-secret`, `vulnerable-dependency`.

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

| case                     | lang | category          | obscurity      | regex |
|--------------------------|------|-------------------|----------------|-------|
| `py-cmdi-ping`           | py   | command-injection | syntactic      | yes   |
| `py-weak-hash-md5`       | py   | weak-cryptography | syntactic      | yes   |
| `js-sqli-concat`         | js   | sql-injection     | syntactic      | yes   |
| `js-weak-random-token`   | js   | weak-randomness   | syntactic      | yes   |
| `py-code-injection-eval` | py   | code-injection    | local-semantic | no    |
| `js-sqli-crossfn`        | js   | sql-injection     | cross-function | no    |

Four cases set the regex floor; two are deliberately beyond per-line pattern
matching, reserved for the model comparison.

## Running the baseline

From the repo root, after `npm run build:core`:

```bash
python -m securepatch_bench bench
```

This scans every case with the regex detector, matches findings against the
answer key, and reports recall overall and per obscurity tier.
