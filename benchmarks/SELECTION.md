# Benchmark case-selection methodology

This document explains **why each benchmark case exists** so the corpus can be
defended in a write-up. Every claim about a case (its weakness class, its
real-world importance, and its presence in prior work) is traceable to a primary
source recorded in the case's `meta.json → provenance` block and collected in
[`REFERENCES.md`](REFERENCES.md).

## Collections, kept separate on purpose

The corpus is two things: **our own authored cases** and the **adopted CWEval
benchmark**. They live in separate directories so results can be reported per
collection and a reviewer can tell at a glance what rests on outside evidence.
The harness records the collection on every result row.

| collection    | what it is | role in the study |
|---------------|------------|-------------------|
| `seeded/`     | cases we authored from scratch | a **control** set we fully own; lets us place bugs anywhere on the obscurity axis |
| `literature/` | cases we authored, with each weakness class drawn from a citable authority (CWE Top 25) | our cases with an **external grounding** trail, and coverage of the deeper obscurity tiers CWEval lacks |
| `cweval/`     | the in-scope (Python/JS) tasks of the **CWEval** benchmark, vendored under Apache-2.0 | **external validity + dynamic oracles**: a standard, peer-reviewed set with functional+security execution oracles |

`seeded/` + `literature/` are "our own"; `cweval/` is the external benchmark we
adopt. We deliberately use **only these** — other benchmarks (real-CVE C/C++
sets, Java SAST suites) are out of language scope and not pursued.

### The `cweval/` collection (adopted wholesale)

CWEval was chosen as the external benchmark because it uniquely fits this project
([paper](https://arxiv.org/abs/2501.08200), [repo](https://github.com/Co1lin/CWEval)):
it covers our languages (Python 25 + JS 23 = **48 in-scope tasks**), and each task
ships an **insecure reference** (→ our scan/fix target), a **secure reference**
(→ a gold patch), and **dual functional + security execution oracles** (→ the
trustworthy fix-verifier that a static detector cannot provide).

How cases are produced (`import-cweval`, see `cweval/ATTRIBUTION.md`):
- `source/` ← CWEval's insecure reference (for Python, assembled from the
  `*_unsafe` function embedded in the test).
- `oracle/` ← CWEval's task (secure reference) + test, **verbatim**.
- `detectable_by_regex` is computed by **running our detector** on the source.
- **Obscurity is provisional.** CWEval does not rate difficulty, so every imported
  case is defaulted to `local-semantic` and flagged `provenance.needs_review`;
  the obscurity tier must be set manually before it is used in the obscurity
  analysis. The same applies to the approximate (whole-file) bug line range on
  cases our detector does not flag.
- **Oracles assume Linux/Docker** (they invoke `ls`, shell operators, `node`); run
  them in CWEval's container, not natively on Windows. Detection on `source/`
  runs anywhere.

## How a `literature/` case is chosen

A vulnerability class is admitted to the literature collection only if it passes
**all four** filters:

1. **Authority — it is in the 2024 CWE Top 25.** MITRE/CISA rank the Top 25 by a
   formula over prevalence and severity across 31,770 CVE records, so membership
   is an evidence-based claim that the weakness matters. Each case records its
   exact rank. ([MITRE 2024 CWE Top 25](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html))
2. **Practitioner relevance — it maps to an OWASP Top 10 (2021) category.** The
   OWASP Top 10 is the most widely used application-security risk list; the
   mapping ties each academic CWE to a category practitioners recognise.
   ([OWASP Top 10 2021](https://owasp.org/Top10/))
3. **Comparability — it appears in at least one peer-reviewed LLM secure-code or
   vulnerability benchmark** (e.g. CWEval, SecurityEval/SALLM). This keeps our
   classes aligned with prior work so numbers can be discussed side by side.
   ([CWEval](https://arxiv.org/abs/2501.08200),
   [SecurityEval](https://doi.org/10.1145/3549035.3561184))
4. **Scope — it is realizable as a small, self-contained program in the tool's
   languages** (Python, JavaScript/TypeScript), runnable with only the standard
   library / built-in test runner.

### What this deliberately excludes (and why)

- **Memory-safety weaknesses** that are C/C++-specific — CWE-787 (#2), CWE-125
  (#6), CWE-416 (#8), CWE-119 (#20), CWE-476 (#21), CWE-190 (#23). They fail
  filter 4 for an interpreted-language tool. CWEval reports these need
  C-specific dynamic oracles (memory-access validity), which is out of scope.
- **Authorization / authentication weaknesses** — CWE-862 (#9), CWE-863 (#18),
  CWE-287 (#14), CWE-306 (#25). These are only meaningful inside a request/
  session framework; a self-contained snippet cannot express them faithfully.
  Recorded here as **deferred**, candidates for a later web-app tier.

## Obscurity stratification (the research axis)

Each case is tagged on a four-tier **obscurity** axis (`syntactic` →
`local-semantic` → `cross-function` → `multi-file`; see
[`README.md`](README.md)). This is the independent variable for the central
research question — "how obscure a bug can the detector / a model find" — and it
is grounded in the **data-contamination** literature: models score far higher on
public, archetypal examples than on novel/private ones (e.g. a ~20-point F1 drop
public→private), so a pattern-matchable one-liner mostly tests *memorisation*,
while deeper tiers test *reasoning*. ([Out of Distribution, Out of Luck](https://arxiv.org/pdf/2507.21817),
[Inference-Time Decontamination](https://arxiv.org/html/2601.19334v1))

Every case also carries a `construction` tag (`archetypal` vs `novel`) so
contamination risk is explicit per case, not assumed away.

## Current literature cases

| case | CWE | Top-25 rank | OWASP 2021 | lang | obscurity | regex |
|------|-----|-------------|------------|------|-----------|-------|
| cwe-079-xss-innerhtml | CWE-79 | 1 | A03 Injection | js | syntactic | detects |
| cwe-089-sqli-python | CWE-89 | 3 | A03 Injection | py | syntactic | detects |
| cwe-022-path-traversal-python | CWE-22 | 5 | A01 Broken Access Control | py | local-semantic | misses |
| cwe-078-cmdi-subprocess | CWE-78 | 7 | A03 Injection | py | syntactic | detects |
| cwe-502-deserialization-pickle | CWE-502 | 16 | A08 Integrity Failures | py | syntactic | detects |
| cwe-798-hardcoded-credentials | CWE-798 | 22 | A07 AuthN Failures | py | syntactic | detects |

"regex" is the *current* detector's outcome, encoded per bug as
`detectable_by_regex`. Two points worth highlighting in a write-up:

- **`cwe-089-sqli-python` started as a coverage gap and drove a detector fix.**
  It is a syntactic one-liner the JS ruleset caught but the Python ruleset did
  not (no Python SQL rule). The benchmark surfaced that asymmetry; a Python SQL
  rule was then added to the base detector to close it — an example of the corpus
  driving non-AI improvements.
- The remaining `misses` (path traversal; cross-function SQL in `seeded/`) are
  genuinely semantic or multi-function — invisible to per-line patterns by
  construction, and where AI detection has to earn its value.

## Threats to validity (state these in the paper)

- **Contamination.** Archetypal constructions are likely in model training data.
  Mitigations: the `construction` tag, the independent `seeded/` control set, and
  a planned tier of novel/post-cutoff cases.
- **Small N.** Six cases per collection is a vertical slice, not a population;
  numbers are illustrative until the corpus is scaled along the same schema.
- **Synthetic vs real.** All cases are seeded. Real CVE-derived cases are a later
  tier (see `docs/RESEARCH_PLAN.md`); the tradeoff is clean labels now vs
  realism later.
- **Static detection oracle.** The current "is it still vulnerable?" check is the
  regex detector, which the literature shows is unstable. A planned upgrade adds
  dynamic exploit oracles + gold patches (CWEval-style func-sec); until then,
  fix-verification numbers must be read with that caveat.

## Reproducibility and extension

- Provenance is **machine-readable** (`meta.json → provenance`) and the loader
  **refuses to load a `literature/` case that cites no source**, so the evidence
  trail cannot silently rot.
- To extend: pick the next in-scope Top-25 CWE (candidates: CWE-94 Code
  Injection #11, CWE-918 SSRF #19, CWE-77 Command Injection #13, CWE-20 Improper
  Input Validation #12, CWE-434 Unrestricted Upload #10), instantiate it across
  the obscurity axis, and fill in the same provenance block.
