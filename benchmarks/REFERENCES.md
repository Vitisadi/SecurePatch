# References

Primary sources behind the benchmark corpus and its
[selection methodology](SELECTION.md). Per-case citations live in each
`meta.json → provenance.sources`; this file is the consolidated bibliography.

## Authoritative weakness rankings / standards

- **2024 CWE Top 25 Most Dangerous Software Weaknesses.** MITRE / CISA
  (Homeland Security Systems Engineering and Development Institute), released
  19 Nov 2024; derived from 31,770 CVE records.
  <https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html>
  Methodology: <https://cwe.mitre.org/top25/archive/2024/2024_methodology.html>
- **OWASP Top 10 — 2021.** OWASP Foundation. <https://owasp.org/Top10/>
- **Individual CWE entries** (canonical definitions + demonstrative examples):
  - CWE-79 Cross-site Scripting — <https://cwe.mitre.org/data/definitions/79.html>
  - CWE-89 SQL Injection — <https://cwe.mitre.org/data/definitions/89.html>
  - CWE-22 Path Traversal — <https://cwe.mitre.org/data/definitions/22.html>
  - CWE-78 OS Command Injection — <https://cwe.mitre.org/data/definitions/78.html>
  - CWE-502 Deserialization of Untrusted Data — <https://cwe.mitre.org/data/definitions/502.html>
  - CWE-798 Use of Hard-coded Credentials — <https://cwe.mitre.org/data/definitions/798.html>

## Adopted benchmark — CWEval

- **CWEval: Outcome-driven Evaluation on Functionality and Security of LLM Code
  Generation.** Peng et al., arXiv:2501.08200, 2025 (LLM4Code 2025).
  Paper <https://arxiv.org/abs/2501.08200> · Repo <https://github.com/Co1lin/CWEval> (Apache-2.0).
  *Role:* its in-scope Python/JS tasks are **vendored as the `cweval/` collection**
  (see `cweval/ATTRIBUTION.md`). 119 tasks / 31 CWEs / 5 languages with **dual
  functional + security oracles**; source of the `func-sec@k` idea and the finding
  that static analysis is unstable for verifying fixes.

## Benchmarks cited by our authored cases

- **SecurityEval Dataset: Mining Vulnerability Examples to Evaluate ML-Based Code
  Generation Techniques.** Siddiq & Santos, MSR4P&S '22, 2022.
  <https://doi.org/10.1145/3549035.3561184>
  *Why we cite it:* 130 Python samples across 75 CWEs — establishes that our
  `literature/` Python classes appear in prior work.
- **SALLM: Security Assessment of LLM-Generated Code.** Siddiq et al. (extends
  SecurityEval with an automated, oracle-based evaluation environment).
  <https://www.researchgate.net/publication/385287164_SALLM_Security_Assessment_of_Generated_Code>

## Motivation for the obscurity axis (data contamination)

- **Out of Distribution, Out of Luck: How Well Can LLMs Trained on Vulnerability
  Datasets Detect Top 25 CWE Weaknesses?** arXiv:2507.21817.
  <https://arxiv.org/pdf/2507.21817> — contamination / generalisation gap.
- **Inference-Time Decontamination (When Benchmarks Leak).** arXiv:2601.19334.
  <https://arxiv.org/html/2601.19334v1> — data-contamination handling.

## Appendix — 2024 CWE Top 25 (as used for case ranks)

Reproduced from the MITRE source above for convenience. Ranks 1–10, 12, and the
two new entries (17, 24) were cross-checked against secondary coverage; **confirm
the full list against the official page before publication.**

| # | CWE | Name | # | CWE | Name |
|---|-----|------|---|-----|------|
| 1 | CWE-79 | Cross-site Scripting | 14 | CWE-287 | Improper Authentication |
| 2 | CWE-787 | Out-of-bounds Write | 15 | CWE-269 | Improper Privilege Management |
| 3 | CWE-89 | SQL Injection | 16 | CWE-502 | Deserialization of Untrusted Data |
| 4 | CWE-352 | Cross-Site Request Forgery | 17 | CWE-200 | Exposure of Sensitive Information |
| 5 | CWE-22 | Path Traversal | 18 | CWE-863 | Incorrect Authorization |
| 6 | CWE-125 | Out-of-bounds Read | 19 | CWE-918 | Server-Side Request Forgery |
| 7 | CWE-78 | OS Command Injection | 20 | CWE-119 | Improper Restriction of Memory Buffer |
| 8 | CWE-416 | Use After Free | 21 | CWE-476 | NULL Pointer Dereference |
| 9 | CWE-862 | Missing Authorization | 22 | CWE-798 | Use of Hard-coded Credentials |
| 10 | CWE-434 | Unrestricted Upload of Dangerous File | 23 | CWE-190 | Integer Overflow or Wraparound |
| 11 | CWE-94 | Improper Control of Code Generation (Code Injection) | 24 | CWE-400 | Uncontrolled Resource Consumption |
| 12 | CWE-20 | Improper Input Validation | 25 | CWE-306 | Missing Authentication for Critical Function |
| 13 | CWE-77 | Command Injection | | | |
