"""Ensemble analysis: does combining detectors help? (research question 2)

Reuses the per-case ``matched`` / ``missed`` bug ids from recorded detection runs
(one file per detector) to answer *"do multiple AIs help?"* without any new model
calls. A bug counts as found by a detector if that detector matched it in any
scan (i.e. detection@k). Ensembles are computed on the *union* of found bug ids:

- **regex + AI**  — does the cheap deterministic safety net lift an AI's recall?
- **union of models** — best single detector vs. combining several; how many bugs
  each detector finds that *no other* detector does (unique catches).
- **voting@t** — bugs found by at least ``t`` detectors (a precision-oriented view).

Recall is computed exactly from bug ids. False positives are computed exactly when
``false_positive_findings`` is present in the JSONL (a finding is a FP in the
ensemble if it appears in >=t detectors' FP lists, matched by type+line). When
that field is absent, FP counts can only be bounded: between the max single count
and the sum — noted, not fabricated.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DetectorRun:
    label: str
    matched: set[str]
    missed: set[str]
    fp: int
    # Per-case FP findings keyed by case_id; empty dict when not available.
    fp_findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def all_bugs(self) -> set[str]:
        return self.matched | self.missed

    @property
    def has_fp_findings(self) -> bool:
        return bool(self.fp_findings)


def load_detector(path: str | Path) -> DetectorRun:
    rows = [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    label = rows[0].get("model") or rows[0].get("detector") or Path(path).stem
    matched: set[str] = set()
    missed: set[str] = set()
    fp = 0
    fp_findings: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        matched |= set(r.get("matched", []))
        missed |= set(r.get("missed", []))
        fp += int(r.get("false_positives", 0))
        if "false_positive_findings" in r:
            case_id = r["case_id"]
            fp_findings.setdefault(case_id, []).extend(r["false_positive_findings"])
    return DetectorRun(label=label, matched=matched, missed=missed, fp=fp,
                       fp_findings=fp_findings)


def _fp_key(finding: dict[str, Any]) -> tuple[str, int]:
    """Canonical key for deduplicating findings across detectors: (type, line)."""
    return (str(finding.get("type", "")), int(finding.get("line", -1)))


def _voting_fp_exact(runs: list["DetectorRun"], t: int) -> int:
    """Count FPs that appear in >= t detectors (exact, requires fp_findings)."""
    # Collect all FP keys per case across all detectors.
    case_fp_counts: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for run in runs:
        for case_id, findings in run.fp_findings.items():
            for f in findings:
                key = _fp_key(f)
                case_fp_counts[(case_id, key)][run.label] += 1
    # A (case, type, line) is an ensemble FP if >= t distinct detectors flagged it.
    total = 0
    for (case_id, key), detector_counts in case_fp_counts.items():
        detectors_with_fp = sum(1 for cnt in detector_counts.values() if cnt > 0)
        if detectors_with_fp >= t:
            total += 1
    return total


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def render_markdown(runs: list[DetectorRun]) -> str:
    universe: set[str] = set()
    for r in runs:
        universe |= r.all_bugs
    total = len(universe)
    regex = next((r for r in runs if r.label == "regex"), None)
    ai = [r for r in runs if r.label != "regex"]
    has_fp_findings = all(r.has_fp_findings for r in runs)
    lines: list[str] = []

    def pct(n: int) -> str:
        return f"{n / total:.0%}" if total else "—"

    def f1_str(tp: int, fp: int, fn: int) -> str:
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        return f"{_f1(prec, rec):.0%}"

    # 1. Single-detector reference.
    lines += ["### Single-detector recall (reference)", "",
              "| Detector | recall | found | FPs | F1 |", "|---|---:|---:|---:|---:|"]
    for r in sorted(runs, key=lambda r: len(r.matched)):
        fn = total - len(r.matched)
        f1 = f1_str(len(r.matched), r.fp, fn)
        lines.append(f"| {r.label} | {pct(len(r.matched))} | {len(r.matched)}/{total} | {r.fp} | {f1} |")
    lines.append("")

    # 2. regex ∪ AI.
    if regex is not None:
        lines += ["### regex + AI (cheap safety net)", "",
                  "| Model | alone | + regex | gain |", "|---|---:|---:|---:|"]
        for r in sorted(ai, key=lambda r: len(r.matched)):
            combined = r.matched | regex.matched
            delta = len(combined) - len(r.matched)
            lines.append(f"| {r.label} | {pct(len(r.matched))} | {pct(len(combined))} | +{delta} |")
        lines.append("")

    # 3. Union of models.
    best = max(runs, key=lambda r: len(r.matched))
    ai_union: set[str] = set().union(*[r.matched for r in ai]) if ai else set()
    all_union: set[str] = set().union(*[r.matched for r in runs]) if runs else set()
    lines += ["### Union of detectors", "",
              "| Ensemble | recall | found |", "|---|---:|---:|",
              f"| best single ({best.label}) | {pct(len(best.matched))} | {len(best.matched)}/{total} |",
              f"| all AI models | {pct(len(ai_union))} | {len(ai_union)}/{total} |",
              f"| all AI + regex | {pct(len(all_union))} | {len(all_union)}/{total} |", ""]
    still_missed = universe - all_union
    lines.append(f"Bugs no detector finds: **{len(still_missed)}**"
                 + (f" ({', '.join(sorted(still_missed))})" if still_missed else "") + "\n")

    # 4. Unique catches (found by exactly one detector).
    finders = Counter()
    for bug in universe:
        who = [r.label for r in runs if bug in r.matched]
        if len(who) == 1:
            finders[who[0]] += 1
    lines += ["### Unique catches (bug found by exactly one detector)", "",
              "| Detector | unique bugs |", "|---|---:|"]
    for r in runs:
        lines.append(f"| {r.label} | {finders.get(r.label, 0)} |")
    lines.append("")

    # 5. Voting — with exact F1 if fp_findings available, bounds otherwise.
    if has_fp_findings:
        lines += ["### Voting@t — recall, FPs, and F1 (exact)", "",
                  "| t | recall | found | FPs | precision | F1 |",
                  "|---|---:|---:|---:|---:|---:|"]
        for t in range(1, len(runs) + 1):
            found = sum(1 for bug in universe
                        if sum(bug in r.matched for r in runs) >= t)
            fp_exact = _voting_fp_exact(runs, t)
            fn = total - found
            prec = found / (found + fp_exact) if (found + fp_exact) else 0.0
            rec = found / total if total else 0.0
            f1 = _f1(prec, rec)
            lines.append(
                f"| >={t} | {rec:.0%} | {found}/{total} | {fp_exact} | {prec:.0%} | {f1:.0%} |"
            )
    else:
        lines += ["### Voting@t (bug found by >= t detectors)", "",
                  "| t | recall | found |", "|---|---:|---:|",
                  "*(re-run bench with updated schema to get exact FP counts and F1)*", ""]
        for t in range(1, len(runs) + 1):
            agree = sum(1 for bug in universe
                        if sum(bug in r.matched for r in runs) >= t)
            lines.append(f"| >={t} | {pct(agree)} | {agree}/{total} |")

    lines.append("")
    return "\n".join(lines)
