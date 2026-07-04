"""Ensemble analysis: does combining detectors help? (research question 2)

Reuses the per-case ``matched`` / ``missed`` bug ids from recorded detection runs
(one file per detector) to answer *"do multiple AIs help?"* without any new model
calls. A bug counts as found by a detector if that detector matched it in any
scan (i.e. detection@k). Ensembles are computed on the *union* of found bug ids:

- **regex + AI**  — does the cheap deterministic safety net lift an AI's recall?
- **union of models** — best single detector vs. combining several; how many bugs
  each detector finds that *no other* detector does (unique catches).
- **voting@t** — bugs found by at least ``t`` detectors (a precision-oriented view).

Recall is computed exactly from bug ids. False positives can only be *bounded*
here: the rows store FP counts, not FP identities, so a union's true FP count is
between the max single count and the sum — noted, not fabricated.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DetectorRun:
    label: str
    matched: set[str]
    missed: set[str]
    fp: int

    @property
    def all_bugs(self) -> set[str]:
        return self.matched | self.missed


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
    for r in rows:
        matched |= set(r.get("matched", []))
        missed |= set(r.get("missed", []))
        fp += int(r.get("false_positives", 0))
    return DetectorRun(label=label, matched=matched, missed=missed, fp=fp)


def render_markdown(runs: list[DetectorRun]) -> str:
    universe: set[str] = set()
    for r in runs:
        universe |= r.all_bugs
    total = len(universe)
    regex = next((r for r in runs if r.label == "regex"), None)
    ai = [r for r in runs if r.label != "regex"]
    lines: list[str] = []

    def pct(n: int) -> str:
        return f"{n / total:.0%}" if total else "—"

    # 1. Single-detector reference.
    lines += ["### Single-detector recall (reference)", "",
              "| Detector | recall | found | FPs |", "|---|---:|---:|---:|"]
    for r in sorted(runs, key=lambda r: len(r.matched)):
        lines.append(f"| {r.label} | {pct(len(r.matched))} | {len(r.matched)}/{total} | {r.fp} |")
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

    # 5. Voting.
    lines += ["### Voting@t (bug found by >= t detectors)", "",
              "| t | recall | found |", "|---|---:|---:|"]
    for t in range(1, len(runs) + 1):
        agree = sum(1 for bug in universe
                    if sum(bug in r.matched for r in runs) >= t)
        lines.append(f"| >={t} | {pct(agree)} | {agree}/{total} |")
    lines.append("")
    return "\n".join(lines)
