"""Match detector findings against the ground-truth answer key.

This is the component every recall number depends on, so its rules are explicit:

* A finding matches a bug when the **type** is identical AND the finding's line
  falls within the bug's line range expanded by ``window`` lines on each side.
* Core findings use **0-based** lines; ground truth is **1-based**. We compare
  ``finding["line"] + 1`` against ``[line_start, line_end]``.
* Matching is one-to-one and greedy: each bug consumes at most one finding and
  each finding is counted once, so duplicate findings cannot inflate recall.

From a match we derive the three standard buckets:
  - matched bugs        -> true positives (detected)
  - unmatched bugs      -> false negatives (missed)
  - unmatched findings  -> false positives (noise)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .corpus import Bug

DEFAULT_WINDOW = 2


@dataclass(frozen=True)
class Match:
    bug: Bug
    finding: dict[str, Any]


@dataclass
class MatchResult:
    matched: list[Match] = field(default_factory=list)
    missed: list[Bug] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)

    @property
    def detected_count(self) -> int:
        return len(self.matched)

    @property
    def bug_count(self) -> int:
        return len(self.matched) + len(self.missed)

    @property
    def recall(self) -> float:
        total = self.bug_count
        return len(self.matched) / total if total else 0.0


def _finding_line_1based(finding: dict[str, Any]) -> int:
    # Core emits 0-based lines; ground truth is 1-based.
    return int(finding.get("line", 0)) + 1


def match_findings(
    bugs: list[Bug],
    findings: list[dict[str, Any]],
    window: int = DEFAULT_WINDOW,
) -> MatchResult:
    """Match ``findings`` against ``bugs`` for a single set already scoped to one
    file (or to a whole case, as long as the line ranges don't collide).
    """
    result = MatchResult()
    remaining = list(findings)

    for bug in bugs:
        low = bug.line_start - window
        high = bug.line_end + window
        hit_index: int | None = None

        for index, finding in enumerate(remaining):
            if finding.get("type") != bug.type:
                continue
            if low <= _finding_line_1based(finding) <= high:
                hit_index = index
                break

        if hit_index is None:
            result.missed.append(bug)
        else:
            result.matched.append(Match(bug=bug, finding=remaining.pop(hit_index)))

    result.false_positives = remaining
    return result
