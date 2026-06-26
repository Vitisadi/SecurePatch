"""Baseline detection benchmark: scan the corpus and score recall.

This is the end-to-end proof that the corpus is wired up: it runs the *current*
regex detector (via the core CLI) over every case and scores it against the
answer key. It establishes the floor that AI models must beat — especially on
the obscure cases, where the regex detector is expected to score zero.

The same per-case structure will later carry model identity and scan index when
the provider adapters land; for now ``detector`` is always ``regex``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core_bridge import scan_file
from .corpus import Bug, BenchmarkCase, load_corpus, OBSCURITY_TIERS
from .matcher import MatchResult, match_findings


@dataclass
class CaseReport:
    case_id: str
    collection: str
    detector: str
    result: MatchResult
    surprises: list[str] = field(default_factory=list)


@dataclass
class TierTally:
    detected: int = 0
    total: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.total if self.total else 0.0


def run_bench(corpus_dir: str | Path | None = None, window: int = 2) -> list[CaseReport]:
    """Scan every case and return a per-case detection report."""
    reports: list[CaseReport] = []
    for case in load_corpus(corpus_dir):
        reports.append(_bench_case(case, window))
    return reports


def _bench_case(case: BenchmarkCase, window: int) -> CaseReport:
    # Scan each source file once and key its findings by resolved path.
    findings_by_path: dict[Path, list[dict[str, Any]]] = {}
    detector = "regex"
    for source_file in case.source_files():
        scan = scan_file(source_file)
        detector = scan.detector
        findings_by_path[source_file.resolve()] = scan.findings

    # Group the answer key by the file each bug lives in, then match per file so
    # a finding in one file can never satisfy a bug in another.
    bugs_by_path: dict[Path, list[Bug]] = defaultdict(list)
    for bug in case.bugs:
        bugs_by_path[case.bug_file(bug)].append(bug)

    combined = MatchResult()
    for path, bugs in bugs_by_path.items():
        per_file = match_findings(bugs, findings_by_path.get(path, []), window=window)
        combined.matched.extend(per_file.matched)
        combined.missed.extend(per_file.missed)
        combined.false_positives.extend(per_file.false_positives)

    surprises = _detect_surprises(combined)
    return CaseReport(
        case_id=case.case_id,
        collection=case.collection,
        detector=detector,
        result=combined,
        surprises=surprises,
    )


def collection_tallies(reports: list[CaseReport]) -> dict[str, TierTally]:
    """Aggregate detected/total per collection (seeded vs literature)."""
    tallies: dict[str, TierTally] = {}
    for report in reports:
        tally = tallies.setdefault(report.collection, TierTally())
        tally.detected += report.result.detected_count
        tally.total += report.result.bug_count
    return tallies


def _detect_surprises(result: MatchResult) -> list[str]:
    """Flag mismatches between a bug's `detectable_by_regex` expectation and the
    actual detector outcome — these point at either a detector gap or a
    mislabeled ground-truth case."""
    surprises: list[str] = []
    for match in result.matched:
        if not match.bug.detectable_by_regex:
            surprises.append(
                f"{match.bug.id}: labeled regex-undetectable but the detector found it"
            )
    for bug in result.missed:
        if bug.detectable_by_regex:
            surprises.append(
                f"{bug.id}: labeled regex-detectable but the detector missed it"
            )
    return surprises


def tier_tallies(reports: list[CaseReport]) -> dict[str, TierTally]:
    """Aggregate detected/total per obscurity tier across all reports."""
    tallies: dict[str, TierTally] = {tier: TierTally() for tier in OBSCURITY_TIERS}
    for report in reports:
        for match in report.result.matched:
            tallies[match.bug.obscurity].detected += 1
            tallies[match.bug.obscurity].total += 1
        for bug in report.result.missed:
            tallies[bug.obscurity].total += 1
    return tallies


def totals(reports: list[CaseReport]) -> tuple[int, int, int]:
    """Return (detected, bug_total, false_positives) summed over all cases."""
    detected = sum(r.result.detected_count for r in reports)
    bug_total = sum(r.result.bug_count for r in reports)
    false_positives = sum(len(r.result.false_positives) for r in reports)
    return detected, bug_total, false_positives
