"""Detection benchmark: scan the corpus with a detector and score recall.

Originally the regex baseline; now detector-agnostic. The same per-case scoring
runs against either the regex detector (the floor AI must beat) or an AI
detector, and supports repeated scans per case so we can measure how detection
accumulates over ``k`` attempts (the "how many scans to find obscure bugs"
question).

For a single scan the report is exactly the old baseline. For ``scans > 1`` the
headline ``result`` is **detection@k** — a bug counts as detected if any scan
found it — and each scan's matches are retained on ``per_scan`` for discovery
curves.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .corpus import Bug, BenchmarkCase, load_corpus, OBSCURITY_TIERS
from .detectors import Detector, RegexDetector
from .matcher import Match, MatchResult, match_findings
from .providers.base import ModelUsage


@dataclass
class CaseReport:
    case_id: str
    collection: str
    detector: str
    result: MatchResult  # detection@k union across scans (== the scan when scans==1)
    per_scan: list[MatchResult] = field(default_factory=list)
    usage: Optional[ModelUsage] = None
    surprises: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class TierTally:
    detected: int = 0
    total: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.total if self.total else 0.0


def run_bench(
    corpus_dir: str | Path | None = None,
    window: int = 2,
    detector: Detector | None = None,
    scans: int = 1,
) -> list[CaseReport]:
    """Scan every case ``scans`` times and return a per-case detection report."""
    det = detector or RegexDetector()
    reports: list[CaseReport] = []
    for case in load_corpus(corpus_dir):
        reports.append(_bench_case(case, window, det, scans))
    return reports


def _bench_case(
    case: BenchmarkCase, window: int, detector: Detector, scans: int
) -> CaseReport:
    # Group the answer key by file once so a finding in one file can never
    # satisfy a bug in another.
    bugs_by_path: dict[Path, list[Bug]] = defaultdict(list)
    for bug in case.bugs:
        bugs_by_path[case.bug_file(bug)].append(bug)

    per_scan: list[MatchResult] = []
    usages: list[ModelUsage] = []
    errors: list[str] = []
    detector_name = detector.name

    for _ in range(scans):
        findings_by_path: dict[Path, list[dict[str, Any]]] = {}
        for source_file in case.source_files():
            ds = detector.scan(source_file)
            detector_name = ds.detector
            if ds.error:
                errors.append(f"{source_file.name}: {ds.error}")
            if ds.usage:
                usages.append(ds.usage)
            findings_by_path[source_file.resolve()] = ds.findings

        combined = MatchResult()
        for path, bugs in bugs_by_path.items():
            per_file = match_findings(bugs, findings_by_path.get(path, []), window=window)
            combined.matched.extend(per_file.matched)
            combined.missed.extend(per_file.missed)
            combined.false_positives.extend(per_file.false_positives)
        per_scan.append(combined)

    union = _union_match(per_scan)
    return CaseReport(
        case_id=case.case_id,
        collection=case.collection,
        detector=detector_name,
        result=union,
        per_scan=per_scan,
        usage=_sum_usage(usages),
        surprises=_detect_surprises(union),
        errors=errors,
    )


def _union_match(per_scan: list[MatchResult]) -> MatchResult:
    """Collapse per-scan results into detection@k: a bug is matched if any scan
    matched it. False positives are taken from the first scan as a representative
    sample (use ``per_scan`` for exact per-scan FP counts)."""
    if len(per_scan) == 1:
        return per_scan[0]

    matched_by_bug: dict[str, Match] = {}
    all_bugs: dict[str, Bug] = {}
    for result in per_scan:
        for match in result.matched:
            matched_by_bug.setdefault(match.bug.id, match)
            all_bugs[match.bug.id] = match.bug
        for bug in result.missed:
            all_bugs[bug.id] = bug

    matched = list(matched_by_bug.values())
    missed = [bug for bug_id, bug in all_bugs.items() if bug_id not in matched_by_bug]
    return MatchResult(
        matched=matched,
        missed=missed,
        false_positives=per_scan[0].false_positives,
    )


def _sum_usage(usages: list[ModelUsage]) -> Optional[ModelUsage]:
    if not usages:
        return None

    def total(attr: str) -> Optional[float]:
        values = [getattr(u, attr) for u in usages if getattr(u, attr) is not None]
        return sum(values) if values else None

    return ModelUsage(
        input_tokens=total("input_tokens"),
        output_tokens=total("output_tokens"),
        cost_usd=total("cost_usd"),
        latency_ms=total("latency_ms"),
    )


def total_usage(reports: list[CaseReport]) -> Optional[ModelUsage]:
    """Aggregate usage across all cases (None if no model was used)."""
    return _sum_usage([r.usage for r in reports if r.usage])


def collection_tallies(reports: list[CaseReport]) -> dict[str, TierTally]:
    """Aggregate detected/total per collection (seeded vs literature vs cweval)."""
    tallies: dict[str, TierTally] = {}
    for report in reports:
        tally = tallies.setdefault(report.collection, TierTally())
        tally.detected += report.result.detected_count
        tally.total += report.result.bug_count
    return tallies


def _detect_surprises(result: MatchResult) -> list[str]:
    """Flag mismatches between a bug's `detectable_by_regex` expectation and the
    actual detector outcome — either a detector gap or a mislabeled case."""
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
