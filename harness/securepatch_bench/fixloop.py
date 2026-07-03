"""The fix + verify loop: detect -> sandbox -> fix -> verify -> verdict.

For each known bug in a case we: copy the case into a sandbox, scan the target
file for a baseline, ask the fixer to patch it, then verify the patch. The four
verify signals collapse into one verdict per attempt:

- ``fixed``     — vuln gone AND tests pass (or skipped) AND compiles AND no new findings
- ``regressed`` — a test broke, the file stopped compiling, or a NEW finding appeared
- ``no-op``     — nothing broke, but the vulnerability is still detected
- ``error``     — the model/patch could not be produced or applied

``regressed`` is the core "did the fix cause a problem?" measurement. Every
attempt is one provenance row: prompt-derived diff, verify detail, usage, verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .corpus import Bug, BenchmarkCase, load_corpus
from .detectors import Detector
from .fixer import AIFixer, FixResult
from .providers.base import ModelUsage
from .sandbox import sandbox_case
from .verify import VerifyResult, verify_fix

VERDICTS = ("fixed", "regressed", "no-op", "error")


@dataclass
class FixAttempt:
    case_id: str
    collection: str
    bug_id: str
    bug_type: str
    obscurity: str
    verdict: str
    fix: FixResult
    verify: Optional[VerifyResult]
    reason: str = ""

    @property
    def usage(self) -> Optional[ModelUsage]:
        return self.fix.usage


@dataclass
class FixLoopReport:
    attempts: list[FixAttempt] = field(default_factory=list)


def run_fixloop(
    fixer: AIFixer,
    detector: Detector,
    corpus_dir: str | Path | None = None,
    collection: str | None = None,
    case_id: str | None = None,
    window: int = 2,
) -> FixLoopReport:
    """Run the fix+verify loop over the corpus (optionally scoped)."""
    report = FixLoopReport()
    for case in load_corpus(corpus_dir, collection=collection):
        if case_id is not None and case.case_id != case_id:
            continue
        for bug in case.bugs:
            report.attempts.append(_fix_one(case, bug, fixer, detector, window))
    if case_id is not None and not report.attempts:
        raise ValueError(f"case '{case_id}' not found in corpus")
    return report


def _fix_one(
    case: BenchmarkCase, bug: Bug, fixer: AIFixer, detector: Detector, window: int
) -> FixAttempt:
    with sandbox_case(case) as sandbox:
        target = sandbox.path(bug.file)

        # Baseline scan: what the detector sees before we touch anything. Used to
        # tell genuinely-new findings apart from pre-existing ones.
        baseline = detector.scan(target)
        baseline_findings = [] if baseline.error else baseline.findings

        vuln = _finding_for_bug(bug, baseline_findings, window)
        fix = fixer.fix(target, vuln, bug.file)
        if not fix.applied:
            return _attempt(case, bug, "error", fix, None, fix.error or "fix not applied")

        verify = verify_fix(sandbox, target, bug, baseline_findings, detector, window)
        verdict, reason = _verdict(verify)
        return _attempt(case, bug, verdict, fix, verify, reason)


def _finding_for_bug(bug: Bug, findings: list, window: int) -> dict:
    """Prefer the detector's own finding for this bug (richer description); fall
    back to the ground-truth bug so we can still fix an undetected vuln."""
    from .matcher import match_findings

    match = match_findings([bug], findings, window=window)
    if match.matched:
        return match.matched[0].finding
    return {
        "type": bug.type,
        "line_start": bug.line_start,
        "cwe": bug.cwe,
        "description": bug.description,
    }


def _verdict(v: VerifyResult) -> tuple[str, str]:
    if v.compiles is False:
        return "regressed", "patched file no longer compiles"
    if v.tests_ran and v.tests_passed is False:
        return "regressed", "a previously-passing test now fails"
    if v.new_findings:
        types = ", ".join(sorted({f.get("type", "?") for f in v.new_findings}))
        return "regressed", f"fix introduced new finding(s): {types}"
    if v.vuln_still_present:
        return "no-op", "vulnerability still detected after fix"
    return "fixed", "vuln gone, compiles, tests pass"


def _attempt(
    case: BenchmarkCase,
    bug: Bug,
    verdict: str,
    fix: FixResult,
    verify: Optional[VerifyResult],
    reason: str,
) -> FixAttempt:
    return FixAttempt(
        case_id=case.case_id,
        collection=case.collection,
        bug_id=bug.id,
        bug_type=bug.type,
        obscurity=bug.obscurity,
        verdict=verdict,
        fix=fix,
        verify=verify,
        reason=reason,
    )


def verdict_tally(report: FixLoopReport) -> dict[str, int]:
    tally = {v: 0 for v in VERDICTS}
    for attempt in report.attempts:
        tally[attempt.verdict] = tally.get(attempt.verdict, 0) + 1
    return tally


def total_usage(report: FixLoopReport) -> Optional[ModelUsage]:
    usages = [a.usage for a in report.attempts if a.usage]
    if not usages:
        return None

    def total(attr: str) -> Optional[float]:
        vals = [getattr(u, attr) for u in usages if getattr(u, attr) is not None]
        return sum(vals) if vals else None

    return ModelUsage(
        input_tokens=total("input_tokens"),
        output_tokens=total("output_tokens"),
        cost_usd=total("cost_usd"),
        latency_ms=total("latency_ms"),
    )
