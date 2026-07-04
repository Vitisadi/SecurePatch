"""A verification pass that filters false positives out of detector findings.

Detection ("scan the whole file for anything wrong") is recall-oriented and
over-flags. Verification is the opposite task: given ONE reported finding, decide
whether it is a real, exploitable vulnerability — a precision-oriented judgment.
That mode-switch is what removes false positives, even with the same model.

``AIVerifier.judge`` is an LLM-as-judge over a single finding (temperature 0 — a
crisp per-shot decision). ``run_verification`` measures its value against ground
truth: because the matcher labels every finding as a true positive (matched a
real bug) or a false positive, we can report exactly how many FPs the judge
removes vs. how many real bugs it wrongly rejects — precision gain vs. recall cost.

Verifier model choice is deliberately separate from the detector's: our ensemble
analysis showed the detectors are a strict hierarchy, so a *weaker* judge would
reject true findings it cannot itself recognize. Use the same model (default) or
a stronger one — never a weaker one.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .corpus import Bug, BenchmarkCase, load_corpus
from .detectors import Detector, LANGUAGE_BY_SUFFIX
from .matcher import match_findings
from .providers.base import ModelProvider, ModelRequest, ModelUsage, ProviderError


@dataclass
class Judgment:
    keep: bool
    reason: str = ""
    usage: Optional[ModelUsage] = None
    error: Optional[str] = None


VERIFY_SYSTEM = (
    "You are a security engineer performing a careful second-pass review. You are "
    "given ONE finding from an automated scan and must decide whether it describes a "
    "real security vulnerability or a false positive. Reject a finding ONLY when it "
    "is genuinely not a vulnerability: the flagged data is sanitized, validated, or a "
    "constant; the operation is not actually security-sensitive; the reported type is "
    "wrong; or the code path cannot execute. Otherwise keep it. Do NOT reject a "
    "finding merely because the file looks like a small example or the input source "
    "is not shown. Respond with JSON only."
)


class AIVerifier:
    """LLM-as-judge that keeps or rejects a single finding."""

    def __init__(
        self,
        provider: ModelProvider,
        model: Optional[str] = None,
        temperature: Optional[float] = 0.0,
        max_output_tokens: int = 512,
    ) -> None:
        self.provider = provider
        self.model = model or provider.default_model
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.name = f"verify:{provider.id}:{self.model}"

    def judge(self, finding: dict[str, Any], code: str, filename: str) -> Judgment:
        language = LANGUAGE_BY_SUFFIX.get(Path(filename).suffix.lower(), "unknown")
        prompt = build_verify_prompt(language, filename, code, finding)
        request = ModelRequest(
            model=self.model,
            prompt=prompt,
            system=VERIFY_SYSTEM,
            max_output_tokens=self.max_output_tokens,
            temperature=self.temperature,
        )
        try:
            response = self.provider.complete(request)
        except ProviderError as exc:
            # Conservative on error: keep the finding (never silently drop a bug).
            return Judgment(keep=True, reason="verifier error", error=str(exc))

        keep, reason = parse_judgment(response.text)
        return Judgment(keep=keep, reason=reason, usage=response.usage)


def build_verify_prompt(
    language: str, filename: str, code: str, finding: dict[str, Any]
) -> str:
    numbered = "\n".join(f"{i + 1}\t{line}" for i, line in enumerate(code.splitlines()))
    line_1based = int(finding.get("line", 0)) + 1
    desc = finding.get("description") or finding.get("title") or ""
    return (
        f"An automated scan reported this finding in {language} file {filename}:\n"
        f"- type: {finding.get('type')}\n"
        f"- line: {line_1based}\n"
        + (f"- description: {desc}\n" if desc else "")
        + "\nFull file (line<TAB>source):\n"
        f"{numbered}\n\n"
        "Does this describe a real security vulnerability at that location? Return JSON:\n"
        '{"verdict": "keep" | "reject", "reason": "<one sentence>"}\n'
        "- \"keep\" if it is a genuine security vulnerability of the reported kind.\n"
        "- \"reject\" ONLY if it is clearly not: the data is sanitized/validated/"
        "constant, the operation is not security-sensitive, the reported type is "
        "wrong, or the code cannot execute.\n"
        "- If you cannot tell whether the input is attacker-controlled (e.g. it "
        "arrives from another function or is not shown), ASSUME it is and keep the "
        "finding. Do not reject just because it is a small example file.\n"
    )


_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def parse_judgment(text: str) -> tuple[bool, str]:
    """Parse the judge's JSON. Defaults to keep on unparseable output."""
    cleaned = _FENCE_RE.sub("", text.strip()).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return True, "unparseable judgment (kept)"
    if not isinstance(data, dict):
        return True, "unparseable judgment (kept)"
    verdict = str(data.get("verdict", "")).strip().lower()
    reason = str(data.get("reason", ""))
    return verdict != "reject", reason


# --------------------------------------------------------------------------- #
# Experiment: measure precision/recall before vs. after verification.
# --------------------------------------------------------------------------- #


@dataclass
class VerifyStats:
    total_bugs: int = 0
    tp_before: int = 0
    fp_before: int = 0
    tp_after: int = 0
    fp_after: int = 0
    tp_dropped: list[str] = field(default_factory=list)  # bug ids wrongly rejected
    usage: Optional[ModelUsage] = None
    errors: list[str] = field(default_factory=list)

    def _precision(self, tp: int, fp: int) -> float:
        return tp / (tp + fp) if (tp + fp) else 0.0

    @property
    def precision_before(self) -> float:
        return self._precision(self.tp_before, self.fp_before)

    @property
    def precision_after(self) -> float:
        return self._precision(self.tp_after, self.fp_after)

    @property
    def recall_before(self) -> float:
        return self.tp_before / self.total_bugs if self.total_bugs else 0.0

    @property
    def recall_after(self) -> float:
        return self.tp_after / self.total_bugs if self.total_bugs else 0.0

    @property
    def fp_removed(self) -> int:
        return self.fp_before - self.fp_after


def run_verification(
    detector: Detector,
    verifier: AIVerifier,
    corpus_dir: str | Path | None = None,
    collection: str | None = None,
    window: int = 2,
) -> VerifyStats:
    """Detect, then judge every finding, scoring FP removal vs. TP loss."""
    stats = VerifyStats()
    usages: list[ModelUsage] = []

    for case in load_corpus(corpus_dir, collection=collection):
        stats.total_bugs += len(case.bugs)
        bugs_by_path: dict[Path, list[Bug]] = defaultdict(list)
        for bug in case.bugs:
            bugs_by_path[case.bug_file(bug)].append(bug)

        for source_file in case.source_files():
            scan = detector.scan(source_file)
            if scan.usage:
                usages.append(scan.usage)
            if scan.error:
                stats.errors.append(f"{source_file.name}: {scan.error}")
            code = source_file.read_text(encoding="utf-8", errors="replace")
            bugs = bugs_by_path.get(source_file.resolve(), [])
            mr = match_findings(bugs, scan.findings, window=window)

            # True positives (matched a real bug) and false positives (noise).
            for m in mr.matched:
                stats.tp_before += 1
                j = verifier.judge(m.finding, code, source_file.name)
                _account(stats, usages, j)
                if j.keep:
                    stats.tp_after += 1
                else:
                    stats.tp_dropped.append(m.bug.id)
            for finding in mr.false_positives:
                stats.fp_before += 1
                j = verifier.judge(finding, code, source_file.name)
                _account(stats, usages, j)
                if j.keep:
                    stats.fp_after += 1

    stats.usage = _sum_usage(usages)
    return stats


def _account(stats: VerifyStats, usages: list[ModelUsage], j: Judgment) -> None:
    if j.usage:
        usages.append(j.usage)
    if j.error:
        stats.errors.append(j.error)


def _sum_usage(usages: list[ModelUsage]) -> Optional[ModelUsage]:
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
