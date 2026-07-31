"""Detection strategies the benchmark can run against a source file.

Both strategies expose the same ``scan(path) -> DetectorScan`` shape so the
benchmark runner is detector-agnostic:

- :class:`RegexDetector` shells out to the core CLI (the current product rules).
- :class:`AIDetector` asks a model provider to find vulnerabilities and parses
  its JSON into the same finding shape the matcher consumes.

A finding only needs ``type`` and ``line`` (0-based, matching the core CLI) for
the matcher; the extra fields are kept for provenance and recording.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set
from typing import Any, Optional, Protocol

from ._proc import run_captured
from .core_bridge import scan_file
from .corpus import KNOWN_TYPES
from .providers.base import ModelProvider, ModelRequest, ModelUsage, ProviderError

# Allowed vulnerability vocabulary, shared with the corpus + matcher. Sorting
# keeps the prompt stable across runs.
ALLOWED_TYPES = sorted(KNOWN_TYPES)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


@dataclass
class DetectorScan:
    """Result of scanning one file: the findings plus optional model metadata."""

    detector: str
    findings: list[dict[str, Any]]
    usage: Optional[ModelUsage] = None
    raw: Any = None
    error: Optional[str] = None


class Detector(Protocol):
    name: str

    def scan(self, source_file: Path) -> DetectorScan: ...


class RegexDetector:
    """The current product detector, via the single-sourced core CLI."""

    name = "regex"

    def scan(self, source_file: Path) -> DetectorScan:
        result = scan_file(source_file)
        return DetectorScan(detector=result.detector, findings=result.findings)


class SastDetectorError(RuntimeError):
    """Raised when the semgrep binary is missing or its output can't be parsed."""


# CWE-number -> our vocabulary, derived directly from every ground_truth.json
# in the corpus (see benchmarks/*/*/ground_truth.json) so the mapping matches
# exactly what the matcher expects, not a guess at semgrep's taxonomy.
SAST_CWE_TO_TYPE = {
    "20": "improper-input-validation",
    "22": "path-traversal",
    "78": "command-injection",
    "79": "xss",
    "89": "sql-injection",
    "95": "code-injection",
    "113": "http-response-splitting",
    "117": "log-injection",
    "326": "weak-cryptography",
    "327": "weak-cryptography",
    "329": "weak-cryptography",
    "338": "weak-randomness",
    "347": "improper-signature-verification",
    "377": "insecure-temp-file",
    "400": "redos",  # CWEval cwe_400_0 is regex injection/ReDoS; kept for Semgrep CWE-400 mapping consistency
    "502": "deserialization",
    "643": "xpath-injection",
    "732": "incorrect-permissions",
    "760": "weak-cryptography",
    "798": "hardcoded-secret",
    "918": "ssrf",
    "943": "sql-injection",  # CWEval cwe_943_0 is SQL injection; CWEval filed under CWE-943 (parent class)
    "1333": "redos",
}

_CWE_NUM_RE = re.compile(r"CWE-(\d+)")

DEFAULT_SEMGREP_CONFIGS = ("p/security-audit", "p/owasp-top-ten", "p/secrets")


class SastDetector:
    """Off-the-shelf static analysis via Semgrep (``pip install semgrep``).

    Runs Semgrep's community security rulesets against a single file and maps
    each finding's CWE metadata onto our vocabulary via :data:`SAST_CWE_TO_TYPE`
    so it scores through the same matcher as the regex and AI detectors.
    Findings whose CWE isn't in our vocabulary are kept with a synthetic
    ``sast-unmapped:<rule-id>`` type — they can never match a bug, so they
    still count honestly as noise/false positives rather than being hidden.
    """

    name = "sast:semgrep"

    def __init__(self, configs: tuple[str, ...] = DEFAULT_SEMGREP_CONFIGS) -> None:
        if shutil.which("semgrep") is None:
            raise SastDetectorError(
                "semgrep not found on PATH. Install it with `pip install semgrep`."
            )
        self.configs = configs

    def scan(self, source_file: Path) -> DetectorScan:
        path = Path(source_file)
        cmd = ["semgrep", "--quiet", "--json", "--metrics=off"]
        for config in self.configs:
            cmd += ["--config", config]
        cmd.append(str(path))

        try:
            proc = run_captured(cmd, timeout=120)
        except OSError as exc:
            return DetectorScan(detector=self.name, findings=[], error=str(exc))

        if proc.returncode not in (0, 1):  # 1 = findings present, still success
            return DetectorScan(
                detector=self.name, findings=[], error=proc.stderr.strip()[:500]
            )

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return DetectorScan(
                detector=self.name, findings=[], error=f"bad semgrep JSON: {exc}"
            )

        findings = [
            f
            for f in (self._to_finding(r, index) for index, r in enumerate(payload.get("results", [])))
            if f is not None
        ]
        return DetectorScan(detector=self.name, findings=findings, raw=payload)

    @staticmethod
    def _to_finding(result: dict[str, Any], index: int) -> Optional[dict[str, Any]]:
        check_id = str(result.get("check_id", f"semgrep-{index}"))
        metadata = result.get("extra", {}).get("metadata", {}) or {}
        cwe_field = metadata.get("cwe", [])
        cwe_list = cwe_field if isinstance(cwe_field, list) else [cwe_field]

        vuln_type = None
        cwe_label = ""
        for entry in cwe_list:
            match = _CWE_NUM_RE.search(str(entry))
            if match and match.group(1) in SAST_CWE_TO_TYPE:
                vuln_type = SAST_CWE_TO_TYPE[match.group(1)]
                cwe_label = f"CWE-{match.group(1)}"
                break
        if vuln_type is None:
            vuln_type = f"sast-unmapped:{check_id}"
            if cwe_list:
                m = _CWE_NUM_RE.search(str(cwe_list[0]))
                cwe_label = f"CWE-{m.group(1)}" if m else ""

        start_line = result.get("start", {}).get("line", 1)
        return {
            "id": check_id,
            "type": vuln_type,
            "line": max(int(start_line) - 1, 0),  # 0-based, matching core findings
            "column": max(int(result.get("start", {}).get("col", 1)) - 1, 0),
            "severity": str(metadata.get("severity", result.get("extra", {}).get("severity", "medium"))).lower(),
            "title": check_id,
            "description": str(result.get("extra", {}).get("message", "")),
            "cwe": cwe_label,
            "source": "sast",
        }


DETECTION_SYSTEM = (
    "You are a precise application-security code reviewer. You find real, "
    "exploitable vulnerabilities in source code and report them as compact JSON. "
    "Report only genuine security issues, not style or performance. Do not "
    "invent vulnerabilities. Respond with JSON only — no Markdown, no prose."
)


class AIDetector:
    """Detect vulnerabilities by prompting a model provider."""

    def __init__(
        self,
        provider: ModelProvider,
        model: Optional[str] = None,
        max_output_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> None:
        self.provider = provider
        self.model = model or provider.default_model
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self.name = f"ai:{provider.id}:{self.model}"

    def scan(self, source_file: Path) -> DetectorScan:
        path = Path(source_file)
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")
        code = path.read_text(encoding="utf-8", errors="replace")
        # Use a generic filename so models cannot infer the CWE/vulnerability
        # class from the path (e.g. "cwe_943_0_js_unsafe.js" leaks CWE-943).
        display_name = f"code{path.suffix.lower()}"
        prompt = build_detection_prompt(language, display_name, code)

        request = ModelRequest(
            model=self.model,
            prompt=prompt,
            system=DETECTION_SYSTEM,
            max_output_tokens=self.max_output_tokens,
            temperature=self.temperature,
        )
        try:
            response = self.provider.complete(request)
        except ProviderError as exc:
            return DetectorScan(detector=self.name, findings=[], error=str(exc))

        return DetectorScan(
            detector=self.name,
            findings=parse_findings(response.text),
            usage=response.usage,
            raw=response.raw,
        )


def build_detection_prompt(language: str, filename: str, code: str) -> str:
    """A line-numbered prompt asking for findings keyed to the allowed vocabulary."""
    numbered = "\n".join(
        f"{i + 1}\t{line}" for i, line in enumerate(code.splitlines())
    )
    return (
        f"Review this {language} file ({filename}) for security vulnerabilities.\n"
        "Report every genuine vulnerability you find.\n\n"
        "Return a JSON object of exactly this shape:\n"
        '{"findings": [{"type": string, "line": integer, "severity": '
        '"low"|"medium"|"high"|"critical", "cwe": string, "title": string, '
        '"description": string}]}\n\n'
        "Rules:\n"
        f"- \"type\" MUST be one of: {', '.join(ALLOWED_TYPES)}.\n"
        "- \"line\" is the 1-based line number (from the numbers below) of the "
        "vulnerable code.\n"
        "- If there are no vulnerabilities, return {\"findings\": []}.\n\n"
        "Code (line<TAB>source):\n"
        f"{numbered}\n"
    )


_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def parse_findings(text: str) -> list[dict[str, Any]]:
    """Parse a model's JSON response into core-shaped finding dicts.

    Returns an empty list (never raises) on malformed output — a model that
    emits unparseable JSON simply scores as detecting nothing for that scan.
    """
    cleaned = _FENCE_RE.sub("", text.strip()).strip()
    if not cleaned:
        return []
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return []

    raw = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(raw, list):
        return []

    findings: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        ftype = item.get("type")
        if not isinstance(ftype, str) or not ftype.strip():
            continue
        line_1based = item.get("line")
        if not isinstance(line_1based, int):
            try:
                line_1based = int(line_1based)
            except (TypeError, ValueError):
                continue
        findings.append(
            {
                "id": item.get("id") or f"ai-{index + 1}",
                "type": ftype.strip().lower(),
                "line": max(line_1based - 1, 0),  # 0-based, matching core findings
                "column": 0,
                "severity": str(item.get("severity", "medium")).lower(),
                "title": str(item.get("title", "")),
                "description": str(item.get("description", "")),
                "cwe": str(item.get("cwe", "")),
                "source": "code",
            }
        )
    return findings


class CachedFindingDetector:
    """Replay pre-computed detection results from a bench JSONL file.

    For the initial baseline scan the detector replays the AI's actual findings
    for matched bugs (including the original description, line, and CWE the
    detector produced) plus any false positives, exactly as the real pipeline
    would see them. For older JSONL files that lack matched_findings, it falls
    back to synthesising findings from ground-truth metadata.

    The rescan (post-fix verification) is delegated to a cheap live detector —
    by default the regex detector — because the oracle handles cweval cases
    authoritatively and native tests handle seeded/literature cases.

    Usage
    -----
    detector = CachedFindingDetector("harness/results/sonnet_detect_r3.jsonl")
    # Before each case in the fix loop, set context so scan() knows which
    # cached findings to serve:
    detector.set_case(case_id, bugs)
    """

    def __init__(
        self,
        jsonl_path: str | Path,
        rescan_detector: "Detector | None" = None,
        label: str = "",
    ) -> None:
        self._matched: Dict[str, Set[str]] = defaultdict(set)       # case_id -> {bug_id}
        self._matched_findings: Dict[str, Dict[str, Any]] = {}      # case_id -> {bug_id: finding}
        self._false_positives: Dict[str, list] = {}                 # case_id -> [finding, ...]
        self._load(Path(jsonl_path))
        self._rescan_detector: "Detector" = rescan_detector or RegexDetector()
        self._current_case_id: str | None = None
        self._current_bugs: list = []
        self._initial_done: Set[str] = set()  # case_ids whose baseline was served
        label = label or Path(jsonl_path).stem
        self.name = f"cached:{label}"

    def _load(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                cid = row.get("case_id", "")
                for bug_id in row.get("matched", []):
                    self._matched[cid].add(bug_id)
                if "matched_findings" in row:
                    self._matched_findings[cid] = row["matched_findings"]
                if "false_positive_findings" in row:
                    self._false_positives[cid] = row["false_positive_findings"]

    def set_case(self, case_id: str, bugs: list) -> None:
        """Call before the fix loop processes each case."""
        self._current_case_id = case_id
        self._current_bugs = bugs
        self._initial_done.discard(case_id)

    def scan(self, source_file: Path) -> "DetectorScan":
        cid = self._current_case_id
        if cid is None or cid in self._initial_done:
            # Second call for this case = post-fix rescan → live detector
            return self._rescan_detector.scan(source_file)

        # First call = baseline scan → replay actual AI findings
        self._initial_done.add(cid)
        matched_ids = self._matched.get(cid, set())
        ai_findings = self._matched_findings.get(cid)  # None for old-format JSOLs
        findings: list = []

        for bug in self._current_bugs:
            if bug.id not in matched_ids:
                continue
            if ai_findings and bug.id in ai_findings:
                # Replay the detector's actual finding text
                findings.append(ai_findings[bug.id])
            else:
                # Fallback for old JSOLs without matched_findings
                findings.append(
                    {
                        "id": bug.id,
                        "type": bug.type,
                        "line": bug.line_start - 1,  # 0-based
                        "column": 0,
                        "severity": "medium",
                        "title": bug.type,
                        "description": bug.description,
                        "cwe": bug.cwe,
                        "source": "cached",
                    }
                )

        # Include false positives so the fixer sees exactly what the detector reported
        findings.extend(self._false_positives.get(cid, []))
        return DetectorScan(detector=self.name, findings=findings)
