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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Protocol

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
    ) -> None:
        self.provider = provider
        self.model = model or provider.default_model
        self.max_output_tokens = max_output_tokens
        self.name = f"ai:{provider.id}:{self.model}"

    def scan(self, source_file: Path) -> DetectorScan:
        path = Path(source_file)
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")
        code = path.read_text(encoding="utf-8", errors="replace")
        prompt = build_detection_prompt(language, path.name, code)

        request = ModelRequest(
            model=self.model,
            prompt=prompt,
            system=DETECTION_SYSTEM,
            max_output_tokens=self.max_output_tokens,
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
