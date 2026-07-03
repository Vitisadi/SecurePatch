"""AI fixer: ask a model to patch a vulnerable file, apply it in a sandbox.

The extension fixes one line at a time; the research fixer generalizes to a
**whole-file rewrite** so multi-line fixes (add an import, validate input, swap
an API) are expressible. The model returns the complete corrected file; we write
it into the sandbox and keep a unified diff for provenance ("see how it fixed
it"). Whole-file replacement applies deterministically — no fuzzy patch context
to misalign — and any collateral damage is caught by the verifier's test + rescan
steps.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .detectors import LANGUAGE_BY_SUFFIX
from .providers.base import ModelProvider, ModelRequest, ModelUsage, ProviderError


@dataclass
class FixResult:
    """Outcome of one fix attempt on one file."""

    applied: bool
    file: Optional[str]  # case-relative path that was rewritten
    diff: str
    original: str
    patched: str
    usage: Optional[ModelUsage] = None
    raw: Any = None
    error: Optional[str] = None


FIX_SYSTEM = (
    "You are a precise application-security engineer. You fix a specific "
    "vulnerability in a source file while preserving all other behavior. You "
    "change only what is needed to remove the vulnerability. You never add "
    "explanations, tests, or unrelated refactors. Respond with JSON only."
)


class AIFixer:
    """Rewrite a vulnerable file via a model provider."""

    def __init__(
        self,
        provider: ModelProvider,
        model: Optional[str] = None,
        max_output_tokens: int = 4096,
    ) -> None:
        self.provider = provider
        self.model = model or provider.default_model
        self.max_output_tokens = max_output_tokens
        self.name = f"fix:{provider.id}:{self.model}"

    def fix(self, target_file: Path, vuln: dict[str, Any], rel_file: str) -> FixResult:
        """Fix ``vuln`` in ``target_file`` (in place). ``rel_file`` is recorded."""
        path = Path(target_file)
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")
        original = path.read_text(encoding="utf-8", errors="replace")
        prompt = build_fix_prompt(language, path.name, original, vuln)

        request = ModelRequest(
            model=self.model,
            prompt=prompt,
            system=FIX_SYSTEM,
            max_output_tokens=self.max_output_tokens,
        )
        try:
            response = self.provider.complete(request)
        except ProviderError as exc:
            return FixResult(
                applied=False, file=rel_file, diff="", original=original,
                patched="", error=str(exc),
            )

        patched = parse_fixed_code(response.text)
        if patched is None:
            return FixResult(
                applied=False, file=rel_file, diff="", original=original,
                patched="", usage=response.usage, raw=response.raw,
                error="model returned no usable fixed file",
            )

        path.write_text(patched, encoding="utf-8")
        diff = _unified_diff(original, patched, rel_file)
        return FixResult(
            applied=True, file=rel_file, diff=diff, original=original,
            patched=patched, usage=response.usage, raw=response.raw,
        )


def build_fix_prompt(
    language: str, filename: str, code: str, vuln: dict[str, Any]
) -> str:
    numbered = "\n".join(f"{i + 1}\t{line}" for i, line in enumerate(code.splitlines()))
    vtype = vuln.get("type", "vulnerability")
    line = vuln.get("line")
    line_1based = (int(line) + 1) if isinstance(line, int) else vuln.get("line_start", "?")
    desc = vuln.get("description") or vuln.get("title") or ""
    cwe = vuln.get("cwe", "")
    return (
        f"Fix a security vulnerability in this {language} file ({filename}).\n\n"
        f"Vulnerability: {vtype}"
        + (f" ({cwe})" if cwe else "")
        + f", around line {line_1based}.\n"
        + (f"Details: {desc}\n" if desc else "")
        + "\n"
        "Return a JSON object of exactly this shape:\n"
        '{"fixed_file": "<the complete corrected file contents>"}\n\n'
        "Rules:\n"
        "- Return the ENTIRE file, not a diff or a snippet.\n"
        "- Fix only this vulnerability; preserve all other behavior and the "
        "public API (function names, signatures, return values).\n"
        "- Do not add comments explaining the fix.\n\n"
        "Code (line<TAB>source):\n"
        f"{numbered}\n"
    )


_FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def parse_fixed_code(text: str) -> Optional[str]:
    """Extract the corrected file from a model response.

    Prefers the ``{"fixed_file": "..."}`` JSON contract; falls back to a fenced
    code block, then to raw text. Returns ``None`` only when nothing usable is
    present (empty/whitespace)."""
    stripped = text.strip()
    if not stripped:
        return None

    # Primary contract: JSON object with a fixed_file string.
    try:
        data = json.loads(stripped)
        if isinstance(data, dict) and isinstance(data.get("fixed_file"), str):
            return data["fixed_file"]
    except json.JSONDecodeError:
        pass

    # Fallback: a fenced code block or bare text.
    unfenced = _FENCE_RE.sub("", stripped).strip()
    return unfenced or None


def _unified_diff(original: str, patched: str, rel_file: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{rel_file}",
            tofile=f"b/{rel_file}",
        )
    )
