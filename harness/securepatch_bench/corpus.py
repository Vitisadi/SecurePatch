"""Loader and validator for the benchmark corpus.

A corpus is a directory of self-describing cases (see ../../benchmarks/README.md):

    benchmarks/<case-id>/
      meta.json
      ground_truth.json
      source/
      tests/

This module turns those files into typed objects and fails loudly on anything
that would silently corrupt the research numbers: unknown vulnerability types,
unknown obscurity tiers, missing source files, or nonsensical line ranges.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


# repo_root/harness/securepatch_bench/corpus.py -> repo_root
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS_DIR = REPO_ROOT / "benchmarks"

# Vocabulary shared with the detector, plus categories the regex rules do not
# cover (those are the obscure cases). Keep in sync with benchmarks/README.md.
KNOWN_TYPES = frozenset(
    {
        "sql-injection",
        "command-injection",
        "code-injection",
        "weak-randomness",
        "xss",
        "weak-cryptography",
        "hardcoded-secret",
        "vulnerable-dependency",
    }
)

# Ordered from shallow to deep so reports can group by increasing obscurity.
OBSCURITY_TIERS = ("syntactic", "local-semantic", "cross-function", "multi-file")
KNOWN_OBSCURITY = frozenset(OBSCURITY_TIERS)

# Extensions the core detector knows how to scan.
SCANNABLE_SUFFIXES = frozenset({".js", ".ts", ".py"})
SCANNABLE_NAMES = frozenset({"package.json", "requirements.txt"})


class CorpusError(ValueError):
    """Raised when a case is missing files or violates the schema."""


@dataclass(frozen=True)
class Bug:
    """One known vulnerability in a case's answer key (1-based line range)."""

    id: str
    file: str
    line_start: int
    line_end: int
    type: str
    cwe: str
    obscurity: str
    detectable_by_regex: bool
    description: str


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    root: Path
    language: str
    category: str
    difficulty: str
    obscurity: str
    entrypoint: str
    test_command: str
    description: str
    bugs: tuple[Bug, ...]

    def source_files(self) -> list[Path]:
        """Absolute paths under source/ that the core detector can scan."""
        source_dir = self.root / "source"
        if not source_dir.is_dir():
            return []
        return sorted(
            path
            for path in source_dir.rglob("*")
            if path.is_file() and _is_scannable(path)
        )

    def bug_file(self, bug: Bug) -> Path:
        """Resolve a bug's case-relative file to an absolute path."""
        return (self.root / bug.file).resolve()


def _is_scannable(path: Path) -> bool:
    return path.suffix.lower() in SCANNABLE_SUFFIXES or path.name.lower() in SCANNABLE_NAMES


def load_corpus(corpus_dir: str | Path | None = None) -> list[BenchmarkCase]:
    """Load and validate every case under ``corpus_dir`` (default: benchmarks/)."""
    root = Path(corpus_dir) if corpus_dir is not None else DEFAULT_CORPUS_DIR
    if not root.is_dir():
        raise CorpusError(f"corpus directory not found: {root}")

    cases: list[BenchmarkCase] = []
    for case_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        meta_path = case_dir / "meta.json"
        if not meta_path.exists():
            # Not a case directory (e.g. shared fixtures); skip silently.
            continue
        cases.append(load_case(case_dir))

    if not cases:
        raise CorpusError(f"no benchmark cases found under {root}")
    return cases


def load_case(case_dir: str | Path) -> BenchmarkCase:
    """Load and validate a single case directory."""
    root = Path(case_dir).resolve()
    meta = _read_json(root / "meta.json")
    truth = _read_json(root / "ground_truth.json")

    case_id = _require_str(meta, "case_id", root)
    if case_id != root.name:
        raise CorpusError(
            f"{root}: case_id '{case_id}' does not match directory name '{root.name}'"
        )

    truth_id = truth.get("case_id")
    if truth_id != case_id:
        raise CorpusError(
            f"{root}: ground_truth.json case_id '{truth_id}' != meta.json '{case_id}'"
        )

    obscurity = _require_str(meta, "obscurity", root)
    if obscurity not in KNOWN_OBSCURITY:
        raise CorpusError(
            f"{case_id}: unknown obscurity '{obscurity}' "
            f"(expected one of {sorted(KNOWN_OBSCURITY)})"
        )

    bugs = tuple(_parse_bug(case_id, root, raw) for raw in truth.get("bugs", []))
    if not bugs:
        raise CorpusError(f"{case_id}: ground_truth.json lists no bugs")

    return BenchmarkCase(
        case_id=case_id,
        root=root,
        language=_require_str(meta, "language", root),
        category=_require_str(meta, "category", root),
        difficulty=str(meta.get("difficulty", "unknown")),
        obscurity=obscurity,
        entrypoint=_require_str(meta, "entrypoint", root),
        test_command=str(meta.get("test_command", "")),
        description=str(meta.get("description", "")),
        bugs=bugs,
    )


def _parse_bug(case_id: str, root: Path, raw: dict) -> Bug:
    bug_id = raw.get("id")
    if not isinstance(bug_id, str) or not bug_id:
        raise CorpusError(f"{case_id}: a bug is missing a string 'id'")

    bug_type = raw.get("type")
    if bug_type not in KNOWN_TYPES:
        raise CorpusError(
            f"{case_id}/{bug_id}: unknown type '{bug_type}' "
            f"(expected one of {sorted(KNOWN_TYPES)})"
        )

    obscurity = raw.get("obscurity")
    if obscurity not in KNOWN_OBSCURITY:
        raise CorpusError(
            f"{case_id}/{bug_id}: unknown obscurity '{obscurity}' "
            f"(expected one of {sorted(KNOWN_OBSCURITY)})"
        )

    line_start = raw.get("line_start")
    line_end = raw.get("line_end")
    if not isinstance(line_start, int) or not isinstance(line_end, int):
        raise CorpusError(f"{case_id}/{bug_id}: line_start/line_end must be integers")
    if line_start < 1 or line_end < line_start:
        raise CorpusError(
            f"{case_id}/{bug_id}: invalid 1-based line range {line_start}..{line_end}"
        )

    rel_file = raw.get("file")
    if not isinstance(rel_file, str) or not rel_file:
        raise CorpusError(f"{case_id}/{bug_id}: missing 'file'")
    if not (root / rel_file).exists():
        raise CorpusError(f"{case_id}/{bug_id}: file '{rel_file}' does not exist")

    detectable = raw.get("detectable_by_regex")
    if not isinstance(detectable, bool):
        raise CorpusError(f"{case_id}/{bug_id}: detectable_by_regex must be true/false")

    return Bug(
        id=bug_id,
        file=rel_file,
        line_start=line_start,
        line_end=line_end,
        type=bug_type,
        cwe=str(raw.get("cwe", "")),
        obscurity=obscurity,
        detectable_by_regex=detectable,
        description=str(raw.get("description", "")),
    )


def _read_json(path: Path) -> dict:
    if not path.exists():
        raise CorpusError(f"missing required file: {path}")
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CorpusError(f"{path}: expected a JSON object at the top level")
    return data


def _require_str(obj: dict, key: str, where: Path) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise CorpusError(f"{where}: meta.json is missing required string '{key}'")
    return value
