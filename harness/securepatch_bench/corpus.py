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
        # emitted by our detector and/or used by our authored cases
        "sql-injection",
        "command-injection",
        "code-injection",
        "path-traversal",
        "deserialization",
        "ssrf",
        "weak-randomness",
        "xss",
        "weak-cryptography",
        "hardcoded-secret",
        "vulnerable-dependency",
        # additional classes introduced by the CWEval corpus
        "improper-input-validation",
        "http-response-splitting",
        "log-injection",
        "redos",
        "improper-signature-verification",
        "insecure-temp-file",
        "resource-exhaustion",
        "xpath-injection",
        "incorrect-permissions",
        "nosql-injection",
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
    collection: str
    language: str
    category: str
    difficulty: str
    obscurity: str
    entrypoint: str
    test_command: str
    description: str
    bugs: tuple[Bug, ...]
    provenance: dict

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


def load_corpus(
    corpus_dir: str | Path | None = None,
    collection: str | None = None,
) -> list[BenchmarkCase]:
    """Load and validate every case under ``corpus_dir`` (default: benchmarks/).

    Cases may live directly under the root or one level down in a *collection*
    folder (e.g. ``seeded/``, ``literature/``). Each case is the directory that
    contains a ``meta.json``. Pass ``collection`` to load only one collection.
    """
    root = (Path(corpus_dir) if corpus_dir is not None else DEFAULT_CORPUS_DIR).resolve()
    if not root.is_dir():
        raise CorpusError(f"corpus directory not found: {root}")

    cases: list[BenchmarkCase] = []
    for meta_path in sorted(root.rglob("meta.json")):
        case_dir = meta_path.parent
        case_collection = _collection_of(root, case_dir)
        if collection is not None and case_collection != collection:
            continue
        cases.append(load_case(case_dir, collection=case_collection))

    if not cases:
        where = f"{root}" + (f" (collection '{collection}')" if collection else "")
        raise CorpusError(f"no benchmark cases found under {where}")
    return cases


def _collection_of(root: Path, case_dir: Path) -> str:
    """The collection is the first path segment between the corpus root and the
    case directory (e.g. 'literature'); cases directly under root are '(root)'."""
    rel = case_dir.resolve().relative_to(root)
    parts = rel.parts
    return parts[0] if len(parts) > 1 else "(root)"


def load_case(case_dir: str | Path, collection: str = "(root)") -> BenchmarkCase:
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

    provenance = _parse_provenance(case_id, collection, meta.get("provenance"))

    return BenchmarkCase(
        case_id=case_id,
        root=root,
        collection=collection,
        language=_require_str(meta, "language", root),
        category=_require_str(meta, "category", root),
        difficulty=str(meta.get("difficulty", "unknown")),
        obscurity=obscurity,
        entrypoint=_require_str(meta, "entrypoint", root),
        test_command=str(meta.get("test_command", "")),
        description=str(meta.get("description", "")),
        bugs=bugs,
        provenance=provenance,
    )


def _parse_provenance(case_id: str, collection: str, raw: object) -> dict:
    """Validate the optional provenance block.

    Cases in the ``literature`` collection must be traceable to a published
    source, so we require a non-empty ``sources`` list there; for other
    collections provenance is optional.
    """
    if raw is None:
        if collection == "literature":
            raise CorpusError(
                f"{case_id}: literature cases require a 'provenance' block with sources"
            )
        return {}
    if not isinstance(raw, dict):
        raise CorpusError(f"{case_id}: provenance must be a JSON object")

    sources = raw.get("sources", [])
    if not isinstance(sources, list):
        raise CorpusError(f"{case_id}: provenance.sources must be a list")
    if collection == "literature" and not sources:
        raise CorpusError(f"{case_id}: literature cases must cite at least one source")
    for source in sources:
        if not isinstance(source, dict) or not source.get("title"):
            raise CorpusError(f"{case_id}: each provenance source needs a 'title'")
    return raw


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
