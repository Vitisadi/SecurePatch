"""Import CWEval tasks into the benchmark corpus as the ``cweval`` collection.

CWEval (Apache-2.0, https://github.com/Co1lin/CWEval) ships, per task:
  <id>_task.<ext>     the prompt + a secure reference solution
  <id>_unsafe.<ext>   (JS) a standalone insecure reference implementation
  <id>_test.py        a pytest oracle marked `functionality` vs `security`
For Python the insecure reference is a ``*_unsafe`` function inside the test.

We vendor each in-scope (Python / JavaScript) task as one corpus case:

  benchmarks/cweval/<lang>-<id>/
    source/  the vulnerable program (our scan / fix target)
    oracle/  CWEval's task + test (+ js unsafe) copied verbatim, for the
             container-based verify step (the oracles assume Linux/Docker)
    meta.json, ground_truth.json   generated; provenance cites CWEval + commit

`detectable_by_regex` is computed by actually running our detector on the
vulnerable source, so it is never guessed. Obscurity is defaulted (CWEval does
not rate difficulty) and flagged ``needs_review`` for manual tiering.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .core_bridge import scan_file

CWEVAL_URL = "https://github.com/Co1lin/CWEval"
CWEVAL_PAPER = "https://arxiv.org/abs/2501.08200"

# CWE number -> our controlled type vocabulary (see corpus.KNOWN_TYPES).
CWE_TYPE = {
    20: "improper-input-validation",
    22: "path-traversal",
    78: "command-injection",
    79: "xss",
    95: "code-injection",
    113: "http-response-splitting",
    117: "log-injection",
    326: "weak-cryptography",
    327: "weak-cryptography",
    329: "weak-cryptography",
    347: "improper-signature-verification",
    377: "insecure-temp-file",
    400: "resource-exhaustion",
    502: "deserialization",
    643: "xpath-injection",
    732: "incorrect-permissions",
    760: "weak-cryptography",
    918: "ssrf",
    943: "nosql-injection",
    1333: "redos",
}

LANG_NAME = {"py": "python", "js": "javascript"}


@dataclass
class ImportSummary:
    imported: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    detected: list[str] = field(default_factory=list)


def import_cweval(
    src: str | Path,
    dest: str | Path,
    langs: tuple[str, ...] = ("py", "js"),
) -> ImportSummary:
    src = Path(src).resolve()
    core = src / "benchmark" / "core"
    if not core.is_dir():
        raise FileNotFoundError(f"{core} not found; is {src} a CWEval checkout?")

    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    commit = _git_commit(src)
    _write_attribution(src, dest, commit)

    summary = ImportSummary()
    for lang in langs:
        lang_dir = core / lang
        for task_file in sorted(lang_dir.glob(f"*_task.{lang}" if lang != "js" else "*_js_task.js")):
            task_id = _task_id(task_file.name, lang)
            try:
                ok = _import_task(lang, task_id, lang_dir, dest, commit, summary)
            except Exception as exc:  # noqa: BLE001 - report, never abort the batch
                summary.skipped.append((f"{lang}-{task_id}", f"error: {exc}"))
                continue
            if not ok:
                continue
    return summary


def _import_task(lang, task_id, lang_dir, dest, commit, summary) -> bool:
    case_id = f"{lang}-{task_id}"
    cwe_num = int(task_id.split("_")[1])
    fallback_type = CWE_TYPE.get(cwe_num, "improper-input-validation")

    # ---- locate CWEval files + build the vulnerable source ------------------
    if lang == "js":
        task_path = lang_dir / f"{task_id}_js_task.js"
        unsafe_path = lang_dir / f"{task_id}_js_unsafe.js"
        test_path = lang_dir / f"{task_id}_js_test.py"
        if not (unsafe_path.exists() and test_path.exists()):
            summary.skipped.append((case_id, "missing unsafe/test file"))
            return False
        source_name = f"{task_id}_js_unsafe.js"
        source_text = unsafe_path.read_text(encoding="utf-8")
        oracle_files = [task_path, unsafe_path, test_path]
    else:
        task_path = lang_dir / f"{task_id}_task.py"
        test_path = lang_dir / f"{task_id}_test.py"
        if not test_path.exists():
            summary.skipped.append((case_id, "missing test file"))
            return False
        built = _python_vulnerable_module(test_path.read_text(encoding="utf-8"))
        if built is None:
            summary.skipped.append((case_id, "no extractable *_unsafe function in test"))
            return False
        source_text = built
        source_name = f"{task_id}_task.py"
        oracle_files = [task_path, test_path]

    # ---- write the case tree ------------------------------------------------
    case_dir = dest / case_id
    src_dir = case_dir / "source"
    oracle_dir = case_dir / "oracle"
    src_dir.mkdir(parents=True, exist_ok=True)
    oracle_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / source_name).write_text(source_text, encoding="utf-8")
    for f in oracle_files:
        if f.exists():
            shutil.copy2(f, oracle_dir / f.name)

    # ---- detection ground truth (run our detector on the source) ------------
    # The bug's type is always the task's CWE class; it counts as detected only
    # if the detector emits *that* class (an incidental finding of another type,
    # e.g. a hardcoded secret inside an XPath-injection task, is not the bug).
    scan = scan_file(src_dir / source_name)
    line_count = source_text.count("\n") + 1
    bug_type = fallback_type
    matching = [f for f in scan.findings if f["type"] == bug_type]
    if matching:
        detectable = True
        line_start = int(matching[0]["line"]) + 1
        line_end = line_start
        summary.detected.append(case_id)
    else:
        detectable = False
        line_start, line_end = 1, line_count

    _write_meta(case_dir, case_id, lang, cwe_num, fallback_type, source_name, commit)
    _write_ground_truth(
        case_dir, case_id, source_name, line_start, line_end, bug_type, cwe_num, detectable
    )
    summary.imported.append(case_id)
    return True


def _python_vulnerable_module(test_src: str) -> str | None:
    """Assemble a standalone vulnerable module from a CWEval Python test.

    The test imports the candidate (``from <id>_task import <name>``) and defines
    the insecure reference as ``<name>_unsafe``. We emit: the test's top-level
    imports (minus pytest and the task import) + the unsafe function verbatim +
    an alias binding the canonical name to it.
    """
    tree = ast.parse(test_src)

    canonical = None
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("_task"):
            canonical = node.names[0].name
            break

    unsafe = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.endswith("_unsafe"):
            unsafe = node
            break

    if canonical is None or unsafe is None:
        return None

    imports = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            seg = ast.get_source_segment(test_src, node) or ""
            if "pytest" in seg:
                continue
            if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("_task"):
                continue
            imports.append(seg)

    unsafe_src = ast.get_source_segment(test_src, unsafe)
    parts = []
    if imports:
        parts.append("\n".join(imports))
    parts.append(unsafe_src)
    parts.append(f"{canonical} = {unsafe.name}")
    return "\n\n\n".join(parts) + "\n"


def _write_meta(case_dir, case_id, lang, cwe_num, category, source_name, commit):
    if lang == "js":
        test_cmd = f"pytest oracle/{case_id.split('-', 1)[1]}_js_test.py  # needs node + CWEval container"
    else:
        test_cmd = f"pytest oracle/  # needs the CWEval pytest config / container"
    meta = {
        "case_id": case_id,
        "language": LANG_NAME[lang],
        "category": category,
        "difficulty": "unknown",
        "obscurity": "local-semantic",
        "entrypoint": f"source/{source_name}",
        "test_command": test_cmd,
        "description": (
            f"CWEval {case_id.split('-', 1)[1]} (CWE-{cwe_num}). Vulnerable source is "
            f"CWEval's insecure reference; the secure reference and the "
            f"functional+security oracle are vendored under oracle/."
        ),
        "provenance": {
            "cwe": f"CWE-{cwe_num}",
            "construction": "adapted",
            "needs_review": True,
            "selection_rationale": (
                "Imported wholesale from the CWEval benchmark (in-scope Python/JS "
                "tasks). Obscurity tier is provisional pending manual review."
            ),
            "sources": [
                {
                    "title": "CWEval: Outcome-driven Evaluation on Functionality and Security of LLM Code Generation",
                    "authors": "Peng et al.",
                    "year": 2025,
                    "url": CWEVAL_PAPER,
                },
                {
                    "title": "CWEval benchmark repository (Apache-2.0)",
                    "url": CWEVAL_URL,
                    "note": f"vendored from commit {commit}",
                },
            ],
        },
    }
    (case_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def _write_ground_truth(case_dir, case_id, source_name, line_start, line_end, bug_type, cwe_num, detectable):
    truth = {
        "case_id": case_id,
        "bugs": [
            {
                "id": f"{case_id}-1",
                "file": f"source/{source_name}",
                "line_start": line_start,
                "line_end": line_end,
                "type": bug_type,
                "cwe": f"CWE-{cwe_num}",
                "obscurity": "local-semantic",
                "detectable_by_regex": detectable,
                "description": (
                    "Vulnerability confirmed by CWEval's security oracle; line range "
                    + ("from our detector." if detectable else "spans the source (approximate; needs_review).")
                ),
            }
        ],
    }
    (case_dir / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")


def _task_id(filename: str, lang: str) -> str:
    if lang == "js":
        return filename[: -len("_js_task.js")]
    return filename[: -len("_task.py")]


def _git_commit(src: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()[:12]
    except Exception:
        return "unknown"


def _write_attribution(src: Path, dest: Path, commit: str) -> None:
    license_src = src / "LICENSE"
    if license_src.exists():
        shutil.copy2(license_src, dest / "LICENSE")
    text = (
        "# CWEval collection — attribution\n\n"
        "Cases in this directory are derived from the **CWEval** benchmark.\n\n"
        f"- Source: {CWEVAL_URL}\n"
        f"- Paper: {CWEVAL_PAPER}\n"
        f"- Vendored from commit: `{commit}`\n"
        "- License: Apache-2.0 (see `LICENSE` in this directory).\n\n"
        "## What we changed\n\n"
        "Per CWEval task we generate a corpus case: the **insecure reference** is\n"
        "placed under `source/` as the scan/fix target; CWEval's original task\n"
        "(secure reference) and test oracle are copied **verbatim** under\n"
        "`oracle/`. For Python, the vulnerable `source/` module is assembled from\n"
        "the `*_unsafe` function embedded in CWEval's test (top-level imports + the\n"
        "function + an alias to the canonical name); the oracle files are\n"
        "unmodified. `meta.json` / `ground_truth.json` are ours.\n\n"
        "The security/functional oracles assume a Linux/Docker environment (e.g.\n"
        "they invoke `ls`, shell operators, `node`); run them via CWEval's\n"
        "container, not natively on Windows.\n"
    )
    (dest / "ATTRIBUTION.md").write_text(text, encoding="utf-8")
