"""Isolated sandbox for applying and verifying fixes.

Applying a fix mutates source and then runs code against it, so every attempt
happens on a **throwaway copy** of the case — never the corpus on disk.
``sandbox_case`` copies the case into a temp directory (preserving the case-id
folder name so the copy re-validates as a real :class:`BenchmarkCase`) and
deletes the whole temp tree on exit.

This is the "never mutate the corpus" guarantee from the research plan (Phase 2):
the loop can rewrite files, run tests, and re-scan freely inside the sandbox.
"""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .corpus import BenchmarkCase, load_case


@dataclass(frozen=True)
class Sandbox:
    """A temp-dir copy of one case. ``case`` is the re-rooted benchmark case."""

    root: Path
    case: BenchmarkCase

    def path(self, rel: str | Path) -> Path:
        """Resolve a case-relative path (e.g. a bug's ``file``) inside the copy."""
        return (self.root / rel).resolve()

    @property
    def has_tests(self) -> bool:
        """True when the case ships a runnable ``tests/`` dir (seeded/literature)."""
        return (self.root / "tests").is_dir()

    @property
    def has_oracle(self) -> bool:
        """True when the case ships a CWEval ``oracle/`` (functionality+security
        pytest checks). Verified in Docker via :mod:`cweval_oracle`."""
        return (self.root / "oracle").is_dir()


@contextmanager
def sandbox_case(case: BenchmarkCase) -> Iterator[Sandbox]:
    """Yield a :class:`Sandbox` copy of ``case``; delete it on exit."""
    tmp = Path(tempfile.mkdtemp(prefix="securepatch-sbx-"))
    try:
        dest = tmp / case.root.name
        shutil.copytree(
            case.root, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
        # Re-validate the copy so bug_file()/source_files() resolve inside the
        # sandbox instead of the corpus.
        sbx_case = load_case(dest, collection=case.collection)
        yield Sandbox(root=dest, case=sbx_case)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
