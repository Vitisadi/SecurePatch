"""Run CWEval oracles in a Docker container to verify a fix.

CWEval ships, per task, a pytest oracle with two kinds of checks:

- ``functionality`` — the function under test must match a known-good reference
  on benign inputs ("still works").
- ``security`` — on malicious inputs it must behave like the *safe* reference,
  i.e. the exploit must not fire ("vuln actually gone").

This is a stronger signal than re-scanning, because it *executes an exploit*
rather than pattern-matching. The catch is the runtime: Unix tools, Node, and a
stack of third-party libs. We isolate all of that in one image (see
``docker/Dockerfile``) and mount a single sandboxed case at ``/work``.

The control tests always carry ``unsafe`` in their name, so ``-k "not unsafe"``
selects only the tests that exercise the code under test.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ._proc import run_captured

IMAGE = "securepatch-cweval"
ORACLE_TIMEOUT_S = 180


class OracleError(RuntimeError):
    """Raised when the oracle cannot be run (no docker, no image, bad case)."""


@dataclass
class OracleOutcome:
    functionality_passed: Optional[bool] = None
    security_passed: Optional[bool] = None
    detail: dict[str, str] = None  # marker -> output tail

    def __post_init__(self) -> None:
        if self.detail is None:
            self.detail = {}


def docker_available() -> bool:
    """True when a Docker daemon is reachable."""
    try:
        proc = run_captured(["docker", "info"], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def image_exists() -> bool:
    try:
        proc = run_captured(["docker", "image", "inspect", IMAGE], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def oracle_under_test_file(case_root: Path, source_suffix: str) -> Path:
    """The oracle file that holds the function under test.

    In an ``oracle/`` dir that is the single file of the source language that is
    neither the ``*_test.py`` harness nor an ``*unsafe*`` control (e.g.
    ``cwe_078_0_task.py`` / ``cwe_078_0_js_task.js``). We overwrite it with the
    fixed source so the oracle exercises the fix.
    """
    oracle = case_root / "oracle"
    candidates = [
        p
        for p in oracle.glob(f"*{source_suffix}")
        if "unsafe" not in p.name and not p.name.endswith("_test.py")
    ]
    if len(candidates) != 1:
        raise OracleError(
            f"expected exactly one under-test oracle file in {oracle} "
            f"for '{source_suffix}', found {[p.name for p in candidates]}"
        )
    return candidates[0]


def install_fix_into_oracle(case_root: Path, fixed_source: Path) -> Path:
    """Copy the fixed source over the oracle's under-test slot; return that path."""
    slot = oracle_under_test_file(case_root, fixed_source.suffix.lower())
    shutil.copyfile(fixed_source, slot)
    return slot


def run_oracle(case_root: Path) -> OracleOutcome:
    """Run the functionality and security oracles for one mounted case."""
    if not docker_available():
        raise OracleError("Docker daemon is not reachable (start Docker Desktop).")
    if not image_exists():
        raise OracleError(
            f"image '{IMAGE}' not built; run `docker build -t {IMAGE} docker/` from harness/."
        )

    outcome = OracleOutcome()
    for marker in ("functionality", "security"):
        passed, detail = _run_marker(case_root, marker)
        outcome.detail[marker] = detail
        if marker == "functionality":
            outcome.functionality_passed = passed
        else:
            outcome.security_passed = passed
    return outcome


def _run_marker(case_root: Path, marker: str) -> tuple[Optional[bool], str]:
    """Run `pytest oracle -m <marker> -k 'not unsafe'` in the container."""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{case_root}:/work",
        IMAGE,
        "python", "-m", "pytest", "oracle",
        "-m", marker,
        "-k", "not unsafe",
        "-q", "-p", "no:cacheprovider",
    ]
    try:
        proc = run_captured(cmd, timeout=ORACLE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None, f"{marker}: timed out after {ORACLE_TIMEOUT_S}s"
    except OSError as exc:
        return None, f"{marker}: failed to run docker: {exc}"

    tail = proc.output.strip()[-2000:]
    # pytest exit codes: 0 = all passed, 1 = failures, 5 = no tests collected.
    if proc.returncode == 0:
        return True, tail
    if proc.returncode == 5:
        return None, f"{marker}: no tests collected\n{tail}"
    return False, tail
