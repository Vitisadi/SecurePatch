"""Automatic verification of a fix inside a sandbox.

After the fixer rewrites a file, the verifier answers the four questions the
research plan (Phase 2 §4) turns into a verdict:

1. Does it still **compile / parse**?            (syntax not broken)
2. Do the case's **tests** still pass?           ("still works")
3. Is the **original vulnerability** gone?       (target bug no longer present)
4. Did the fix introduce **new findings**?       (re-scan vs a baseline)

How 2 and 3 are measured depends on what the case ships:

- ``tests/`` (seeded/literature) -> run the unit tests natively; the "vuln gone"
  check is a re-scan of the patched file with the detector.
- ``oracle/`` (CWEval) -> run the pytest oracle in Docker: its ``functionality``
  marker is the "still works" signal and its ``security`` marker is a stronger,
  exploit-based "vuln gone" signal (replacing the re-scan for those cases).
- neither, or Docker unavailable -> fall back to re-scan only.

Nothing here needs a human. The ``regressed`` signal (a broken test, a new
finding, or a compile failure) is the automatable "did the fix cause a problem?".
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import cweval_oracle
from ._proc import run_captured
from .corpus import Bug
from .detectors import Detector
from .matcher import match_findings
from .sandbox import Sandbox

TEST_TIMEOUT_S = 120
COMPILE_TIMEOUT_S = 30


@dataclass
class VerifyResult:
    compiles: Optional[bool] = None          # None => language not compile-checked
    tests_ran: bool = False
    tests_passed: Optional[bool] = None       # None => skipped (no runnable tests)
    vuln_still_present: bool = True
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    vuln_check: str = "rescan"                # "rescan" | "oracle-security"
    detail: dict[str, str] = field(default_factory=dict)


def verify_fix(
    sandbox: Sandbox,
    target_file: Path,
    bug: Bug,
    baseline_findings: list[dict[str, Any]],
    detector: Detector,
    window: int = 2,
) -> VerifyResult:
    """Run compile + tests + vuln/new-finding checks against a patched file."""
    result = VerifyResult()

    # 1. Compile / parse check (native; works for .py and .js on any OS).
    result.compiles, compile_detail = _compile_check(target_file)
    if compile_detail:
        result.detail["compile"] = compile_detail

    # 4. New findings: always a detector re-scan vs the pre-fix baseline. This
    # also gives the default "vuln still present" answer, which the oracle path
    # may override with a stronger signal below.
    rescan = detector.scan(target_file)
    if rescan.error:
        result.detail["rescan"] = rescan.error
    else:
        post_match = match_findings([bug], rescan.findings, window=window)
        result.vuln_still_present = post_match.detected_count > 0
        before = {(f.get("type"), f.get("line")) for f in baseline_findings}
        result.new_findings = [
            f for f in rescan.findings if (f.get("type"), f.get("line")) not in before
        ]

    # 2 + 3. Tests / stronger vuln signal.
    if sandbox.has_tests and sandbox.case.test_command:
        result.tests_ran = True
        result.tests_passed, test_detail = _run_tests(
            sandbox.root, sandbox.case.test_command
        )
        result.detail["tests"] = test_detail
    elif sandbox.has_oracle:
        _verify_via_oracle(sandbox, target_file, result)

    return result


def _verify_via_oracle(
    sandbox: Sandbox, target_file: Path, result: VerifyResult
) -> None:
    """Run the CWEval Docker oracle, folding its two signals into ``result``.

    On any oracle problem (no Docker, no image, bad case) we leave the re-scan
    result in place and record why — the run degrades to re-scan-only rather
    than failing the whole attempt.
    """
    try:
        cweval_oracle.install_fix_into_oracle(sandbox.root, target_file)
        outcome = cweval_oracle.run_oracle(sandbox.root)
    except cweval_oracle.OracleError as exc:
        result.detail["oracle"] = f"skipped: {exc}"
        return

    result.detail.update({f"oracle-{k}": v for k, v in outcome.detail.items()})

    if outcome.functionality_passed is not None:
        result.tests_ran = True
        result.tests_passed = outcome.functionality_passed
    if outcome.security_passed is not None:
        # Security oracle is authoritative for "is the vuln gone" on these cases.
        result.vuln_still_present = not outcome.security_passed
        result.vuln_check = "oracle-security"


def _compile_check(target_file: Path) -> tuple[Optional[bool], str]:
    """Syntax-check a file. Returns (ok, detail); ok is None if unsupported."""
    suffix = target_file.suffix.lower()
    if suffix == ".py":
        cmd = [sys.executable, "-m", "py_compile", str(target_file)]
    elif suffix == ".js":
        cmd = ["node", "--check", str(target_file)]
    else:
        # .ts/.jsx/etc. need a real toolchain; skip rather than guess.
        return None, ""
    try:
        proc = run_captured(cmd, timeout=COMPILE_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"compile check failed to run: {exc}"
    ok = proc.returncode == 0
    return ok, "" if ok else (proc.stderr or proc.stdout).strip()[:2000]


def _run_tests(cwd: Path, test_command: str) -> tuple[bool, str]:
    """Run the case's test command in the sandbox. Returns (passed, detail)."""
    try:
        proc = run_captured(
            test_command, shell=True, cwd=str(cwd), timeout=TEST_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        return False, f"tests timed out after {TEST_TIMEOUT_S}s"
    except OSError as exc:
        return False, f"tests failed to run: {exc}"
    passed = proc.returncode == 0
    return passed, proc.output.strip()[-2000:]
