"""Robust subprocess capture.

CPython 3.9's threaded ``communicate`` (what ``capture_output=True`` uses) can
raise ``IndexError: list index out of range`` on Windows when the parent's own
stdout is redirected to a file — which is exactly the case for a backgrounded
harness run. Writing the child's stdout/stderr to temp files instead of pipes
avoids the threaded reader entirely, so capture works the same in the foreground
and in the background.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional, Sequence, Union

_Cmd = Union[str, Sequence[str]]


@dataclass
class Captured:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def run_captured(
    cmd: _Cmd,
    *,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
    shell: bool = False,
) -> Captured:
    """Run ``cmd`` capturing output via temp files. Raises the same exceptions as
    :func:`subprocess.run` (``OSError``, ``TimeoutExpired``)."""
    with tempfile.TemporaryFile(
        mode="w+", encoding="utf-8", errors="replace"
    ) as out, tempfile.TemporaryFile(
        mode="w+", encoding="utf-8", errors="replace"
    ) as err:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            shell=shell,
            stdout=out,
            stderr=err,
            stdin=subprocess.DEVNULL,
        )
        out.seek(0)
        err.seek(0)
        return Captured(proc.returncode, out.read(), err.read())
