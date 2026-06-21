"""Bridge to the @securepatch/core detection engine.

Detection logic is single-sourced in TypeScript (shared with the VS Code
extension). The harness shells out to the compiled Node CLI and parses its JSON
so we never reimplement or drift from the extension's rules.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# repo_root/harness/securepatch_bench/core_bridge.py -> repo_root
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CLI = REPO_ROOT / "core" / "dist" / "cli.js"


class CoreBridgeError(RuntimeError):
    """Raised when the core CLI is missing, fails, or returns unparseable output."""


@dataclass(frozen=True)
class ScanResult:
    file: str
    detector: str
    findings: list[dict[str, Any]]
    schema_version: int

    @property
    def finding_count(self) -> int:
        return len(self.findings)


def _resolve_cli() -> Path:
    override = os.environ.get("SECUREPATCH_CORE_CLI")
    cli_path = Path(override) if override else DEFAULT_CLI
    if not cli_path.exists():
        raise CoreBridgeError(
            f"core CLI not found at {cli_path}. Build it first: `npm run build:core` "
            f"from the repo root, or set SECUREPATCH_CORE_CLI."
        )
    return cli_path


def scan_file(file_path: str | os.PathLike[str]) -> ScanResult:
    """Run `securepatch-core scan <file>` and return the parsed result."""
    cli_path = _resolve_cli()
    target = Path(file_path).resolve()

    proc = subprocess.run(
        ["node", str(cli_path), "scan", str(target)],
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        raise CoreBridgeError(
            f"core scan failed (exit {proc.returncode}) for {target}: {proc.stderr.strip()}"
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise CoreBridgeError(
            f"could not parse core CLI output for {target}: {exc}"
        ) from exc

    return ScanResult(
        file=payload["file"],
        detector=payload["detector"],
        findings=payload["findings"],
        schema_version=payload["schemaVersion"],
    )
