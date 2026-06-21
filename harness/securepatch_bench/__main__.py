"""Command-line entry point for the SecurePatch research harness.

Week 1 commands (proof the end-to-end bridge works):

    python -m securepatch_bench scan <file>      # detect via the core CLI
    python -m securepatch_bench scan <file> --record results/run.jsonl

Later weeks add `run` (the full experiment grid: cases x models x scans).
"""

from __future__ import annotations

import argparse
import sys

from .core_bridge import CoreBridgeError, scan_file
from .results import ResultWriter


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        result = scan_file(args.file)
    except CoreBridgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"{result.file}")
    print(f"detector={result.detector} findings={result.finding_count}")
    for finding in result.findings:
        print(
            f"  [{finding['severity']}] {finding['id']} "
            f"line {finding['line'] + 1}: {finding['title']}"
        )

    if args.record:
        with ResultWriter(args.record) as writer:
            writer.write(
                {
                    "phase": "detect",
                    "detector": result.detector,
                    "file": result.file,
                    "finding_count": result.finding_count,
                    "findings": result.findings,
                }
            )
        print(f"recorded 1 row -> {args.record}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securepatch-bench")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan one file via the core detection CLI.")
    scan.add_argument("file", help="Path to the file to scan.")
    scan.add_argument(
        "--record",
        metavar="JSONL",
        help="Append the scan result as a row to this JSONL file.",
    )
    scan.set_defaults(func=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
