"""Command-line entry point for the SecurePatch research harness.

    python -m securepatch_bench scan <file>      # detect one file via the core CLI
    python -m securepatch_bench scan <file> --record results/run.jsonl

    python -m securepatch_bench bench            # baseline: scan the whole corpus
    python -m securepatch_bench bench --record results/baseline.jsonl

`bench` scores the current regex detector against the labeled benchmark corpus
(detection recall, overall and per obscurity tier). Later weeks add `run` (the
full experiment grid: cases x models x scans).
"""

from __future__ import annotations

import argparse
import sys

from . import bench as bench_mod
from .corpus import CorpusError, OBSCURITY_TIERS
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


def _cmd_bench(args: argparse.Namespace) -> int:
    try:
        reports = bench_mod.run_bench(args.benchmarks, window=args.window)
    except (CorpusError, CoreBridgeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    detected, bug_total, false_positives = bench_mod.totals(reports)
    tallies = bench_mod.tier_tallies(reports)

    print(f"detector=regex  cases={len(reports)}  window={args.window}")
    print()
    print("per case:")
    for report in reports:
        res = report.result
        print(
            f"  {report.case_id:<26} detected {res.detected_count}/{res.bug_count}"
            f"  fp={len(res.false_positives)}"
        )
        for note in report.surprises:
            print(f"      ! {note}")

    print()
    print("by obscurity tier:")
    for tier in OBSCURITY_TIERS:
        tally = tallies[tier]
        if tally.total == 0:
            continue
        print(f"  {tier:<16} {tally.detected}/{tally.total}  recall={tally.recall:.0%}")

    recall = detected / bug_total if bug_total else 0.0
    print()
    print(f"overall: detected {detected}/{bug_total} (recall {recall:.0%}), "
          f"false positives {false_positives}")

    if args.record:
        with ResultWriter(args.record) as writer:
            for report in reports:
                res = report.result
                writer.write(
                    {
                        "phase": "bench",
                        "detector": report.detector,
                        "case_id": report.case_id,
                        "window": args.window,
                        "detected": res.detected_count,
                        "bug_count": res.bug_count,
                        "false_positives": len(res.false_positives),
                        "missed": [bug.id for bug in res.missed],
                        "matched": [m.bug.id for m in res.matched],
                        "surprises": report.surprises,
                    }
                )
        print(f"recorded {len(reports)} rows -> {args.record}")

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

    bench = sub.add_parser(
        "bench",
        help="Scan the benchmark corpus with the regex detector and score recall.",
    )
    bench.add_argument(
        "--benchmarks",
        metavar="DIR",
        default=None,
        help="Corpus directory (default: repo benchmarks/).",
    )
    bench.add_argument(
        "--window",
        type=int,
        default=2,
        help="Line tolerance when matching a finding to a bug (default: 2).",
    )
    bench.add_argument(
        "--record",
        metavar="JSONL",
        help="Append one result row per case to this JSONL file.",
    )
    bench.set_defaults(func=_cmd_bench)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
