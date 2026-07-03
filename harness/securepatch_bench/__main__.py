"""Command-line entry point for the SecurePatch research harness.

    python -m securepatch_bench scan <file>      # regex detection on one file
    python -m securepatch_bench scan <file> --record results/run.jsonl

    python -m securepatch_bench detect <file> --provider anthropic   # AI on one file

    python -m securepatch_bench bench            # regex baseline over the corpus
    python -m securepatch_bench bench --detector ai --provider openai --scans 5
    python -m securepatch_bench bench --record results/baseline.jsonl

`bench` scores a detector against the labeled benchmark corpus (detection recall,
overall and per obscurity tier). The regex detector is the floor; AI detectors
are scored the same way and over repeated scans (detection@k).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import bench as bench_mod
from . import cweval_import
from . import fixloop as fixloop_mod
from .corpus import CorpusError, OBSCURITY_TIERS, DEFAULT_CORPUS_DIR
from .core_bridge import CoreBridgeError, scan_file
from .detectors import AIDetector, Detector, RegexDetector
from .fixer import AIFixer
from .providers import ProviderError, get_provider
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


def _cmd_detect(args: argparse.Namespace) -> int:
    try:
        provider = get_provider(args.provider)
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    detector = AIDetector(provider, model=args.model)
    scan = detector.scan(args.file)
    if scan.error:
        print(f"error: {scan.error}", file=sys.stderr)
        return 1

    print(f"{args.file}")
    print(f"detector={scan.detector} findings={len(scan.findings)}")
    for finding in scan.findings:
        print(
            f"  [{finding['severity']}] {finding['type']} "
            f"line {finding['line'] + 1}: {finding['title']}"
        )
    if scan.usage:
        print(f"  usage: {_usage_line(scan.usage)}")

    if args.record:
        with ResultWriter(args.record) as writer:
            writer.write(
                {
                    "phase": "detect",
                    "detector": scan.detector,
                    "provider": args.provider,
                    "model": detector.model,
                    "file": args.file,
                    "finding_count": len(scan.findings),
                    "findings": scan.findings,
                    "usage": scan.usage.as_dict() if scan.usage else None,
                }
            )
        print(f"recorded 1 row -> {args.record}")

    return 0


def _build_detector(args: argparse.Namespace) -> Detector:
    if args.detector == "ai":
        if not args.provider:
            raise ProviderError("--provider is required when --detector ai")
        provider = get_provider(args.provider)
        return AIDetector(provider, model=args.model)
    return RegexDetector()


def _cmd_bench(args: argparse.Namespace) -> int:
    try:
        detector = _build_detector(args)
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        wall_start = time.perf_counter()
        reports = bench_mod.run_bench(
            args.benchmarks, window=args.window, detector=detector, scans=args.scans
        )
        wall_seconds = time.perf_counter() - wall_start
    except (CorpusError, CoreBridgeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    detected, bug_total, false_positives = bench_mod.totals(reports)
    tallies = bench_mod.tier_tallies(reports)
    detector_name = reports[0].detector if reports else detector.name

    print(
        f"detector={detector_name}  cases={len(reports)}  "
        f"scans={args.scans}  window={args.window}"
    )
    print()
    print("per case:")
    for report in reports:
        res = report.result
        label = "detected@k" if args.scans > 1 else "detected"
        print(
            f"  {report.case_id:<26} {label} {res.detected_count}/{res.bug_count}"
            f"  fp={len(res.false_positives)}{_case_cost_line(report.usage)}"
        )
        for note in report.surprises:
            print(f"      ! {note}")
        for err in report.errors:
            print(f"      x {err}")

    print()
    print("by collection:")
    for name, tally in sorted(bench_mod.collection_tallies(reports).items()):
        print(f"  {name:<16} {tally.detected}/{tally.total}  recall={tally.recall:.0%}")

    print()
    print("by obscurity tier:")
    for tier in OBSCURITY_TIERS:
        tally = tallies[tier]
        if tally.total == 0:
            continue
        print(f"  {tier:<16} {tally.detected}/{tally.total}  recall={tally.recall:.0%}")

    recall = detected / bug_total if bug_total else 0.0
    print()
    print(
        f"overall: detected {detected}/{bug_total} (recall {recall:.0%}), "
        f"false positives {false_positives}"
    )
    usage = bench_mod.total_usage(reports)
    if usage:
        print(f"model usage: {_usage_line(usage)}")
        if usage.cost_usd is not None and len(reports):
            print(f"avg per case: ${usage.cost_usd / len(reports):.4f}")
    print(f"wall time: {wall_seconds:.1f}s total ({wall_seconds / max(len(reports), 1):.1f}s/case)")

    if args.record:
        provider = args.provider if args.detector == "ai" else None
        model = detector.model if isinstance(detector, AIDetector) else None
        with ResultWriter(args.record) as writer:
            for report in reports:
                res = report.result
                writer.write(
                    {
                        "phase": "bench",
                        "detector": report.detector,
                        "provider": provider,
                        "model": model,
                        "case_id": report.case_id,
                        "collection": report.collection,
                        "window": args.window,
                        "scans": args.scans,
                        "detected": res.detected_count,
                        "bug_count": res.bug_count,
                        "false_positives": len(res.false_positives),
                        "missed": [bug.id for bug in res.missed],
                        "matched": [m.bug.id for m in res.matched],
                        "per_scan_matched": [
                            [m.bug.id for m in s.matched] for s in report.per_scan
                        ],
                        "per_scan_false_positives": [
                            len(s.false_positives) for s in report.per_scan
                        ],
                        "usage": report.usage.as_dict() if report.usage else None,
                        "surprises": report.surprises,
                        "errors": report.errors,
                    }
                )
        print(f"recorded {len(reports)} rows -> {args.record}")

    return 0


def _case_cost_line(usage) -> str:
    """Compact per-case cost/latency suffix for the per-case bench line.

    Empty for detectors with no model usage (e.g. regex)."""
    if not usage:
        return ""
    parts = []
    if usage.cost_usd is not None:
        parts.append(f"${usage.cost_usd:.4f}")
    if usage.latency_ms is not None:
        parts.append(f"{usage.latency_ms / 1000:.1f}s")
    return ("  " + "  ".join(parts)) if parts else ""


def _cmd_fix(args: argparse.Namespace) -> int:
    try:
        provider = get_provider(args.provider)
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    fixer = AIFixer(provider, model=args.model)
    detector = AIDetector(provider, model=args.model)

    try:
        wall_start = time.perf_counter()
        report = fixloop_mod.run_fixloop(
            fixer,
            detector,
            corpus_dir=args.benchmarks,
            collection=args.collection,
            case_id=args.case,
            window=args.window,
        )
        wall_seconds = time.perf_counter() - wall_start
    except (CorpusError, CoreBridgeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    tally = fixloop_mod.verdict_tally(report)
    print(f"fixer={fixer.name}  attempts={len(report.attempts)}  window={args.window}")
    print()
    print("per attempt:")
    for att in report.attempts:
        v = att.verify
        checks = ""
        if v is not None:
            bits = []
            if v.compiles is not None:
                bits.append("compile" + ("ok" if v.compiles else "FAIL"))
            if v.tests_ran:
                bits.append("tests" + ("ok" if v.tests_passed else "FAIL"))
            else:
                bits.append("tests-skip")
            bits.append("vuln" + ("still" if v.vuln_still_present else "gone"))
            if v.new_findings:
                bits.append(f"new={len(v.new_findings)}")
            checks = "  [" + " ".join(bits) + "]"
        print(
            f"  {att.case_id:<26} {att.verdict:<9} {att.bug_type}"
            f"{checks}{_case_cost_line(att.usage)}"
        )
        if att.reason:
            print(f"      - {att.reason}")

    print()
    print("verdicts:")
    for verdict in fixloop_mod.VERDICTS:
        print(f"  {verdict:<10} {tally.get(verdict, 0)}")

    usage = fixloop_mod.total_usage(report)
    print()
    if usage:
        print(f"model usage: {_usage_line(usage)}")
        if usage.cost_usd is not None and report.attempts:
            print(f"avg per attempt: ${usage.cost_usd / len(report.attempts):.4f}")
    per = wall_seconds / max(len(report.attempts), 1)
    print(f"wall time: {wall_seconds:.1f}s total ({per:.1f}s/attempt)")

    if args.record:
        with ResultWriter(args.record) as writer:
            for att in report.attempts:
                v = att.verify
                writer.write(
                    {
                        "phase": "fix",
                        "provider": args.provider,
                        "model": fixer.model,
                        "case_id": att.case_id,
                        "collection": att.collection,
                        "bug_id": att.bug_id,
                        "bug_type": att.bug_type,
                        "obscurity": att.obscurity,
                        "verdict": att.verdict,
                        "reason": att.reason,
                        "diff": att.fix.diff,
                        "fix_error": att.fix.error,
                        "compiles": v.compiles if v else None,
                        "tests_ran": v.tests_ran if v else False,
                        "tests_passed": v.tests_passed if v else None,
                        "vuln_still_present": v.vuln_still_present if v else None,
                        "vuln_check": v.vuln_check if v else None,
                        "new_findings": len(v.new_findings) if v else 0,
                        "verify_detail": v.detail if v else {},
                        "usage": att.usage.as_dict() if att.usage else None,
                    }
                )
        print(f"recorded {len(report.attempts)} rows -> {args.record}")

    return 0


def _usage_line(usage) -> str:
    parts = []
    if usage.input_tokens is not None or usage.output_tokens is not None:
        parts.append(f"tokens in/out={usage.input_tokens}/{usage.output_tokens}")
    if usage.cost_usd is not None:
        parts.append(f"cost=${usage.cost_usd:.4f}")
    if usage.latency_ms is not None:
        parts.append(f"latency={usage.latency_ms:.0f}ms")
    return "  ".join(parts) if parts else "(no usage reported)"


def _cmd_import_cweval(args: argparse.Namespace) -> int:
    dest = args.dest or (DEFAULT_CORPUS_DIR / "cweval")
    try:
        summary = cweval_import.import_cweval(args.src, dest)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"imported {len(summary.imported)} cases -> {dest}")
    print(f"  detector flags {len(summary.detected)} of them at import time")
    if summary.skipped:
        print(f"skipped {len(summary.skipped)}:")
        for case_id, reason in summary.skipped:
            print(f"  {case_id}: {reason}")
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

    detect = sub.add_parser(
        "detect",
        help="Scan one file with an AI provider (smoke test for provider setup).",
    )
    detect.add_argument("file", help="Path to the file to scan.")
    detect.add_argument(
        "--provider",
        required=True,
        help="Model provider id (openai | anthropic).",
    )
    detect.add_argument(
        "--model",
        default=None,
        help="Model id (default: the provider's default model).",
    )
    detect.add_argument(
        "--record",
        metavar="JSONL",
        help="Append the scan result as a row to this JSONL file.",
    )
    detect.set_defaults(func=_cmd_detect)

    bench = sub.add_parser(
        "bench",
        help="Scan the benchmark corpus with a detector and score recall.",
    )
    bench.add_argument(
        "--benchmarks",
        metavar="DIR",
        default=None,
        help="Corpus directory (default: repo benchmarks/).",
    )
    bench.add_argument(
        "--detector",
        choices=["regex", "ai"],
        default="regex",
        help="Detector to score (default: regex).",
    )
    bench.add_argument(
        "--provider",
        default=None,
        help="Model provider id when --detector ai (openai | anthropic).",
    )
    bench.add_argument(
        "--model",
        default=None,
        help="Model id when --detector ai (default: the provider's default).",
    )
    bench.add_argument(
        "--scans",
        type=int,
        default=1,
        help="Repeated scans per case; >1 reports detection@k (default: 1).",
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

    fix = sub.add_parser(
        "fix",
        help="Detect -> sandbox -> fix -> verify each bug and score the verdict.",
    )
    fix.add_argument(
        "--provider",
        required=True,
        help="Model provider id used for both fixing and re-scan (openai | anthropic).",
    )
    fix.add_argument(
        "--model",
        default=None,
        help="Model id (default: the provider's default).",
    )
    fix.add_argument(
        "--benchmarks",
        metavar="DIR",
        default=None,
        help="Corpus directory (default: repo benchmarks/).",
    )
    fix.add_argument(
        "--collection",
        default=None,
        help="Only fix one collection (e.g. seeded | literature | cweval). "
        "seeded/literature have runnable tests; cweval verifies by re-scan only.",
    )
    fix.add_argument(
        "--case",
        default=None,
        help="Only fix a single case by id (e.g. py-cmdi-ping).",
    )
    fix.add_argument(
        "--window",
        type=int,
        default=2,
        help="Line tolerance when matching a finding to a bug (default: 2).",
    )
    fix.add_argument(
        "--record",
        metavar="JSONL",
        help="Append one row per fix attempt (with diff + verdict) to this JSONL file.",
    )
    fix.set_defaults(func=_cmd_fix)

    imp = sub.add_parser(
        "import-cweval",
        help="Vendor in-scope CWEval tasks into benchmarks/cweval/.",
    )
    imp.add_argument("src", help="Path to a CWEval checkout (repo root).")
    imp.add_argument(
        "--dest",
        metavar="DIR",
        default=None,
        help="Output collection dir (default: benchmarks/cweval).",
    )
    imp.set_defaults(func=_cmd_import_cweval)

    return parser


def _load_env() -> None:
    """Load API keys from ``harness/.env`` if python-dotenv is installed.

    Optional so the regex path keeps working without the provider extras.
    Real environment variables always win over the file (``override=False``).
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    # harness/.env — two levels up from this file (securepatch_bench/__main__.py).
    env_path = Path(__file__).resolve().parents[1] / ".env"
    load_dotenv(env_path, override=False)
    # Fall back to a .env discovered from the current working directory too.
    if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
        load_dotenv(override=False)


def main(argv: list[str] | None = None) -> int:
    _load_env()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
