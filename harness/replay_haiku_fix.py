"""Re-verify Haiku fixer records by extracting the correct fixed_file from
the stored diff instead of re-querying the model.

The original runs wrote JSON blobs to the file ({"fixed_file": "..."}) because
the response parser tried json.loads BEFORE stripping markdown fences. The fix
is in fixer.py. This script recovers verdicts from the existing data.

Usage:
    python replay_haiku_fix.py results/fix_*_haiku_v2.jsonl
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from securepatch_bench.corpus import load_corpus
from securepatch_bench.detectors import RegexDetector
from securepatch_bench.fixer import parse_fixed_code
from securepatch_bench.fixloop import _verdict
from securepatch_bench.sandbox import sandbox_case
from securepatch_bench.verify import verify_fix


def extract_fixed_file(diff: str):
    """Pull the content that was written to the file from the unified diff."""
    plus_lines = [
        l[1:] for l in diff.splitlines()
        if l.startswith("+") and not l.startswith("+++")
    ]
    written = "\n".join(plus_lines)
    # Try to unwrap {"fixed_file": "..."} — the bug we're fixing
    try:
        data = json.loads(written)
        if isinstance(data, dict) and isinstance(data.get("fixed_file"), str):
            return data["fixed_file"]
    except json.JSONDecodeError:
        pass
    # Already raw code (not a JSON blob) — no re-verification needed
    return None


def replay_file(jsonl_path: Path) -> None:
    rows = [json.loads(l) for l in jsonl_path.open() if l.strip()]

    # Dedup by (case_id, bug_id) — take first occurrence
    seen: set = set()
    deduped = []
    for r in rows:
        k = (r.get("case_id"), r.get("bug_id"))
        if k not in seen:
            seen.add(k)
            deduped.append(r)

    # Build case lookup from corpus
    cases = {c.case_id: c for c in load_corpus()}
    bugs_by_case = {}
    for c in cases.values():
        bugs_by_case[c.case_id] = {b.id: b for b in c.bugs}

    detector = RegexDetector()  # post-fix rescan uses regex (same as live runs)
    updated = 0
    out_rows = []

    for r in deduped:
        diff = r.get("diff", "")
        fixed_code = extract_fixed_file(diff)

        if fixed_code is None:
            # Not a JSON blob — verdict was already correct, keep as-is
            out_rows.append(r)
            continue

        case_id = r["case_id"]
        bug_id = r["bug_id"]
        case = cases.get(case_id)
        bug = bugs_by_case.get(case_id, {}).get(bug_id)
        if case is None or bug is None:
            print(f"  WARN: {case_id}/{bug_id} not found in corpus, skipping")
            out_rows.append(r)
            continue

        # Apply the correctly-extracted patch and re-verify
        with sandbox_case(case) as sandbox:
            target = sandbox.path(bug.file)
            baseline_scan = detector.scan(target)
            baseline_findings = [] if baseline_scan.error else baseline_scan.findings

            target.write_text(fixed_code, encoding="utf-8")
            verify = verify_fix(sandbox, target, bug, baseline_findings, detector, window=2)

        verdict, reason = _verdict(verify)
        new_r = dict(r)
        new_r["verdict"] = verdict
        new_r["reason"] = reason
        new_r["compiles"] = verify.compiles
        new_r["tests_ran"] = verify.tests_ran
        new_r["tests_passed"] = verify.tests_passed
        new_r["vuln_still_present"] = verify.vuln_still_present
        new_r["new_findings"] = verify.new_findings or []
        new_r["verify_detail"] = verify.detail
        new_r["_replayed"] = True  # provenance marker
        out_rows.append(new_r)
        updated += 1
        status = f"{verdict:10} {reason}"
        print(f"  {case_id:35} {status}")

    # Overwrite with corrected records
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for r in out_rows:
            fh.write(json.dumps(r) + "\n")

    tally: dict = {}
    for r in out_rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print(f"  => {updated} re-verified  |  verdicts: {tally}\n")


if __name__ == "__main__":
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        print("Usage: python replay_haiku_fix.py results/fix_*_haiku_v2.jsonl")
        sys.exit(1)
    for p in paths:
        print(f"\n=== {p.name} ===")
        replay_file(p)
    print("Done.")
