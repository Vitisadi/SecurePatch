"""Generate a ground-truth detection JSONL for use with --detect-jsonl.

Every bug is marked as matched with its corpus metadata as the finding.
Zero false positives. This lets the fixer receive perfect detection context
so we can measure pure fixer capability independent of detector quality.
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))
from securepatch_bench.corpus import load_corpus

out = Path("results/ground_truth_detect.jsonl")

rows = []
for case in load_corpus():
    matched = []
    matched_findings = {}
    for bug in case.bugs:
        matched.append(bug.id)
        matched_findings[bug.id] = {
            "id": bug.id,
            "type": bug.type,
            "line": bug.line_start,
            "column": 0,
            "severity": "high",
            "title": bug.type.replace("-", " ").title(),
            "description": bug.description or "",
            "cwe": bug.cwe or "",
            "source": "ground-truth",
        }
    rows.append({
        "run_id": "ground-truth",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "detect",
        "detector": "ground-truth",
        "provider": None,
        "model": None,
        "case_id": case.case_id,
        "collection": case.collection,
        "matched": matched,
        "matched_findings": matched_findings,
        "false_positive_findings": [],
    })

with open(out, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")

print(f"Wrote {len(rows)} cases to {out}")
print(f"Total bugs (matched): {sum(len(r['matched']) for r in rows)}")
