"""Detection@k discovery curves from recorded detection runs.

Answers the project's headline question — *how many scans does it take to find
obscure bugs?* — from the per-scan data already captured in the detection JSONL
(`per_scan_matched`). For each model and obscurity tier we compute
**detection@k**: the fraction of ground-truth bugs found in *any* of the first
``k`` scans, for k = 1..scans.

Recall rises with k when a bug is only found intermittently (the "needs repeated
scans" effect); a flat curve means the model either always finds it or never
does. Tier breakdown shows whether the obscure (local-semantic / cross-function)
bugs are the ones that need more attempts.

No new model calls — this reads the existing `results/*detect*.jsonl` rows.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .corpus import OBSCURITY_TIERS, load_corpus


def bug_tier_map(corpus_dir: str | Path | None = None) -> dict[str, str]:
    """Map every ground-truth bug id -> its obscurity tier."""
    tiers: dict[str, str] = {}
    for case in load_corpus(corpus_dir):
        for bug in case.bugs:
            tiers[bug.id] = bug.obscurity
    return tiers


@dataclass
class DiscoveryCurve:
    label: str
    scans: int
    # tier -> total bug count (tier "overall" aggregates all)
    total: dict[str, int] = field(default_factory=dict)
    # k -> tier -> detected count
    detected: dict[int, dict[str, int]] = field(default_factory=dict)

    def recall(self, k: int, tier: str) -> Optional[float]:
        tot = self.total.get(tier, 0)
        if not tot:
            return None
        return self.detected.get(k, {}).get(tier, 0) / tot


def curve_for_file(
    path: str | Path, bug_tiers: dict[str, str]
) -> DiscoveryCurve:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"{path}: no rows")
    scans = max(int(r.get("scans", 1)) for r in rows)
    label = rows[0].get("model") or rows[0].get("detector") or Path(path).stem

    total: Counter = Counter()
    detected: dict[int, Counter] = {k: Counter() for k in range(1, scans + 1)}

    for row in rows:
        per_scan = row.get("per_scan_matched") or []
        all_bugs = set(row.get("matched", [])) | set(row.get("missed", []))
        for bug_id in all_bugs:
            tier = bug_tiers.get(bug_id, "unknown")
            total[tier] += 1
            total["overall"] += 1
        for k in range(1, scans + 1):
            cumulative: set = set()
            for i in range(min(k, len(per_scan))):
                cumulative |= set(per_scan[i])
            for bug_id in all_bugs & cumulative:
                tier = bug_tiers.get(bug_id, "unknown")
                detected[k][tier] += 1
                detected[k]["overall"] += 1

    return DiscoveryCurve(
        label=label, scans=scans, total=dict(total),
        detected={k: dict(v) for k, v in detected.items()},
    )


def render_markdown(curves: list[DiscoveryCurve]) -> str:
    """Render detection@k tables: one 'overall' table, then one per tier."""
    max_k = max(c.scans for c in curves)
    ks = list(range(1, max_k + 1))
    lines: list[str] = []

    def table(tier: str, heading: str) -> None:
        # Skip a tier no curve has bugs for.
        if not any(c.total.get(tier, 0) for c in curves):
            return
        lines.append(f"### {heading}")
        lines.append("")
        header = "| Model | " + " | ".join(f"@{k}" for k in ks) + " | bugs |"
        sep = "|---|" + "---:|" * (len(ks) + 1)
        lines.append(header)
        lines.append(sep)
        for c in curves:
            cells = []
            for k in ks:
                r = c.recall(k, tier)
                cells.append(f"{r:.0%}" if r is not None else "—")
            lines.append(f"| {c.label} | " + " | ".join(cells) + f" | {c.total.get(tier, 0)} |")
        lines.append("")

    table("overall", "Detection@k - overall")
    for tier in OBSCURITY_TIERS:
        table(tier, f"Detection@k - {tier}")
    return "\n".join(lines)
