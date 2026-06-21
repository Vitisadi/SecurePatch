"""Append-only JSONL result store.

Every experiment run (later: each case x model x scan-index) becomes one JSON
line. JSONL is chosen because many parallel workers can append safely and the
file is trivially loadable into pandas/SQLite for analysis.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def new_run_id() -> str:
    return uuid.uuid4().hex


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResultWriter:
    """Appends dict rows to a JSONL file, stamping each with id + timestamp.

    Usable as a context manager:

        with ResultWriter("results/run.jsonl") as writer:
            writer.write({"case": "demo", "verdict": "detected"})
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = None

    def __enter__(self) -> "ResultWriter":
        self._fh = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def write(self, row: dict[str, Any]) -> dict[str, Any]:
        """Write one row, returning it with the injected `run_id` / `timestamp`."""
        if self._fh is None:
            raise RuntimeError("ResultWriter is not open; use it as a context manager.")
        enriched = {"run_id": new_run_id(), "timestamp": utc_now_iso(), **row}
        self._fh.write(json.dumps(enriched) + "\n")
        self._fh.flush()
        return enriched

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
