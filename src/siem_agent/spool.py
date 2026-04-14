from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


class AgentSpool:
    def __init__(self, state_dir: Path, max_batches: int = 200) -> None:
        self.path = state_dir / "spool.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_batches = max(20, int(max_batches))

    def append_batch(self, batch: Dict[str, object]) -> None:
        rows = self.read_all()
        rows.append(batch)
        if len(rows) > self.max_batches:
            rows = rows[-self.max_batches:]
        self._write_all(rows)

    def read_all(self) -> List[Dict[str, object]]:
        if not self.path.exists():
            return []
        rows: List[Dict[str, object]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows

    def replace(self, rows: List[Dict[str, object]]) -> None:
        self._write_all(rows)

    def depth(self) -> int:
        return len(self.read_all())

    def _write_all(self, rows: List[Dict[str, object]]) -> None:
        content = "\n".join(json.dumps(row, separators=(",", ":")) for row in rows)
        self.path.write_text(content + ("\n" if content else ""), encoding="utf-8")
