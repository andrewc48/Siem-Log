from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import SIEMConfig


class LogManager:
    def __init__(self, config: SIEMConfig) -> None:
        self.log_dir = Path(config.log_directory)
        self.archive_dir = self.log_dir / "archive"
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self.events_retention_hours: float = config.events_retention_hours
        self.alerts_retention_hours: float = config.alerts_retention_hours
        self.archive_retention_days: int = max(1, int(config.archive_retention_days))
        self.prune_interval_minutes: int = config.log_prune_interval_minutes

    def _archive_path_for(self, source_path: Path) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m")
        return self.archive_dir / f"{source_path.stem}_{stamp}.jsonl"

    @staticmethod
    def _count_lines(path: Path) -> int:
        if not path.exists():
            return 0
        try:
            with path.open("r", encoding="utf-8") as handle:
                return sum(1 for _ in handle)
        except OSError:
            return 0

    def _append_archive_lines(self, source_path: Path, lines: list[str]) -> int:
        if not lines:
            return 0
        target = self._archive_path_for(source_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")
        return len(lines)

    def _prune_file(self, path: Path, retention_hours: float) -> int:
        if not path.exists():
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
        lines = path.read_text(encoding="utf-8").splitlines()
        kept, expired = [], []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                ts_str = record.get("timestamp", "")
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    kept.append(line)
                else:
                    expired.append(line)
            except (json.JSONDecodeError, ValueError, KeyError):
                kept.append(line)
        path.write_text(
            "\n".join(kept) + ("\n" if kept else ""), encoding="utf-8"
        )
        return self._append_archive_lines(path, expired)

    def prune_all(self) -> dict:
        removed = {
            "events.jsonl":      self._prune_file(self.log_dir / "events.jsonl",      self.events_retention_hours),
            "connections.jsonl": self._prune_file(self.log_dir / "connections.jsonl", self.events_retention_hours),
            "packets.jsonl":     self._prune_file(self.log_dir / "packets.jsonl",     self.events_retention_hours),
            "bluetooth.jsonl":   self._prune_file(self.log_dir / "bluetooth.jsonl",   self.events_retention_hours),
            "firewall_blocks.jsonl": self._prune_file(self.log_dir / "firewall_blocks.jsonl", self.events_retention_hours),
            "alerts.jsonl":      self._prune_file(self.log_dir / "alerts.jsonl",      self.alerts_retention_hours),
        }
        removed["archive_expired_files"] = self._prune_archive_files()
        return removed

    def update_retention(self, events_hours: float, alerts_hours: float, archive_days: int | None = None) -> None:
        self.events_retention_hours = events_hours
        self.alerts_retention_hours = alerts_hours
        if archive_days is not None:
            self.archive_retention_days = max(1, int(archive_days))

    def _prune_archive_files(self) -> int:
        if not self.archive_dir.exists():
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=float(self.archive_retention_days))
        removed = 0
        for path in self.archive_dir.glob("*.jsonl"):
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    path.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue
        return removed

    def clear_archive(self) -> dict:
        removed_files = 0
        removed_lines = 0
        removed_bytes = 0
        if not self.archive_dir.exists():
            return {"files": 0, "lines": 0, "bytes": 0}
        for path in self.archive_dir.glob("*.jsonl"):
            try:
                removed_lines += self._count_lines(path)
                removed_bytes += path.stat().st_size
                path.unlink(missing_ok=True)
                removed_files += 1
            except OSError:
                continue
        return {"files": removed_files, "lines": removed_lines, "bytes": removed_bytes}

    def start_background_pruner(self) -> None:
        def _loop() -> None:
            while True:
                time.sleep(self.prune_interval_minutes * 60)
                try:
                    self.prune_all()
                except Exception:
                    pass
        threading.Thread(target=_loop, daemon=True).start()
