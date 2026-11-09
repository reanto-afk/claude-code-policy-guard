"""Estado em disco (propostas, travas, orçamento) com trava de arquivo entre processos."""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

EMPTY_STATE = {"next_id": 1, "proposals": [], "locks": {}, "budget": {}}
MAX_SESSIONS = 200


class Store:
    def __init__(self, home: str | os.PathLike):
        self.home = Path(home)
        self.state_path = self.home / "state.json"
        self.audit_path = self.home / "audit.tsv"
        self._lock_path = self.home / ".lock"

    @contextmanager
    def locked(self, timeout: float = 5.0, stale_after: float = 30.0):
        self.home.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except FileExistsError:
                try:
                    if time.time() - self._lock_path.stat().st_mtime > stale_after:
                        self._lock_path.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"trava ocupada: {self._lock_path}")
                time.sleep(0.05)
        try:
            yield
        finally:
            self._lock_path.unlink(missing_ok=True)

    def load(self) -> dict:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return json.loads(json.dumps(EMPTY_STATE))
        for key, value in EMPTY_STATE.items():
            data.setdefault(key, json.loads(json.dumps(value)))
        return data

    def save(self, data: dict) -> None:
        budget = data["budget"]
        if len(budget) > MAX_SESSIONS:  # mantém só as sessões mais recentes
            keep = sorted(budget, key=lambda s: budget[s].get("ts", 0))[-MAX_SESSIONS:]
            data["budget"] = {s: budget[s] for s in keep}
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_path)
