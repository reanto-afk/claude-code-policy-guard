"""Log de auditoria em TSV. Nunca grava os argumentos, só o hash deles (os motivos também não os citam)."""
from __future__ import annotations

from datetime import datetime, timezone

HEADER = "ts\tsession\ttool\tdecision\trule\targs_sha256\treason\n"


def _clean(value) -> str:
    return str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")


def append_audit(store, event, verdict, digest: str, now: float) -> None:
    store.home.mkdir(parents=True, exist_ok=True)
    new = not store.audit_path.exists()
    ts = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="seconds")
    row = "\t".join(_clean(x) for x in (ts, event.session_id, event.tool_name, verdict.decision,
                                         verdict.rule, digest[:16], verdict.reason))
    with open(store.audit_path, "a", encoding="utf-8", newline="") as fh:
        if new:
            fh.write(HEADER)
        fh.write(row + "\n")


def tail(store, n: int = 20) -> list[str]:
    try:
        lines = store.audit_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    return lines[:1] + lines[1:][-n:]
