"""Resposta humana às propostas: "ok 1 3 / não 2"."""
from __future__ import annotations

import re

from .guard import prune, summarize
from .store import Store

APPROVE_WORDS = {"ok", "sim", "yes", "aprovo", "approve"}
REJECT_WORDS = {"não", "nao", "no", "recuso", "reject"}


def parse_reply(text: str) -> tuple[set[int], set[int]]:
    approve: set[int] = set()
    reject: set[int] = set()
    for segment in re.split(r"[/\n]+", text):
        segment = segment.strip()
        if not segment:
            continue
        m = re.match(r"([^\W\d_]+)\s*(.*)", segment)
        if not m:
            raise ValueError(f"comece com ok/não: '{segment}'")
        verb, rest = m.group(1).lower(), m.group(2)
        ids = {int(x) for x in re.findall(r"\d+", rest)}
        if not ids:
            raise ValueError(f"sem número de proposta em '{segment}'")
        if verb in APPROVE_WORDS:
            approve |= ids
        elif verb in REJECT_WORDS:
            reject |= ids
        else:
            raise ValueError(f"palavra desconhecida '{verb}' (use ok/sim ou não/nao)")
    clash = approve & reject
    if clash:
        raise ValueError(f"proposta aprovada e recusada ao mesmo tempo: {sorted(clash)}")
    if not approve and not reject:
        raise ValueError("resposta vazia")
    return approve, reject


def apply_reply(store: Store, text: str, now: float) -> list[str]:
    approve, reject = parse_reply(text)
    lines = []
    with store.locked():
        state = store.load()
        prune(state, now)
        by_id = {p["id"]: p for p in state["proposals"]}
        for pid in sorted(approve | reject):
            p = by_id.get(pid)
            if p is None:
                lines.append(f"#{pid}: não existe")
                continue
            if p["status"] != "pending":
                lines.append(f"#{pid}: nada feito, já está '{p['status']}'")
                continue
            p["status"] = "approved" if pid in approve else "rejected"
            p["decided_at"] = now
            word = "aprovada" if pid in approve else "recusada"
            lines.append(f"#{pid}: {word} · {summarize(p['tool'], p['input'])}")
        store.save(state)
    return lines
