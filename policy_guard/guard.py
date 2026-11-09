"""Decisão final: autoproteção, travas por item, orçamento de mutações e aprovação humana."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Callable

from .audit import append_audit
from .config import Policy
from .engine import PATH_ARGS, Event, Verdict, evaluate
from .store import Store

READ_ONLY_BUILTINS = {"Read", "Glob", "Grep", "LS"}
SELF_MARKERS = ("policy-guard", "policy_guard")
KEEP_PROPOSALS = 500


def args_hash(event: Event) -> str:
    """Impressão digital da chamada: a aprovação só vale para estes argumentos exatos."""
    canonical = json.dumps({"tool": event.tool_name, "input": event.tool_input},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")


def prune(state: dict, now: float) -> None:
    for p in state["proposals"]:
        if p["status"] in ("pending", "approved") and p["expires_at"] < now:
            p["status"] = "expired"
    state["proposals"] = state["proposals"][-KEEP_PROPOSALS:]
    state["locks"] = {k: v for k, v in state["locks"].items() if v["until"] > now}


def summarize(tool: str, tool_input: dict, limit: int = 160) -> str:
    text = json.dumps(tool_input, ensure_ascii=False, sort_keys=True)
    return f"{tool} {text if len(text) <= limit else text[:limit] + '…'}"


class Guard:
    def __init__(self, policy: Policy, store: Store, policy_path: str | None = None,
                 now: Callable[[], float] = time.time, notify: Callable[[str], None] | None = None):
        self.policy = policy
        self.store = store
        self.policy_path = policy_path
        self.now = now
        self.notify = notify

    def decide(self, event: Event) -> Verdict:
        verdict, proposal = self._decide(event)
        append_audit(self.store, event, verdict, args_hash(event), self.now())
        if proposal and self.notify:
            try:
                self.notify(f"Proposta #{proposal['id']} aguardando aprovação: "
                            f"{summarize(proposal['tool'], proposal['input'])}\n"
                            f"Aprovar: policy-guard approve \"ok {proposal['id']}\"")
            except Exception as exc:  # aviso nunca derruba a decisão
                append_audit(self.store, event, Verdict("notify-error", str(exc)), "", self.now())
        return verdict

    # -- autoproteção: o agente não mexe na política nem no estado (não aprova a si mesmo)
    def _self_protection(self, event: Event) -> str | None:
        if event.tool_name in READ_ONLY_BUILTINS:
            return None
        home = os.path.realpath(self.store.home)
        policy = os.path.realpath(self.policy_path) if self.policy_path else None
        for key in PATH_ARGS:
            raw = event.tool_input.get(key)
            if not isinstance(raw, str):
                continue
            target = raw if os.path.isabs(raw) else os.path.join(event.cwd, raw)
            target = os.path.realpath(target)
            if target == policy or target == home or target.startswith(home + os.sep):
                return f"arquivo protegido pelo policy-guard (argumento {key})"
        if event.tool_name == "Bash":
            cmd = str(event.tool_input.get("command", "")).lower()
            names = list(SELF_MARKERS) + [Path(home).name.lower()]
            if policy:
                names.append(Path(policy).name.lower())
            hit = next((n for n in names if n and n in cmd), None)
            if hit:
                return f"comando toca o policy-guard ('{hit}'); só um humano pode fazer isso"
        return None

    def _decide(self, event: Event) -> tuple[Verdict, dict | None]:
        reason = self._self_protection(event)
        if reason:
            return Verdict("deny", reason, "autoproteção"), None

        v = evaluate(self.policy, event)
        if v.decision == "deny":
            return v, None
        headless = self.policy.mode == "headless"
        if v.decision == "ask" and headless:
            v = replace(v, decision="approve")  # sem humano no terminal: pergunta vira proposta
        elif v.decision == "approve" and not headless:
            v = replace(v, decision="ask")  # humano no terminal: usa o prompt nativo
        if not v.mutation and v.decision != "approve":
            return v, None

        with self.store.locked():
            state = self.store.load()
            now = self.now()
            prune(state, now)

            if v.mutation:
                lock = state["locks"].get(v.entity) if v.entity else None
                if lock:
                    return Verdict("deny", f"item '{v.entity}' travado até {fmt_ts(lock['until'])}: "
                                           f"{lock['reason']}", v.rule, True, v.entity), None
                budget = self.policy.mutation_budget
                used = state["budget"].get(event.session_id, {}).get("used", 0)
                if budget is not None and used >= budget:
                    return Verdict("deny", f"orçamento de {budget} mutação(ões) por sessão esgotado",
                                   v.rule, True, v.entity), None

            proposal = None
            if v.decision == "approve":
                h = args_hash(event)
                match = next((p for p in reversed(state["proposals"])
                              if p["hash"] == h and p["status"] in ("pending", "approved", "rejected")), None)
                if match and match["status"] == "approved":
                    match["status"] = "used"
                    match["used_at"] = now
                    v = replace(v, decision="allow", reason=f"proposta #{match['id']} aprovada por humano")
                elif match and match["status"] == "pending":
                    return Verdict("deny", f"proposta #{match['id']} aguardando aprovação humana; "
                                           f"não repita até ser aprovada", v.rule, v.mutation, v.entity), None
                elif match:
                    return Verdict("deny", f"proposta #{match['id']} foi recusada por humano",
                                   v.rule, v.mutation, v.entity), None
                else:
                    proposal = {
                        "id": state["next_id"], "hash": h, "tool": event.tool_name,
                        "input": event.tool_input, "session": event.session_id, "rule": v.rule,
                        "status": "pending", "created_at": now,
                        "expires_at": now + self.policy.proposal_ttl_hours * 3600,
                    }
                    state["next_id"] += 1
                    state["proposals"].append(proposal)
                    v = Verdict("deny", f"ação exige aprovação humana: proposta #{proposal['id']} criada "
                                        f"(aprovação: policy-guard approve \"ok {proposal['id']}\")",
                                v.rule, v.mutation, v.entity)

            if v.decision == "allow" and v.mutation:
                entry = state["budget"].setdefault(event.session_id, {"used": 0})
                entry["used"] += 1
                entry["ts"] = now
            self.store.save(state)
        return v, proposal
