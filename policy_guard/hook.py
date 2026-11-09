"""Ponte com o hook PreToolUse do Claude Code: JSON no stdin, decisão JSON no stdout.

Qualquer erro (política ausente, TOML inválido, estado corrompido) vira bloqueio: fail-closed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TextIO

from .config import load_policy
from .engine import Event, Verdict
from .guard import Guard
from .notify import make_notifier
from .store import Store


def resolve_paths(cwd: str, policy: str | None, home: str | None) -> tuple[str, str]:
    policy = policy or os.environ.get("POLICY_GUARD_POLICY") or str(Path(".claude") / "policy-guard.toml")
    home = home or os.environ.get("POLICY_GUARD_HOME") or ".policy-guard"
    base = Path(cwd)
    return str(base / policy), str(base / home)  # caminho absoluto em policy/home ignora base


def output(verdict: Verdict) -> str:
    decision = verdict.decision if verdict.decision in ("allow", "deny", "ask") else "deny"
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": f"[policy-guard] {verdict.reason}",
    }}, ensure_ascii=False)


def run_hook(stdin: TextIO, stdout: TextIO, policy: str | None = None, home: str | None = None) -> int:
    try:
        raw = json.load(stdin)
        if not isinstance(raw, dict) or not isinstance(raw.get("tool_name"), str):
            raise ValueError("entrada do hook sem tool_name")
        tool_input = raw.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            raise ValueError("tool_input não é objeto")
        cwd = raw.get("cwd") or os.getcwd()
        event = Event(raw["tool_name"], tool_input, str(raw.get("session_id") or ""), cwd)
        policy_path, home_path = resolve_paths(cwd, policy, home)
        guard = Guard(load_policy(policy_path), Store(home_path), policy_path=policy_path,
                      notify=make_notifier())
        verdict = guard.decide(event)
    except Exception as exc:
        verdict = Verdict("deny", f"falha no policy-guard, bloqueado por segurança "
                                  f"({type(exc).__name__}: {exc})", "fail-closed")
    stdout.write(output(verdict))
    return 0
