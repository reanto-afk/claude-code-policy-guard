"""Avaliação pura (sem estado) de uma chamada de ferramenta contra a política."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from .bash import find_operator, matches_allowlist
from .config import Policy, Rule

PATH_ARGS = ("file_path", "notebook_path", "path")


@dataclass(frozen=True)
class Event:
    tool_name: str
    tool_input: dict = field(default_factory=dict)
    session_id: str = ""
    cwd: str = "."


@dataclass(frozen=True)
class Verdict:
    decision: str  # allow | deny | ask | approve
    reason: str
    rule: str | None = None
    mutation: bool = False
    entity: str | None = None


def relative_inside(raw: str, cwd: str) -> str | None:
    """Caminho relativo a cwd (com /), já resolvendo '..' e links; None se cair fora de cwd."""
    base = Path(os.path.realpath(cwd))
    target = Path(raw)
    if not target.is_absolute():
        target = base / target
    target = Path(os.path.realpath(target))
    try:
        return target.relative_to(base).as_posix()
    except ValueError:
        return None


def _check_constraints(rule: Rule, event: Event) -> str | None:
    """None se a regra se aplica; senão o motivo de não se aplicar."""
    if rule.paths:
        raw = next((event.tool_input[k] for k in PATH_ARGS if isinstance(event.tool_input.get(k), str)), None)
        if raw is None:
            return "sem caminho no argumento"
        rel = relative_inside(raw, event.cwd)
        if rel is None:
            return "caminho fora do projeto"
        if not any(fnmatchcase(rel, pat) for pat in rule.paths):
            return f"caminho fora de {list(rule.paths)}"
    if rule.commands:
        command = event.tool_input.get("command")
        if not isinstance(command, str):
            return "sem comando"
        if not matches_allowlist(command, rule.commands):
            return "comando fora da allowlist"
    return None


def evaluate(policy: Policy, event: Event) -> Verdict:
    """Primeira regra cujo `tools` casa E cujas restrições passam decide. Sem regra: `default`."""
    if event.tool_name == "Bash" and not policy.allow_shell_operators:
        op = find_operator(str(event.tool_input.get("command", "")))
        if op:
            return Verdict("deny", f"Bash com operador de shell ({op}); rode um comando por vez")

    first_miss = None
    for rule in policy.rules:
        if not any(fnmatchcase(event.tool_name, pat) for pat in rule.tools):
            continue
        miss = _check_constraints(rule, event)
        if miss:
            first_miss = first_miss or f"regra '{rule.name}' não se aplica: {miss}"
            continue
        entity = None
        if rule.entity_arg and event.tool_input.get(rule.entity_arg) is not None:
            entity = str(event.tool_input[rule.entity_arg])
        return Verdict(rule.decision, f"regra '{rule.name}'", rule.name, rule.mutation, entity)

    reason = first_miss or f"nenhuma regra cobre '{event.tool_name}'"
    return Verdict(policy.default, f"{reason} (default: {policy.default})")
