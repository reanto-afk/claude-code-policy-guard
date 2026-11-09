"""Carrega e valida a política (arquivo TOML)."""
from __future__ import annotations

import os
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path

DECISIONS = ("allow", "deny", "ask", "approve")
MODES = ("headless", "interactive")


class PolicyError(ValueError):
    """Política inválida. O hook trata como bloqueio (fail-closed)."""


@dataclass(frozen=True)
class Rule:
    name: str
    tools: tuple[str, ...]
    decision: str
    paths: tuple[str, ...] = ()
    commands: tuple[tuple[str, ...], ...] = ()
    mutation: bool = False
    entity_arg: str | None = None


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    default: str = "deny"
    mode: str = "headless"
    mutation_budget: int | None = None
    proposal_ttl_hours: float = 24.0
    allow_shell_operators: bool = False


def _str_list(value, where: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError(f"{where}: esperado texto ou lista de textos")
    return tuple(value)


def _parse_rule(raw: dict, index: int) -> Rule:
    where = f"rule[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: esperado uma tabela [[rule]]")
    unknown = set(raw) - {"name", "tools", "decision", "paths", "commands", "mutation", "entity_arg"}
    if unknown:
        raise PolicyError(f"{where}: chave(s) desconhecida(s): {', '.join(sorted(unknown))}")
    decision = raw.get("decision")
    if decision not in DECISIONS:
        raise PolicyError(f"{where}: decision deve ser um de {DECISIONS}")
    if "tools" not in raw:
        raise PolicyError(f"{where}: falta 'tools'")
    commands = tuple(tuple(shlex.split(c)) for c in _str_list(raw.get("commands", []), f"{where}.commands"))
    if any(not c for c in commands):
        raise PolicyError(f"{where}.commands: comando vazio")
    entity_arg = raw.get("entity_arg")
    if entity_arg is not None and not isinstance(entity_arg, str):
        raise PolicyError(f"{where}.entity_arg: esperado texto")
    return Rule(
        name=str(raw.get("name") or f"rule-{index}"),
        tools=_str_list(raw["tools"], f"{where}.tools"),
        decision=decision,
        paths=_str_list(raw.get("paths", []), f"{where}.paths"),
        commands=commands,
        mutation=bool(raw.get("mutation", False)),
        entity_arg=entity_arg,
    )


def parse_policy(data: dict) -> Policy:
    unknown = set(data) - {"version", "default", "mode", "mutation_budget", "proposal_ttl_hours",
                           "allow_shell_operators", "rule"}
    if unknown:
        raise PolicyError(f"chave(s) desconhecida(s) no topo: {', '.join(sorted(unknown))}")
    if data.get("version", 1) != 1:
        raise PolicyError("version: só a versão 1 é suportada")
    default = data.get("default", "deny")
    if default not in ("allow", "deny", "ask"):
        raise PolicyError("default deve ser allow, deny ou ask")
    mode = os.environ.get("POLICY_GUARD_MODE") or data.get("mode", "headless")
    if mode not in MODES:
        raise PolicyError(f"mode deve ser um de {MODES}")
    budget = data.get("mutation_budget")
    if budget is not None and (not isinstance(budget, int) or budget < 0):
        raise PolicyError("mutation_budget deve ser inteiro >= 0")
    ttl = data.get("proposal_ttl_hours", 24)
    if not isinstance(ttl, (int, float)) or ttl <= 0:
        raise PolicyError("proposal_ttl_hours deve ser > 0")
    rules = data.get("rule", [])
    if not isinstance(rules, list):
        raise PolicyError("use [[rule]] para declarar regras")
    return Policy(
        rules=tuple(_parse_rule(r, i) for i, r in enumerate(rules)),
        default=default,
        mode=mode,
        mutation_budget=budget,
        proposal_ttl_hours=float(ttl),
        allow_shell_operators=bool(data.get("allow_shell_operators", False)),
    )


def load_policy(path: str | os.PathLike) -> Policy:
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"política não encontrada: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"TOML inválido em {path}: {exc}") from exc
    return parse_policy(data)
