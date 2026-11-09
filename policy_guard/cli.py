"""CLI: hook, check, proposals, approve, lock/unlock/locks, audit, install, validate."""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .approvals import apply_reply
from .audit import tail
from .config import PolicyError, load_policy
from .engine import Event, evaluate
from .guard import fmt_ts, prune, summarize
from .hook import resolve_paths, run_hook
from .store import Store

HOOK_MARKER = "policy_guard hook"


def _paths(args) -> tuple[str, str]:
    return resolve_paths(os.getcwd(), args.policy, args.home)


def cmd_hook(args) -> int:
    stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
    return run_hook(stdin, sys.stdout, args.policy, args.home)


def cmd_check(args) -> int:
    policy_path, _ = _paths(args)
    tool_input = json.loads(args.input) if args.input else {}
    v = evaluate(load_policy(policy_path), Event(args.tool, tool_input, "check", os.getcwd()))
    print(f"{v.decision.upper():8} {v.reason}" + (" [mutação]" if v.mutation else ""))
    return 0 if v.decision == "allow" else 1


def cmd_validate(args) -> int:
    policy_path, _ = _paths(args)
    policy = load_policy(policy_path)
    print(f"OK: {policy_path} · {len(policy.rules)} regra(s) · modo {policy.mode} · default {policy.default}")
    return 0


def cmd_proposals(args) -> int:
    _, home = _paths(args)
    store = Store(home)
    state = store.load()
    prune(state, time.time())
    shown = [p for p in state["proposals"] if args.all or p["status"] in ("pending", "approved")]
    if not shown:
        print("nenhuma proposta" + ("" if args.all else " pendente"))
    for p in shown:
        print(f"#{p['id']:<4} {p['status']:9} {fmt_ts(p['created_at'])}  {summarize(p['tool'], p['input'])}")
    return 0


def cmd_approve(args) -> int:
    _, home = _paths(args)
    for line in apply_reply(Store(home), args.reply, time.time()):
        print(line)
    return 0


def cmd_lock(args) -> int:
    _, home = _paths(args)
    store = Store(home)
    with store.locked():
        state = store.load()
        until = time.time() + args.hours * 3600
        state["locks"][args.entity] = {"until": until, "reason": args.reason}
        store.save(state)
    print(f"'{args.entity}' travado até {fmt_ts(until)}")
    return 0


def cmd_unlock(args) -> int:
    _, home = _paths(args)
    store = Store(home)
    with store.locked():
        state = store.load()
        found = state["locks"].pop(args.entity, None)
        store.save(state)
    print(f"'{args.entity}' destravado" if found else f"'{args.entity}' não estava travado")
    return 0


def cmd_locks(args) -> int:
    _, home = _paths(args)
    state = Store(home).load()
    prune(state, time.time())
    if not state["locks"]:
        print("nenhuma trava ativa")
    for entity, lock in sorted(state["locks"].items()):
        print(f"{entity}  até {fmt_ts(lock['until'])}  {lock['reason']}")
    return 0


def cmd_audit(args) -> int:
    _, home = _paths(args)
    for line in tail(Store(home), args.n):
        print(line)
    return 0


def hook_command(policy: str | None) -> str:
    cmd = f'"{sys.executable}" -m {HOOK_MARKER}'
    return cmd + (f' --policy "{os.path.abspath(policy)}"' if policy else "")


def install(settings_path: Path, command: str) -> str:
    """Grava (ou atualiza) o PreToolUse no settings.json, com backup. Idempotente."""
    data = {}
    if settings_path.exists():
        data = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
        backup = settings_path.with_name(f"{settings_path.name}.bak-{datetime.now():%Y%m%d-%H%M%S}")
        shutil.copy2(settings_path, backup)
    entries = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    for entry in entries:
        for hook in entry.get("hooks", []):
            if HOOK_MARKER in hook.get("command", ""):
                if hook["command"] == command and entry.get("matcher") == "*":
                    return "já instalado, nada mudou"
                hook["command"] = command
                entry["matcher"] = "*"
                settings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                return "comando do hook atualizado"
    entries.append({"matcher": "*", "hooks": [{"type": "command", "command": command}]})
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return "hook instalado"


def cmd_install(args) -> int:
    settings = Path(args.settings or Path(".claude") / "settings.json")
    print(f"{install(settings, hook_command(args.policy))}: {settings}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="policy-guard", description="Guardrails para agentes do Claude Code.")
    p.add_argument("--version", action="version", version=__version__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", help="arquivo TOML (padrão: .claude/policy-guard.toml)")
    common.add_argument("--home", help="pasta de estado (padrão: .policy-guard)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hook", parents=[common], help="modo hook PreToolUse (lê JSON do stdin)").set_defaults(fn=cmd_hook)
    s = sub.add_parser("check", parents=[common], help="avalia uma chamada sem gravar estado")
    s.add_argument("tool")
    s.add_argument("input", nargs="?", help="tool_input em JSON")
    s.set_defaults(fn=cmd_check)
    sub.add_parser("validate", parents=[common], help="valida a política").set_defaults(fn=cmd_validate)
    s = sub.add_parser("proposals", parents=[common], help="lista propostas")
    s.add_argument("--all", action="store_true")
    s.set_defaults(fn=cmd_proposals)
    s = sub.add_parser("approve", parents=[common], help='responde propostas: "ok 1 3 / não 2"')
    s.add_argument("reply")
    s.set_defaults(fn=cmd_approve)
    s = sub.add_parser("lock", parents=[common], help="trava um item por N horas")
    s.add_argument("entity")
    s.add_argument("--hours", type=float, default=24)
    s.add_argument("--reason", default="travado manualmente")
    s.set_defaults(fn=cmd_lock)
    s = sub.add_parser("unlock", parents=[common], help="destrava um item")
    s.add_argument("entity")
    s.set_defaults(fn=cmd_unlock)
    sub.add_parser("locks", parents=[common], help="lista travas ativas").set_defaults(fn=cmd_locks)
    s = sub.add_parser("audit", parents=[common], help="últimas linhas do log de auditoria")
    s.add_argument("-n", type=int, default=20)
    s.set_defaults(fn=cmd_audit)
    s = sub.add_parser("install", parents=[common], help="registra o hook no settings.json do projeto")
    s.add_argument("--settings", help="padrão: .claude/settings.json")
    s.set_defaults(fn=cmd_install)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (PolicyError, ValueError, TimeoutError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
