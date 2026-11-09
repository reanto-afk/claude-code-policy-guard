"""MCP de brinquedo (stdio, sem dependências) com uma lista de tarefas, para a demo do policy-guard.

Ferramentas: list_todos (leitura), create_todo (mutação), delete_todo (destrutiva).
Dados em todos.json ao lado deste arquivo (ou em TODO_DB).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

DB = Path(os.environ.get("TODO_DB") or Path(__file__).with_name("todos.json"))
SEED = [{"id": 1, "title": "Escrever o README"}, {"id": 2, "title": "Gravar o GIF da demo"},
        {"id": 3, "title": "Revisar a política"}]

TOOLS = [
    {"name": "list_todos", "description": "Lista as tarefas.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "create_todo", "description": "Cria uma tarefa.",
     "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]}},
    {"name": "delete_todo", "description": "Apaga uma tarefa pelo id.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}},
]


def load() -> list[dict]:
    if not DB.exists():
        DB.write_text(json.dumps(SEED, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.loads(DB.read_text(encoding="utf-8"))


def save(todos: list[dict]) -> None:
    DB.write_text(json.dumps(todos, ensure_ascii=False, indent=2), encoding="utf-8")


def call(name: str, args: dict) -> str:
    todos = load()
    if name == "list_todos":
        return "\n".join(f"{t['id']}: {t['title']}" for t in todos) or "(vazia)"
    if name == "create_todo":
        new = {"id": max((t["id"] for t in todos), default=0) + 1, "title": str(args["title"])}
        save(todos + [new])
        return f"criada {new['id']}: {new['title']}"
    if name == "delete_todo":
        rest = [t for t in todos if t["id"] != int(args["id"])]
        if len(rest) == len(todos):
            raise ValueError(f"tarefa {args['id']} não existe")
        save(rest)
        return f"apagada {args['id']}"
    raise ValueError(f"ferramenta desconhecida: {name}")


def handle(msg: dict) -> dict | None:
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # notificação: sem resposta
        return None
    if method == "initialize":
        result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "todo", "version": "0.1.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params", {})
        try:
            text, error = call(params.get("name", ""), params.get("arguments") or {}), False
        except Exception as exc:
            text, error = str(exc), True
        result = {"content": [{"type": "text", "text": text}], "isError": error}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"método {method} não existe"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> None:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    for line in sys.stdin:
        if not line.strip():
            continue
        reply = handle(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
