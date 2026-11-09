import pytest

from policy_guard.config import PolicyError, parse_policy
from policy_guard.engine import Event, evaluate


def ev(tool, cwd=".", **tool_input):
    return Event(tool, tool_input, "s1", cwd)


@pytest.mark.parametrize("tool,inp,expected", [
    ("Read", {"file_path": "/etc/hosts"}, "allow"),
    ("Bash", {"command": "git status"}, "allow"),
    ("Bash", {"command": "git push origin main"}, "approve"),
    ("Bash", {"command": "rm -rf workspace"}, "deny"),
    ("Bash", {"command": "git status && rm -rf /"}, "deny"),
    ("mcp__todo__list_todos", {}, "allow"),
    ("mcp__github__get_issue", {"n": 1}, "allow"),
    ("mcp__todo__create_todo", {"title": "x"}, "allow"),
    ("mcp__todo__delete_todo", {"id": 2}, "approve"),
    ("WebFetch", {"url": "https://example.com"}, "deny"),
])
def test_decisoes_da_politica_de_exemplo(policy, tool, inp, expected):
    assert evaluate(policy, Event(tool, inp, "s1", ".")).decision == expected


def test_escrita_dentro_e_fora_do_workspace(policy, tmp_path):
    cwd = str(tmp_path)
    assert evaluate(policy, ev("Write", cwd, file_path="workspace/a.txt")).decision == "allow"
    assert evaluate(policy, ev("Write", cwd, file_path=str(tmp_path / "workspace" / "b.md"))).decision == "allow"
    assert evaluate(policy, ev("Write", cwd, file_path="README.md")).decision == "deny"
    out = evaluate(policy, ev("Write", cwd, file_path="workspace/../../fora.txt"))
    assert out.decision == "deny" and "fora do projeto" in out.reason


def test_mutacao_e_entidade(policy):
    v = evaluate(policy, ev("mcp__todo__delete_todo", id=7))
    assert v.mutation and v.entity == "7" and v.rule == "MCP: apagar precisa de humano"


def test_motivo_explica_regra_que_nao_se_aplicou(policy):
    v = evaluate(policy, ev("Bash", command="curl https://exemplo.com"))
    assert v.decision == "deny" and "allowlist" in v.reason


def test_operadores_liberados_por_politica():
    pol = parse_policy({"allow_shell_operators": True,
                        "rule": [{"tools": "Bash", "commands": ["ls"], "decision": "allow"}]})
    assert evaluate(pol, ev("Bash", command="ls | wc -l")).decision == "allow"


@pytest.mark.parametrize("data", [
    {"rule": [{"tools": "Read", "decision": "talvez"}]},
    {"rule": [{"decision": "allow"}]},
    {"rule": [{"tools": "Read", "decision": "allow", "extra": 1}]},
    {"default": "approve"},
    {"mutation_budget": -1},
    {"version": 2},
    {"regras": []},
])
def test_politica_invalida(data):
    with pytest.raises(PolicyError):
        parse_policy(data)


def test_modo_por_variavel_de_ambiente(monkeypatch):
    monkeypatch.setenv("POLICY_GUARD_MODE", "interactive")
    assert parse_policy({}).mode == "interactive"
