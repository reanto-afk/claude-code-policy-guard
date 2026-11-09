import io
import json
import shutil

import pytest

from policy_guard.approvals import parse_reply
from policy_guard.cli import HOOK_MARKER, install, main
from policy_guard.hook import run_hook

from .conftest import EXAMPLE


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".claude").mkdir()
    shutil.copy(EXAMPLE, tmp_path / ".claude" / "policy-guard.toml")
    return tmp_path


def hook(payload, **kw):
    out = io.StringIO()
    stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
    assert run_hook(stdin, out, **kw) == 0
    return json.loads(out.getvalue())["hookSpecificOutput"]


def test_contrato_do_hook(project):
    res = hook({"session_id": "s", "cwd": str(project), "hook_event_name": "PreToolUse",
                "tool_name": "mcp__todo__delete_todo", "tool_input": {"id": 2}})
    assert res["hookEventName"] == "PreToolUse"
    assert res["permissionDecision"] == "deny"
    assert "proposta #1" in res["permissionDecisionReason"]
    assert (project / ".policy-guard" / "state.json").exists()


@pytest.mark.parametrize("payload", ["não é json", "[]", {"tool_input": {}}, {"tool_name": "Read", "tool_input": "x"}])
def test_entrada_ruim_bloqueia(project, payload):
    res = hook(payload)
    assert res["permissionDecision"] == "deny"
    assert "falha no policy-guard" in res["permissionDecisionReason"]


def test_sem_politica_bloqueia_tudo(tmp_path):
    res = hook({"cwd": str(tmp_path), "tool_name": "Read", "tool_input": {"file_path": "a"}})
    assert res["permissionDecision"] == "deny" and "política não encontrada" in res["permissionDecisionReason"]


def test_ciclo_pela_cli(project, monkeypatch, capsys):
    monkeypatch.chdir(project)
    hook({"session_id": "s", "cwd": str(project), "tool_name": "mcp__todo__delete_todo", "tool_input": {"id": 2}})
    assert main(["proposals"]) == 0 and "#1" in capsys.readouterr().out
    assert main(["approve", "sim 1"]) == 0 and "aprovada" in capsys.readouterr().out
    res = hook({"session_id": "s", "cwd": str(project), "tool_name": "mcp__todo__delete_todo", "tool_input": {"id": 2}})
    assert res["permissionDecision"] == "allow"
    assert main(["lock", "9", "--hours", "1", "--reason", "teste"]) == 0
    assert main(["locks"]) == 0 and "9" in capsys.readouterr().out
    assert main(["check", "Bash", '{"command": "rm -rf /"}']) == 1
    assert main(["validate"]) == 0
    assert main(["audit", "-n", "5"]) == 0 and "allow" in capsys.readouterr().out


def test_install_idempotente_com_backup(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": ["Read"]}}), encoding="utf-8")
    assert install(settings, f"py -m {HOOK_MARKER}") == "hook instalado"
    assert install(settings, f"py -m {HOOK_MARKER}") == "já instalado, nada mudou"
    assert install(settings, f"py -m {HOOK_MARKER} --policy x") == "comando do hook atualizado"
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["permissions"] == {"allow": ["Read"]}
    assert len(data["hooks"]["PreToolUse"]) == 1
    assert len(list(settings.parent.glob("settings.json.bak-*"))) >= 1


@pytest.mark.parametrize("text,ok,no", [
    ("ok 1 3 / não 2", {1, 3}, {2}), ("sim #4", {4}, set()), ("nao 5, 6", set(), {5, 6}),
])
def test_parse_reply(text, ok, no):
    assert parse_reply(text) == (ok, no)


@pytest.mark.parametrize("text", ["", "ok", "talvez 1", "ok 1 / não 1"])
def test_parse_reply_invalido(text):
    with pytest.raises(ValueError):
        parse_reply(text)
