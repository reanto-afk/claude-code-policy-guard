from policy_guard.approvals import apply_reply
from policy_guard.engine import Event

DELETE = "mcp__todo__delete_todo"


def ev(tool, session="s1", cwd=".", **tool_input):
    return Event(tool, tool_input, session, cwd)


def test_fluxo_completo_de_aprovacao(make_guard, policy, clock):
    guard = make_guard(policy)
    v = guard.decide(ev(DELETE, id=2))
    assert v.decision == "deny" and "proposta #1 criada" in v.reason

    v = guard.decide(ev(DELETE, id=2))
    assert v.decision == "deny" and "aguardando" in v.reason  # não duplica proposta

    assert apply_reply(guard.store, "ok 1", clock())[0].startswith("#1: aprovada")
    v = guard.decide(ev(DELETE, id=2))
    assert v.decision == "allow" and "#1 aprovada" in v.reason

    v = guard.decide(ev(DELETE, id=2))  # aprovação vale uma vez só
    assert v.decision == "deny" and "proposta #2 criada" in v.reason


def test_aprovacao_so_vale_para_os_mesmos_argumentos(make_guard, policy, clock):
    guard = make_guard(policy)
    guard.decide(ev(DELETE, id=2))
    apply_reply(guard.store, "ok 1", clock())
    v = guard.decide(ev(DELETE, id=3))  # agente troca o argumento depois de aprovado
    assert v.decision == "deny" and "proposta #2 criada" in v.reason


def test_recusa(make_guard, policy, clock):
    guard = make_guard(policy)
    guard.decide(ev(DELETE, id=1))
    guard.decide(ev(DELETE, id=2))
    lines = apply_reply(guard.store, "ok 2 / não 1", clock())
    assert lines[0].startswith("#1: recusada") and lines[1].startswith("#2: aprovada")
    assert "recusada" in guard.decide(ev(DELETE, id=1)).reason
    assert guard.decide(ev(DELETE, id=2)).decision == "allow"


def test_proposta_expira(make_guard, policy, clock):
    guard = make_guard(policy)
    guard.decide(ev(DELETE, id=2))
    clock.advance(25)
    assert "já está 'expired'" in apply_reply(guard.store, "ok 1", clock())[0]
    assert "proposta #2 criada" in guard.decide(ev(DELETE, id=2)).reason


def test_orcamento_de_mutacoes_por_sessao(make_guard, policy):
    guard = make_guard(policy)  # mutation_budget = 3
    for i in range(3):
        assert guard.decide(ev("mcp__todo__create_todo", title=f"t{i}")).decision == "allow"
    v = guard.decide(ev("mcp__todo__create_todo", title="t4"))
    assert v.decision == "deny" and "orçamento" in v.reason
    assert guard.decide(ev("mcp__todo__create_todo", session="s2", title="t4")).decision == "allow"
    assert guard.decide(ev("mcp__todo__list_todos")).decision == "allow"  # leitura não gasta


def test_trava_por_item(make_guard, policy, clock):
    guard = make_guard(policy)
    with guard.store.locked():
        state = guard.store.load()
        state["locks"]["2"] = {"until": clock() + 3600, "reason": "em revisão"}
        guard.store.save(state)
    v = guard.decide(ev(DELETE, id=2))
    assert v.decision == "deny" and "travado" in v.reason and "em revisão" in v.reason
    assert "proposta #1" in guard.decide(ev(DELETE, id=3)).reason
    clock.advance(2)
    assert "proposta #2" in guard.decide(ev(DELETE, id=2)).reason


def test_modo_interativo_usa_prompt_nativo(make_guard, policy_data):
    guard = make_guard(dict(policy_data, mode="interactive"))
    assert guard.decide(ev(DELETE, id=2)).decision == "ask"
    assert guard.store.load()["proposals"] == []


def test_agente_nao_aprova_a_si_mesmo(make_guard, policy, tmp_path):
    guard = make_guard(policy)
    cwd = str(tmp_path)
    for tool, inp in [
        ("Bash", {"command": "python -m policy_guard approve 'ok 1'"}),
        ("Bash", {"command": "cat .policy-guard/state.json"}),
        ("Write", {"file_path": ".policy-guard/state.json", "content": "{}"}),
        ("Edit", {"file_path": str(tmp_path / "policy.toml"), "old_string": "a", "new_string": "b"}),
    ]:
        v = guard.decide(Event(tool, inp, "s1", cwd))
        assert v.decision == "deny" and v.rule == "autoproteção", (tool, inp)
    assert guard.decide(Event("Read", {"file_path": ".policy-guard/state.json"}, "s1", cwd)).decision == "allow"


def test_auditoria_nao_grava_argumentos(make_guard, policy):
    guard = make_guard(policy)
    guard.decide(ev("Bash", command="cat segredo-TOKEN-123"))
    log = guard.store.audit_path.read_text(encoding="utf-8")
    assert "TOKEN-123" not in log
    assert log.startswith("ts\tsession\ttool\tdecision")


def test_aviso_de_proposta_e_falha_de_aviso_nao_derruba(make_guard, policy):
    sent = []
    guard = make_guard(policy, notify=sent.append)
    guard.decide(ev(DELETE, id=2))
    assert sent and "Proposta #1" in sent[0] and 'ok 1' in sent[0]

    def broken(_):
        raise OSError("webhook fora do ar")
    guard = make_guard(policy, notify=broken)
    assert guard.decide(ev(DELETE, id=3)).decision == "deny"
    assert "notify-error" in guard.store.audit_path.read_text(encoding="utf-8")
