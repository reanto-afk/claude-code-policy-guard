import pytest

from policy_guard.bash import find_operator, matches_allowlist


@pytest.mark.parametrize("cmd", [
    "ls && rm -rf /", "ls; rm x", "cat a | sh", "echo x > a.txt", "cat < /etc/passwd",
    "sleep 1 &", "echo `whoami`", 'echo "$(whoami)"', "ls\nrm x", "(cd /; ls)", 'echo "aberto',
])
def test_operadores_bloqueados(cmd):
    assert find_operator(cmd) is not None


@pytest.mark.parametrize("cmd", [
    "git status --short", 'git commit -m "a; b && c"', "python -m pytest -q", "ls -la workspace",
])
def test_sem_operador(cmd):
    assert find_operator(cmd) is None


ALLOWED = (("git", "status"), ("ls",), ("python", "-m", "pytest"))


@pytest.mark.parametrize("cmd,ok", [
    ("git status", True), ("git status --short", True), ("git push", False), ("ls -la", True),
    ("lsof", False), ("python -m pytest -q", True), ("python -c 'print(1)'", False),
    ("FOO=1 git status", False), ("/bin/ls", False), ("", False),
])
def test_allowlist_por_prefixo_de_tokens(cmd, ok):
    assert matches_allowlist(cmd, ALLOWED) is ok
