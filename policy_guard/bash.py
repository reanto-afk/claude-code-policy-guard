"""Análise de comandos Bash: encadeamento, redirecionamento e allowlist por prefixo de tokens."""
from __future__ import annotations

import shlex

# Expansões que o bash executa mesmo dentro de aspas duplas: bloqueadas em qualquer posição.
_ALWAYS_BLOCKED = ("`", "$(", "\n", "\r")
_OPERATOR_CHARS = set("();<>|&")


def find_operator(command: str) -> str | None:
    """Devolve o primeiro operador de shell encontrado (fora de aspas), ou None."""
    for token in _ALWAYS_BLOCKED:
        if token in command:
            return repr(token)
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        for tok in lexer:
            if tok and set(tok) <= _OPERATOR_CHARS:
                return tok
    except ValueError:  # aspas sem fechar
        return "aspas sem fechar"
    return None


def tokens(command: str) -> list[str] | None:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return None


def matches_allowlist(command: str, allowed: tuple[tuple[str, ...], ...]) -> bool:
    """True se o comando começa exatamente pelos tokens de alguma entrada da allowlist.

    Ex.: a entrada ("git", "status") aceita "git status --short", mas não "git push".
    """
    toks = tokens(command)
    if not toks:
        return False
    return any(tuple(toks[: len(entry)]) == entry for entry in allowed)
