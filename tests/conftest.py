import tomllib
from pathlib import Path

import pytest

from policy_guard.config import parse_policy
from policy_guard.guard import Guard
from policy_guard.store import Store

EXAMPLE = Path(__file__).parent.parent / "examples" / "demo" / ".claude" / "policy-guard.toml"


class Clock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, hours: float) -> None:
        self.t += hours * 3600


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    for var in ("POLICY_GUARD_MODE", "POLICY_GUARD_POLICY", "POLICY_GUARD_HOME", "POLICY_GUARD_WEBHOOK"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def policy_data():
    return tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))


@pytest.fixture
def policy(policy_data):
    return parse_policy(policy_data)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def make_guard(tmp_path, clock):
    def factory(data=None, notify=None):
        pol = parse_policy(data) if isinstance(data, dict) else data
        return Guard(pol, Store(tmp_path / ".policy-guard"), policy_path=str(tmp_path / "policy.toml"),
                     now=clock, notify=notify)
    return factory
