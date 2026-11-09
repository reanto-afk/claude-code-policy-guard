"""Aviso opcional de proposta nova por webhook (Slack ou Discord)."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable


def make_notifier(url: str | None = None, fmt: str | None = None) -> Callable[[str], None] | None:
    url = url or os.environ.get("POLICY_GUARD_WEBHOOK")
    if not url:
        return None
    fmt = (fmt or os.environ.get("POLICY_GUARD_WEBHOOK_FORMAT") or "slack").lower()
    if fmt not in ("slack", "discord"):
        raise ValueError("POLICY_GUARD_WEBHOOK_FORMAT deve ser slack ou discord")
    key = "text" if fmt == "slack" else "content"

    def send(text: str) -> None:
        req = urllib.request.Request(
            url, data=json.dumps({key: text}).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "policy-guard"},
        )
        with urllib.request.urlopen(req, timeout=3):
            pass

    return send
