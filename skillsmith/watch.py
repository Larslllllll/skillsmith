"""Rug-pull watch helpers: baseline a GitHub-hosted SKILL.md and re-check it.

Uses the public REST API (https://skillsmith.ch). The API key comes from
--api-key or the SKILLSMITH_API_KEY environment variable."""
from __future__ import annotations

import json
import os
import urllib.request

API_BASE = os.environ.get("SKILLSMITH_API_BASE", "https://skillsmith.ch")


def _post(path: str, payload: dict, api_key: str) -> dict:
    req = urllib.request.Request(
        API_BASE + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _get(path: str) -> dict:
    with urllib.request.urlopen(API_BASE + path, timeout=60) as resp:
        return json.loads(resp.read().decode())


def create_watch(url: str, api_key: str, webhook_url: str = "") -> dict:
    payload = {"url": url}
    if api_key:
        payload["api_key"] = api_key
    if webhook_url:
        payload["webhook_url"] = webhook_url
    return _post("/api/watch", payload, api_key)


def check_watch(watch_id: str, api_key: str) -> dict:
    from urllib.parse import urlencode
    return _get("/api/watch?" + urlencode({"watch_id": watch_id, "api_key": api_key}))
