"""Key-less verdict lookup via /api/public_scan."""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request

API_BASE = os.environ.get("SKILLSMITH_API_BASE", "https://skillsmith.ch")


def public_scan(sha256: str) -> dict:
    req = urllib.request.Request(f"{API_BASE}/api/public_scan?sha256={sha256}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e128:
        if e128.code == 404:
            return {"error": "unknown_hash"}
        raise


def sha256_of_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
