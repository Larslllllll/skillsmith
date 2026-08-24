import argparse
import skillsmith.watch as w
from skillsmith.cli import _cmd_watch


def test_watch_create_and_check(monkeypatch, capsys):
    import skillsmith.watch as w
    calls = []
    monkeypatch.setattr(w, "_post", lambda p, pl, k: calls.append(("post", p)) or {"watch_id": "W123", "baseline_sha256": "abc"})
    monkeypatch.setattr(w, "_get", lambda p: calls.append(("get", p)) or {"status": "unchanged", "checks": 3})
    from skillsmith.cli import _cmd_watch
    import argparse
    a = argparse.Namespace(url="https://github.com/o/r/blob/main/SKILL.md", watch_id=None,
                           webhook="", api_key="k" * 20, list=False, delete=None)
    assert _cmd_watch(a) == 0
    b = argparse.Namespace(url=None, watch_id="W123", webhook="", api_key="k" * 20, list=False, delete=None)
    assert _cmd_watch(b) == 0
    out = capsys.readouterr().out
    assert "W123" in out and "ok" in out

def test_watch_changed_exit_code(monkeypatch):
    import skillsmith.watch as w
    monkeypatch.setattr(w, "_get", lambda p: {"status": "changed", "checks": 5})
    from skillsmith.cli import _cmd_watch
    import argparse
    a = argparse.Namespace(url=None, watch_id="X", webhook="", api_key="k" * 20, list=False, delete=None)
    assert _cmd_watch(a) == 2  # changed -> exit 2


def test_lookup_clean_and_unknown(monkeypatch, capsys):
    import skillsmith.cli as cl
    monkeypatch.setattr(cl, "public_scan", lambda d: {
        "name": "demo", "risk_level": "clean", "risk_score": 100,
        "lint_ok": True, "parse_ok": True, "seen_count": 2})
    from skillsmith.cli import _cmd_lookup
    a = argparse.Namespace(hash="a" * 64, file=None)
    assert _cmd_lookup(a) == 0
    out = capsys.readouterr().out
    assert "demo" in out and "clean" in out
    monkeypatch.setattr(cl, "public_scan", lambda d: {"error": "unknown_hash"})
    b = argparse.Namespace(hash="b" * 64, file=None)
    assert _cmd_lookup(b) == 1
    assert "not scanned yet" in capsys.readouterr().out


def test_watch_delete_cli(monkeypatch, capsys):
    import skillsmith.cli as cl
    import urllib.request as _ur
    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"deleted": true}'
    opened = {}
    def fake_urlopen(req, timeout=30):
        opened["url"] = req.full_url
        opened["method"] = req.get_method()
        return FakeResp()
    monkeypatch.setattr(_ur, "urlopen", fake_urlopen)
    a = argparse.Namespace(url=None, watch_id=None, webhook="", api_key="k" * 20,
                           list=False, delete="W1")
    assert cl._cmd_watch(a) == 0
    assert opened["method"] == "DELETE" and "watch_id=W1" in opened["url"]
    assert "deleted: W1" in capsys.readouterr().out
