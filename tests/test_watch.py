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
                           webhook="", api_key="k" * 20)
    assert _cmd_watch(a) == 0
    b = argparse.Namespace(url=None, watch_id="W123", webhook="", api_key="k" * 20)
    assert _cmd_watch(b) == 0
    out = capsys.readouterr().out
    assert "W123" in out and "ok" in out

def test_watch_changed_exit_code(monkeypatch):
    import skillsmith.watch as w
    monkeypatch.setattr(w, "_get", lambda p: {"status": "changed", "checks": 5})
    from skillsmith.cli import _cmd_watch
    import argparse
    a = argparse.Namespace(url=None, watch_id="X", webhook="", api_key="k" * 20)
    assert _cmd_watch(a) == 2  # changed -> exit 2
