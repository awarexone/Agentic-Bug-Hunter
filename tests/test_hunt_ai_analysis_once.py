"""The CLI must not repeat AI analysis already performed by hunt_target()."""

from types import SimpleNamespace

import engine
from tools import hunt as orchestrator


def test_cmd_hunt_does_not_repeat_ai_analysis(tmp_path, monkeypatch, capsys):
    recon_dir = tmp_path / "recon" / "example.com"
    live_dir = recon_dir / "live"
    live_dir.mkdir(parents=True)
    (live_dir / "urls.txt").write_text("https://example.com/\\n")

    monkeypatch.setattr(engine, "RECON", tmp_path / "recon")

    calls = {"scope": 0, "hunt": 0}

    def fake_set_scope_checker(checker):
        calls["scope"] += 1

    def fake_hunt_target(target, **kwargs):
        calls["hunt"] += 1
        assert target == "example.com"
        assert kwargs == {"quick": False, "cve_hunt": True}
        return {"scan": True, "reports": 2}

    def unexpected_brain_creation():
        raise AssertionError("cmd_hunt must not create a second Brain instance")

    monkeypatch.setattr(orchestrator, "set_scope_checker", fake_set_scope_checker)
    monkeypatch.setattr(orchestrator, "hunt_target", fake_hunt_target)
    monkeypatch.setattr(engine, "_get_brain", unexpected_brain_creation)

    engine.cmd_hunt(
        SimpleNamespace(
            target="example.com",
            scope_domain=["example.com"],
            quick=False,
        )
    )

    output = capsys.readouterr().out
    assert calls == {"scope": 1, "hunt": 1}
    assert "Report generation completed: 2 report(s)." in output
    assert "Hunt finished." in output
