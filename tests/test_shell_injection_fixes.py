"""hunt.py's run_graphql_audit and engine.py's _run_shell both built a
shell=True command string via f-string interpolation of target-controlled
values — double-quoting doesn't stop $(...)/backtick substitution. Both
must use argv-list Popen instead. See SECURITY-REVIEW-2026-08-22.md
findings #4 and #5 (HIGH)."""
import os
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import engine


class TestEngineRunShellNoInjection:
    def test_shell_metacharacters_in_arg_do_not_execute(self, tmp_path):
        marker = tmp_path / "should_not_exist"
        payload = f'x$(touch {marker})'
        success, output = engine._run_shell(["echo", payload])
        assert not marker.exists()
        assert payload in output  # printed literally, not evaluated

    def test_normal_command_still_runs(self):
        success, output = engine._run_shell(["echo", "hello"])
        assert success
        assert "hello" in output


class TestHuntGraphqlAuditNoInjection:
    def test_malicious_url_does_not_execute(self, tmp_path, monkeypatch):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "hunt", os.path.join(REPO_ROOT, "bughunter", "tools", "hunt.py")
        )
        hunt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hunt)

        marker = tmp_path / "should_not_exist_graphql"
        monkeypatch.setattr(hunt, "RECON_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(hunt, "TOOLS_DIR", str(tmp_path / "tools"))
        monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
        os.makedirs(os.path.join(tmp_path, "tools"), exist_ok=True)
        # A no-op stand-in for graphql_audit.sh so the test only checks
        # that the malicious URL string never reaches a shell.
        script_path = os.path.join(tmp_path, "tools", "graphql_audit.sh")
        with open(script_path, "w") as f:
            f.write("#!/bin/bash\necho \"got: $1\"\n")
        os.chmod(script_path, 0o755)

        urls_dir = os.path.join(tmp_path, "recon", "target.com", "urls")
        os.makedirs(urls_dir, exist_ok=True)
        malicious_url = f'https://target.com/graphql"$(touch {marker})"'
        with open(os.path.join(urls_dir, "all.txt"), "w") as f:
            f.write(malicious_url + "\n")

        hunt.run_graphql_audit("target.com")
        assert not marker.exists()


class TestHuntTargetValidation:
    """Issue #153: run_recon (and the cve/zero-day/lead-board paths reached
    through hunt_target) build shell=True strings by interpolating the target.
    A target of $(...) or `...` was evaluated by the shell. hunt_target must
    reject any target carrying shell metacharacters before it runs."""

    def _load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "hunt_v", os.path.join(REPO_ROOT, "bughunter", "tools", "hunt.py")
        )
        hunt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hunt)
        return hunt

    def test_command_substitution_target_rejected(self):
        hunt = self._load()
        for payload in ('$(touch /tmp/x)', '`id`', 'a.com;id', 'a.com|id',
                        'a.com && id', 'a com', 'a.com>b'):
            try:
                hunt._validate_target(payload)
                assert False, f"accepted malicious target {payload!r}"
            except ValueError:
                pass

    def test_legit_targets_pass(self):
        hunt = self._load()
        for good in ('example.com', 'sub.example.co.uk', '192.168.1.1',
                     '10.0.0.0/24', 'targets/list.txt', 'a-b_c.example.com'):
            assert hunt._validate_target(good) == good

    def test_hunt_target_does_not_execute_injection(self, tmp_path, monkeypatch):
        hunt = self._load()
        marker = tmp_path / "should_not_exist_recon"
        # If validation is bypassed, run_recon would shell-eval this.
        called = {"recon": False}
        monkeypatch.setattr(hunt, "run_recon",
                            lambda *a, **k: called.__setitem__("recon", True))
        result = hunt.hunt_target(f'$(touch {marker})', recon_only=True)
        assert not marker.exists()
        assert result["success"] is False
        assert called["recon"] is False  # rejected before any shell path
