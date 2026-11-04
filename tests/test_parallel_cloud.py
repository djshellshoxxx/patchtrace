"""Contract tests for API-funded parallel task isolation (no API usage)."""
import importlib.util
from pathlib import Path


def _agent():
    path = Path(__file__).resolve().parents[1] / "tools" / "parallel_cloud" / "agent.py"
    spec = importlib.util.spec_from_file_location("parallel_agent_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_eight_unique_isolated_task_names():
    agent = _agent()
    assert len(agent.TASKS) == 8
    assert len(set(agent.TASKS)) == 8
    all_prefixes = [path for scope in agent.TASKS.values() for path in scope]
    assert len(all_prefixes) == len(set(all_prefixes))


def test_scope_rejects_cross_module_changes_and_traversal():
    agent = _agent()
    scope = agent.TASKS["tooltips"]
    assert agent.allowed("src/patchtrace/tooltips.py", scope)
    assert agent.allowed("tests/test_tooltips_case.py", scope)
    for path in ("src/patchtrace/backend.py", "tests/test_nway.py",
                 "../tests/test_tooltips.py", "/tests/test_tooltips.py",
                 "tests/../tests/test_tooltips.py", ".github/workflows/test.yml"):
        assert not agent.allowed(path, scope)


def test_no_executable_workflow_paths_are_ever_allowed():
    agent = _agent()
    for scope in agent.TASKS.values():
        assert not agent.allowed(".github/workflows/codex-autonomous.yml", scope)
        assert not agent.allowed("tools/parallel_cloud/guard.py", scope)
        assert not agent.allowed("AGENTS.md", scope)


def test_context_selection_reserves_source_and_test_slots(tmp_path):
    agent = _agent()
    source = tmp_path / "src" / "patchtrace" / "nway"
    tests = tmp_path / "tests"
    source.mkdir(parents=True)
    tests.mkdir()
    for index in range(20):
        (source / f"source_{index:02}.py").write_text("value = 1\\n")
    (tests / "test_nway_case.py").write_text("def test_example(): assert True\\n")
    chosen = agent.select_context(list(source.glob("*.py")) + list(tests.glob("*.py")), tmp_path)
    assert any(x.startswith("FILE src/") for x in chosen)
    assert any(x.startswith("FILE tests/") for x in chosen)


def test_red_gate_accepts_assertion_failure_but_refuses_collection_errors():
    from subprocess import CompletedProcess

    agent = _agent()
    assertion = CompletedProcess([], 1, "1 failed, 3 passed in 0.20s", "")
    collection = CompletedProcess([], 2, "1 error in 0.10s", "")
    passing = CompletedProcess([], 0, "4 passed", "")
    assert agent.is_valid_red(assertion)
    assert not agent.is_valid_red(collection)
    assert not agent.is_valid_red(passing)


def test_edited_tests_must_pass_after_source_fix():
    from subprocess import CompletedProcess

    agent = _agent()
    assert agent.is_valid_green(CompletedProcess([], 0, "4 passed", ""))
    assert not agent.is_valid_green(CompletedProcess([], 1, "1 failed", ""))
    assert not agent.is_valid_green(CompletedProcess([], 0, "1 skipped", ""))


def test_receipt_requires_test_first_evidence(tmp_path, monkeypatch):
    import importlib.util
    import sys

    directory = Path(__file__).resolve().parents[1] / "tools" / "parallel_cloud"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("parallel_guard_under_test", directory / "guard.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    (tmp_path / "parallel.patch").write_text("example")
    receipt = {
        "task": "tooltips", "status": "patch_ready_for_validation",
        "accounted_cost_usd": 0.2, "budget_usd": 25,
        "attempts": [{"phase": "test"}, {"phase": "source"}],
        "red_verified": False, "green_verified": True
    }
    (tmp_path / "parallel-agent-receipt.json").write_text(__import__("json").dumps(receipt))
    import pytest

    with pytest.raises(ValueError, match="red/green"):
        guard.validate_artifact("tooltips", tmp_path)


def test_duplicate_edit_paths_and_unchanged_files_are_refused(tmp_path, monkeypatch):
    import json

    agent = _agent()
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    path = tmp_path / "tests" / "test_tooltips.py"
    path.parent.mkdir()
    path.write_text("x = 1\\n")
    payload = {"files": [{"path": "tests/test_tooltips.py", "content": "x = 2\\n"},
                         {"path": "tests/test_tooltips.py", "content": "x = 3\\n"}]}
    import pytest

    with pytest.raises(ValueError, match="Duplicate"):
        agent.parse_edit(json.dumps(payload), agent.TASKS["tooltips"], "test")
    with pytest.raises(ValueError, match="Unchanged"):
        agent.parse_edit(json.dumps({"files": [{"path": "tests/test_tooltips.py",
                                                "content": "x = 1\\n"}]}),
                         agent.TASKS["tooltips"], "test")


def test_focused_test_runner_isolates_api_credentials(monkeypatch):
    agent = _agent()
    monkeypatch.setenv("PATCHTRACE_OPENAI_API_KEY", "secret-must-not-reach-child")
    monkeypatch.setenv("GH_TOKEN", "github-secret")
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["env"] = kwargs["env"]
        from subprocess import CompletedProcess
        return CompletedProcess(command, 1, "1 failed", "")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    agent.run_focused_tests(["tests/test_tooltips.py"])
    assert observed["command"][:5] == ["sudo", "-n", "-u", "nobody", "env"]
    assert "PATCHTRACE_OPENAI_API_KEY" not in observed["env"]
    assert "GH_TOKEN" not in observed["env"]
    assert "secret-must-not-reach-child" not in str(observed["command"])


def test_incomplete_api_response_is_rejected(monkeypatch):
    import io

    agent = _agent()
    monkeypatch.setenv("PATCHTRACE_OPENAI_API_KEY", "fake-test-only")
    payload = b'{"status":"incomplete","output":[],"usage":{"input_tokens":1,"output_tokens":1}}'
    monkeypatch.setattr(agent.urllib.request, "urlopen",
                        lambda request, timeout: io.BytesIO(payload))
    import pytest

    with pytest.raises(RuntimeError, match="incomplete"):
        agent.query_api([{"role": "user", "content": "test"}])


def test_publisher_rejects_forged_low_cost(tmp_path, monkeypatch):
    import importlib.util
    import json
    import pytest

    directory = Path(__file__).resolve().parents[1] / "tools" / "parallel_cloud"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("parallel_guard_audit", directory / "guard.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    receipt = {
        "task": "tooltips", "status": "patch_ready_for_validation",
        "red_verified": True, "green_verified": True,
        "red_exit_code": 1, "green_exit_code": 0,
        "accounted_cost_usd": 0.000001, "budget_usd": 25,
        "accounting_input_usd_per_m": 20, "accounting_output_usd_per_m": 100,
        "attempts": [
            {"phase": "test", "input_tokens": 10000, "output_tokens": 1000},
            {"phase": "source", "input_tokens": 10000, "output_tokens": 1000},
        ],
    }
    (tmp_path / "parallel-agent-receipt.json").write_text(json.dumps(receipt))
    (tmp_path / "parallel.patch").write_text("example")
    with pytest.raises(ValueError, match="reconcile"):
        guard.validate_artifact("tooltips", tmp_path)


def test_active_pr_file_overlap_blocks_paid_work(monkeypatch):
    import importlib.util

    directory = Path(__file__).resolve().parents[1] / "tools" / "parallel_cloud"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("parallel_guard_overlap", directory / "guard.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)

    def fake_api(path):
        if "/pulls?state=open" in path:
            return [{"number": 221, "head": {"ref": "other-agent-feature"}}]
        if "/pulls/221/files" in path:
            return [{"filename": "src/patchtrace/tooltips.py"}]
        raise AssertionError(path)

    monkeypatch.setattr(guard, "github_api", fake_api)
    assert guard.check_ownership("tooltips") is False
    assert guard.check_ownership("runtime") is True


def test_sandboxed_test_subprocess_has_no_runner_credential_tokens(monkeypatch):
    agent = _agent()
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "runtime-private-token")
    monkeypatch.setenv("PATCHTRACE_OPENAI_API_KEY", "api-private-token")
    captured = {}

    def fake_run(command, **kwargs):
        from subprocess import CompletedProcess
        captured["environment"] = kwargs["env"]
        captured["command"] = command
        return CompletedProcess(command, 0, "1 passed", "")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    agent.run_focused_tests(["tests/test_tooltips.py"])
    assert set(captured["environment"]) == {"PATH"}
    assert "ACTIONS_RUNTIME_TOKEN" not in str(captured["command"])
    assert "PATCHTRACE_OPENAI_API_KEY" not in str(captured["command"])


def test_exact_replacements_are_supported_on_large_existing_files(tmp_path, monkeypatch):
    import json

    agent = _agent()
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    target = tmp_path / "src" / "patchtrace" / "artifact_bytes.py"
    target.parent.mkdir(parents=True)
    target.write_text("header = 1\n" + "filler = 0\n" * 6000 + "result = 2\n")
    proposal = {"files": [{"path": "src/patchtrace/artifact_bytes.py",
                            "replacements": [{"old": "result = 2\n", "new": "result = 3\n"}]}]}
    edits = agent.parse_edit(json.dumps(proposal), agent.TASKS["artifact"], "source")
    assert edits["src/patchtrace/artifact_bytes.py"].startswith("header = 1\n")
    assert edits["src/patchtrace/artifact_bytes.py"].endswith("result = 3\n")


def test_exact_replacements_refuse_ambiguous_or_missing_snippets(tmp_path, monkeypatch):
    import json
    import pytest

    agent = _agent()
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    target = tmp_path / "tests" / "test_artifact_bytes.py"
    target.parent.mkdir()
    target.write_text("same = 1\nsame = 1\n")
    for fragment in ("same = 1\n", "missing = 0\n"):
        proposal = {"files": [{"path": "tests/test_artifact_bytes.py",
                                "replacements": [{"old": fragment, "new": "new = 2\n"}]}]}
        with pytest.raises(ValueError, match="exactly once"):
            agent.parse_edit(json.dumps(proposal), agent.TASKS["artifact"], "test")
