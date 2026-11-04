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
    scope = agent.TASKS["diagnostics"]
    assert agent.allowed("src/patchtrace/diagnostics.py", scope)
    assert agent.allowed("tests/test_diagnostics_case.py", scope)
    for path in ("src/patchtrace/backend.py", "tests/test_nway.py",
                 "../tests/test_diagnostics.py", "/tests/test_diagnostics.py",
                 "tests/../tests/test_diagnostics.py", ".github/workflows/test.yml"):
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
        "task": "diagnostics", "status": "patch_ready_for_validation",
        "accounted_cost_usd": 0.2, "budget_usd": 25,
        "attempts": [{"phase": "test"}, {"phase": "source"}],
        "red_verified": False, "green_verified": True
    }
    (tmp_path / "parallel-agent-receipt.json").write_text(__import__("json").dumps(receipt))
    import pytest

    with pytest.raises(ValueError, match="red/green"):
        guard.validate_artifact("diagnostics", tmp_path)


def test_duplicate_edit_paths_and_unchanged_files_are_refused(tmp_path, monkeypatch):
    import json

    agent = _agent()
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    path = tmp_path / "tests" / "test_diagnostics.py"
    path.parent.mkdir()
    path.write_text("x = 1\\n")
    payload = {"files": [{"path": "tests/test_diagnostics.py", "content": "x = 2\\n"},
                         {"path": "tests/test_diagnostics.py", "content": "x = 3\\n"}]}
    import pytest

    with pytest.raises(ValueError, match="Duplicate"):
        agent.parse_edit(json.dumps(payload), agent.TASKS["diagnostics"], "test")
    with pytest.raises(ValueError, match="Unchanged"):
        agent.parse_edit(json.dumps({"files": [{"path": "tests/test_diagnostics.py",
                                                "content": "x = 1\\n"}]}),
                         agent.TASKS["diagnostics"], "test")
