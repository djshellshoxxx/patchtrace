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
