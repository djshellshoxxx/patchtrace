"""Read-only local backend discovery must not execute candidates or traverse whole drives."""
from __future__ import annotations

from pathlib import Path

import pytest

from patchtrace.runtime_discovery import discover_local_runtimes


def make_ghidra(root: Path) -> Path:
    (root / "Ghidra").mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text("application.version=12.0.4")
    return root


def test_finds_dedicated_venv_and_installed_ghidra_without_execution(tmp_path, monkeypatch):
    local = tmp_path / "Local App Data"
    python = local / "PatchTrace-backend" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"stub; must never execute")
    tools = tmp_path / "Tools"
    ghidra = make_ghidra(tools / "ghidra_12.0.4_PUBLIC")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("must not execute tools"))
    discovered = discover_local_runtimes(
        {"LOCALAPPDATA": str(local), "USERPROFILE": str(tmp_path)},
        search_roots=[tools])
    assert discovered.python_executables == (python.resolve(),)
    assert discovered.ghidra_roots == (ghidra.resolve(),)


def test_explicit_hints_are_deduplicated_and_ignored_when_invalid(tmp_path):
    py = tmp_path / "venv with spaces" / "Scripts" / "python.exe"
    py.parent.mkdir(parents=True)
    py.touch()
    ghidra = make_ghidra(tmp_path / "Ghidra 工具")
    discovered = discover_local_runtimes(
        {"PATCHTRACE_BACKEND_PYTHON": str(py), "GHIDRA_INSTALL_DIR": str(ghidra)},
        search_roots=[tmp_path])
    assert discovered.python_executables == (py.resolve(),)
    assert discovered.ghidra_roots == (ghidra.resolve(),)
    empty = discover_local_runtimes(
        {"PATCHTRACE_BACKEND_PYTHON": str(tmp_path / "missing.exe"),
         "GHIDRA_INSTALL_DIR": str(tmp_path / "missing")})
    assert not empty.python_executables and not empty.ghidra_roots


def test_never_recursively_scans_unrelated_directory_trees(tmp_path):
    nested = make_ghidra(tmp_path / "Tools" / "unrelated" / "ghidra_deep")
    discovered = discover_local_runtimes({}, search_roots=[tmp_path / "Tools"])
    assert nested not in discovered.ghidra_roots
    assert not discovered.python_executables


def test_does_not_accept_symlinked_ghidra_or_python(tmp_path):
    target = make_ghidra(tmp_path / "real" / "ghidra_original")
    alias = tmp_path / "Tools" / "ghidra_link"
    alias.parent.mkdir(parents=True)
    try:
        alias.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("test host does not permit creating directory symlinks")
    found = discover_local_runtimes({"GHIDRA_INSTALL_DIR": str(alias)}, search_roots=[alias.parent])
    assert not found.ghidra_roots


def test_discovery_finds_installed_offline_bundle_layout(tmp_path):
    local = tmp_path / 'Local App Data'
    target = local / 'PatchTrace' / 'runtimes' / 'offline-runtime-v1' / 'payload'
    python = target / 'python' / 'python.exe'
    python.parent.mkdir(parents=True)
    python.write_bytes(b'stub')
    ghidra = make_ghidra(target / 'ghidra')
    found = discover_local_runtimes({'LOCALAPPDATA': str(local)})
    assert found.python_executables == (python.resolve(),)
    assert found.ghidra_roots == (ghidra.resolve(),)
