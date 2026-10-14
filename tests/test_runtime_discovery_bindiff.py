"""SPEC-29 §8: read-only BinDiff path pre-fill (env, fixed install paths, bounded runtime dirs; never PATH)."""
from __future__ import annotations

import pytest

from patchtrace.runtime_discovery import RuntimeCandidates, discover_local_runtimes


def stub(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"stub; must never execute")
    return path


def test_bindiff_candidates_prefilled_without_execution_or_path_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("must not execute tools"))
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("must not execute tools"))
    explicit = stub(tmp_path / "explicit" / "bindiff")
    program = stub(tmp_path / "Program Files" / "BinDiff" / "bin" / "bindiff.exe")
    local = tmp_path / "Local"
    runtime = stub(local / "PatchTrace" / "runtimes" / "bindiff8" / "bin" / "bindiff.exe")
    home = tmp_path / "home"
    user_runtime = stub(home / ".local" / "share" / "patchtrace" / "runtimes" / "bindiff-8" / "bin" / "bindiff")
    on_path = stub(tmp_path / "pathdir" / "bindiff")
    opt = stub(tmp_path / "opt" / "bindiff" / "bin" / "bindiff")
    found = discover_local_runtimes(
        {"PATCHTRACE_BINDIFF": str(explicit), "PROGRAMFILES": str(tmp_path / "Program Files"),
         "LOCALAPPDATA": str(local), "HOME": str(home), "PATH": str(on_path.parent)},
        bindiff_system_paths=[program, opt])
    assert set(found.bindiff_executables) == {p.resolve() for p in (explicit, program, runtime, user_runtime, opt)}
    assert on_path.resolve() not in found.bindiff_executables


def test_default_system_paths_use_program_files(tmp_path):
    program = stub(tmp_path / "PF" / "BinDiff" / "bin" / "bindiff.exe")
    found = discover_local_runtimes({"PROGRAMFILES": str(tmp_path / "PF")})
    assert program.resolve() in found.bindiff_executables


def test_bindiff_symlinks_dirs_and_missing_paths_are_not_candidates(tmp_path):
    real = stub(tmp_path / "real" / "bindiff")
    hints = [tmp_path / "real"]  # a directory
    link = tmp_path / "link-bindiff"
    try:
        link.symlink_to(real)
        hints.append(link)
    except (OSError, NotImplementedError):
        pass  # no symlink privilege on this Windows account; the directory/missing cases still run
    found = discover_local_runtimes({"PATCHTRACE_BINDIFF": str(tmp_path / "missing" / "bindiff")},
                                    bindiff_system_paths=hints)
    assert found.bindiff_executables == ()


def test_runtime_candidates_positional_construction_still_valid():
    assert RuntimeCandidates((), ()).bindiff_executables == ()
