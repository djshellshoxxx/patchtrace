"""Independent ordinary Git-layout checks for the retained receipt repair."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tools.research_qualification.receipt import git_head


def git(directory: Path, *args: str) -> str:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    result = subprocess.run(
        ["git", "-c", "user.name=Receipt reviewer", "-c", "user.email=review@example.invalid", *args],
        cwd=directory, env=env, capture_output=True, text=True, check=True, timeout=15,
    )
    return result.stdout.strip()


def test_real_worktree_identity_is_distinct_and_survives_packed_refs(tmp_path, monkeypatch):
    repo = tmp_path / "main checkout"
    repo.mkdir()
    git(repo, "init", "--template=", "--initial-branch=main")
    git(repo, "commit", "--allow-empty", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    linked = tmp_path / "linked checkout"
    git(repo, "worktree", "add", "-b", "topic", str(linked))
    git(linked, "commit", "--allow-empty", "-m", "topic")
    topic = git(linked, "rev-parse", "HEAD")
    assert topic != base
    assert git_head(repo) == base
    assert git_head(linked) == topic
    git(repo, "pack-refs", "--all", "--prune")
    assert not (repo / ".git/refs/heads/topic").exists()
    assert git_head(linked) == topic
    detached = tmp_path / "detached checkout"
    git(repo, "worktree", "add", "--detach", str(detached), base)
    assert git_head(detached) == base
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("git_head executed a process"))
    assert git_head(linked) == topic


def test_real_separate_git_directory(tmp_path):
    root = tmp_path / "separate checkout"
    root.mkdir()
    metadata = tmp_path / "outside metadata"
    git(root, "init", "--template=", "--initial-branch=main", "--separate-git-dir", str(metadata))
    git(root, "commit", "--allow-empty", "-m", "base")
    assert git_head(root) == git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize("namespace", ["bisect", "worktree", "rewritten"])
def test_private_namespace_does_not_take_common_ref(tmp_path, namespace):
    root, common = tmp_path / "checkout", tmp_path / "shared.git"
    private = common / "worktrees/topic"
    root.mkdir()
    private.mkdir(parents=True)
    (root / ".git").write_text("gitdir: ../shared.git/worktrees/topic\n", encoding="utf-8")
    (private / "commondir").write_text("../..\n", encoding="utf-8")
    ref = f"refs/{namespace}/check"
    (private / "HEAD").write_text(f"ref: {ref}\n", encoding="utf-8")
    for directory, value in [(common, "a" * 40), (private, "b" * 40)]:
        path = directory / ref
        path.parent.mkdir(parents=True)
        path.write_text(value + "\n", encoding="utf-8")
    assert git_head(root) == "b" * 40


def test_invalid_utf8_metadata_is_unknown(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git/HEAD").write_bytes(b"\xff\xfe")
    assert git_head(tmp_path) is None
