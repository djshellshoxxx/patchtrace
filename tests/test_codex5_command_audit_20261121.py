"""Bounded CODEX-5 per-invocation source audit: no external processes or I/O."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.ci_pip_install_audit import run_scalars, unhashed_installs


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


@pytest.mark.parametrize(
    ("run_lines", "expected"),
    [
        ("      - run: python -m pip install --require-hashes -r lock.txt\n", 0),
        ("      - run: python -m pip install unrelated\n", 1),
        ("      - run: python -m pip install --no-index -r wheelhouse.txt\n", 0),
        ("      - run: |\n          python -m pip install --require-hashes -r safe.txt\n          python -m pip install unpinned\n", 1),
        ("      - run: |\n          python -m pip install unpinned # --require-hashes\n", 1),
        ("      - run: echo 'pip install unpinned'\n", 0),
        ("      - run: python -m pip install unpinned && python -m pip install --require-hashes -r lock.txt\n", 1),
        ("      - run: pip install unpinned; pip install --no-index -r offline.txt\n", 1),
        ("      - run: 'python -m pip install --require-hashes -r lock.txt'\n", 0),
        ("      - run: \"python -m pip install --require-hashes -r lock.txt\"\n", 0),
        ("      - run: >-\n          python -m pip install\n          --require-hashes -r lock.txt\n", 0),
        ("      - run: |\n          python -m pip install \\\n            --require-hashes -r lock.txt\n", 0),
        ("      - run: |\n          FOO=1 python -m pip install unpinned || pip install --no-index offline\n", 1),
        ("      - run: |\n          echo --no-index; python -m pip install unpinned\n", 1),
        ("      - run: |\n          python -m pip install unpinned | cat --require-hashes\n", 1),
    ],
)
def test_code5_flags_are_per_install_invocation(run_lines: str, expected: int) -> None:
    source = "jobs:\n  sample:\n    steps:\n" + run_lines
    assert len(unhashed_installs(source)) == expected


def test_non_run_yaml_text_cannot_create_an_install() -> None:
    source = (
        "jobs:\n  sample:\n    steps:\n"
        "      - uses: actions/example@123\n"
        "        with:\n          args: python -m pip install unpinned\n"
        "        env:\n          SCRIPT: python -m pip install unpinned\n"
    )
    assert list(run_scalars(source)) == []
    assert unhashed_installs(source) == []


def test_multiple_run_steps_cannot_share_a_flag() -> None:
    source = (
        "jobs:\n  sample:\n    steps:\n"
        "      - run: python -m pip install unpinned\n"
        "      - run: python -m pip install --require-hashes -r lock.txt\n"
    )
    assert unhashed_installs(source) == [(1, "python -m pip install unpinned")]


@pytest.mark.xfail(strict=True, reason="CODEX-5: repository-wide hashed wheel closure still open")
def test_all_explicit_workflow_pip_installs_are_protected() -> None:
    paths = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    assert paths, "No GitHub Actions workflow sources found"
    violations = [
        f"{path.name}:run{ordinal}: {command}"
        for path in paths
        for ordinal, command in unhashed_installs(path.read_text(encoding="utf-8"))
    ]
    assert not violations, "\n".join(violations)
