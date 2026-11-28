"""Bounded CODEX-5 source audit; no shell, package or target execution."""
from __future__ import annotations

import builtins
import runpy
from pathlib import Path

import pytest
import yaml

from tools.ci_pip_install_audit import WorkflowAuditError, pip_installs, run_scalars, unhashed_installs

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


class UnprotectedPipInstalls(AssertionError):
    """Successfully parsed installs lack a boundary; parser failures are distinct."""


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


@pytest.mark.xfail(
    strict=True,
    raises=UnprotectedPipInstalls,
    reason="CODEX-5: repository-wide hashed wheel closure still open",
)
def test_all_explicit_workflow_pip_installs_are_protected() -> None:
    paths = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    assert paths, "No GitHub Actions workflow sources found"
    violations = [
        f"{path.name}:run{ordinal}: {command}"
        for path in paths
        for ordinal, command in unhashed_installs(path.read_text(encoding="utf-8"))
    ]
    if violations:
        raise UnprotectedPipInstalls("\n".join(violations))


@pytest.mark.parametrize(("source", "expected"), [
    ("jobs:\n  sample:\n    steps:\n      - run: | # comment\n          python -m pip install unpinned\n", 1),
    ("jobs:\n  sample:\n    steps:\n      - run: >-\n          python -m pip install unpinned\n\n          python -m pip install --require-hashes -r lock.txt\n", 1),
    ("jobs:\n  sample:\n    steps:\n      - run: echo fixture\n        env:\n          run: python -m pip install unpinned\n", 0),
    ("jobs:\n  sample:\n    steps:\n      - run: |\n          if ! python -m pip install --only-binary=:all: ghidriff; then\n            echo skipped\n          fi\n", 1),
])
def test_independent_recovery_controls(source: str, expected: int) -> None:
    assert len(unhashed_installs(source)) == expected


def _workflow(command: str) -> str:
    return yaml.safe_dump({"jobs": {"sample": {"steps": [{"run": command}]}}})


@pytest.mark.parametrize(("command", "expected"), [
    ("if ! python -m pip install unsafe; then echo failed; fi", 1),
    ("if python -m pip install --require-hashes -r lock; then pip install unsafe; fi", 1),
    ("if false; then echo done; elif ! pip install unsafe; then echo failed; fi", 1),
    ("while ! python3.12 -m pip install unsafe; do echo retry; done", 1),
    ("until pip3 install --no-index -r offline; do echo retry; done", 0),
    ("if false; then echo no; else pip install unsafe; fi", 1),
    ("FLAG=1 env sudo /opt/python3.12 -m pip install unsafe", 1),
    ("python.exe -m pip install --require-hashes -r lock", 0),
    ("pip3.exe install unsafe", 1),
    ("python -m pip install \\\n --require-hashes -r lock", 0),
    ("python -m pip install unsafe & pip install --no-index -r offline", 1),
    ("printf '%s' 'python -m pip install unsafe'", 0),
    ("Write-Output 'python -m pip install unsafe'", 0),
    ("python -m pip install unsafe -- --require-hashes", 1),
    ("python -m pip install -r --require-hashes", 1),
    ("python -m pip install --require-hashes --no-require-hashes unsafe", 1),
    ("python -m pip install --no-deps --only-binary :all: --require-hashes -r lock", 0),
])
def test_supported_conditionals_and_boundary_tokens(command: str, expected: int) -> None:
    assert len(unhashed_installs(_workflow(command))) == expected


@pytest.mark.parametrize("command", [
    "python -m pip install `\n --require-hashes -r lock",
    "bash -c 'python -m pip install --require-hashes -r lock'",
    "eval 'pip install unsafe'",
    '"$PYTHON" -m pip install unsafe',
    "python -I -m pip install unsafe",
    "pip --isolated install unsafe",
    "sudo -n python -m pip install unsafe",
    "env -i python -m pip install unsafe",
    "xargs pip install unsafe",
    "if ! (python -m pip install unsafe); then echo failed; fi",
    "{ python -m pip install unsafe; }",
    "python -m pip install unsafe > output --require-hashes",
    "python -m pip install unsafe &&& echo --require-hashes",
    'python -m pip install "unterminated',
    'echo "$(python -m pip install --require-hashes -r lock)"',
    "python -m pip install `command` --require-hashes",
    "python - <<'PY'\nprint('python -m pip install unsafe')\nPY",
    "python - <<'PY'\nprint('unterminated')",
    "pip install --unknown-option --require-hashes",
])
def test_unsupported_matching_source_fails_closed(command: str) -> None:
    with pytest.raises(WorkflowAuditError):
        unhashed_installs(_workflow(command))


@pytest.mark.parametrize("source", [
    "jobs: [",
    "jobs: []",
    "jobs: {sample: []}",
    "jobs: {sample: {steps: {}}}",
    "jobs: {sample: {steps: [null]}}",
    "jobs: {sample: {steps: [{run: true}]}}",
    "jobs: {sample: {steps: [{run: ''}]}}",
    "jobs: {sample: {steps: [{run: pip install unsafe, run: echo safe}]}}",
    "jobs: {sample: {steps: [{run: echo safe}]}, sample: {steps: []}}",
    "jobs: !!python/object/apply:builtins.print ['not executed']",
    "",
])
def test_invalid_or_ambiguous_workflow_is_an_error(source: str) -> None:
    with pytest.raises(WorkflowAuditError):
        unhashed_installs(source)


def test_only_step_run_values_are_extracted() -> None:
    source = """defaults:
  run:
    shell: bash
    working-directory: python -m pip install metadata
env:
  run: python -m pip install metadata
jobs:
  reusable:
    uses: ./.github/workflows/other.yml
  sample:
    defaults:
      run:
        shell: bash
    steps:
      - uses: actions/example@123
        with:
          run: python -m pip install metadata
      - run: | # literal header comment
          echo first
        env:
          run: python -m pip install metadata
      - run: >-
          python -m pip install unsafe

          python -m pip install --require-hashes -r lock
"""
    assert list(run_scalars(source)) == [
        "echo first\n",
        "python -m pip install unsafe\npython -m pip install --require-hashes -r lock",
    ]
    assert unhashed_installs(source) == [(2, "python -m pip install unsafe")]


def test_missing_yaml_dependency_is_an_import_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def unavailable_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ModuleNotFoundError("PyYAML dependency unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable_yaml)
    with pytest.raises(ModuleNotFoundError, match="PyYAML dependency unavailable"):
        runpy.run_path(str(WORKFLOWS.parents[1] / "tools" / "ci_pip_install_audit.py"))


def test_actual_workflow_scan_matches_reviewed_source_census() -> None:
    expected = {
        "backend-bundle.yml": (26, 3, 2), "codex-cloud.yml": (1, 0, 0),
        "corpus-tier-r.yml": (23, 7, 7), "diff-and-score.yml": (6, 1, 1),
        "live-backend.yml": (8, 1, 1), "live-bindiff.yml": (6, 1, 1),
        "live-capa.yml": (5, 1, 1), "live-intel-tools.yml": (10, 2, 2),
        "live-kbc.yml": (3, 1, 1), "live-kev.yml": (3, 1, 1),
        "live-nvd.yml": (3, 1, 1), "live-rizin.yml": (7, 1, 1),
        "live-unified.yml": (9, 2, 2), "nightly-fuzz.yml": (5, 2, 2),
        "optional-deps.yml": (2, 1, 1), "pages.yml": (3, 1, 0),
        "pilot-eval.yml": (5, 2, 1), "qa-windows.yml": (37, 4, 4),
        "unified-corpus.yml": (17, 3, 3), "unified-live-gates.yml": (26, 7, 7),
        "winbindex-pairs.yml": (3, 1, 1),
    }
    actual = {}
    protected = []
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        source = path.read_text(encoding="utf-8")
        installs = pip_installs(source)
        actual[path.name] = (len(list(run_scalars(source))), len(installs), len(unhashed_installs(source)))
        protected.extend((path.name, item.command) for item in installs if item.has_boundary)
    assert actual == expected
    assert protected == [
        ("backend-bundle.yml", "python -m pip install --require-hashes --only-binary=:all: "
         "-r tools/requirements-sigstore-ci.lock"),
        ("pages.yml", "python -m pip install --require-hashes --only-binary=:all: -r tools/site/requirements-ci.lock"),
        ("pilot-eval.yml", "python -m pip install --require-hashes --only-binary=:all: "
         "-r tools/calibration/pilot/requirements-ci.lock"),
    ]
    assert unhashed_installs((WORKFLOWS / "winbindex-pairs.yml").read_text()) == [
        (2, "if ! python -m pip install --only-binary=:all: ghidriff")
    ]


@pytest.mark.parametrize(("source", "error"), [
    ("jobs: [", WorkflowAuditError),
    (_workflow("bash -c 'pip install unsafe'"), WorkflowAuditError),
    (_workflow("pip install unsafe"), UnprotectedPipInstalls),
])
def test_expected_failure_gate_keeps_parser_failures_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, error: type[Exception],
) -> None:
    (tmp_path / "sample.yml").write_text(source)
    monkeypatch.setattr(__import__(__name__, fromlist=["WORKFLOWS"]), "WORKFLOWS", tmp_path)
    with pytest.raises(error):
        test_all_explicit_workflow_pip_installs_are_protected()
    mark = next(mark for mark in test_all_explicit_workflow_pip_installs_are_protected.pytestmark
                if mark.name == "xfail")
    assert mark.kwargs["raises"] is UnprotectedPipInstalls
    assert mark.kwargs["strict"] is True


def test_empty_workflow_discovery_is_not_an_expected_hash_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(__import__(__name__, fromlist=["WORKFLOWS"]), "WORKFLOWS", tmp_path)
    with pytest.raises(AssertionError, match="No GitHub Actions workflow sources found") as caught:
        test_all_explicit_workflow_pip_installs_are_protected()
    assert not isinstance(caught.value, UnprotectedPipInstalls)


@pytest.mark.parametrize(("command", "expected"), [
    ("echo word#; python -m pip install sample-package", 1),
    ("echo `\npython -m pip install sample-package\n`\n", None),
    ("echo ';' python -m pip install sample-package", 0),
    ("printf '%s' '&&' python -m pip install sample-package", 0),
    ("echo okay # python -m pip install $(not-executed)", 0),
    ("echo word\\#; python -m pip install sample-package", 1),
    ("echo 'word#'; python -m pip install sample-package", 1),
    ("echo word #; python -m pip install sample-package", 0),
    ('echo "$(python -m pip install sample-package)"', None),
])
def test_peer_lexical_controls(command: str, expected: int | None) -> None:
    if expected is None:
        with pytest.raises(WorkflowAuditError):
            unhashed_installs(_workflow(command))
    else:
        assert len(unhashed_installs(_workflow(command))) == expected


@pytest.mark.parametrize(("command", "expected"), [
    ('echo "$(find "$ROOT" -type d)"\npython -m pip install unsafe', 1),
    ("echo '$(python -m pip install literal)'", 0),
    ("echo '&&'; python -m pip install unsafe", 1),
    ("echo \\; python -m pip install literal", 0),
    ("python -m pi\\\np ins\\\ntall unsafe", 1),
    ('echo "$(\npython -m pip install unsafe\n)"', None),
    ('echo "$(python -m pi\\\np install unsafe)"', None),
])
def test_lexical_spans_keep_independent_commands_and_literals_distinct(
    command: str, expected: int | None,
) -> None:
    if expected is None:
        with pytest.raises(WorkflowAuditError):
            unhashed_installs(_workflow(command))
    else:
        assert len(unhashed_installs(_workflow(command))) == expected


@pytest.mark.parametrize(("command", "expected"), [
    ("echo <(python -m pip install sample-package)", None),
    ("echo >(python -m pip install sample-package)", None),
    ("echo '<(python -m pip install sample-package)'", 0),
    ("echo '>(python -m pip install sample-package)'", 0),
    ('echo "<(python -m pip install sample-package)"', 0),
    ('echo ">(python -m pip install sample-package)"', 0),
    ("echo <(\npython -m pip install sample-package\n)", None),
    ("echo >(\npython -m pip install sample-package\n)", None),
    (r"echo \<\(python -m pip install sample-package\)", 0),
    (r"echo \>\(python -m pip install sample-package\)", 0),
    ("echo <(printf safe); python -m pip install unsafe", 1),
    ("echo >(cat); python -m pip install unsafe", 1),
])
def test_executable_process_substitution_is_refused_but_quoted_literals_are_data(
    command: str, expected: int | None,
) -> None:
    if expected is None:
        with pytest.raises(WorkflowAuditError):
            unhashed_installs(_workflow(command))
    else:
        assert len(unhashed_installs(_workflow(command))) == expected
