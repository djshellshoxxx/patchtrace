"""Static checks of every .github/workflows/*.yml, without a YAML library (none is a dependency of the project).

GitHub reads a workflow only after the push: pages.yml carried `run: python -m pip install --only-binary=:all: -r ...`, a plain
scalar with ": " inside, so the file was invalid YAML, every run failed in zero seconds without a job, and nothing in the
repository noticed before the merge."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / '.github' / 'workflows').glob('*.yml'))
KEY_LINE = re.compile(r'^(\s*)(?:- )?([A-Za-z_][\w-]*):\s*(.*)$')


def scalar_problems(text: str) -> list[str]:
    """Lines whose plain (unquoted) value contains ": " (a trailing " # comment" is fine), and tabs, outside block scalars."""
    problems, in_block, indent = [], False, 0
    for number, line in enumerate(text.splitlines(), 1):
        if '\t' in line:
            problems.append(f'line {number}: tab character')
        if in_block:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                in_block = False
            else:
                continue
        match = KEY_LINE.match(line)
        if not match:
            continue
        value = match.group(3)
        if value in ('|', '>', '|-', '>-', '|+', '>+'):
            in_block, indent = True, len(match.group(1)) + (2 if line.lstrip().startswith('- ') else 0)
        elif value and value[0] not in '\'"[{&*!#':
            plain = re.split(r'\s#', value, maxsplit=1)[0].rstrip()
            if ': ' in plain or plain.endswith(':'):
                problems.append(f'line {number}: a plain scalar with ": " must be quoted: {line.strip()}')
    return problems


def test_the_scalar_check_flags_the_pages_workflow_mistake_and_nothing_else():
    bad = '      - run: python -m pip install --only-binary=:all: -r requirements.txt pytest\n'
    assert len(scalar_problems(bad)) == 1
    assert scalar_problems('      - run: "python -m pip install --only-binary=:all: -r requirements.txt"\n') == []
    assert scalar_problems('      - run: |\n          echo a: b # c\n      - name: next\n') == []
    assert scalar_problems('    branches: [main, \'codex/**\']\n    paths: ["a: b"]\n') == []
    assert scalar_problems('      - name: x  # a comment: with a colon\n') == []
    assert len(scalar_problems('      - name: x:\n      - run: echo a: b  # c\n')) == 2      # a trailing ":" is a mapping too
    assert scalar_problems('\tkey: value\n') == ['line 1: tab character']


@pytest.mark.parametrize('path', WORKFLOWS, ids=lambda p: p.stem)
def test_workflow_has_no_unquoted_colon_scalars_or_tabs(path):
    assert scalar_problems(path.read_text(encoding='utf-8')) == []


@pytest.mark.parametrize('path', WORKFLOWS, ids=lambda p: p.stem)
def test_workflow_has_the_top_level_keys_github_requires(path):
    text = path.read_text(encoding='utf-8')
    for key in ('name', 'on', 'jobs'):
        assert re.search(rf'^{key}:', text, re.M), f'{path.name}: missing top-level `{key}:`'


QA_WORKFLOW = WORKFLOWS[0].parent / 'qa-windows.yml'


def test_qa_workflow_runs_the_qt_gate_at_20x_on_linux_and_5x_on_windows():
    text = QA_WORKFLOW.read_text(encoding='utf-8')
    assert re.search(r'os: ubuntu-latest\s+repeat: 20', text) and re.search(r'os: windows-latest\s+repeat: 5', text)
    assert 'python tools/qt_gate.py --repeat ${{ matrix.repeat }}' in text


def test_qa_workflow_reports_each_matrix_leg_to_the_release_notes():
    text = QA_WORKFLOW.read_text(encoding='utf-8')
    assert 'qa-leg-result.txt' in text
    assert '--result "qa-ubuntu=$QA_LINUX"' in text and '--result "qa-windows=$QA_WINDOWS"' in text
    assert '--result "qa-ubuntu=$QA_RESULT"' not in text
