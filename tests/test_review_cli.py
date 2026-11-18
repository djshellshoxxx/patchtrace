"""`patchtrace review match|finding|note` (docs/specs/manual-corrections-exchange.md section 6).

Evidence class: hermetic, on the synthetic sample project. Nothing here is live evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest

from patchtrace import cli
from patchtrace.cli_commands import discover
from patchtrace.models import AnalystAnnotation, Finding, FunctionMatch
from patchtrace.sample import create_sample
from patchtrace.service import ProjectService

SRC = Path(__file__).resolve().parents[1] / 'src'
ESC, RLO = '\x1b', '‮'
MATCH_STATES = get_args(FunctionMatch.model_fields['review'].annotation)
FINDING_STATES = get_args(Finding.model_fields['review'].annotation)


@pytest.fixture
def project(tmp_path):
    create_sample(tmp_path / 'p').close()
    return tmp_path / 'p'


def run(capsys, *argv):
    code = cli.main([str(item) for item in argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def result(capsys, *argv):
    code, out, err = run(capsys, *argv, '--json')
    assert out.count('\n') == 1, (out, err)
    envelope = json.loads(out)
    assert envelope['contract'] == 'enrichment-cli/1' and set(envelope) >= {'command', 'status', 'result', 'warnings'}
    return code, envelope, err


def tree(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*')) if path.is_file() and path.name != '.patchtrace.lock'}


def dump(root: Path) -> dict:
    with ProjectService.open(root, maintenance=False) as service:
        return service.project.model_dump(mode='json')


def changed(before, after, path='') -> list[str]:
    """Paths of every value that differs between two project dumps."""
    if isinstance(before, dict) and isinstance(after, dict) and set(before) == set(after):
        return [hit for key in sorted(before) for hit in changed(before[key], after[key], f'{path}/{key}')]
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        return [hit for index, pair in enumerate(zip(before, after, strict=True))
                for hit in changed(*pair, f'{path}/{index}')]
    return [] if before == after else [path]


def test_the_adapter_is_discovered_and_thin():
    verbs, failed = discover()
    assert 'review' in verbs and 'review' not in failed
    adapter = SRC / 'patchtrace' / 'cli_commands' / 'review.py'
    assert len(adapter.read_text(encoding='utf-8').splitlines()) <= 25


def test_the_choices_are_the_model_vocabularies(capsys):
    from patchtrace import review_cli
    assert review_cli.MATCH_STATES == MATCH_STATES and review_cli.FINDING_STATES == FINDING_STATES
    kinds = get_args(AnalystAnnotation.model_fields['kind'].annotation)
    assert set(kinds) - set(review_cli.NOTE_KINDS) == {'match-override', 'validation'}  # written by the service only
    assert review_cli.NOTE_KINDS == tuple(k for k in kinds if k in review_cli.NOTE_KINDS)
    for leaf, states in (('match', MATCH_STATES), ('finding', FINDING_STATES)):
        assert cli.main(['review', leaf, '--help']) == 0
        text = capsys.readouterr().out
        assert all(state in text for state in states), text


@pytest.mark.parametrize('status', [s for s in MATCH_STATES if s != 'unreviewed'])
def test_review_match_changes_exactly_that_relation(project, capsys, status):
    before = dump(project)
    target = before['matches'][2]
    code, envelope, _ = result(capsys, 'review', 'match', project, '--match', target['id'], '--status', status)
    assert code == 0 and envelope['command'] == 'review match' and envelope['status'] == 'complete'
    assert envelope['result'] == {'match_id': target['id'], 'status': status, 'previous': 'unreviewed'}
    assert changed(before, dump(project)) == ['/matches/2/review']
    assert dump(project)['matches'][2]['review'] == status


def test_review_finding_changes_exactly_that_finding_and_keeps_the_conclusion_unless_told(project, capsys):
    before = dump(project)
    finding = before['interpretations'][0]['findings'][0]
    where = '/interpretations/0/findings/0'
    conclusion = f'guard is real{RLO}\nsecond line'
    code, envelope, _ = result(capsys, 'review', 'finding', project, '--finding', finding['id'],
                               '--status', 'accepted', '--conclusion', conclusion)
    assert code == 0 and envelope['command'] == 'review finding'
    assert envelope['result'] == {'finding_id': finding['id'], 'status': 'accepted', 'previous': 'unreviewed',
                                  'conclusion': conclusion}
    first = dump(project)
    assert changed(before, first) == [f'{where}/analyst_conclusion', f'{where}/review']
    assert first['interpretations'][0]['findings'][0]['analyst_conclusion'] == conclusion  # stored unchanged, as data
    # Without --conclusion the stored one is kept (the bare service call would erase it).
    assert run(capsys, 'review', 'finding', project, '--finding', finding['id'], '--status', 'needs-review')[0] == 0
    second = dump(project)
    assert changed(first, second) == [f'{where}/review']
    code, out, _err = run(capsys, 'review', 'finding', project, '--finding', finding['id'], '--status', 'needs-review',
                          '--conclusion', '')
    assert code == 0 and changed(second, dump(project)) == [f'{where}/analyst_conclusion']
    assert dump(project)['interpretations'][0]['findings'][0]['analyst_conclusion'] == ''
    assert dump(project)['revision'] == before['revision']


@pytest.mark.parametrize('kind', ['note', 'bookmark'])
def test_review_note_appends_exactly_one_annotation(project, capsys, kind):
    before = dump(project)
    target = before['matches'][0]['id']
    text = f'check the caller{ESC}[2J{RLO}\nnext line'
    flags = [] if kind == 'note' else ['--kind', kind]  # note is the default
    code, envelope, _ = result(capsys, 'review', 'note', project, '--target', target, '--text', text, *flags)
    after = dump(project)
    added = after['annotations'][-1]
    assert code == 0 and envelope['command'] == 'review note'
    assert envelope['result'] == {'annotation_id': added['id'], 'target_id': target, 'kind': kind}
    assert (added['target_id'], added['kind'], added['text'], added['stale']) == (target, kind, text, False)
    assert len(after['annotations']) == len(before['annotations']) + 1
    assert changed(before, {**after, 'annotations': after['annotations'][:-1]}) == []
    assert after['revision'] == before['revision']


def test_untrusted_text_is_escaped_in_text_output(project, capsys):
    target = dump(project)['interpretations'][0]['findings'][0]['id']
    hostile = f'a{ESC}[31mb{RLO}c\nforged: line'
    for argv in (['note', project, '--target', target, '--text', hostile],
                 ['finding', project, '--finding', target, '--status', 'accepted', '--conclusion', hostile]):
        code, out, _err = run(capsys, 'review', *argv)
        assert code == 0 and ESC not in out and RLO not in out and len(out.splitlines()) == 1, out


@pytest.mark.parametrize('argv, message', [
    (['match', '--match', 'no-such-id', '--status', 'accepted'], 'match does not belong to project'),
    (['finding', '--finding', 'no-such-id', '--status', 'accepted'], 'finding does not belong to project'),
    (['note', '--target', 'no-such-id', '--text', 'x'], 'annotation target is not owned by project'),
    (['note', '--target', 'MATCH', '--text', '   '], 'must not be blank'),
    (['note', '--target', 'MATCH', '--text', 'x' * 32768], '32767'),
    (['finding', '--finding', 'FINDING', '--status', 'accepted', '--conclusion', 'x' * 32768], '32767'),
    (['match', '--match', 'MATCH', '--status', 'approved'], "invalid choice: 'approved'"),
    (['finding', '--finding', 'FINDING', '--status', 'approved'], "invalid choice: 'approved'"),
    (['note', '--target', 'MATCH', '--text', 'x', '--kind', 'match-override'], "invalid choice: 'match-override'"),
    (['note', '--target', 'MATCH', '--text', 'x', '--kind', 'validation'], "invalid choice: 'validation'"),
    (['match', '--status', 'accepted'], '--match'),
], ids=['unknown-match', 'unknown-finding', 'unknown-note-target', 'blank-note', 'note-too-long', 'conclusion-too-long',
        'match-status-outside-the-model', 'finding-status-outside-the-model', 'kind-reserved-for-corrections',
        'kind-reserved-for-restores', 'missing-identifier'])
def test_refusals_exit_2_and_change_nothing(project, capsys, argv, message):
    before, snapshot = tree(project), dump(project)
    names = {'MATCH': snapshot['matches'][0]['id'], 'FINDING': snapshot['interpretations'][0]['findings'][0]['id']}
    argv = [argv[0], project, *(names.get(item, item) for item in argv[1:])]
    code, envelope, err = result(capsys, 'review', *argv)
    assert code == 2 and envelope['status'] == 'failed' and envelope['result'] is None
    assert message in err and 'Traceback' not in err and tree(project) == before


def test_a_storage_failure_exits_3_and_keeps_the_prior_snapshot(project, capsys, monkeypatch):
    from patchtrace.persistence import ProjectStore
    before = tree(project)
    target = dump(project)['matches'][0]['id']

    def fail(self, candidate):
        raise ValueError('PT-STORAGE: project save failed; prior snapshot retained')
    monkeypatch.setattr(ProjectStore, 'save', fail)
    code, _out, err = run(capsys, 'review', 'match', project, '--match', target, '--status', 'accepted')
    monkeypatch.undo()
    assert code == 3 and 'prior snapshot retained' in err and tree(project) == before


def test_a_locked_or_missing_project_is_a_clean_exit_2(project, tmp_path, capsys):
    target = dump(project)['matches'][0]['id']
    with ProjectService.open(project):
        code, _out, err = run(capsys, 'review', 'match', project, '--match', target, '--status', 'accepted')
        assert code == 3 and 'PT-STORAGE: project is locked' in err and 'Traceback' not in err
    code, _out, err = run(capsys, 'review', 'note', tmp_path / 'absent', '--target', 'x', '--text', 'y')
    assert code == 2 and 'PT-STORAGE' in err


def test_no_qt_is_imported_on_any_review_path(project):
    snapshot = dump(project)
    code = ('import sys\nfrom patchtrace import cli\nimport patchtrace.review_cli\n'
            f'p = {str(project)!r}\n'
            f'codes = [cli.main(["review", "match", p, "--match", {snapshot["matches"][0]["id"]!r}, "--status", "accepted", "--json"]),\n'
            f'         cli.main(["review", "finding", p, "--finding", {snapshot["interpretations"][0]["findings"][0]["id"]!r}, "--status", "rejected", "--json"]),\n'
            f'         cli.main(["review", "note", p, "--target", {snapshot["id"]!r}, "--text", "from a script", "--json"])]\n'
            'print(codes, sorted(m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))), file=sys.stderr)')
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          env=dict(os.environ, PYTHONPATH=str(SRC)), timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stderr.strip().splitlines()[-1] == '[0, 0, 0] []'
    assert [json.loads(line)['status'] for line in done.stdout.splitlines()] == ['complete'] * 3
