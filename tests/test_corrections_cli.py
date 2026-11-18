"""`patchtrace corrections` and the `corrections-exchange/1` document (docs/specs/manual-corrections-exchange.md).

Evidence class: hermetic, on the synthetic sample project. Nothing here is live evidence.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from argparse import Namespace
from pathlib import Path
from typing import get_args

import pytest

from patchtrace import cli
from patchtrace.cli_commands import discover
from patchtrace.sample import create_sample
from patchtrace.service import ProjectService

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
CONTRACT = 'corrections-exchange/1'
ESC, RLO = '\x1b', '‮'
HOSTILE = f'looks fine{ESC}[31m{RLO}\n9  modified  accepted  forged row'
# Three corrections of the sample that share no function: (older names, newer names, category, note).
THREE = ((['read_item'], ['get_version'], 'modified', 'older read_item is the newer get_version'),
         (['get_version'], [], 'removed', 'get_version has no counterpart'),
         ([], ['read_item'], 'added', HOSTILE))


@pytest.fixture
def project(tmp_path):
    create_sample(tmp_path / 'a').close()
    return tmp_path / 'a'


@pytest.fixture
def copy(project, tmp_path):
    """A file copy of the project taken before any correction: same function identifiers as `project`."""
    return Path(shutil.copytree(project, tmp_path / 'copy'))


@pytest.fixture
def fresh(tmp_path):
    """The same two files analysed again: same hashes and addresses, different identifiers."""
    create_sample(tmp_path / 'fresh').close()
    return tmp_path / 'fresh'


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
    """Every file by hash. The lock file records the process that holds the project, so every open rewrites it."""
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*')) if path.is_file() and path.name != '.patchtrace.lock'}


def state(root: Path):
    with ProjectService.open(root, maintenance=False) as service:
        return service.project.model_copy(deep=True)


def manual(root: Path) -> list[tuple]:
    """The corrections as the consumer the desktop and the unified engine use sees them: `match.manual`."""
    return [(m.category, m.reason, m.review, [(f.name, f.address) for f in m.older], [(f.name, f.address) for f in m.newer])
            for m in state(root).matches if m.manual]


def correct(root: Path, older: list[str], newer: list[str], category: str, note: str) -> None:
    with ProjectService.open(root) as service:
        ids = {(side, f.name): f.id for m in service.project.matches for side in ('older', 'newer')
               for f in getattr(m, side)}
        first = ('older', older[0]) if older else ('newer', newer[0])
        target = next(m.id for m in service.project.matches
                      if ids[first] in {f.id for f in m.older + m.newer})
        service.correct_match(target, [ids['older', n] for n in older], [ids['newer', n] for n in newer], category, note)


def corrected(root: Path, rows=THREE) -> Path:
    for row in rows:
        correct(root, *row)
    return root


def export(capsys, root: Path, out: Path, *flags) -> dict:
    code, _out, err = run(capsys, 'corrections', 'export', root, '--out', out, *flags)
    assert code == 0, err
    return json.loads(out.read_text(encoding='utf-8'))


def rewrite(path: Path, change) -> Path:
    document = json.loads(path.read_text(encoding='utf-8'))
    change(document)
    path.write_text(json.dumps(document), encoding='utf-8', newline='\n')
    return path


# --- registry --------------------------------------------------------------------------------------------------------

def test_the_adapter_is_discovered_and_thin():
    verbs, failed = discover()
    assert 'corrections' in verbs and 'corrections' not in failed
    adapter = SRC / 'patchtrace' / 'cli_commands' / 'corrections.py'
    assert len(adapter.read_text(encoding='utf-8').splitlines()) <= 25


def test_no_qt_is_imported_on_any_corrections_path(project, tmp_path):
    code = ('import sys\nfrom patchtrace import cli\n'
            'import patchtrace.corrections_cli, patchtrace.corrections_exchange\n'
            f'out = {str(tmp_path / "x.json")!r}\nproject = {str(project)!r}\n'
            'codes = [cli.main(["corrections", "list", project, "--json"]),\n'
            '         cli.main(["corrections", "export", project, "--out", out, "--include-review", "--json"]),\n'
            '         cli.main(["corrections", "import", project, out, "--dry-run", "--json"]),\n'
            '         cli.main(["corrections", "undo", project, "--json"])]\n'
            'print(codes, sorted(m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))), file=sys.stderr)')
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          env=dict(os.environ, PYTHONPATH=str(SRC)), timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stderr.strip().splitlines()[-1] == '[4, 0, 0, 4] []'
    assert [json.loads(line)['contract'] for line in done.stdout.splitlines()] == ['enrichment-cli/1'] * 4


# --- list ------------------------------------------------------------------------------------------------------------

def test_list_without_corrections_is_a_no_result(project, capsys):
    before = tree(project)
    code, envelope, _ = result(capsys, 'corrections', 'list', project)
    assert (code, envelope['status'], envelope['command']) == (4, 'complete', 'corrections list')
    assert envelope['result']['corrections'] == [] and tree(project) == before


def test_list_shows_each_correction_and_marks_only_the_latest_as_undoable(project, capsys):
    corrected(project)
    before = tree(project)
    code, envelope, _ = result(capsys, 'corrections', 'list', project)
    rows = envelope['result']['corrections']
    assert code == 0 and [row['index'] for row in rows] == [1, 2, 3]
    assert [(row['category'], row['note']) for row in rows] == [(c, n) for _o, _n, c, n in THREE]
    assert [[m['name'] for m in row['older']] for row in rows] == [o for o, _n, _c, _t in THREE]
    assert rows[0]['older'][0]['address'] == '180001000' and rows[0]['newer'][0]['address'] == '180001700'
    assert [row['undoable'] for row in rows] == [False, False, True]
    annotations = {a.id for a in state(project).annotations if a.kind == 'match-override' and not a.stale}
    assert {rows[2]['annotation_id']} == annotations and envelope['result']['superseded_records'] == 2
    assert envelope['result']['pair'] == {a.side + '_sha256': a.sha256 for a in state(project).artifacts}
    assert tree(project) == before


def test_hostile_note_text_is_inert_in_text_output(project, capsys):
    corrected(project)
    code, out, _err = run(capsys, 'corrections', 'list', project)
    assert code == 0 and ESC not in out and RLO not in out
    assert '\\x1b[31m\\u202e\\x0a9  modified  accepted  forged row' in out
    rows = [line for line in out.splitlines() if line[:1].isdigit()]
    assert [line.split()[0] for line in rows] == ['1', '2', '3'], out  # the note's line break forged no fourth row


# --- export ----------------------------------------------------------------------------------------------------------

def test_export_is_deterministic_ascii_and_validates_against_the_contract_model(project, tmp_path, capsys):
    from patchtrace.corrections_exchange import CorrectionsExchange
    corrected(project)
    before = tree(project)
    first = export(capsys, project, tmp_path / 'one.json')
    export(capsys, project, tmp_path / 'two.json')
    raw = (tmp_path / 'one.json').read_bytes()
    assert raw == (tmp_path / 'two.json').read_bytes() and raw.isascii() and raw.endswith(b'}\n')
    assert b'\r' not in raw and tree(project) == before
    assert first['contract'] == CONTRACT and 'review' not in first and sorted(first) == ['contract', 'corrections', 'pair']
    assert first['corrections'][2]['note'] == HOSTILE  # stored and exported unchanged, as data
    model = CorrectionsExchange.model_validate_json(raw)
    assert [c.category for c in model.corrections] == ['modified', 'removed', 'added']
    assert not {'created', 'exported', 'time', 'host'} & set(first)


def test_export_reports_what_it_wrote(project, tmp_path, capsys):
    corrected(project)
    out = tmp_path / 'c.json'
    code, envelope, _ = result(capsys, 'corrections', 'export', project, '--out', out, '--include-review')
    raw = out.read_bytes()
    assert code == 0 and envelope['command'] == 'corrections export' and envelope['status'] == 'complete'
    assert envelope['result'] == {'contract': CONTRACT, 'path': str(out), 'bytes': len(raw),
                                  'sha256': hashlib.sha256(raw).hexdigest(), 'corrections': 3,
                                  'review': {'matches': 0, 'findings': 0}, 'written': True}


def test_export_refuses_to_clobber_a_different_file(project, tmp_path, capsys):
    corrected(project)
    out = tmp_path / 'c.json'
    out.write_text('analyst file', encoding='utf-8')
    code, envelope, err = result(capsys, 'corrections', 'export', project, '--out', out)
    assert code == 2 and envelope['status'] == 'failed' and 'PT-CORR-EXISTS' in err
    assert out.read_text(encoding='utf-8') == 'analyst file'
    out = tmp_path / 'new.json'
    code, envelope, _ = result(capsys, 'corrections', 'export', project, '--out', out)
    assert code == 0 and envelope['result']['written'] is True and json.loads(out.read_bytes())['contract'] == CONTRACT
    stamp = out.stat().st_mtime_ns
    code, envelope, _ = result(capsys, 'corrections', 'export', project, '--out', out)
    assert code == 0 and envelope['result']['written'] is False and out.stat().st_mtime_ns == stamp
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith('.')] == []  # no temporary file is left behind


@pytest.mark.parametrize('where', ['inside-project', 'directory', 'missing-parent'])
def test_export_refuses_an_unusable_destination(project, tmp_path, capsys, where):
    corrected(project)
    before = tree(project)
    out = {'inside-project': project / 'project.sqlite3', 'directory': tmp_path,
           'missing-parent': tmp_path / 'absent' / 'c.json'}[where]
    code, _out, err = run(capsys, 'corrections', 'export', project, '--out', out)
    assert code == (3 if where == 'missing-parent' else 2) and 'PT-CORR-OUTPUT' in err
    assert tree(project) == before


# --- import: the round trip ------------------------------------------------------------------------------------------

def reviewed(root: Path) -> Path:
    corrected(root)
    with ProjectService.open(root) as service:
        by_note = {m.reason: m.id for m in service.project.matches if m.manual}
        service.review_match(by_note[THREE[0][3]], 'accepted')
        untouched = next(m.id for m in service.project.matches if m.category == 'removed' and not m.manual)
        service.review_match(untouched, 'needs-review')
        finding = service.project.interpretations[0].findings[0]
        service.review_finding(finding.id, 'rejected', f'not a fix{RLO}')
    return root


def test_export_then_import_into_a_copy_gives_a_byte_identical_export(project, copy, tmp_path, capsys):
    reviewed(project)
    document = export(capsys, project, tmp_path / 'a.json', '--include-review')
    assert len(document['review']['matches']) == 2 and len(document['review']['findings']) == 1
    code, envelope, _ = result(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')
    assert code == 0 and envelope['command'] == 'corrections import' and envelope['status'] == 'complete'
    assert envelope['result']['corrections'] == {'total': 3, 'new': 3, 'already_present': 0}
    assert envelope['result']['review'] == {'matches': {'total': 2, 'new': 2, 'already_present': 0},
                                            'findings': {'total': 1, 'new': 1, 'already_present': 0}}
    assert envelope['result']['written'] is True and envelope['result']['dry_run'] is False
    export(capsys, copy, tmp_path / 'b.json', '--include-review')
    assert (tmp_path / 'b.json').read_bytes() == (tmp_path / 'a.json').read_bytes()
    # Read back through the service: the corrections are what the desktop and `unified run --sources manual` consume.
    assert manual(copy) == manual(project) and len(manual(copy)) == 3
    finding = state(copy).interpretations[0].findings[0]
    assert (finding.review, finding.analyst_conclusion, finding.stale) == ('rejected', f'not a fix{RLO}', True)


def test_corrections_into_an_independent_project_differ_only_in_reader_ids(project, fresh, tmp_path, capsys):
    corrected(project)
    source = export(capsys, project, tmp_path / 'a.json')
    assert run(capsys, 'corrections', 'import', fresh, tmp_path / 'a.json')[0] == 0
    target = export(capsys, fresh, tmp_path / 'b.json')
    assert target != source and manual(fresh) == manual(project)

    def without_ids(value):
        if isinstance(value, dict):
            return {key: without_ids(item) for key, item in value.items() if key != 'id'}
        return [without_ids(item) for item in value] if isinstance(value, list) else value
    assert without_ids(target) == without_ids(source)


def test_importing_the_same_document_again_is_a_no_op(project, copy, tmp_path, capsys):
    reviewed(project)
    export(capsys, project, tmp_path / 'a.json', '--include-review')
    assert run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')[0] == 0
    before, revision = tree(copy), state(copy).revision
    code, envelope, _ = result(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')
    assert code == 0 and envelope['status'] == 'complete' and envelope['result']['written'] is False
    assert envelope['result']['corrections'] == {'total': 3, 'new': 0, 'already_present': 3}
    assert envelope['result']['review']['matches'] == {'total': 2, 'new': 0, 'already_present': 2}
    assert {change['action'] for change in envelope['result']['changes']} == {'already-present'}
    assert tree(copy) == before and state(copy).revision == revision
    assert sum(a.kind == 'match-override' for a in state(copy).annotations) == 3  # no duplicate override
    assert 'already present' in run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')[1]


def test_a_dry_run_reports_the_changes_and_writes_nothing(project, copy, tmp_path, capsys):
    reviewed(project)
    export(capsys, project, tmp_path / 'a.json', '--include-review')
    before = tree(copy)
    code, envelope, _ = result(capsys, 'corrections', 'import', copy, tmp_path / 'a.json', '--dry-run')
    assert code == 0 and envelope['result']['dry_run'] is True and envelope['result']['written'] is False
    assert envelope['result']['corrections'] == {'total': 3, 'new': 3, 'already_present': 0}
    assert [(c['index'], c['action'], c['category']) for c in envelope['result']['changes']] == [
        (1, 'apply', 'modified'), (2, 'apply', 'removed'), (3, 'apply', 'added')]
    assert envelope['result']['revision']['after'] == envelope['result']['revision']['before'] + 3
    assert tree(copy) == before and manual(copy) == []
    text = run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json', '--dry-run')[1]
    assert 'Dry run' in text and 'nothing was written' in text and ESC not in text and tree(copy) == before


def test_a_different_name_at_the_same_address_is_a_warning_not_a_refusal(project, copy, tmp_path, capsys):
    corrected(project, THREE[:1])
    export(capsys, project, tmp_path / 'a.json')
    rewrite(tmp_path / 'a.json', lambda d: d['corrections'][0]['older'][0].update(name='FUN_180001000', id=None))
    code, envelope, _ = result(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')
    assert code == 0 and len(envelope['warnings']) == 1 and 'FUN_180001000' in envelope['warnings'][0]
    assert manual(copy) == manual(project)


# --- import: refusals leave the project unchanged --------------------------------------------------------------------

def refused(capsys, target: Path, document: Path, code_name: str) -> str:
    before = tree(target)
    code, envelope, err = result(capsys, 'corrections', 'import', target, document)
    assert code == 2 and envelope['status'] == 'failed' and envelope['result'] is None, err
    assert code_name in err and code_name in envelope['error']
    assert tree(target) == before and manual(target) == []
    return err


def test_a_document_of_another_pair_is_refused(project, copy, tmp_path, capsys):
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    rewrite(tmp_path / 'a.json', lambda d: d['pair'].update(newer_sha256='0' * 64))
    refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-PAIR')


def test_a_document_in_the_swapped_orientation_is_refused_and_says_so(project, copy, tmp_path, capsys):
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    with ProjectService.open(copy) as service:
        service.swap_orientation()
    err = refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-ORIENTATION')
    assert 'other way round' in err and 'never mirrored' in err


@pytest.mark.parametrize('change', [
    lambda m: m.update(address='180009990'), lambda m: m.pop('address'), lambda m: m.update(address='not hex'),
], ids=['no-function-at-address', 'no-address', 'unreadable-address'])
def test_an_unresolved_member_refuses_the_whole_document(project, copy, tmp_path, capsys, change):
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    rewrite(tmp_path / 'a.json', lambda d: change(d['corrections'][2]['newer'][0]))
    err = refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-MEMBER')
    assert 'correction 3' in err and 'newer' in err


def test_three_valid_corrections_and_an_invalid_fourth_apply_none(project, copy, tmp_path, capsys):
    corrected(project)
    document = export(capsys, project, tmp_path / 'a.json')
    older = next(f for m in state(project).matches for f in m.older if f.name == 'debug_dump')
    newer = next(f for m in state(project).matches for f in m.newer if f.name == 'report_invalid_index')
    # Every member resolves, so only the service can refuse it: a split needs several newer functions.
    fourth = {'category': 'split', 'note': 'not a split', 'older': [{'address': older.address, 'name': older.name}],
              'newer': [{'address': newer.address, 'name': newer.name}]}
    rewrite(tmp_path / 'a.json', lambda d: d['corrections'].append(fourth))
    assert len(document['corrections']) == 3
    err = refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-INVALID')
    assert 'correction 4' in err and 'split requires one older and multiple newer' in err
    assert state(copy).revision == 1 and not any(a.kind == 'match-override' for a in state(copy).annotations)


def test_a_function_named_by_two_corrections_is_refused(project, copy, tmp_path, capsys):
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    rewrite(tmp_path / 'a.json', lambda d: d['corrections'][1]['older'].append(d['corrections'][0]['older'][0]))
    refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-DUPLICATE')


def test_an_existing_different_correction_is_never_overwritten(project, copy, tmp_path, capsys):
    corrected(project, THREE[:1])
    export(capsys, project, tmp_path / 'a.json')
    correct(copy, ['read_item'], ['read_item'], 'unchanged', 'the analyst of the copy disagrees')
    before, kept = tree(copy), manual(copy)
    code, _out, err = run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')
    assert code == 2 and 'PT-CORR-CONFLICT' in err and tree(copy) == before and manual(copy) == kept


@pytest.mark.parametrize('change', [
    lambda d: d.update(contract='corrections-exchange/2'), lambda d: d.update(exported='2026-11-11'),
    lambda d: d['corrections'][0].update(category='renamed'), lambda d: d['corrections'][0].update(note='  '),
    lambda d: d['corrections'][0].update(note='x' * 32768), lambda d: d['pair'].update(older_sha256='ABC'),
    lambda d: d['corrections'][0].update(older=[], newer=[]),
    lambda d: d.update(review={'matches': [], 'findings': [], 'notes': []}),
], ids=['other-contract', 'unknown-field', 'category-outside-the-model', 'blank-note', 'note-too-long', 'bad-sha256',
        'no-member', 'unknown-review-field'])
def test_a_document_outside_the_contract_is_refused(project, copy, tmp_path, capsys, change):
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    rewrite(tmp_path / 'a.json', change)
    refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-CONTRACT')


@pytest.mark.parametrize('text', [
    '{"contract": "corrections-exchange/1", "contract": "corrections-exchange/1"}',
    '[' * 200 + ']' * 200, '{"contract": NaN}', '{"contract": 1e999}', '{} {}', '{"a": "\\ud800"}', '',
    b'\xff\xfe{}', b'\xef\xbb\xbf{}',
], ids=['duplicate-key', 'deep-nesting', 'nan', 'overflowing-number', 'trailing-data', 'lone-surrogate', 'empty',
        'not-utf-8', 'byte-order-mark'])
def test_input_that_is_not_strict_json_is_refused_with_exit_2(copy, tmp_path, capsys, text):
    path = tmp_path / 'bad.json'
    path.write_bytes(text if isinstance(text, bytes) else text.encode('utf-8'))
    refused(capsys, copy, path, 'PT-CORR-JSON')


def test_a_document_over_the_size_cap_or_not_a_file_is_refused(copy, tmp_path, capsys, monkeypatch):
    from patchtrace import corrections_exchange
    assert corrections_exchange.MAX_DOCUMENT_BYTES == 16 * 1024 * 1024
    monkeypatch.setattr(corrections_exchange, 'MAX_DOCUMENT_BYTES', 64)
    (tmp_path / 'big.json').write_text('{"contract": "corrections-exchange/1", "padding": "' + 'x' * 64 + '"}',
                                       encoding='utf-8')
    assert '64 bytes' in refused(capsys, copy, tmp_path / 'big.json', 'PT-CORR-JSON')
    refused(capsys, copy, tmp_path, 'PT-CORR-JSON')
    refused(capsys, copy, tmp_path / 'absent.json', 'PT-CORR-JSON')


def test_a_review_entry_that_names_no_relation_or_finding_is_refused(project, copy, tmp_path, capsys):
    reviewed(project)
    export(capsys, project, tmp_path / 'a.json', '--include-review')
    rewrite(tmp_path / 'a.json', lambda d: d['review']['findings'][0].update(digest='0' * 64))
    assert 'finding' in refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-REVIEW')
    export(capsys, project, tmp_path / 'b.json', '--include-review')
    rewrite(tmp_path / 'b.json', lambda d: d['review']['matches'][1].update(newer=d['corrections'][2]['newer']))
    assert 'relation' in refused(capsys, copy, tmp_path / 'b.json', 'PT-CORR-REVIEW')


def test_a_failed_commit_keeps_the_prior_snapshot(project, copy, tmp_path, capsys, monkeypatch):
    from patchtrace.persistence import ProjectStore
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    before = tree(copy)

    def fail(self, candidate):
        raise ValueError('PT-STORAGE: project save failed; prior snapshot retained')
    monkeypatch.setattr(ProjectStore, 'save', fail)
    code, _out, err = run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')
    monkeypatch.undo()
    assert code == 3 and 'prior snapshot retained' in err and tree(copy) == before and manual(copy) == []


def test_a_cancelled_import_writes_nothing(project, copy, tmp_path, capsys):
    from patchtrace import corrections_cli
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    before, cancel = tree(copy), threading.Event()
    cancel.set()
    args = Namespace(action='import', project=copy, file=tmp_path / 'a.json', dry_run=False, json=True)
    assert corrections_cli.run(args, cancel) == 5
    assert json.loads(capsys.readouterr().out)['status'] == 'cancelled' and tree(copy) == before


def test_a_locked_project_is_a_clean_refusal(project, tmp_path, capsys):
    with ProjectService.open(project):
        for leaf in (['list', project], ['undo', project], ['export', project, '--out', tmp_path / 'c.json']):
            code, _out, err = run(capsys, 'corrections', *leaf)
            assert code == 3 and 'PT-STORAGE: project is locked' in err and 'Traceback' not in err
    assert not (tmp_path / 'c.json').exists()


def test_cancellation_between_two_corrections_stops_before_anything_is_stored(project, copy, tmp_path, capsys):
    from patchtrace import corrections_exchange as exchange
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    document, before = exchange.read_document(tmp_path / 'a.json'), tree(copy)
    with ProjectService.open(copy, maintenance=False) as service:
        answers = iter([False, False, True])  # before the first correction, at the first, at the second
        with pytest.raises(exchange.Cancelled):
            exchange.plan_import(service, document, lambda: next(answers))
        assert not any(m.manual for m in service.project.matches)
    assert tree(copy) == before


def test_a_member_without_an_address_is_exported_with_a_warning_and_never_imported(project, copy, tmp_path, capsys):
    with ProjectService.open(project) as service:
        candidate = service.project.model_copy(deep=True)
        next(f for m in candidate.matches for f in m.newer if f.name == 'get_version').address = None
        service.project = candidate
        service.save()
    corrected(project, THREE[:1])
    code, envelope, err = result(capsys, 'corrections', 'export', project, '--out', tmp_path / 'a.json')
    assert code == 0 and len(envelope['warnings']) == 1 and '1 correction(s)' in envelope['warnings'][0]
    member = json.loads((tmp_path / 'a.json').read_text(encoding='utf-8'))['corrections'][0]['newer'][0]
    assert 'address' not in member and member['name'] == 'get_version'
    assert 'no usable address' in refused(capsys, copy, tmp_path / 'a.json', 'PT-CORR-MEMBER')


def twin_finding(root: Path) -> str:
    """A second finding with the same claim from the same provider: same digest, another identifier."""
    from patchtrace.models import uid
    with ProjectService.open(root) as service:
        run = service.project.interpretations[0].model_copy(deep=True)
        run.id = uid()
        for record in (run.findings[0], run.findings[0].hypothesis, *run.findings[0].alternatives):
            record.id = uid()
        service.add_interpretation(run)
        return run.findings[0].id


def test_findings_with_one_digest_are_told_apart_by_the_stored_id_or_refused(project, fresh, tmp_path, capsys):
    twin = twin_finding(project)
    target = Path(shutil.copytree(project, tmp_path / 'same-ids'))
    with ProjectService.open(project) as service:
        service.review_finding(twin, 'accepted', 'the second run is the one I checked')
    document = export(capsys, project, tmp_path / 'a.json', '--include-review')
    assert [f['id'] for f in document['review']['findings']] == [twin]
    assert run(capsys, 'corrections', 'import', target, tmp_path / 'a.json')[0] == 0
    states = {f.id: f.review for i in state(target).interpretations for f in i.findings}
    assert states[twin] == 'accepted' and sorted(states.values()) == ['accepted', 'unreviewed']
    twin_finding(fresh)  # two findings with that digest and neither has the document's id
    assert 'no single finding' in refused(capsys, fresh, tmp_path / 'a.json', 'PT-CORR-REVIEW')


def test_an_empty_document_imports_as_nothing_to_do(project, copy, tmp_path, capsys):
    assert export(capsys, project, tmp_path / 'a.json')['corrections'] == []
    before = tree(copy)
    code, out, _err = run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')
    assert code == 0 and 'holds no correction' in out and tree(copy) == before


def test_name_warnings_are_bounded(project, copy, tmp_path, capsys, monkeypatch):
    from patchtrace import corrections_exchange as exchange
    corrected(project, THREE[:1])
    export(capsys, project, tmp_path / 'a.json')
    rewrite(tmp_path / 'a.json', lambda d: [m.update(name='other') for c in d['corrections'] for m in c['older'] + c['newer']])
    monkeypatch.setattr(exchange, 'MAX_WARNINGS', 1)
    code, envelope, _ = result(capsys, 'corrections', 'import', copy, tmp_path / 'a.json', '--dry-run')
    assert code == 0 and len(envelope['warnings']) == 2 and envelope['warnings'][1].startswith('1 more functions')


# --- undo ------------------------------------------------------------------------------------------------------------

def relations(root: Path) -> list[dict]:
    return sorted((m.model_dump(mode='json') for m in state(root).matches), key=lambda m: m['id'])


def test_undo_restores_the_relations_the_latest_correction_replaced(project, capsys):
    original = relations(project)
    corrected(project, THREE[:1])
    after_first = relations(project)
    corrected(project, THREE[1:2])
    assert relations(project) != after_first
    latest = next(a.id for a in state(project).annotations if a.kind == 'match-override' and not a.stale)
    code, envelope, _ = result(capsys, 'corrections', 'undo', project)
    assert code == 0 and envelope['command'] == 'corrections undo' and envelope['status'] == 'complete'
    assert envelope['result']['annotation_id'] == latest and envelope['result']['restored_relations'] == 1
    assert envelope['result']['revision'] == {'before': 3, 'after': 4}
    assert relations(project) == after_first and relations(project) != original  # only the latest one was undone
    before = tree(project)
    code, envelope, _ = result(capsys, 'corrections', 'undo', project)  # the service keeps one level of undo
    assert code == 4 and envelope['status'] == 'complete' and tree(project) == before
    assert 'superseded' in run(capsys, 'corrections', 'undo', project)[1]


def test_undo_of_a_single_correction_gives_back_the_original_relations(project, capsys):
    original = relations(project)
    corrected(project, THREE[:1])
    assert run(capsys, 'corrections', 'undo', project)[0] == 0
    assert relations(project) == original and manual(project) == []


def test_undo_of_a_named_annotation_goes_through_the_service_rule(project, capsys):
    corrected(project, THREE[:2])
    stale, active = [a.id for a in state(project).annotations if a.kind == 'match-override']
    before = tree(project)
    for annotation in (stale, 'no-such-annotation'):
        code, _out, err = run(capsys, 'corrections', 'undo', project, '--annotation', annotation)
        assert code == 2 and 'only an active override can be restored' in err and tree(project) == before
    code, envelope, _ = result(capsys, 'corrections', 'undo', project, '--annotation', active)
    assert code == 0 and envelope['result']['annotation_id'] == active


def test_an_import_can_be_undone_one_step_like_the_desktop(project, copy, tmp_path, capsys):
    corrected(project)
    export(capsys, project, tmp_path / 'a.json')
    assert run(capsys, 'corrections', 'import', copy, tmp_path / 'a.json')[0] == 0
    assert run(capsys, 'corrections', 'undo', copy)[0] == 0
    assert manual(copy) == manual(project)[:2]


# --- usage and schema ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('argv', [['corrections'], ['corrections', 'export', 'p'], ['corrections', 'import', 'p'],
                                  ['corrections', 'frobnicate', 'p']],
                         ids=['no-leaf', 'export-without-out', 'import-without-file', 'unknown-leaf'])
def test_usage_errors_exit_2(capsys, argv):
    code, out, err = run(capsys, *argv, '--json')
    assert code == 2 and err.startswith('error: patchtrace corrections') and json.loads(out)['status'] == 'failed'


def test_a_missing_project_exits_2_for_every_leaf(tmp_path, capsys):
    for leaf in (['list'], ['undo'], ['export', '--out', tmp_path / 'c.json'], ['import', tmp_path / 'c.json']):
        code, _out, err = run(capsys, 'corrections', leaf[0], tmp_path / 'absent', *leaf[1:])
        assert code == 2 and 'PT-STORAGE' in err, leaf


def generator():
    spec = importlib.util.spec_from_file_location('generate_corrections_schemas',
                                                  ROOT / 'tools' / 'generate_corrections_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_schema_equals_a_fresh_regeneration():
    gen = generator()
    rendered = gen.render()
    assert [path.name for path in rendered] == ['CorrectionsExchange.json']
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'
    assert {p.name for p in gen.OUT.iterdir()} == {p.name for p in rendered}


def test_the_status_vocabularies_are_read_from_the_models():
    from patchtrace import corrections_exchange as exchange
    from patchtrace.models import Finding, FunctionMatch
    schema = exchange.CorrectionsExchange.model_json_schema()['$defs']
    assert tuple(schema['Correction']['properties']['category']['enum']) == get_args(FunctionMatch.model_fields['category'].annotation)
    assert tuple(schema['ReviewedMatch']['properties']['status']['enum']) == get_args(FunctionMatch.model_fields['review'].annotation)
    assert tuple(schema['ReviewedFinding']['properties']['status']['enum']) == get_args(Finding.model_fields['review'].annotation)


@pytest.mark.parametrize('kind', ['matches', 'findings'])
def test_duplicate_review_targets_refuse_without_writes(project, copy, tmp_path, capsys, kind):
    reviewed(project)
    path = tmp_path / 'review.json'
    export(capsys, project, path, '--include-review')
    rewrite(path, lambda d: d['review'][kind].append(dict(d['review'][kind][0], status='unreviewed')))
    refused(capsys, copy, path, 'PT-CORR-DUPLICATE')


def test_finding_review_does_not_transfer_to_independent_analysis(project, fresh, tmp_path, capsys):
    reviewed(project)
    path = tmp_path / 'review.json'
    export(capsys, project, path, '--include-review')
    refused(capsys, fresh, path, 'PT-CORR-REVIEW')


def test_export_publication_does_not_replace_competing_file(tmp_path, monkeypatch):
    from patchtrace.cli_commands import CliError
    from patchtrace.corrections_cli import _publish
    out = tmp_path / 'out.json'
    link = os.link

    def compete(source, destination):
        out.write_bytes(b'foreign')
        return link(source, destination)

    monkeypatch.setattr(os, 'link', compete)
    with pytest.raises(CliError, match='PT-CORR-EXISTS'):
        _publish(out, b'ours')
    assert out.read_bytes() == b'foreign'
    assert sorted(p.name for p in tmp_path.iterdir()) == ['out.json']


@pytest.mark.parametrize('phase', ['stale', 'cancelled', 'postcommit'])
def test_import_commit_boundary(project, copy, monkeypatch, phase):
    from patchtrace import corrections_exchange as exchange
    from patchtrace.corrections_cli import open_project
    corrected(project)
    document = exchange.build_document(state(project))
    with open_project(copy) as service:
        plan = exchange.plan_import(service, document)
        if phase == 'stale':
            service.review_match(service.project.matches[0].id, 'accepted')
            before = tree(copy)
            with pytest.raises(exchange.ExchangeError, match='PT-CORR-STALE'):
                exchange.commit(service, plan)
            assert tree(copy) == before
        elif phase == 'cancelled':
            before = tree(copy)
            with pytest.raises(exchange.Cancelled):
                exchange.commit(service, plan, lambda: True)
            assert tree(copy) == before
        else:
            real_save = service.store.save

            def committed_then_interrupted(candidate):
                real_save(candidate)
                raise KeyboardInterrupt

            monkeypatch.setattr(service.store, 'save', committed_then_interrupted)
            with pytest.raises(KeyboardInterrupt):
                exchange.commit(service, plan)
            assert service.project == service.store.load(recover_interrupted=False)
            assert sum(m.manual for m in service.project.matches) == 3


def test_import_work_budget_and_export_byte_limit(project, copy, monkeypatch):
    from patchtrace import corrections_exchange as exchange
    from patchtrace.corrections_cli import open_project
    corrected(project)
    document = exchange.build_document(state(project))
    with open_project(copy) as service:
        before = tree(copy)
        monkeypatch.setattr(exchange, 'MAX_IMPORT_WORK_BYTES', 1)
        with pytest.raises(exchange.ExchangeError, match='PT-CORR-LIMIT'):
            exchange.plan_import(service, document)
        assert tree(copy) == before
    monkeypatch.setattr(exchange, 'MAX_DOCUMENT_BYTES', 1)
    with pytest.raises(exchange.ExchangeError, match='PT-CORR-LIMIT'):
        exchange.render(document)


def test_read_only_and_dry_run_preserve_interrupted_run(project, tmp_path, capsys):
    from patchtrace.models import AnalysisRun
    with ProjectService.open(project) as service:
        service.project.runs.append(AnalysisRun(status='running'))
        service.save()
    before = tree(project)
    out = tmp_path / 'empty.json'
    export(capsys, project, out)
    run(capsys, 'corrections', 'list', project)
    assert run(capsys, 'corrections', 'import', project, out, '--dry-run')[0] == 0
    assert tree(project) == before


def test_actual_candidate_growth_budget_is_enforced(project, copy, monkeypatch):
    from patchtrace import corrections_exchange as exchange
    from patchtrace.corrections_cli import open_project
    corrected(project)
    document = exchange.build_document(state(project))
    with open_project(copy) as service:
        before = tree(copy)
        # The cheap original-size estimate fits; retained correction history makes actual work larger.
        monkeypatch.setattr(exchange, 'MAX_IMPORT_WORK_BYTES', len(exchange._project_bytes(service.project)) * 3)
        with pytest.raises(exchange.ExchangeError, match='candidate growth'):
            exchange.plan_import(service, document)
        assert tree(copy) == before


def test_same_finding_id_with_changed_evidence_refuses(project, copy, tmp_path, capsys):
    reviewed(project)
    path = tmp_path / 'review.json'
    export(capsys, project, path, '--include-review')
    with ProjectService.open(copy) as service:
        service.project.interpretations[0].findings[0].hypothesis.explanation += ' changed evidence'
        service.save()
    refused(capsys, copy, path, 'PT-CORR-REVIEW')


@pytest.mark.parametrize('kind', ['match', 'finding'])
def test_cancellation_during_review_planning_never_commits(project, copy, monkeypatch, kind):
    from patchtrace import corrections_exchange as exchange
    from patchtrace.corrections_cli import open_project
    reviewed(project)
    document = exchange.build_document(state(project), include_review=True)
    event = threading.Event()
    name = f'review_{kind}'
    original = getattr(ProjectService, name)

    def reviewed_then_cancelled(self, *args):
        original(self, *args)
        event.set()

    monkeypatch.setattr(ProjectService, name, reviewed_then_cancelled)
    with open_project(copy) as service:
        before = tree(copy)
        with pytest.raises(exchange.Cancelled):
            plan = exchange.plan_import(service, document, event.is_set)
            exchange.commit(service, plan, event.is_set)
        assert tree(copy) == before
