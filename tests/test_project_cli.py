"""`patchtrace project` (docs/specs/cli-project-compare.md section 3): the headless project lifecycle.

Every test drives `patchtrace.cli.main` in process, except one subprocess smoke through `python -m patchtrace`.
Inputs are the synthetic PE fixture; nothing here runs an engine. Evidence class: synthetic, never live.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.cli_commands import discover
from patchtrace.models import AnalysisRun
from patchtrace.persistence import ProjectLock, ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

SRC = Path(cli.__file__).resolve().parents[1]
ENVELOPE = {'command', 'contract', 'result', 'status', 'warnings'}
LOCK = '.patchtrace.lock'  # every opener rewrites its holder record there; it is not project content


def run(args, capsys):
    code = cli.main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def jrun(args, capsys):
    code, out, err = run([*args, '--json'], capsys)
    assert out.count('\n') == 1 and out.endswith('\n'), out  # exactly one document
    doc = json.loads(out)
    assert doc['contract'] == 'enrichment-cli/1' and ENVELOPE <= set(doc)
    return code, doc, err


def tree(root: Path) -> dict[str, str]:
    """Every file and directory below `root` with its content hash, the lock file excepted."""
    listing = {}
    for path in sorted(root.rglob('*')):
        if path.name == LOCK:
            continue
        key = path.relative_to(root).as_posix()
        listing[key] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else 'dir'
    return listing


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def func(name, address, code):
    return {'name': name, 'fullname': name, 'address': f'{address:x}', 'code': code, 'calling': [], 'called': [],
            'sig': f'int {name}(void)'}


def ghidriff_json(older: str, newer: str) -> dict:
    """A Ghidriff-shaped result for the pair with these input hashes: one modified, one added function."""
    return {'old_meta': {'SHA256': older}, 'new_meta': {'SHA256': newer},
            'functions': {'added': [func('guard', 0x2000, 'int guard(void) { return 0; }')], 'deleted': [],
                          'modified': [{'old': func('f', 0x1000, 'int f(void) { return 1; }'),
                                        'new': func('f', 0x1010, 'int f(void) { if (x) return 2; return 1; }'),
                                        'diff': '', 'diff_type': ['code'], 'ratio': 0.75,
                                        'match_types': ['SymbolsHash']}]}}


@pytest.fixture
def inputs(tmp_path):
    folder = tmp_path / 'in'
    folder.mkdir()
    paths = []
    for index, name in enumerate(('old.dll', 'new.dll')):
        path = folder / name
        path.write_bytes(synthetic_pe(index))
        paths.append(path)
    return paths


@pytest.fixture
def project(inputs, tmp_path, capsys):
    root = tmp_path / 'proj'
    code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--name', 'pair',
                         '--project', root], capsys)
    assert code == 0, doc
    return root


@pytest.fixture
def result_file(inputs, tmp_path):
    path = tmp_path / 'result.ghidriff.json'
    path.write_text(json.dumps(ghidriff_json(sha(inputs[0]), sha(inputs[1]))), encoding='utf-8')
    return path


@pytest.fixture
def sample(tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    root = service.root
    service.close()
    return root


# --- registration -------------------------------------------------------------------------------------------

def test_the_verb_is_discovered_and_every_leaf_has_help(capsys):
    verbs, failed = discover()
    assert 'project' in verbs and 'project' not in failed
    for leaf in ('create', 'info', 'runs', 'import-json', 'backup', 'swap', 'sample'):
        code, out, err = run(['project', leaf, '--help'], capsys)
        assert code == 0 and f'usage: patchtrace project {leaf}' in out and err == ''


def test_a_missing_leaf_or_unknown_flag_is_a_usage_error(capsys):
    assert run(['project'], capsys)[0] == 2
    code, doc, err = jrun(['project', 'info', '--no-such-flag', 'x'], capsys)
    assert code == 2 and doc['status'] == 'failed' and 'Traceback' not in err


# --- create -------------------------------------------------------------------------------------------------

def test_create_reports_both_hashes_sizes_and_the_project_id(inputs, tmp_path, capsys):
    before = [path.read_bytes() for path in inputs]
    root = tmp_path / 'proj'
    code, doc, err = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--name', 'my pair',
                           '--project', root], capsys)
    assert code == 0 and err == ''
    assert set(doc) == ENVELOPE and doc['command'] == 'project create' and doc['status'] == 'complete'
    result = doc['result']
    assert result['artifacts'] == [
        {'side': 'older', 'name': 'old.dll', 'size': 1024, 'sha256': sha(inputs[0])},
        {'side': 'newer', 'name': 'new.dll', 'size': 1024, 'sha256': sha(inputs[1])}]
    assert result['name'] == 'my pair' and result['identical'] is False and result['revision'] == 0
    assert Path(result['project']) == root.resolve()
    with ProjectService.open(root) as service:
        assert service.project.id == result['project_id'] and service.project.runs == []
    assert [path.read_bytes() for path in inputs] == before  # inputs are never modified
    assert (root / 'artifacts' / f'{sha(inputs[0])}.bin').read_bytes() == before[0]


def test_create_text_names_each_side_and_says_nothing_was_executed(inputs, tmp_path, capsys):
    root = tmp_path / 'proj'
    code, out, err = run(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root], capsys)
    assert code == 0 and err == ''
    lines = out.splitlines()
    assert lines[0] == f'older: old.dll {sha(inputs[0])} (1024 bytes)'
    assert lines[1] == f'newer: new.dll {sha(inputs[1])} (1024 bytes)'
    assert lines[2].startswith(f'project: {root.resolve()} (id ') and 'not executed or modified' in lines[-1]
    with ProjectService.open(root) as service:
        assert service.project.name == 'Untitled comparison'  # the service default when --name is absent


def test_create_refuses_a_directory_that_holds_a_project_with_the_acquire_wording(project, inputs, capsys):
    before = tree(project)
    code, doc, err = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', project],
                          capsys)
    assert code == 2 and doc['command'] == 'project create' and doc['result'] is None
    assert doc['error'] == 'project directory already contains a project'  # as `acquire fetch --project`
    assert tree(project) == before and 'Traceback' not in err


def test_create_refuses_a_directory_with_other_content(inputs, tmp_path, capsys):
    root = tmp_path / 'busy'
    root.mkdir()
    (root / 'notes.txt').write_text('mine', encoding='utf-8')
    code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root], capsys)
    assert code == 2 and doc['error'] == 'the project directory must be absent or empty'
    assert tree(root) == {'notes.txt': hashlib.sha256(b'mine').hexdigest()}


def _x86(tmp_path: Path) -> Path:
    image = bytearray(synthetic_pe(1))
    struct.pack_into('<H', image, 0x84, 0x14C)  # IMAGE_FILE_MACHINE_I386
    path = tmp_path / 'x86.dll'
    path.write_bytes(bytes(image))
    return path


def _text_file(tmp_path: Path) -> Path:
    path = tmp_path / 'readme.dll'
    path.write_bytes(b'this is not a portable executable ' * 4)
    return path


BAD_SECOND_INPUTS = {
    'not-a-pe': (_text_file, 'PT-INPUT: missing DOS MZ header'),
    'not-amd64': (_x86, 'PT-INPUT: only PE AMD64 inputs are supported'),
    'missing-file': (lambda tmp_path: tmp_path / 'absent.dll', 'PT-INPUT: cannot read or preserve input'),
}


@pytest.mark.parametrize('case', list(BAD_SECOND_INPUTS), ids=list(BAD_SECOND_INPUTS))
def test_a_refused_second_input_exits_2_and_leaves_no_partial_project(case, inputs, tmp_path, capsys):
    make, message = BAD_SECOND_INPUTS[case]
    root = tmp_path / 'proj'
    code, doc, err = jrun(['project', 'create', '--older', inputs[0], '--newer', make(tmp_path), '--project', root],
                          capsys)
    assert code == 2 and doc['error'].startswith(message) and 'Traceback' not in err
    # The service rolled back the first input's copy and the database; at most its lock inode stays (by design).
    assert not root.exists() or [p.name for p in root.rglob('*')] == [LOCK]
    code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root], capsys)
    assert code == 0, doc  # and the same directory can be used again


def test_identical_inputs_are_recorded_not_refused(inputs, tmp_path, capsys):
    root = tmp_path / 'same'
    code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[0], '--project', root], capsys)
    assert code == 0 and doc['result']['identical'] is True
    code, doc, _ = jrun(['project', 'runs', root], capsys)
    assert code == 0 and [r['status'] for r in doc['result']['runs']] == ['identical']
    assert doc['result']['latest_completed'] is None


def _missing(tmp_path: Path) -> Path:
    return tmp_path / 'absent.dll'


def _a_directory(tmp_path: Path) -> Path:
    return tmp_path / 'in'  # holds the inputs; a directory is not an input file


BAD_FIRST_INPUTS = {
    'missing-file': (_missing, 'PT-INPUT: cannot read or preserve input'),
    'not-a-pe': (_text_file, 'PT-INPUT: missing DOS MZ header'),
    'a-directory': (_a_directory, 'PT-INPUT: input must be a regular file'),
}


@pytest.mark.parametrize('case', list(BAD_FIRST_INPUTS), ids=list(BAD_FIRST_INPUTS))
def test_a_refused_first_input_exits_2_and_leaves_no_partial_project(case, inputs, tmp_path, capsys):
    make, message = BAD_FIRST_INPUTS[case]
    root = tmp_path / 'proj'
    code, doc, err = jrun(['project', 'create', '--older', make(tmp_path), '--newer', inputs[1], '--project', root],
                          capsys)
    assert code == 2 and doc['command'] == 'project create' and doc['status'] == 'failed'
    assert doc['error'].startswith(message) and 'Traceback' not in err
    assert not root.exists() or [p.name for p in root.rglob('*')] == [LOCK]
    code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root], capsys)
    assert code == 0, doc  # the same directory can be used again


def test_an_unreadable_input_exits_2_and_names_the_input(inputs, tmp_path, capsys, monkeypatch):
    """A permission failure on an input is the analyst's to correct: exit 2, never a traceback. The fault is injected
    where the input is first read (`file_fingerprint`) because root reads any file whatever its mode bits."""
    from patchtrace import ingestion
    real = ingestion.file_fingerprint

    def denied(path):
        if Path(path) == inputs[0]:
            raise PermissionError(13, 'Permission denied')
        return real(path)
    monkeypatch.setattr(ingestion, 'file_fingerprint', denied)
    root = tmp_path / 'proj'
    code, doc, err = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root], capsys)
    assert code == 2 and doc['error'] == 'PT-INPUT: cannot read or preserve input: Permission denied'
    assert 'Traceback' not in err
    assert not root.exists() or [p.name for p in root.rglob('*')] == [LOCK]


@pytest.mark.skipif(sys.platform == 'win32' or getattr(os, 'geteuid', lambda: 0)() == 0,
                    reason='needs an unprivileged POSIX user: chmod cannot deny reads or writes to root')
def test_chmod_denied_input_and_parent_exit_2_on_an_unprivileged_user(inputs, tmp_path, capsys):
    parent = tmp_path / 'locked'
    parent.mkdir()
    inputs[0].chmod(0)
    parent.chmod(0o500)
    try:
        code, doc, err = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project',
                               parent / 'proj'], capsys)
        assert code == 2 and doc['error'].startswith('PT-INPUT: cannot read or preserve input')
        assert 'Traceback' not in err and [p.name for p in parent.iterdir()] == []
        inputs[0].chmod(0o644)
        code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project',
                             parent / 'proj'], capsys)
        assert code == 2 and doc['error'].startswith('PT-STORAGE: project directory cannot be created')
    finally:
        parent.chmod(0o755)
        inputs[0].chmod(0o644)


def test_a_project_directory_that_is_a_regular_file_is_refused_and_untouched(inputs, tmp_path, capsys):
    target = tmp_path / 'notes.txt'
    target.write_text('mine', encoding='utf-8')
    for project in (target, target / 'child'):  # the path itself, and a path below it
        code, doc, err = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', project],
                              capsys)
        assert code == 2 and doc['error'] == 'the project directory must be absent or empty'
        assert 'Traceback' not in err
    assert target.read_text(encoding='utf-8') == 'mine'


# --- sample -------------------------------------------------------------------------------------------------

def test_sample_creates_the_synthetic_project(tmp_path, capsys):
    root = tmp_path / 'demo'
    code, doc, _ = jrun(['project', 'sample', '--project', root], capsys)
    assert code == 0 and doc['command'] == 'project sample'
    result = doc['result']
    assert result['sample'] is True and result['matches']['total'] == 4 and result['run_id']
    with ProjectService.open(root) as service:
        assert service.project.sample and service.project.runs[-1].id == result['run_id']
    code, doc, _ = jrun(['project', 'sample', '--project', root], capsys)
    assert code == 2 and doc['error'] == 'project directory already contains a project'


# --- info ---------------------------------------------------------------------------------------------------

def test_info_summarises_the_project_without_writing(sample, capsys):
    before = tree(sample)
    code, doc, err = jrun(['project', 'info', sample], capsys)
    assert code == 0 and err == '' and doc['command'] == 'project info' and doc['status'] == 'complete'
    result = doc['result']
    with ProjectService.open(sample, maintenance=False) as service:
        stored = service.project
    assert result['project'] == {'id': stored.id, 'name': 'Synthetic bounds-check walkthrough',
                                 'created': stored.created, 'revision': stored.revision, 'schema_version': 1,
                                 'database_version': 1, 'sample': True}
    assert [(a['side'], a['name'], a['size'], a['format'], a['architecture']) for a in result['artifacts']] == [
        ('older', 'older_sample.dll', 1024, 'PE', 'x86-64'), ('newer', 'newer_sample.dll', 1024, 'PE', 'x86-64')]
    assert result['orientation'] == {a['side']: a['sha256'] for a in result['artifacts']}
    assert result['runs'] == {'total': 1, 'latest_completed': stored.runs[0].id, 'by_status': {
        'queued': 0, 'running': 0, 'completed': 1, 'failed': 0, 'cancelled': 0, 'identical': 0}}
    assert result['matches'] == {'total': 4, 'manual': 0, 'by_category': {
        'modified': 2, 'added': 1, 'removed': 1, 'unmatched': 0, 'ambiguous': 0, 'split': 0, 'merged': 0,
        'unchanged': 0}, 'by_review': {'unreviewed': 4, 'accepted': 0, 'rejected': 0, 'needs-review': 0}}
    assert result['findings'] == {'total': 1, 'interpretations': 1, 'stale': 0, 'by_review': {
        'unreviewed': 1, 'accepted': 0, 'rejected': 0, 'needs-review': 0}}
    assert result['annotations'] == {'note': {'total': 1, 'stale': 0}, 'bookmark': {'total': 0, 'stale': 0},
                                     'match-override': {'total': 0, 'stale': 0},
                                     'validation': {'total': 0, 'stale': 0}}
    assert result['derived'] == {}
    assert tree(sample) == before


def test_info_text_is_a_fixed_block(sample, capsys):
    code, out, _ = run(['project', 'info', sample], capsys)
    assert code == 0
    assert [line.split(':')[0] for line in out.splitlines()] == [
        'project', 'contract', 'older', 'newer', 'runs', 'matches', 'findings', 'annotations', 'derived results']
    assert 'matches: 4 (modified 2, added 1, removed 1)' in out and 'derived results: none stored' in out


def test_info_counts_manual_corrections_and_derived_results(sample, capsys):
    assert run(['rank', sample], capsys)[0] == 0  # stores derived enrichment entries in the database
    with ProjectService.open(sample) as service:
        match = next(m for m in service.project.matches if m.category == 'modified')
        service.correct_match(match.id, [match.older[0].id], [match.newer[0].id], 'modified', 'checked by hand')
    before = tree(sample)
    code, doc, _ = jrun(['project', 'info', sample], capsys)
    result = doc['result']
    assert code == 0 and result['matches']['manual'] == 1
    assert result['annotations']['match-override'] == {'total': 1, 'stale': 0}
    assert result['annotations']['note'] == {'total': 1, 'stale': 1}  # the correction invalidated the older note
    assert result['derived']['ranking']['entries'] >= 1 and set(result['derived']['ranking']) == {'entries', 'stale'}
    assert tree(sample) == before


def test_read_only_leaves_do_not_even_repair_an_interrupted_run(project, capsys):
    """`ProjectService.open` rewrites a stored running run as failed; a reader must not."""
    with ProjectService.open(project) as service:
        service.project.runs.append(AnalysisRun(status='running'))
        service.save()
    before = tree(project)
    code, doc, _ = jrun(['project', 'info', project], capsys)
    assert code == 0 and doc['result']['runs']['by_status']['running'] == 1
    code, doc, _ = jrun(['project', 'runs', project], capsys)
    assert code == 0 and [r['status'] for r in doc['result']['runs']] == ['running']
    assert tree(project) == before


# --- runs ---------------------------------------------------------------------------------------------------

def test_runs_on_a_project_without_runs_exits_4(project, capsys):
    code, doc, _ = jrun(['project', 'runs', project], capsys)
    assert code == 4 and doc['status'] == 'complete'
    assert doc['result'] == {'runs': [], 'latest_completed': None}
    assert run(['project', 'runs', project], capsys)[1] == 'No analysis runs recorded.\n'


def test_runs_lists_every_run_newest_first(project, result_file, capsys):
    assert run(['project', 'import-json', project, result_file], capsys)[0] == 0
    with ProjectService.open(project) as service:
        completed = service.project.runs[0]
        failed = AnalysisRun(status='failed', backend_version='5.0.1', error='PT-BACKEND: Ghidra exited with code 7',
                             settings={'ghidra_version': '12.0.4', 'python_version': '3.12.0', 'timeout_seconds': 60})
        (service.root / 'runs' / f'quarantine-{failed.id}').mkdir(parents=True)
        service.record_terminal_run(failed)
        cancelled = AnalysisRun(status='cancelled', error='PT-CANCEL: analysis cancelled')
        service.record_terminal_run(cancelled)
    before = tree(project)
    code, doc, err = jrun(['project', 'runs', project], capsys)
    assert code == 0 and err == '' and doc['command'] == 'project runs'
    rows = doc['result']['runs']
    assert [(r['id'], r['status']) for r in rows] == [
        (cancelled.id, 'cancelled'), (failed.id, 'failed'), (completed.id, 'completed')]
    assert doc['result']['latest_completed'] == completed.id
    assert [r['current'] for r in rows] == [False, False, True]
    assert rows[0] | {'created': ''} == {
        'id': cancelled.id, 'status': 'cancelled', 'backend': 'ghidriff', 'backend_version': 'unknown',
        'created': '', 'tools': {}, 'error': 'PT-CANCEL: analysis cancelled', 'error_code': 'PT-CANCEL',
        'raw_path': None, 'raw_sha256': None, 'output_dir': None, 'quarantined': False, 'current': False}
    assert rows[1]['tools'] == {'ghidra_version': '12.0.4', 'python_version': '3.12.0'}
    assert (rows[1]['error_code'], rows[1]['output_dir'], rows[1]['quarantined']) == (
        'PT-BACKEND', f'runs/quarantine-{failed.id}', True)
    assert rows[2]['backend'] == 'ghidriff-import' and rows[2]['error'] is None and rows[2]['error_code'] is None
    assert rows[2]['raw_path'] == f'runs/{completed.id}/raw/result.ghidriff.json'
    assert rows[2]['raw_sha256'] == sha(result_file) and rows[2]['output_dir'] == f'runs/{completed.id}'
    assert all(r['created'] for r in rows)
    assert tree(project) == before


def test_runs_text_marks_the_current_run_and_escapes_untrusted_error_text(project, result_file, capsys):
    assert run(['project', 'import-json', project, result_file], capsys)[0] == 0
    with ProjectService.open(project) as service:
        completed = service.project.runs[0].id
        failed = AnalysisRun(status='failed', error='PT-BACKEND: \x1b[31mred‮ alert\nsecond line')
        service.record_terminal_run(failed)
    code, out, _ = run(['project', 'runs', project], capsys)
    assert code == 0
    lines = out.splitlines()
    assert lines[1].startswith(f'  {failed.id}  failed')
    assert lines[2] == '    error: PT-BACKEND: \\x1b[31mred\\u202e alert\\x0asecond line'
    assert lines[3].startswith(f'* {completed}  completed') and 'ghidriff-import' in lines[3]
    assert '\x1b' not in out and '‮' not in out


# --- import-json --------------------------------------------------------------------------------------------

def test_create_then_import_json_then_rank_end_to_end(inputs, result_file, tmp_path, capsys):
    """F-D01: two local files become an analysed, rankable project without the desktop (no engine is run)."""
    root = tmp_path / 'case'
    assert run(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root], capsys)[0] == 0
    code, doc, err = jrun(['project', 'import-json', root, result_file], capsys)
    assert code == 0 and err == '' and doc['command'] == 'project import-json' and doc['status'] == 'complete'
    result = doc['result']
    assert result['backend'] == 'ghidriff-import' and result['revision'] == 1
    assert result['matches']['total'] == 2
    assert (result['matches']['by_category']['modified'], result['matches']['by_category']['added']) == (1, 1)
    raw = root / result['raw_path']
    assert raw.read_bytes() == result_file.read_bytes() and result['raw_sha256'] == sha(result_file)
    code, doc, _ = jrun(['project', 'info', root], capsys)
    assert doc['result']['runs']['latest_completed'] == result['run_id']
    code, doc, _ = jrun(['rank', root], capsys)
    assert code == 0 and doc['status'] == 'complete'
    assert sorted(entry['function'] for entry in doc['result']['entries']) == ['f', 'guard']


def test_import_json_text_output(project, result_file, capsys):
    code, out, _ = run(['project', 'import-json', project, result_file], capsys)
    assert code == 0 and out.splitlines()[0].startswith('imported run ')
    assert 'matches: 2 (modified 1, added 1)' in out


def _other_pair(tmp_path, inputs):
    path = tmp_path / 'other.json'
    path.write_text(json.dumps(ghidriff_json(sha(inputs[0]), 'a' * 64)), encoding='utf-8')
    return path


def _malformed(tmp_path, inputs):
    path = tmp_path / 'broken.json'
    path.write_text('{"functions": ', encoding='utf-8')
    return path


def _duplicate_keys(tmp_path, inputs):
    path = tmp_path / 'dup.json'
    text = json.dumps(ghidriff_json(sha(inputs[0]), sha(inputs[1])))
    path.write_text('{"old_meta": {}, ' + text[1:], encoding='utf-8')
    return path


def _nameless_function(tmp_path, inputs):
    raw = ghidriff_json(sha(inputs[0]), sha(inputs[1]))
    raw['functions']['added'][0]['name'] = ''
    path = tmp_path / 'nameless.json'
    path.write_text(json.dumps(raw), encoding='utf-8')
    return path


BAD_RESULTS = {
    'another-pair': (_other_pair, 'PT-SCHEMA: newer diff input hash does not match this project'),
    'malformed-json': (_malformed, 'PT-SCHEMA: analysis output is unreadable or malformed UTF-8 JSON'),
    'duplicate-keys': (_duplicate_keys, 'PT-SCHEMA: duplicate JSON key old_meta'),
    'nameless-function': (_nameless_function, 'PT-SCHEMA: enhanced function requires a nonempty name'),
    'missing-file': (lambda tmp_path, inputs: tmp_path / 'absent.json',
                     'PT-SCHEMA: analysis output is unreadable or malformed UTF-8 JSON'),
}


@pytest.mark.parametrize('case', list(BAD_RESULTS), ids=list(BAD_RESULTS))
def test_a_refused_import_exits_2_and_leaves_the_project_unchanged(case, project, inputs, tmp_path, capsys):
    make, message = BAD_RESULTS[case]
    before = tree(project)
    code, doc, err = jrun(['project', 'import-json', project, make(tmp_path, inputs)], capsys)
    assert code == 2 and doc['command'] == 'project import-json' and doc['error'] == message
    assert 'Traceback' not in err and tree(project) == before


def test_a_storage_failure_during_import_exits_3_and_discards_the_staged_copy(project, result_file, capsys,
                                                                             monkeypatch):
    def refuse(self, prepared):
        raise ValueError('PT-STORAGE: project save failed; prior snapshot retained')
    monkeypatch.setattr(ProjectService, 'apply_import', refuse)
    before = tree(project)
    code, doc, _ = jrun(['project', 'import-json', project, result_file], capsys)
    assert code == 3 and doc['error'] == 'PT-STORAGE: project save failed; prior snapshot retained'
    assert tree(project) == before  # the raw copy staged by prepare_import is gone again


# --- backup -------------------------------------------------------------------------------------------------

def test_backup_writes_a_verified_copy(sample, tmp_path, capsys):
    out = tmp_path / 'backups' / 'copy-1'
    code, doc, err = jrun(['project', 'backup', sample, '--out', out], capsys)
    assert code == 0 and err == '' and doc['command'] == 'project backup'
    result = doc['result']
    assert Path(result['backup']) == out.resolve() and result['verified'] is True
    with ProjectService.open(sample, maintenance=False) as source, ProjectService.open(out) as copy:
        assert copy.project == source.project
        assert (result['project_id'], result['revision']) == (source.project.id, source.project.revision)
    files, copied = tree(sample), tree(out)
    assert set(copied) == set(files)  # SQLite's online backup is not byte-identical; the snapshot equality is above
    assert {k: v for k, v in copied.items() if k != 'project.sqlite3'} == {
        k: v for k, v in files.items() if k != 'project.sqlite3'}
    code, text, _ = run(['project', 'backup', sample, '--out', tmp_path / 'copy-2'], capsys)
    assert code == 0 and 'verified' in text and str((tmp_path / 'copy-2').resolve()) in text


def test_backup_never_overwrites_and_never_writes_into_the_project(sample, tmp_path, capsys):
    existing = tmp_path / 'existing'
    existing.mkdir()
    before = tree(sample)
    for destination in (existing, sample / 'inside'):
        code, doc, _ = jrun(['project', 'backup', sample, '--out', destination], capsys)
        assert code == 2 and doc['error'] == 'PT-STORAGE: backup destination must be new and outside project'
    assert tree(sample) == before and list(existing.iterdir()) == []


def test_a_backup_that_does_not_verify_exits_3_and_names_the_copy(sample, tmp_path, capsys, monkeypatch):
    real = ProjectStore.backup

    def damaged(self, destination):
        path = real(self, destination)
        artifact = next((path / 'artifacts').glob('*.bin'))
        artifact.chmod(0o644)
        artifact.write_bytes(artifact.read_bytes()[:-1] + b'\x01')
        return path
    monkeypatch.setattr(ProjectStore, 'backup', damaged)
    out = tmp_path / 'bad-copy'
    code, doc, err = jrun(['project', 'backup', sample, '--out', out], capsys)
    assert code == 3 and 'PT-STORAGE: backup did not verify' in doc['error'] and str(out.resolve()) in doc['error']
    assert out.is_dir() and 'Traceback' not in err  # kept for inspection, never reported as verified


# --- swap ---------------------------------------------------------------------------------------------------

def test_swap_without_confirm_exits_2_explains_and_changes_nothing(sample, capsys):
    before = tree(sample)
    code, doc, err = jrun(['project', 'swap', sample], capsys)
    assert code == 2 and doc['command'] == 'project swap' and doc['error'].startswith('PT-CLI-CONFIRM: ')
    for phrase in ('older and the newer artifact exchange sides', 'revision', 'stale', '--confirm'):
        assert phrase in doc['error']
    assert tree(sample) == before and 'Traceback' not in err


def test_swap_with_confirm_exchanges_the_sides_and_reports_what_went_stale(sample, capsys):
    with ProjectService.open(sample, maintenance=False) as service:
        was = service.project.model_copy(deep=True)
    code, doc, _ = jrun(['project', 'swap', sample, '--confirm'], capsys)
    assert code == 0 and doc['command'] == 'project swap'
    result = doc['result']
    sides = {a.side: a.sha256 for a in was.artifacts}
    assert [(a['side'], a['sha256']) for a in result['artifacts']] == [
        ('older', sides['newer']), ('newer', sides['older'])]
    assert result['revision'] == was.revision + 1 and result['matches']['total'] == 4
    assert result['invalidated'] == {'interpretations': 1, 'findings': 1, 'annotations': 1}
    with ProjectService.open(sample, maintenance=False) as service:
        now = service.project
    assert sorted(m.category for m in now.matches) == sorted(m.category for m in was.matches)
    assert {m.id: m.category for m in now.matches} != {m.id: m.category for m in was.matches}  # added <-> removed
    assert all(a.stale for a in now.annotations) and now.runs == was.runs
    code, out, _ = run(['project', 'swap', sample, '--confirm'], capsys)
    assert code == 0 and 'older and newer exchanged' in out


# --- failures that are not the analyst's input --------------------------------------------------------------

def _leaves(root: Path, tmp_path: Path, result: Path) -> dict[str, list]:
    return {'info': ['project', 'info', root], 'runs': ['project', 'runs', root],
            'import-json': ['project', 'import-json', root, result],
            'backup': ['project', 'backup', root, '--out', tmp_path / 'never-written'],
            'swap': ['project', 'swap', root, '--confirm']}


LEAVES = ('info', 'runs', 'import-json', 'backup', 'swap')


@pytest.mark.parametrize('leaf', LEAVES, ids=list(LEAVES))
def test_a_project_held_open_elsewhere_exits_3_and_names_the_lock(leaf, project, result_file, tmp_path, capsys):
    before = tree(project)
    holder = ProjectService.open(project)  # stands in for the desktop: the same exclusive lock
    try:
        code, doc, err = jrun(_leaves(project, tmp_path, result_file)[leaf], capsys)
    finally:
        holder.close()
    assert code == 3 and doc['command'] == f'project {leaf}' and doc['status'] == 'failed'
    assert doc['error'].startswith('PT-STORAGE: project is locked by another writer or lock is inaccessible')
    assert LOCK in doc['error'] and 'Traceback' not in err
    assert tree(project) == before and not (tmp_path / 'never-written').exists()


def test_create_into_a_directory_locked_by_another_process_exits_3(inputs, tmp_path, capsys):
    root = tmp_path / 'held'
    root.mkdir()
    holder = ProjectLock(root)
    try:
        code, doc, _ = jrun(['project', 'create', '--older', inputs[0], '--newer', inputs[1], '--project', root],
                            capsys)
    finally:
        holder.close()
    assert code == 3 and LOCK in doc['error'] and [p.name for p in root.iterdir()] == [LOCK]


@pytest.mark.parametrize('leaf', LEAVES, ids=list(LEAVES))
def test_a_path_that_is_not_a_project_exits_2(leaf, result_file, tmp_path, capsys):
    empty = tmp_path / 'empty'
    empty.mkdir()
    for root, message in ((tmp_path / 'absent', 'PT-STORAGE: project directory does not exist'),
                          (empty, 'PT-STORAGE: project database is missing')):
        code, doc, err = jrun(_leaves(root, tmp_path, result_file)[leaf], capsys)
        assert code == 2 and doc['error'] == message and 'Traceback' not in err
    assert not (tmp_path / 'never-written').exists()


@pytest.mark.parametrize('leaf', LEAVES, ids=list(LEAVES))
def test_a_project_path_that_is_a_file_exits_2_and_is_left_alone(leaf, result_file, tmp_path, capsys):
    target = tmp_path / 'notes.txt'
    target.write_text('mine', encoding='utf-8')
    code, doc, err = jrun(_leaves(target, tmp_path, result_file)[leaf], capsys)
    assert code == 2 and doc['command'] == f'project {leaf}' and doc['status'] == 'failed'
    assert doc['error'] == 'PT-STORAGE: project path is not a directory' and 'Traceback' not in err
    assert target.read_text(encoding='utf-8') == 'mine' and not (tmp_path / 'never-written').exists()


# --- import cleanliness and the installed entry point -------------------------------------------------------

def test_the_project_verb_never_imports_qt(tmp_path):
    root = tmp_path / 'demo'
    code = ('import sys\nfrom patchtrace import cli\n'
            f'codes = [cli.main(argv) for argv in (["project", "sample", "--project", {str(root)!r}],'
            f' ["project", "info", {str(root)!r}], ["project", "runs", {str(root)!r}],'
            f' ["project", "backup", {str(root)!r}, "--out", {str(tmp_path / "copy")!r}],'
            f' ["project", "swap", {str(root)!r}, "--confirm"])]\n'
            'import patchtrace.project_cli\n'
            'bad = sorted(m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui")))\n'
            'print(codes, bad, file=sys.stderr)')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, PYTHONPATH=str(SRC)))
    assert result.returncode == 0, result.stderr
    assert result.stderr.strip().splitlines()[-1] == '[0, 0, 0, 0, 0] []'


def test_the_entry_point_creates_and_reads_a_sample_project(tmp_path):
    root = tmp_path / 'smoke'
    env = dict(os.environ, PYTHONPATH=str(SRC))

    def patchtrace(*args):
        return subprocess.run([sys.executable, '-m', 'patchtrace', *map(str, args)], capture_output=True, text=True,
                              timeout=120, env=env, stdin=subprocess.DEVNULL)
    created = patchtrace('project', 'sample', '--project', root)
    assert created.returncode == 0, created.stderr
    assert f'project: {root.resolve()}' in created.stdout
    info = patchtrace('project', 'info', root, '--json')
    assert info.returncode == 0 and info.stderr == ''
    doc = json.loads(info.stdout)
    assert doc['command'] == 'project info' and doc['result']['project']['sample'] is True
    assert doc['result']['matches']['total'] == 4
