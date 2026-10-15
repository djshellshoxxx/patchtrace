"""SPEC-31 S0b CLI (07 s10, s12): `patchtrace unified run|show|explain|status` and the hidden `_worker`, through
`cli.main` over synthetic projects. Nothing here is live evidence."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest
from unified_s0_fixtures import OLD_SHA, make_project, rz, rzdiff_set

import patchtrace
from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.sample import synthetic_pe
from patchtrace.secondary.evidence_view import BANNED
from patchtrace.secondary.store import publish_engine_set
from patchtrace.service import ProjectService
from patchtrace.unified import cli as unified_cli
from patchtrace.unified import pipeline, store
from patchtrace.unified.contracts import DECISIONS, MATERIALITIES, Atom, ChangeClass, SideRef
from patchtrace.unified.exchange import ALL_SOURCES
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.pipeline import UnifiedOptions

NOTE_START = 'Unified results are experimental, derived and ordinal'


@pytest.fixture
def root(tmp_path):
    path = tmp_path / 'project'
    make_project(path).close()
    return path


@contextlib.contextmanager
def opened(path):
    service = ProjectService.open(path)
    try:
        yield service
    finally:
        service.close()


def call(capsys, *argv):
    code = cli.main([str(a) for a in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def document(out: str) -> dict:
    assert out.count('\n') == 1 and out.endswith('\n'), out  # exactly one JSON document on stdout
    return json.loads(out)


def run_json(capsys, root, *extra):
    code, out, err = call(capsys, 'unified', 'run', root, '--in-process', '--json', *extra)
    return code, document(out), err


def show_rows(capsys, root) -> list[dict]:
    return document(call(capsys, 'unified', 'show', root, '--json', '--limit', 100)[1])['result']['rows']


def first_row_id(capsys, root, name='read_item') -> str:
    return next(r['row_id'] for r in show_rows(capsys, root) if r['older'] and r['older'][0]['name'] == name)


def move_on(service, reason='moved on') -> None:
    """An analyst's correction: the project's inputs change, so a stored result is no longer current."""
    deleted = next(m for m in service.project.matches if m.category == 'removed')
    added = next(m for m in service.project.matches if m.category == 'added')
    service.correct_match(deleted.id, [deleted.older[0].id], [added.newer[0].id], 'modified', reason)


def crafted(service, edit_row):
    """A valid result whose rows were edited: written beside the real one and published through `pipeline.publish`
    (so it passes the same verification as any worker output)."""
    request = pipeline.prepare(service, UnifiedOptions(isolate=False))
    output = pipeline.execute(request)
    manifest = store.verify_result_dir(output.staged)
    rows = [edit_row(r) for r in store.read_rows(output.staged, manifest)]
    facts = list(store.read_facts(output.staged, manifest))
    staged = store.new_staging_dir(service.root, request.plan.run_id)
    store.write_result(staged, older_sha256=manifest.older_sha256, newer_sha256=manifest.newer_sha256,
                       ghidriff_run_id=manifest.ghidriff_run_id, ghidriff_raw_sha256=manifest.ghidriff_raw_sha256,
                       ir_older=None, ir_newer=None, sources=manifest.sources, manual_digest=manifest.manual_digest,
                       config_digest=manifest.config_digest, status=manifest.status, limitations=manifest.limitations,
                       rows=rows, facts=facts)
    shutil.rmtree(output.staged)
    return pipeline.publish(service, request, dataclasses.replace(output, staged=staged))


def no_project(tmp_path) -> Path:
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    ProjectService.create(older, newer, 'no run', tmp_path / 'norun').close()
    return tmp_path / 'norun'


# --- registration and contract ---------------------------------------------------------------------------------------

def test_the_command_is_registered_with_a_small_hook():
    parser = cli._parser()
    assert 'unified' in cli.COMMANDS and cli.HANDLERS['unified'] is unified_cli.dispatch
    choices = next(a for a in parser._actions if getattr(a, 'choices', None)).choices
    assert 'unified' in choices


def test_the_lists_copied_into_the_parser_match_the_contracts():
    """cli.py keeps its own copies so that building the parser stays cheap; they must not drift."""
    assert unified_cli.SOURCES == ALL_SOURCES
    assert unified_cli.DECISIONS == DECISIONS and unified_cli.MATERIALITIES == MATERIALITIES
    assert unified_cli.CLASSES == get_args(ChangeClass)
    assert unified_cli.VERBS == ('run', 'show', 'explain', 'status')


def test_cli_unified_worker_hidden_from_help(capsys):
    for argv in (['--help'], ['unified', '--help'], ['unified', 'run', '--help']):
        code = cli.main(argv)
        out = capsys.readouterr().out
        assert code == 0 and '_worker' not in out and 'usage:' in out
    assert cli.main(['unified', '_worker', '--self-check']) == 0  # hidden, not absent
    assert 'self-check ok' in capsys.readouterr().out
    assert cli.main(['unified', '_worker']) == 2 and 'usage: unified _worker' in capsys.readouterr().err


def test_help_names_the_experimental_label(capsys):
    cli.main(['unified', '--help'])
    assert 'experimental, derived, ordinal' in ' '.join(capsys.readouterr().out.split())


# --- run ----------------------------------------------------------------------------------------------------------------

def test_cli_unified_run_exit_codes(capsys, root, tmp_path, monkeypatch):
    code, doc, err = run_json(capsys, root)
    assert code == 0 and doc['status'] == 'complete' and doc['command'] == 'unified run'
    assert doc['contract'] == 'enrichment-cli/1' and doc['warnings'][0].startswith(NOTE_START)
    result = doc['result']
    assert result['stale'] is False and result['cached'] is False and result['mode'] == 's0'
    assert result['sources'] == ['ghidriff'] and result['selected_sources'] == ['bindiff', 'ghidriff', 'manual', 'rz-diff']
    assert result['counts']['decisions']['matched'] == 4 and sum(result['counts']['materiality'].values()) == 6
    assert [s['stage'] for s in result['stages']] == ['prepare', 'compute', 'verify', 'publish']
    assert 'unified: write 3/3' in err  # progress is a diagnostic: stderr only
    again = run_json(capsys, root)
    assert again[0] == 0 and again[1]['result']['cached'] is True
    assert again[1]['result']['result_id'] == result['result_id']

    # 2: nothing runnable, or invalid arguments (the failure is one JSON document with the command name)
    empty = no_project(tmp_path)
    for argv in (['unified', 'run', empty, '--in-process'], ['unified', 'run', tmp_path / 'missing', '--in-process'],
                 ['unified', 'run', root, '--sources', 'ghidriff,bogus'], ['unified', 'run', root, '--sources', ','],
                 ['unified', 'run', root, '--timeout', '5']):
        code, out, err = call(capsys, *argv, '--json')
        failure = document(out)
        assert code == 2 and 'error:' in err, (argv, err)
        assert failure['status'] == 'failed' and failure['command'] == 'unified run' and failure['result'] is None
    code, out, _ = call(capsys, 'unified', 'run', empty, '--in-process', '--json')
    assert 'no-completed-run' in document(out)['error']
    assert call(capsys, 'unified', 'run', root, '--bogus-flag')[0] == 2  # argparse: before the command is known

    # 3: a partial result (an engine set for another pair), a typed runtime failure, an unexpected exception
    with opened(root) as service:
        project = service.project
        wrong_pair = rzdiff_set([rz(0x1000, 0x1080)], older=OLD_SHA, newer=project.artifacts[1].sha256)
        guard = Guard(project.id, project.runs[-1].id, project.runs[-1].raw_sha256, wrong_pair.file_sha256)
        publish_engine_set(EnrichmentStore(service.store), guard, guard, project.revision, wrong_pair)
    code, doc, _ = run_json(capsys, root, '--refresh')  # the stored complete result has the same id: recompute
    assert code == 3 and doc['status'] == 'partial' and 'rz-diff-pair-mismatch' in doc['result']['limitations']

    def limit(*args, **kwargs):
        raise UnifiedError('PT-UNIFIED-LIMIT', 'A unified limit was reached', reason='rows-cap')
    monkeypatch.setattr(pipeline, 'run_unified', limit)
    code, out, err = call(capsys, 'unified', 'run', root, '--in-process', '--json')
    assert code == 3 and 'PT-UNIFIED-LIMIT' in err and 'rows-cap' in document(out)['error']

    def crash(*args, **kwargs):
        raise RuntimeError('unexpected')
    monkeypatch.setattr(pipeline, 'run_unified', crash)
    code, out, err = call(capsys, 'unified', 'run', root, '--in-process', '--json')
    assert code == 3 and document(out)['status'] == 'failed' and 'Traceback' not in err

    # 5: cancelled, by a typed error and by the keyboard
    def cancelled(*args, **kwargs):
        raise UnifiedError('PT-UNIFIED-CANCEL', 'Unified analysis was cancelled', reason='cancelled')
    monkeypatch.setattr(pipeline, 'run_unified', cancelled)
    code, out, _ = call(capsys, 'unified', 'run', root, '--in-process', '--json')
    assert code == 5 and document(out)['status'] == 'cancelled'

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(pipeline, 'run_unified', interrupt)
    code, out, err = call(capsys, 'unified', 'run', root, '--in-process', '--json')
    assert code == 5 and document(out)['status'] == 'cancelled' and 'cancelled' in err


def test_run_says_that_extraction_is_not_available_unless_told_not_to_extract(capsys, root):
    _, doc, _ = run_json(capsys, root)
    assert [w.startswith(('Unified results', 'extraction is not available')) for w in doc['warnings'][:2]] == [True, True]
    _, quiet, _ = run_json(capsys, root, '--no-extract', '--refresh')
    assert len(quiet['warnings']) == 1 and quiet['warnings'][0].startswith(NOTE_START)


def test_cli_unified_run_exit_code_4_when_nothing_is_material_or_under_review(capsys, root):
    """Zero rows (no source with data selected) is a legitimate empty result: `--fail-on-none` turns it into 4."""
    code, doc, _ = run_json(capsys, root, '--sources', 'manual')
    assert code == 0 and sum(doc['result']['counts']['decisions'].values()) == 0
    code, doc, _ = run_json(capsys, root, '--sources', 'manual', '--fail-on-none')
    assert code == 4 and doc['status'] == 'complete'
    code, doc, _ = run_json(capsys, root, '--fail-on-none')  # the full result has a material row
    assert code == 0


def test_cli_unified_run_with_the_real_worker_child_process(capsys, root):
    code, out, err = call(capsys, 'unified', 'run', root, '--json')
    assert code == 0, err
    assert document(out)['result']['counts']['decisions']['matched'] == 4
    with opened(root) as service:
        assert pipeline.recent_runs(service)[0].provenance['worker'] == 'child'
        assert pipeline.load_current(service, pipeline.make_plan(service)).state == 'current'


def test_cli_unified_run_text_output(capsys, root):
    code, out, err = call(capsys, 'unified', 'run', root, '--in-process')
    lines = out.splitlines()
    assert code == 0 and lines[0] == 'unified run: complete (experimental, derived, ordinal)'
    assert lines[1].startswith('result: ') and lines[2].startswith('rows: 6 (matched 4') and 'material 1' in lines[3]
    assert lines[4] == 'sources: ghidriff' and lines[5] == 'limitations: ir-not-extracted'  # the inputs that exist
    assert 'warning: ' + NOTE_START in err


# --- show -----------------------------------------------------------------------------------------------------------------

def test_cli_unified_show_json_single_document(capsys, root):
    run_json(capsys, root)
    code, out, _ = call(capsys, 'unified', 'show', root, '--json')
    doc = document(out)
    result = doc['result']
    assert code == 0 and doc['command'] == 'unified show' and doc['warnings'][0].startswith(NOTE_START)
    assert (result['total'], result['filtered'], len(result['rows'])) == (6, 6, 6)
    assert result['state'] == 'current' and result['stale'] is False and result['changed_inputs'] == []
    row = next(r for r in result['rows'] if r['older'] and r['older'][0]['name'] == 'read_item')
    assert (row['decision'], row['materiality'], row['change_classes']) == ('matched', 'material', ['call-added'])
    assert row['older'] == [{'kind': 'function', 'name': 'read_item', 'rva': 0x1000}]
    stored = {'row_id', 'decision', 'materiality', 'older', 'newer', 'change_classes', 'support', 'contest', 'hints',
              'flags'}
    added = {'function', 'addresses', 'decision_text', 'glyph', 'change_text', 'proof', 'tier', 'edit_group',
             'collapsed', 'cells'}   # S4a: what the Unified view shows, added beside the stored fields (additive)
    assert set(row) == stored | added


def test_show_filters_combine_and_totals_stay_whole(capsys, root):
    run_json(capsys, root)

    def shown(*extra):
        code, out, _ = call(capsys, 'unified', 'show', root, '--json', *extra)
        return code, document(out)['result']
    assert shown('--change', 'material')[1]['filtered'] == 1
    assert shown('--decision', 'older-only', '--decision', 'newer-only')[1]['filtered'] == 2
    assert shown('--class', 'constant', '--class', 'address-only')[1]['filtered'] == 2
    assert shown('--decision', 'matched', '--change', 'review')[1]['filtered'] == 1
    code, result = shown('--limit', '2')
    assert code == 0 and result['total'] == result['filtered'] == 6 and len(result['rows']) == 2
    code, result = shown('--decision', 'contested')
    assert code == 4 and result['filtered'] == 0 and result['rows'] == [] and result['total'] == 6
    code, out, err = call(capsys, 'unified', 'show', root, '--change', 'bogus')
    assert code == 2 and 'invalid choice' in err


def test_show_text_table(capsys, root):
    run_json(capsys, root)
    code, out, _ = call(capsys, 'unified', 'show', root, '--change', 'material')
    lines = out.splitlines()
    assert code == 0 and lines[0].startswith('unified show: result ') and '1 match, 1 shown' in lines[0]
    head = next(i for i, line in enumerate(lines) if line.startswith('ROW '))
    assert lines[head].split() == ['ROW', 'DECISION', 'CHANGE', 'FUNCTION', 'ADDRESSES', 'GHIDRIFF']
    assert lines[head + 1].split()[1:] == ['[=]', 'Matched', 'Material:', 'call-added', 'read_item', '0x1000', '>',
                                           '0x1080', 'SymbolsHash']


def test_show_before_any_run_asks_for_one(capsys, root):
    code, out, err = call(capsys, 'unified', 'show', root, '--json')
    assert code == 2 and 'unified run' in document(out)['error'] and 'no unified result yet' in err
    with opened(root) as service:
        assert not service.store.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='enrichment_entries'").fetchone()  # reading created nothing


def test_a_stale_result_is_shown_with_its_changed_inputs(capsys, root):
    run_json(capsys, root)
    with opened(root) as service:
        move_on(service)
    code, out, _ = call(capsys, 'unified', 'show', root, '--json')
    doc = document(out)
    assert code == 0 and doc['result']['stale'] is True and doc['result']['state'] == 'stale'
    assert 'manual_digest' in doc['result']['changed_inputs'] and any('stale' in w for w in doc['warnings'])
    code, doc, _ = run_json(capsys, root)  # a new run makes the current one
    assert code == 0 and doc['result']['cached'] is False
    assert document(call(capsys, 'unified', 'show', root, '--json')[1])['result']['stale'] is False


@pytest.mark.parametrize('damage', ['truncated', 'deflate'])
def test_a_damaged_stored_result_is_reported_not_a_crash(capsys, root, damage):
    run_json(capsys, root)
    with opened(root) as service:
        directory = pipeline.load_current(service, pipeline.make_plan(service)).directory
    part = directory / 'rows.jsonl.gz'
    os.chmod(part, stat.S_IWRITE | stat.S_IREAD)
    part.write_bytes(part.read_bytes()[:-9] if damage == 'truncated'
                     else b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff' + b'\xff' * 64)
    for verb, extra in (('show', []), ('explain', ['--row', 'abcdef01'])):
        code, out, err = call(capsys, 'unified', verb, root, *extra, '--json')
        assert code == 3 and 'unusable' in document(out)['error'] and 'Traceback' not in err
    code, out, _ = call(capsys, 'unified', 'status', root, '--json')
    assert code == 0 and document(out)['result']['state'] == 'invalid'
    code, doc, _ = run_json(capsys, root, '--refresh')  # a refresh repairs it
    assert code == 0 and doc['result']['cached'] is False
    assert document(call(capsys, 'unified', 'status', root, '--json')[1])['result']['state'] == 'current'


# --- explain ---------------------------------------------------------------------------------------------------------------

def test_explain_gives_atoms_facts_and_provenance(capsys, root):
    run_json(capsys, root)
    row_id = first_row_id(capsys, root)
    code, out, _ = call(capsys, 'unified', 'explain', root, '--row', row_id[:10], '--json')
    result = document(out)['result']
    assert code == 0 and result['row']['row_id'] == row_id and result['state'] == 'current'
    assert [a['source'] for a in result['row']['atoms']] == ['ghidriff']
    assert result['facts']['verdict'] == 'material' and result['facts']['second_channel'] == 'C6'
    assert result['facts']['deltas'][0]['cls'] == 'call-added'
    assert result['provenance']['sources'] == [{'source': 'ghidriff', 'version': '1'}]
    code, text, _ = call(capsys, 'unified', 'explain', root, '--row', row_id.upper())
    assert code == 0 and text.startswith(f'row {row_id[:16]}: matched, change material')
    assert 'Atoms (1):' in text and 'delta call-added' in text and 'second channel C6' in text
    assert 'K1: ghidriff SymbolsHash tier A' in text and 'classes: call-added' in text
    assert 'Provenance:' in text and f'result {result["provenance"]["result_id"]}' in text
    assert result['detail'] in text and text.endswith(result['detail'] + '\n')   # the window's own text, shared


@pytest.mark.parametrize('row, message', [('abc', 'at least 8'), ('zzzzzzzz', 'hexadecimal'), ('', 'at least 8'),
                                          ('00000000', 'no row starts with')], ids=['short', 'nonhex', 'empty', 'none'])
def test_explain_refuses_bad_row_arguments(capsys, root, row, message):
    run_json(capsys, root)
    code, out, err = call(capsys, 'unified', 'explain', root, '--row', row, '--json')
    assert code == 2 and message in err and document(out)['status'] == 'failed'


def test_explain_refuses_an_ambiguous_prefix(capsys, root, monkeypatch):
    run_json(capsys, root)
    monkeypatch.setattr(unified_cli, 'PREFIX_MIN', 0)  # an empty prefix matches every row
    code, _, err = call(capsys, 'unified', 'explain', root, '--row', '')
    assert code == 2 and '6 rows start with' in err and 'give more digits' in err


# --- status ---------------------------------------------------------------------------------------------------------------

def test_status_reports_none_current_stale_and_why(capsys, root):
    code, out, _ = call(capsys, 'unified', 'status', root, '--json')
    result = document(out)['result']
    assert code == 0 and result['state'] == 'none' and result['reason'] == 'no-result' and result['runs'] == []
    assert result['ir'] == {'available': False, 'reason': 's0-mode'} and result['planned_result_id']
    run_json(capsys, root)
    code, out, _ = call(capsys, 'unified', 'status', root, '--json')
    result = document(out)['result']
    assert result['state'] == 'current' and result['result_id'] == result['planned_result_id']
    assert result['sources'] == [{'source': 'ghidriff', 'version': '1'}] and result['status'] == 'complete'
    assert result['limitations'] == ['ir-not-extracted'] and result['changed_inputs'] == []
    assert [r['status'] for r in result['runs']] == ['ok'] and result['engine_version'] == 'ude/1'
    with opened(root) as service:
        move_on(service)
    code, out, _ = call(capsys, 'unified', 'status', root, '--json')
    result = document(out)['result']
    assert result['state'] == 'stale' and result['reason'] == 'guard-moved'
    assert result['result_id'] != result['planned_result_id']
    assert {'sources', 'manual_digest'} <= set(result['changed_inputs'])
    code, text, _ = call(capsys, 'unified', 'status', root)
    assert 'unified status: stale [guard-moved]' in text and 'inputs changed since that result:' in text


def test_status_of_a_project_that_cannot_run_still_answers(capsys, tmp_path):
    code, out, _ = call(capsys, 'unified', 'status', no_project(tmp_path), '--json')
    result = document(out)['result']
    assert code == 0 and result['state'] == 'none' and result['planned_result_id'] is None
    assert result['plan_error'] == 'no-completed-run'


# --- crafted results: unknown sources and hostile text ------------------------------------------------------------------

def test_unknown_source_id_renders_generically(capsys, root):
    """A result written by a newer engine may carry a source id this build does not know: it is shown as it is."""
    def add_atom(row):
        if not (row.older and row.newer):
            return row
        extra = Atom(source='newengine', step='future-pass', tier='B', cardinality='1:1', cls='E-NAME',
                     older_rva=row.older[0].rva, newer_rva=row.newer[0].rva)
        return row.model_copy(update={'atoms': (*row.atoms, extra)})
    with opened(root) as service:
        crafted(service, add_atom)
    row_id = first_row_id(capsys, root)
    code, text, _ = call(capsys, 'unified', 'explain', root, '--row', row_id)
    assert code == 0 and '[1] newengine future-pass tier B E-NAME 1:1 0x1000 -> 0x1080' in text
    code, out, _ = call(capsys, 'unified', 'explain', root, '--row', row_id, '--json')
    assert code == 0 and 'newengine' in {a['source'] for a in document(out)['result']['row']['atoms']}
    assert call(capsys, 'unified', 'show', root)[0] == 0


@pytest.mark.parametrize('how', ['built', 'written-raw'], ids=['built', 'raw'])
def test_hostile_names_are_plain_text_on_a_terminal(capsys, root, how):
    """S0a-FIX (02 s9.1) turns controls and bidirectional characters into U+FFFD when a name is built and when a
    stored row is read back; whether a hostile name was built by the contract or written into the file raw, the
    command never prints one."""
    hostile = 'evil\x1b[31m\u202e\u2066name\r\nnext\x00line'
    assert SideRef(rva=1, name=hostile, kind='function').name == 'evil\ufffd[31m\ufffd\ufffdname\ufffd\ufffdnext\ufffdline'
    make = SideRef if how == 'built' else SideRef.model_construct  # model_construct skips the validator

    def rename(row):
        older = tuple(make(rva=s.rva, name=hostile, kind=s.kind) for s in row.older)
        return row.model_copy(update={'older': older})
    with opened(root) as service:
        crafted(service, rename)
    forbidden = set('\x1b\u202e\u2066\r\x00')
    code, out, _ = call(capsys, 'unified', 'show', root)
    assert code == 0 and not set(out) & forbidden and 'evil\ufffd[31m' in out and 'name' in out
    code, out, _ = call(capsys, 'unified', 'show', root, '--json')
    rows = document(out)['result']['rows']
    assert all(not set(s['name'] or '') & forbidden for r in rows for s in r['older'])
    code, text, _ = call(capsys, 'unified', 'explain', root, '--row', rows[0]['row_id'])
    assert code == 0 and not set(text) & forbidden


def test_no_banned_word_in_any_text_the_command_prints(capsys, root):
    texts = []
    for argv in (['--help'], ['unified', '--help'], ['unified', 'run', '--help'], ['unified', 'show', '--help'],
                 ['unified', 'explain', '--help'], ['unified', 'status', '--help']):
        cli.main(argv)
        texts.append(capsys.readouterr().out)
    texts.append(call(capsys, 'unified', 'status', root)[1])
    _, out, err = call(capsys, 'unified', 'run', root, '--in-process')
    texts += [out, err]
    texts.append(call(capsys, 'unified', 'status', root)[1])
    texts.append(call(capsys, 'unified', 'show', root)[1])
    texts.append(call(capsys, 'unified', 'explain', root, '--row', first_row_id(capsys, root))[1])
    texts.append(call(capsys, 'unified', 'run', root, '--in-process', '--sources', 'manual')[1])
    for text in texts:
        lowered = text.lower()
        for word in BANNED:  # stems match as prefixes, the rest as whole words ('provenance' is fine)
            tail = '' if word in ('probab', 'vulnerab', 'exploit', 'likelihood') else r'\b'
            assert not re.search(r'\b' + re.escape(word) + tail, lowered), (word, text[:400])
        assert '%' not in text, text[:400]


# --- isolation of the command line -----------------------------------------------------------------------------------------

def source_env() -> dict[str, str]:
    env = dict(os.environ)
    env['PYTHONPATH'] = str(Path(patchtrace.__file__).resolve().parents[1])
    env['PYTHONUTF8'] = '1'
    return env


@pytest.mark.parametrize('argv', [['unified', '--help'], ['unified', 'run', '--help'], ['unified', 'status', 'PROJECT'],
                                  ['unified', 'show', 'PROJECT'], ['unified', 'run', 'PROJECT', '--in-process'],
                                  ['unified', '_worker', '--self-check']],
                         ids=['help', 'run-help', 'status', 'show', 'run', 'worker'])
def test_cli_unified_never_imports_qt(root, argv):
    code = ('import sys\nfrom patchtrace import cli\n'
            'rc = cli.main([a if a != "PROJECT" else sys.argv[1] for a in sys.argv[2:]])\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))]\n'
            'print("BAD", bad, file=sys.stderr)\nraise SystemExit(90 if bad else (rc or 0))\n')
    result = subprocess.run([sys.executable, '-c', code, str(root), *argv], capture_output=True, text=True,
                            env=source_env(), timeout=120)
    assert result.returncode in (0, 2), result.stderr  # 2: show before a run; Qt is the point of this test
    assert 'BAD []' in result.stderr, result.stderr


def test_the_hidden_worker_runs_as_python_dash_m_with_the_c3_recipe(tmp_path):
    from patchtrace.secondary.binexport_run import worker_argv, worker_env
    result = subprocess.run([*worker_argv(), 'unified', '_worker', '--self-check'], capture_output=True, text=True,
                            env=worker_env(), cwd=tmp_path, timeout=120)
    assert result.returncode == 0 and 'self-check ok' in result.stdout, result.stderr


# --- S4 polish: usage errors before any project access, a document on every failure, exit codes in help ----------------

@pytest.mark.parametrize('argv, message', [
    (['run', '--timeout', '59'], '--timeout'), (['run', '--timeout', '86401'], '--timeout'),
    (['run', '--timeout', 'soon'], 'invalid int'), (['show', '--limit', '-1'], '--limit'),
    (['show', '--limit', 'many'], 'invalid int'), (['run', '--python', 'py'], '--python and --ghidra-dir'),
    (['show', '--source', 'Bad_Id'], 'source id')],
    ids=['timeout-low', 'timeout-high', 'timeout-text', 'limit-negative', 'limit-text', 'python-alone', 'source-id'])
def test_usage_errors_exit_2_with_one_failed_document_before_the_project_is_opened(capsys, tmp_path, argv, message):
    missing = tmp_path / 'never-created'
    code, out, err = call(capsys, 'unified', argv[0], missing, '--json', *argv[1:])
    doc = document(out)
    assert code == 2 and doc['status'] == 'failed' and doc['result'] is None and doc['contract'] == 'enrichment-cli/1'
    assert message in doc['error'] and 'does not exist' not in doc['error'] and doc['command'] in ('unified', f'unified {argv[0]}')
    assert not missing.exists()


@pytest.mark.parametrize('verb', ['run', 'show', 'explain', 'status'])
def test_a_missing_project_is_a_failed_document_with_exit_2_in_every_verb(capsys, tmp_path, verb):
    extra = ['--row', 'abcdef01'] if verb == 'explain' else []
    code, out, _ = call(capsys, 'unified', verb, tmp_path / 'missing', '--json', *extra)
    doc = document(out)
    assert code == 2 and doc['status'] == 'failed' and doc['command'] == f'unified {verb}' and doc['error']


def test_help_documents_the_exit_codes_and_the_json_document(capsys):
    for argv in (['unified', '--help'], ['unified', 'run', '--help'], ['unified', 'show', '--help']):
        assert cli.main(argv) == 0
        text = ' '.join(capsys.readouterr().out.split())
        for fragment in ('0 ok', '2 invalid argument', '3 runtime failure or partial', '5 cancelled', 'enrichment-cli/1'):
            assert fragment in text, (argv, fragment)
    cli.main(['unified', 'show', '--help'])
    assert '4 no row listed' in ' '.join(capsys.readouterr().out.split())
    cli.main(['unified', 'run', '--help'])
    assert '4 only with --fail-on-none' in ' '.join(capsys.readouterr().out.split())


def test_cancelled_run_prints_a_cancelled_document_with_exit_5(capsys, root, monkeypatch):
    def cancelled(*_a, **_k):
        raise UnifiedError('PT-UNIFIED-CANCEL', 'cancelled')
    monkeypatch.setattr(pipeline, 'run_unified', cancelled)
    code, doc, _ = run_json(capsys, root)
    assert code == 5 and doc['status'] == 'cancelled' and doc['command'] == 'unified run'


def test_the_timeout_bounds_match_the_limits():
    from patchtrace.unified.limits import DEFAULT_LIMITS
    assert (unified_cli.TIMEOUT_MIN, unified_cli.TIMEOUT_MAX) == (DEFAULT_LIMITS.l34_timeout_min_s,
                                                                  DEFAULT_LIMITS.l34_timeout_max_s)
