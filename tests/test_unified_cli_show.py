"""SPEC-31 S4a CLI polish (07 s10): `unified show` and `unified explain` print what the Unified tab shows, through the
read model: review order, badges, per-source cells, the collapsed-rows count (U-03) and the shared section text. The
projects are synthetic (stored engine sets made up in code), so none of it is live evidence."""
from __future__ import annotations

import dataclasses
import json
import re
import shutil

import pytest
from unified_read_support import delta, make_facts
from unified_s0_fixtures import bd, bindiff_set, make_project, rz, rzdiff_set

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary.store import publish_engine_set
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline, read_model, read_text, store
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.pipeline import UnifiedOptions


def call(capsys, *argv):
    code = cli.main([str(a) for a in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def document(out: str) -> dict:
    assert out.count('\n') == 1 and out.endswith('\n'), out        # exactly one JSON document on stdout
    return json.loads(out)


def run(root):
    assert cli.main(['unified', 'run', str(root), '--in-process']) == 0


def shown(capsys, root, *extra):
    code, out, _ = call(capsys, 'unified', 'show', root, '--json', *extra)
    return code, document(out)['result']


ROW_LINE = re.compile(r'[0-9a-f]{12} ')


def table(text: str):
    """(header cells, one list of cells per row) of the text table of `unified show`."""
    lines = text.splitlines()
    head = next(i for i, line in enumerate(lines) if line.startswith('ROW '))
    return lines[head].split(), [line.split() for line in lines[head + 1:] if ROW_LINE.match(line)]


@pytest.fixture(scope='module')
def engines(tmp_path_factory):
    """A project whose stored BinDiff and rz-diff sets agree on one pair, disagree on another and add rows of their own."""
    root = tmp_path_factory.mktemp('engines') / 'project'
    make_project(root).close()
    service = ProjectService.open(root)
    try:
        sides = {a.side: a.sha256 for a in service.project.artifacts}
        project, last = service.project, service.project.runs[-1]
        for match_set in (
                bindiff_set([bd(0x1000, 0x1080, 'function: hash matching'), bd(0x1600, 0x1780, 'function: hash matching'),
                             bd(0x1900, 0x1980, 'function: name hash matching')], older=sides['older'],
                            newer=sides['newer']),
                rzdiff_set([rz(0x1000, 0x1080), rz(0x1c00, 0x1c80)], older=sides['older'], newer=sides['newer'])):
            guard = Guard(project.id, last.id, last.raw_sha256, match_set.file_sha256)
            publish_engine_set(EnrichmentStore(service.store), guard, guard, project.revision, match_set)
    finally:
        service.close()
    run(root)
    return root


@pytest.fixture(scope='module')
def collapsed(tmp_path_factory):
    """The plain project, with one row now `unchanged` (UNCH/1) and one `cosmetic` with a structural proof."""
    root = tmp_path_factory.mktemp('collapsed') / 'project'
    make_project(root).close()
    service = ProjectService.open(root)
    try:
        request = pipeline.prepare(service, UnifiedOptions(isolate=False))
        output = pipeline.execute(request)
        manifest = store.verify_result_dir(output.staged)
        rows, facts = list(store.read_rows(output.staged, manifest)), list(store.read_facts(output.staged, manifest))
        edited, replaced = [], {}
        for row in rows:
            first = row.older[0].rva if row.older else None
            if first == 0x1300:          # an unnamed pair with no stored code: now byte-identical
                row = row.model_copy(update={'materiality': 'unchanged'})
                replaced[row.row_id] = make_facts(row, 'unchanged', proof='UNCH/1')
            elif first == 0x1200:        # format_name: its COS-PSEUDO/1 verdict becomes a structural proof
                replaced[row.row_id] = make_facts(row, 'cosmetic', proof='COS-ADDR/1',
                                                  deltas=[delta('address-only', older=0x1200, newer=0x1280, new=None)])
            edited.append(row)
        kept = [replaced.pop(f.row_id, f) for f in facts] + list(replaced.values())
        staged = store.new_staging_dir(service.root, request.plan.run_id)
        store.write_result(
            staged, older_sha256=manifest.older_sha256, newer_sha256=manifest.newer_sha256,
            ghidriff_run_id=manifest.ghidriff_run_id, ghidriff_raw_sha256=manifest.ghidriff_raw_sha256, ir_older=None,
            ir_newer=None, sources=manifest.sources, manual_digest=manifest.manual_digest,
            config_digest=manifest.config_digest, status=manifest.status, limitations=manifest.limitations,
            rows=edited, facts=kept)
        shutil.rmtree(output.staged)
        pipeline.publish(service, request, dataclasses.replace(output, staged=staged))
    finally:
        service.close()
    return root


# --- show -------------------------------------------------------------------------------------------------------------


def test_show_lists_the_most_important_rows_first_with_each_source_in_its_own_column(capsys, engines):
    code, out, _ = call(capsys, 'unified', 'show', engines)
    head, rows = table(out)
    assert code == 0 and head == ['ROW', 'DECISION', 'CHANGE', 'FUNCTION', 'ADDRESSES', 'GHIDRIFF', 'BINDIFF', 'RZ-DIFF']
    assert [r[1:3] for r in rows[:3]] == [['[!]', 'Contested'], ['[=]', 'Matched'], ['[=]', 'Matched']]
    assert rows[0][3:5] == ['Review:', 'constant'] and rows[1][3:5] == ['Material:', 'call-added']
    first = out.splitlines()
    assert first[0].startswith('unified show: result ') and '9 rows, 9 match, 9 shown' in first[0]
    assert first[1] == '9 rows - 1 material - 1 review - 1 contested - 1 older-only - 2 newer-only'
    assert first[2].startswith('Unified: ude/1, run ') and 'Sources: Ghidriff 1, BinDiff 8.0, rz-diff 0.9.1' in first[2]
    assert 'Not present: Diaphora, PatchTrace ladder, PatchTrace bytes, Analyst' in first[2]
    assert out.splitlines()[-1] == 'Native values are engine-specific and never combined.'
    contested = next(line for line in out.splitlines() if '[!] Contested' in line)
    assert 'SymbolsHash' in contested and 'pairs elsewhere' in contested and 'no record' in contested
    code, result = shown(capsys, engines)
    assert [r['decision'] for r in result['rows']][:2] == ['contested', 'matched']     # the same order, as data
    by_name = {r['function']: r for r in result['rows']}
    assert [(c['source'], c['kind']) for c in by_name['get_version']['cells']] == [
        ('ghidriff', 'value'), ('bindiff', 'pairs-elsewhere'), ('rz-diff', 'no-record')]
    assert by_name['read_item']['cells'][1]['text'] == 'sim 1.0  algo hash matching'
    assert by_name['read_item']['cells'][2]['text'] == 'byte sim 0.5'
    assert [(s['source'], s['unit'], s['version']) for s in result['sources']] == [
        ('ghidriff', 'match type (raw)', '1'), ('bindiff', 'similarity / algorithm', '8.0'),
        ('rz-diff', 'byte similarity', '0.9.1')]
    assert result['counts']['rows'] == 9 and result['counts']['decision/contested'] == 1 and result['hidden'] == 0


def test_show_collapses_unchanged_and_structural_cosmetic_by_default(capsys, collapsed):
    code, result = shown(capsys, collapsed)
    assert code == 0 and (result['total'], result['filtered'], result['hidden']) == (6, 4, 2)
    assert result['evidence_classes']['E-NAME'] == 3 and result['evidence_classes']['E-BODY'] == 1   # rows per class
    assert {r['function'] for r in result['rows']} == {'read_item', 'get_version', 'debug_dump', 'report_invalid_index'}
    code, out, _ = call(capsys, 'unified', 'show', collapsed)
    assert '- 2 cosmetic/unchanged hidden' in out.splitlines()[1]
    assert '2 more rows are collapsed by default (unchanged, or cosmetic with a structural proof); ' \
           'list them with --all or --change' in out
    # one switch shows them all, and asking for a materiality always lists it
    code, result = shown(capsys, collapsed, '--all')
    assert (result['total'], result['filtered'], result['hidden']) == (6, 6, 0)
    by_name = {r['function']: r for r in result['rows']}
    assert (by_name['format_name']['collapsed'], by_name['format_name']['proof']) == (True, 'COS-ADDR/1')
    assert by_name['sub_1380']['change_text'] == 'Unchanged' and by_name['sub_1380']['collapsed'] is True
    assert by_name['format_name']['change_text'] == 'Cosmetic (proof COS-ADDR/1): address-only'
    code, out, _ = call(capsys, 'unified', 'show', collapsed, '--all')
    assert 'cosmetic/unchanged hidden' not in out and 'collapsed by default' not in out
    for change, name in (('cosmetic', 'format_name'), ('unchanged', 'sub_1380')):
        code, result = shown(capsys, collapsed, '--change', change)
        assert code == 0 and [r['function'] for r in result['rows']] == [name] and result['hidden'] == 0
    # the order puts the proven rows last
    assert [r['function'] for r in shown(capsys, collapsed, '--all')[1]['rows']][-2:] == ['format_name', 'sub_1380']


def test_show_filters_by_source_and_search(capsys, engines):
    def names(*extra):
        code, result = shown(capsys, engines, *extra)
        return code, sorted(r['function'] for r in result['rows'])
    assert names('--source', 'bindiff') == (0, ['get_version', 'read_item', 'sub_1780', 'sub_1980'])
    assert names('--source', 'rz-diff') == (0, ['read_item', 'sub_1c80'])
    assert names('--source', 'rz-diff', '--source', 'bindiff', '--decision', 'candidate') == (0, ['sub_1c80'])
    assert names('--search', '0x1c80') == (0, ['sub_1c80']) and names('--search', 'GET_VERSION') == (0, ['get_version'])
    assert names('--search', '1980', '--source', 'bindiff') == (0, ['sub_1980'])
    assert names('--source', 'diaphora') == (4, [])
    code, out, err = call(capsys, 'unified', 'show', engines, '--source', 'Bad Source')
    assert code == 2 and 'a source id is lower-case letters' in err


def test_show_limit_zero_still_gives_the_totals(capsys, engines):
    code, out, _ = call(capsys, 'unified', 'show', engines, '--limit', 0)
    assert code == 0 and '9 match, 0 shown' in out and '9 more rows match; raise --limit to list them' in out
    head, rows = table(out)
    assert rows == []
    code, result = shown(capsys, engines, '--limit', 3)
    assert code == 0 and (result['total'], result['filtered'], len(result['rows'])) == (9, 9, 3)


def test_show_text_for_no_matching_row_is_still_a_table_and_exit_4(capsys, collapsed):
    code, out, _ = call(capsys, 'unified', 'show', collapsed, '--decision', 'contested')
    assert code == 4 and '6 rows, 0 match, 0 shown' in out and table(out)[1] == []


def test_show_cancelled_and_unreadable_rows_map_to_the_exit_codes(capsys, engines, monkeypatch):
    def cancelled(*args, **kwargs):
        raise read_model.Cancelled()
    monkeypatch.setattr(read_model, 'load_unified', cancelled)
    code, out, err = call(capsys, 'unified', 'show', engines, '--json')
    assert code == 5 and document(out)['status'] == 'cancelled' and 'cancelled' in err
    monkeypatch.undo()

    def unreadable(*args, **kwargs):
        raise UnifiedError('PT-UNIFIED-STORE', 'A unified result part is unreadable', reason='part-unreadable')
    monkeypatch.setattr(read_model, 'records_for', unreadable)
    code, out, err = call(capsys, 'unified', 'show', engines, '--json')
    assert code == 3 and 'part-unreadable' in document(out)['error'] and 'Traceback' not in err


# --- explain ------------------------------------------------------------------------------------------------------------


def test_explain_prints_the_same_text_as_the_window(capsys, engines):
    rows = shown(capsys, engines)[1]['rows']
    contested = next(r for r in rows if r['decision'] == 'contested')
    code, text, _ = call(capsys, 'unified', 'explain', engines, '--row', contested['row_id'][:12])
    assert code == 0 and text.startswith(f'row {contested["row_id"][:16]}: contested, change review')
    service = ProjectService.open(engines)
    try:
        loaded = pipeline.load_current(service, pipeline.make_plan(service))
    finally:
        service.close()
    vm = read_model.load_unified(read_model.UnifiedLoadRequest('p', loaded=loaded, extraction_configured=True))
    row = next(r for r in vm.rows if r.row_id == contested['row_id'])
    detail = read_model.row_detail(vm, row)
    assert text.endswith(detail + '\n')                     # one text for the window and the terminal
    for header in read_text.SECTIONS:
        assert header in text
    assert 'Strong contest: 1 piece(s) of evidence pair an endpoint differently.' in text
    assert 'bindiff hash matching tier A E-BODY 1:1 0x1600 -> 0x1780' in text
    code, out, _ = call(capsys, 'unified', 'explain', engines, '--row', contested['row_id'][:12], '--json')
    result = document(out)['result']
    assert result['detail'] == detail and result['row']['decision'] == 'contested' and set(result) == {
        'row', 'facts', 'provenance', 'state', 'detail'}


def test_explain_a_stale_result_says_so_in_the_text(capsys, engines, tmp_path):
    row = shown(capsys, engines)[1]['rows'][0]
    project = tmp_path / 'copy'
    shutil.copytree(engines, project)                      # the module's project stays untouched
    service = ProjectService.open(project)
    try:
        deleted = next(m for m in service.project.matches if m.category == 'removed')
        added = next(m for m in service.project.matches if m.category == 'added')
        service.correct_match(deleted.id, [deleted.older[0].id], [added.newer[0].id], 'modified', 'moved on')
    finally:
        service.close()
    code, text, err = call(capsys, 'unified', 'explain', project, '--row', row['row_id'][:12])
    assert code == 0 and 'Note: This result is stale: ' in text and 'a manual correction changed the inputs' in text
    assert 'the stored result is stale' in err
