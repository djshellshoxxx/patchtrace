"""WB2 G4/G7: `patchtrace graph ...` through the Qt-free dispatcher over real synthetic projects."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading

import pytest
from callgraph_cli_support import match_id, run, series_root, svc_project

from patchtrace.callgraph.contracts_evolution import NeighbourhoodEvolution
from patchtrace.callgraph.export_json import GraphExport

P = 'FUN_1400018c0'


@pytest.fixture(scope='module')
def project(tmp_path_factory):
    return svc_project(tmp_path_factory.mktemp('svc') / 'proj')


@pytest.fixture(scope='module')
def series(tmp_path_factory):
    return series_root(tmp_path_factory.mktemp('ser') / 'root')


def digest(path) -> str:
    """Content hash of a project tree; the advisory lock file is rewritten by every open and is not data."""
    return hashlib.sha256(b''.join(p.read_bytes() for p in sorted(path.rglob('*')) if p.is_file() and p.name != '.patchtrace.lock')).hexdigest()


# --- envelope and exit codes -------------------------------------------------------------------------------------

def test_json_mode_is_one_enrichment_document(project):
    result = run('delta', str(project), '--json')
    assert result.code == 0 and result.out.count('\n') == 1
    document = result.document
    assert document['contract'] == 'enrichment-cli/1' and document['command'] == 'graph delta'
    assert document['status'] == 'complete' and document['result']['total'] == 5


def test_delta_lists_the_known_answer(project):
    result = run('delta', str(project), '--json').document['result']
    by_label = {d['newer_label']: d for d in result['deltas']}
    assert by_label[P]['state'] == 'compared' and by_label[P]['downgrade'] == 'none'
    assert {c['cls'] for c in by_label[P]['changes']} == {'same-link', 'call-to-new-function', 'added-call'}
    assert by_label['FUN_140001d40']['downgrade'] == 'hub-only'
    assert by_label['FUN_140001640']['downgrade'] == 'renumber-only'
    assert [g for g in result['groups']] == []  # no callee shared by two changed pairs


def test_delta_limit_and_match_filter(project):
    assert run('delta', str(project), '--limit', '2', '--json').document['result']['shown'] == 2
    one = run('delta', str(project), '--match', match_id(project, P), '--json').document['result']
    assert one['total'] == 1 and one['deltas'][0]['newer_label'] == P


def test_unknown_match_and_bad_arguments_exit_2(project):
    assert run('delta', str(project), '--match', 'nope').code == 2
    assert run('neighbours', str(project), '--name', 'DriverEntry', '--depth', '9').code == 2
    assert run('neighbours', str(project)).code == 2
    assert run('paths', str(project), '--from', P, '--to', 'x', '--max-paths', '6').code == 2


def test_missing_project_exits_2(tmp_path):
    result = run('leads', str(tmp_path / 'absent'))
    assert result.code == 2 and 'PT-GRAPH-INPUT' in result.err


def test_function_not_in_the_change_set_exits_2_with_reason(project):
    result = run('neighbours', str(project), '--name', 'NoSuchFunction')
    assert result.code == 2 and 'function-not-indexed' in result.err


def test_cancel_exits_5(project):
    cancelled = threading.Event()
    cancelled.set()
    assert run('delta', str(project), cancel=cancelled).code == 5


def test_capped_neighbours_is_partial_exit_3(project):
    result = run('neighbours', str(project), '--name', 'FUN_140001640', '--side', 'newer', '--max-nodes', '2',
                 '--json')
    assert result.code == 3 and result.document['status'] == 'partial'
    assert result.document['result']['views'][0]['truncated'] is True


def test_no_observed_path_is_complete_with_zero_entries_exit_4(project):
    result = run('paths', str(project), '--from', 'FUN_1400018c0', '--to', 'DriverEntry', '--json')
    assert result.code == 4 and result.document['status'] == 'complete'
    assert result.document['result']['results'][0]['paths'] == []


# --- verbs -------------------------------------------------------------------------------------------------------

def test_neighbours_by_match_function_and_name_agree(project):
    by_match = run('neighbours', str(project), '--match', match_id(project, P), '--side', 'newer', '--json')
    by_name = run('neighbours', str(project), '--name', P, '--side', 'newer', '--json')
    assert by_match.code == by_name.code == 0
    assert by_match.document['result'] == by_name.document['result']
    [view] = by_name.document['result']['views']
    labels = {n['label'] for n in view['nodes']}
    assert {P, 'FUN_140001640', 'FUN_140001f00', 'ntoskrnl.exe::ProbeForRead'} <= labels
    callees = run('neighbours', str(project), '--name', P, '--side', 'newer', '--direction', 'callees', '--json')
    assert 'FUN_140001640' not in {n['label'] for n in callees.document['result']['views'][0]['nodes']}


def test_leads_rank_the_new_function_first(project):
    result = run('leads', str(project), '--json').document['result']
    first = result['leads'][0]
    assert first['signals'][0]['id'] == 'new-function-called' and first['entry']['state'] in {'reached', 'not-reached',
                                                                                              'unknown'}
    assert {lead['signals'][0]['id'] for lead in result['leads']} == {'new-function-called', 'hub-only'}


def test_paths_to_an_import_by_api_name(project):
    result = run('paths', str(project), '--from', 'FUN_140001640', '--to', 'ProbeForRead', '--json')
    assert result.code == 0
    [found] = result.document['result']['results']
    [path] = found['paths']
    assert [found['labels'][n] for n in path] == ['FUN_140001640', P, 'ntoskrnl.exe::ProbeForRead']
    assert 'Observed path of at most 2 calls' in found['note']


def test_text_mode_prints_untrusted_names_as_plain_lines(project):
    result = run('delta', str(project))
    assert result.code == 0 and result.out.startswith('5 of 5 deltas') and '\x00' not in result.out


def test_graph_modules_import_no_qt():
    code = ('import sys\n'
            'import patchtrace.callgraph.cli, patchtrace.callgraph.cli_ports, patchtrace.callgraph.dot, '
            'patchtrace.callgraph.export_json\n'
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in {'PySide6', 'PyQt5', 'PyQt6'} "
            "or m.startswith('patchtrace.ui'))\n"
            'sys.exit(1 if bad else 0)\n')
    assert subprocess.run([sys.executable, '-c', code], check=False).returncode == 0


# --- export ------------------------------------------------------------------------------------------------------

def test_export_dot_and_json_files(project, tmp_path):
    mid = match_id(project, P)
    dot = tmp_path / 'p.dot'
    result = run('export', str(project), '--match', mid, '--format', 'dot', '--output', str(dot), '--json')
    assert result.code == 0 and result.document['result']['path'] == 'p.dot'
    text = dot.read_bytes()
    assert text.startswith(b'// patchtrace call graph export') and b'\r' not in text
    assert 'subgraph cluster_older' in text.decode('utf-8')
    out = tmp_path / 'p.json'
    assert run('export', str(project), '--match', mid, '--format', 'json', '--output', str(out)).code == 0
    export = GraphExport.model_validate_json(out.read_text(encoding='utf-8'))
    assert export.match_id == mid and export.older is not None and export.newer is not None


def test_export_refuses_overwrite_without_the_flag(project, tmp_path):
    mid, target = match_id(project, P), tmp_path / 'x.dot'
    args = ('export', str(project), '--match', mid, '--format', 'dot', '--output', str(target))
    assert run(*args).code == 0
    first = target.read_bytes()
    assert run(*args).code == 2 and target.read_bytes() == first
    assert run(*args, '--overwrite').code == 0


def test_export_to_a_directory_uses_a_content_name(project, tmp_path):
    result = run('export', str(project), '--match', match_id(project, P), '--format', 'dot', '--output',
                 str(tmp_path), '--json')
    assert result.code == 0
    name = result.document['result']['path']
    assert name.startswith('callgraph-') and name.endswith('.dot') and (tmp_path / name).is_file()


def test_export_unknown_match_exits_2(project, tmp_path):
    result = run('export', str(project), '--match', 'nope', '--format', 'dot', '--output', str(tmp_path / 'n.dot'))
    assert result.code == 2 and 'function-not-indexed' in result.err


def test_verbs_do_not_modify_the_project(project, tmp_path):
    before = digest(project)
    run('delta', str(project))
    run('leads', str(project))
    run('export', str(project), '--match', match_id(project, P), '--format', 'dot', '--output', str(tmp_path))
    assert digest(project) == before


# --- series (G7) -------------------------------------------------------------------------------------------------

def lineage(evolution: NeighbourhoodEvolution, label: str):
    return next(item for item in evolution.lineages if label in item.labels_by_ordinal)


def test_series_matrix_marks_dropped_and_appeared_callees(series):
    root, chain = series
    result = run('series', str(root), '--chain', chain, '--json')
    assert result.code == 0 and result.document['command'] == 'graph series'
    evolution = NeighbourhoodEvolution.model_validate_json(json.dumps(result.document['result']['evolution']))
    assert evolution.focus_labels == ('F', 'F', 'F')
    x, y = lineage(evolution, 'X'), lineage(evolution, 'Y')
    assert x.cells == ('present', 'present', 'absent') and [(e.kind, e.ordinal) for e in x.events] == [('dropped', 2)]
    assert y.cells == ('absent', 'present', 'present') and [(e.kind, e.ordinal) for e in y.events] == [('appeared', 1)]


def test_series_accepts_a_chain_id_prefix_and_rejects_unknown_ones(series):
    root, chain = series
    assert run('series', str(root), '--chain', chain[:12]).code == 0
    assert run('series', str(root), '--chain', 'f' * 64).code == 2
    assert run('series', str(root / 'nowhere'), '--chain', chain).code == 2


def test_series_opens_pair_projects_read_only(series):
    root, chain = series
    before = digest(root)
    assert run('series', str(root), '--chain', chain).code == 0
    assert digest(root) == before


def test_series_with_a_missing_pair_project_is_partial_with_unknown_cells(tmp_path):
    import shutil
    root, chain = series_root(tmp_path / 'broken')
    from patchtrace.nway import series as store
    ref = store.load(root / store.SERIES_FILE).pair_projects[1]
    shutil.rmtree(root / ref.path)
    result = run('series', str(root), '--chain', chain, '--json')
    assert result.code == 3 and result.document['status'] == 'partial'
    assert any('unknown' in w for w in result.document['warnings'])
    evolution = NeighbourhoodEvolution.model_validate_json(json.dumps(result.document['result']['evolution']))
    assert 'absent' not in lineage(evolution, 'X').cells[2:] and lineage(evolution, 'X').cells[2] == 'unknown'
