"""WB2 G2: project input, raw matches parsing and graceful degradation."""
from __future__ import annotations

import pytest
from callgraph_graph_support import graph_input, project_and_raw, reader_for

from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.project_input import read_project_input
from patchtrace.callgraph.raw_matches import load_raw_matches, parse_raw_matches
from patchtrace.callgraph.snapshot import snapshot_key
from patchtrace.models import AnalystAnnotation, FunctionMatch


def test_svc_input_has_both_sides_run_and_hashes():
    data = graph_input('svc_pair')
    assert [len(data.side_entries(s)) for s in ('older', 'newer')] == [5, 8]
    assert data.raw.status == 'ok' and data.older_sha256 != data.newer_sha256
    assert {p.category for p in data.pairs} == {'modified', 'added'}
    assert next(p for p in data.pairs if p.category == 'modified').via == 'ghidriff:Symbols'


def test_input_without_completed_run_is_refused():
    project, _ = project_and_raw('svc_pair')
    project.runs[0].status = 'failed'
    with pytest.raises(GraphError) as excinfo:
        read_project_input(project)
    assert excinfo.value.code == 'PT-GRAPH-INPUT'


def test_external_records_are_flagged_from_address_and_metadata():
    data = graph_input('svc_pair')
    external = {e.label for e in data.entries if e.external}
    assert external == {'ntoskrnl.exe::ProbeForRead', 'ntoskrnl.exe::EtwWriteTransfer'}


def test_missing_raw_reader_degrades_to_absent():
    data = graph_input('svc_pair', with_raw=False)
    assert data.raw.status == 'absent' and data.raw.matches is None and data.raw.notes


@pytest.mark.parametrize('message', ['PT-NWAY-PAIR: raw does not match its recorded SHA-256', 'missing'],
                         ids=['hash-mismatch', 'missing-file'])
def test_reader_failure_degrades_with_a_note_and_never_raises(message):
    def reader(_root, _project):
        raise RuntimeError(message)
    result = load_raw_matches(reader, None, None)
    assert result.status == 'degraded' and result.matches is None and message[:12] in result.notes[0]


def test_reader_without_matches_section_is_absent_with_its_note():
    result = load_raw_matches(lambda r, p: (None, ('raw output has no matches section',)), None, None)
    assert (result.status, result.notes) == ('absent', ('raw output has no matches section',))


@pytest.mark.parametrize('matches', [
    {'name_matches': []},
    {'name_matches': {'a': 'b'}},
    {'name_matches': {'a': [['b']]}},
    {'name_matches': {'a': [['b', 'x']]}},
    {'address_matches': {'zz': [['10', []]]}},
    {'address_matches': {'10': [['gg', []]]}},
], ids=['table-list', 'bare-string', 'short-pair', 'types-not-list', 'bad-source', 'bad-target'])
def test_malformed_matches_degrade(matches):
    result = load_raw_matches(lambda r, p: (matches, ()), None, None)
    assert result.status == 'degraded' and result.matches is None


def test_address_matches_skip_external_locations_whole():
    parsed = parse_raw_matches({'address_matches': {
        '1000': [['2000', ['A']]], 'EXTERNAL:0c': [['EXTERNAL:0c', []]],
        '1100': [['2100', []], ['EXTERNAL:0d', []]]}})
    assert dict(parsed.addresses) == {0x1000: ((0x2000, 'A'),)}
    assert dict(parsed.reverse_addresses) == {0x2000: ((0x1000, 'A'),)}


def test_name_matches_keep_one_to_many_and_reverse():
    parsed = parse_raw_matches({'name_matches': {'a': [['x', ['T']], ['y', []]], 'b': [['x', ['U']]]}})
    assert parsed.names['a'] == (('x', 'T'), ('y', ''))
    assert parsed.reverse_names['x'] == (('a', 'T'), ('b', 'U'))


def test_manual_digest_and_key_change_on_override_annotation_and_manual_match():
    project, raw = project_and_raw('svc_pair')
    base = read_project_input(project, None, reader_for(raw))
    project.annotations = [AnalystAnnotation(target_id='m1', kind='match-override', text='pair F with P')]
    overridden = read_project_input(project, None, reader_for(raw))
    modified = [m for m in project.matches if m.category == 'modified']
    older, newer = modified[1].older, modified[2].newer
    project.matches = [*project.matches, FunctionMatch(run_id=project.runs[0].id, older=older, newer=newer,
                                                      category='modified', manual=True)]
    manual = read_project_input(project, None, reader_for(raw))
    keys = {snapshot_key(d) for d in (base, overridden, manual)}
    assert len(keys) == 3 and len({d.manual_digest for d in (base, overridden, manual)}) == 3


def test_rejected_match_is_not_a_pair_and_changes_the_digest():
    project, raw = project_and_raw('svc_pair')
    base = read_project_input(project, None, reader_for(raw))
    next(m for m in project.matches if m.category == 'modified').review = 'rejected'
    rejected = read_project_input(project, None, reader_for(raw))
    assert len(rejected.pairs) == len(base.pairs) - 1 and rejected.manual_digest != base.manual_digest
