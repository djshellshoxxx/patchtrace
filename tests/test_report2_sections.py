"""SPEC-50 RPT2-4: section builders over fake Protocol ports; absent producers give None."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from test_report2_support import FakeEvidence, _report

from patchtrace.nway.contracts import BuildRef, Chain, FunctionNode, PairEdge, PairRef, Series
from patchtrace.nway.graph import series_id
from patchtrace.report2 import text
from patchtrace.report2.sections import collect
from patchtrace.report2.sections.advisories import AdvisoryRecord, build_advisories
from patchtrace.report2.sections.build_facts import FactRecord, build_build_facts
from patchtrace.report2.sections.engine_evidence import build_engine_evidence
from patchtrace.report2.sections.leads import LeadRecord, build_leads
from patchtrace.report2.sections.series import build_series
from patchtrace.report2.sections.symbols import build_symbols
from patchtrace.report2.sections.unified_result import build_unified_result
from patchtrace.reports import ExportError
from patchtrace.secondary.evidence import EvidenceAssessment, assess_reports

SHA = 'c' * 64


class _Port:
    """Generic fake: every port method returns the configured payload."""

    def __init__(self, payload, stale=False):
        self.payload, self.stale = payload, stale

    def __getattr__(self, name):
        if name == 'is_stale':
            return lambda: self.stale
        return lambda: self.payload


@pytest.mark.parametrize('builder', [build_engine_evidence, build_series, build_unified_result, build_symbols,
                                     build_build_facts, build_advisories, build_leads],
                         ids=['evidence', 'series', 'unified', 'symbols', 'facts', 'advisories', 'leads'])
def test_every_builder_returns_none_without_a_port(builder):
    assert builder(None) is None


@pytest.mark.parametrize('builder,empty', [
    (build_engine_evidence, None), (build_engine_evidence, EvidenceAssessment((), (), ('none ran',))),
    (build_series, None), (build_symbols, None), (build_symbols, {}), (build_symbols, {'symbol_mode': 'weird'}),
    (build_build_facts, []), (build_advisories, []), (build_leads, [])],
    ids=['ev-none', 'ev-empty', 'series', 'sym-none', 'sym-empty', 'sym-weird', 'facts', 'adv', 'leads'])
def test_empty_producer_output_is_none_not_a_negative(builder, empty):
    assert builder(_Port(empty)) is None


def test_collect_with_no_ports_is_all_absent():
    sections = collect()
    assert [getattr(sections, k) for k in ('engine_evidence', 'series', 'unified_result', 'build_facts', 'symbols',
                                           'advisories', 'leads')] == [None] * 7 and sections.truncated == ()


# --- engine evidence -----------------------------------------------------------------------------------------

def _assessment():
    return assess_reports((_report('bindiff', '8.0', [('m1', 'agreement'), ('m2', 'disagreement'),
                                                     ('m3', 'not-comparable')]),
                           _report('rz-diff', '0.9', [('m1', 'absent'), ('m2', 'absent'), ('m3', 'not-comparable')])))


def test_engine_evidence_keeps_engines_separate_and_missing_unknown():
    built = build_engine_evidence(FakeEvidence(_assessment(), stale=True)).value
    rows = {r.match_id: r for r in built.rows}
    assert [(e.name, e.version) for e in built.engines] == [('bindiff', '8.0'), ('rz-diff', '0.9')]
    assert built.stale is True
    a, b, c = rows['m1'], rows['m2'], rows['m3']
    assert (a.verdict, a.supporting_engines, a.missing_engines) == ('corroborated', ['bindiff'], ['rz-diff'])
    assert {ch.engine: ch.state for ch in a.channels} == {'ghidriff': 'present', 'bindiff': 'present',
                                                           'rz-diff': 'absent'}
    assert (b.verdict, b.contradicting_engines) == ('contested', ['bindiff'])
    assert c.verdict == 'insufficient' and {ch.state for ch in c.channels if ch.engine != 'ghidriff'} == {
        'not_comparable'}
    assert any('rz-diff' in ch.note for ch in a.channels if ch.engine == 'rz-diff')


def test_engine_evidence_has_no_aggregate_and_notes_shared_origin_once():
    built = build_engine_evidence(FakeEvidence(_assessment())).value
    dumped = built.model_dump()
    assert not {'mean', 'average', 'combined_score', 'confidence'} & set(dumped)
    assert sum('shared disassembly' in line for line in built.limitations) == 1


def test_engine_evidence_rows_are_capped_and_the_rest_is_summarized(monkeypatch):
    monkeypatch.setattr(text, 'MAX_EVIDENCE_ROWS', 2)
    ids = [f'm{i}' for i in range(5)]
    assessment = assess_reports((_report('bindiff', '1', [(i, 'agreement') for i in ids]),))
    built = build_engine_evidence(FakeEvidence(assessment))
    assert len(built.value.rows) == 2
    assert (built.truncated.section, built.truncated.omitted_count) == ('engine_evidence', 3)


def test_engine_text_is_normalized_once():
    assessment = assess_reports((_report('bind\u202eiff', '1', [('m1', 'agreement')]),))
    built = build_engine_evidence(FakeEvidence(assessment)).value
    assert built.engines[0].name == 'bind<U+202E>iff'


# --- series --------------------------------------------------------------------------------------------------

def _series():
    node = [FunctionNode(ordinal=i, name='f') for i in range(3)]
    edge = lambda a, b: PairEdge(from_node=node[a], to_node=node[b], category='modified', match_id=f'm{a}')  # noqa: E731
    chain = Chain(chain_id=SHA, nodes=tuple(node), edges=(edge(0, 1), edge(1, 2)), hops=2, weakest_match_type='x',
                  gaps=(1,))
    hashes = [str(i) * 64 for i in range(3)]
    return Series(series_id=series_id(hashes), builds=tuple(BuildRef(ordinal=i, label=f'b{i}', artifact_sha256=str(i) * 64)
                                              for i in range(3)),
                  pair_projects=(PairRef(from_ordinal=0, to_ordinal=1, path='a', project_id='p', revision=1),
                                 PairRef(from_ordinal=1, to_ordinal=2, path='b', project_id='q', revision=1)),
                  node_count=3, chains=(chain,))


def test_series_orientation_by_ordinal_and_gaps_are_unknown():
    built = build_series(_Port(_series(), stale=True)).value
    assert [(b.ordinal, b.label) for b in built.builds] == [(0, 'b0'), (1, 'b1'), (2, 'b2')]
    assert [(p.older_ordinal, p.newer_ordinal) for p in built.pairs] == [(0, 1), (1, 2)]
    assert built.chains[0].ordinals == [0, 1, 2] and built.stale is True
    assert built.gaps[0].after_ordinal == 1 and 'unknown' in built.gaps[0].reason


# --- unified result ------------------------------------------------------------------------------------------

def _loaded(state='current', status='complete'):
    manifest = SimpleNamespace(result_id=SHA, status=status, sources=(SimpleNamespace(source='bindiff'),
                                                                      SimpleNamespace(source='rz-diff')))
    return SimpleNamespace(state=state, manifest=manifest, pointer=SimpleNamespace(manifest_sha256='d' * 64),
                           directory=None)


def test_unified_result_is_a_reference_only_and_reads_no_bulk_rows(monkeypatch):
    import patchtrace.unified.store as store

    def boom(*_a, **_k):
        raise AssertionError('bulk rows must not be read')
    monkeypatch.setattr(store, 'read_rows', boom)
    monkeypatch.setattr(store, 'read_facts', boom)
    monkeypatch.setattr(store, 'part_lines', boom)
    built = build_unified_result(_Port(_loaded())).value
    assert built.model_dump() == {'result_id': SHA, 'manifest_sha256': 'd' * 64,
                                  'engines': ['bindiff', 'ghidriff', 'rz-diff'], 'status': 'complete', 'stale': False}


@pytest.mark.parametrize('state,expected', [('stale', True), ('current', False)], ids=['stale', 'current'])
def test_unified_result_stale_flag(state, expected):
    assert build_unified_result(_Port(_loaded(state))).value.stale is expected


@pytest.mark.parametrize('state', ['none', 'invalid'])
def test_unified_result_absent_or_invalid_is_none(state):
    assert build_unified_result(_Port(SimpleNamespace(state=state, manifest=None, pointer=None))) is None


# --- symbols -------------------------------------------------------------------------------------------------

def test_symbols_servers_only_online_and_pdb_names_are_basenames():
    staged = [{'name': 'C:\\sym\\ntdll.pdb', 'guid_age': 'A' * 33, 'sha256': SHA}]
    online = build_symbols(_Port({'symbol_mode': 'online', 'symbol_servers': ['ghidra-configured'],
                                  'staged_symbols': staged, 'launcher_version': '1.2'})).value
    assert online.servers == ['ghidra-configured'] and online.staged[0].pdb_name == 'ntdll.pdb'
    assert online.launcher_version == '1.2'
    local = build_symbols(_Port({'symbol_mode': 'local', 'symbol_servers': ['ghidra-configured'],
                                 'launcher_version': 'none'})).value
    assert local.servers == [] and local.launcher_version is None


def test_symbols_malformed_staged_row_refuses_the_export():
    with pytest.raises(ExportError, match='PT-EXPORT-SECTION'):
        build_symbols(_Port({'symbol_mode': 'local', 'staged_symbols': [
            {'name': 'x.pdb', 'guid_age': 'zz', 'sha256': SHA}]}))


# --- build facts, advisories, leads --------------------------------------------------------------------------

def test_build_facts_are_observed_in_file_and_values_are_capped():
    built = build_build_facts(_Port([FactRecord('older', 'file_version', 'v' * 600, 'pe'),
                                     FactRecord('newer', 'timestamp_claim', '2020-01-01', 'pe')]))
    assert built.value[0].truncated is True and built.value[0].value.endswith('[truncated 88 chars]')
    assert {f.claim_level for f in built.value} == {'observed-in-file'}


def test_build_facts_unknown_fact_name_refuses():
    with pytest.raises(ExportError, match='PT-EXPORT-SECTION'):
        build_build_facts(_Port([FactRecord('older', 'free_text', 'x', 'pe')]))


def test_build_facts_cap_summarizes_the_rest(monkeypatch):
    monkeypatch.setattr(text, 'MAX_BUILD_FACTS', 1)
    built = build_build_facts(_Port([FactRecord('older', 'file_version', str(i), 'pe') for i in range(4)]))
    assert len(built.value) == 1 and built.truncated.omitted_count == 3


def test_advisory_text_is_vendor_claim_verbatim_and_capped():
    body = 'x\n' + 'y' * 5000
    built = build_advisories(_Port([AdvisoryRecord('cve', 'CVE-2024-0001', body, kev_listed=True)])).value[0]
    assert built.claim_level == 'vendor-claim' and built.truncated is True and built.text.startswith('x\ny')
    assert built.kev_listed is True


@pytest.mark.parametrize('kind,ident', [('cve', 'CVE-24-1'), ('kb', 'KB1'), ('cwe', 'CWE-<b>'),
                                        ('cve', 'CVE-2024-0001\n# x')], ids=['cve', 'kb', 'cwe', 'newline'])
def test_advisory_bad_ids_refuse_the_export(kind, ident):
    with pytest.raises(ExportError, match='PT-EXPORT-SECTION'):
        build_advisories(_Port([AdvisoryRecord(kind, ident, 't')]))


@pytest.mark.parametrize('ident', ['KB1234', 'KB12345', 'KB1234567890'], ids=['4', '5', '10'])
def test_advisory_canonical_kb_ids_of_any_width_do_not_refuse_the_export(ident):
    """KBA-07: one canonical `kb-syntax/1` id outside 6-8 digits refused the whole export."""
    assert build_advisories(_Port([AdvisoryRecord('kb', ident, 't')])).value[0].id == ident


def test_advisory_cap_summarizes_the_rest(monkeypatch):
    monkeypatch.setattr(text, 'MAX_ADVISORIES', 2)
    built = build_advisories(_Port([AdvisoryRecord('cve', f'CVE-2024-{1000 + i}', 't') for i in range(5)]))
    assert len(built.value) == 2 and built.truncated.omitted_count == 3
    sections = collect(advisories=_Port([AdvisoryRecord('cve', f'CVE-2024-{1000 + i}', 't') for i in range(5)]))
    assert [(t.section, t.omitted_count) for t in sections.truncated] == [('advisories', 3)]


def test_leads_list_independent_channels_and_reject_none():
    built = build_leads(_Port([LeadRecord('l1', 'k', ('a', 'b'), 's')])).value[0]
    assert built.channels == ['a', 'b']
    with pytest.raises(ExportError, match='PT-EXPORT-SECTION'):
        build_leads(_Port([LeadRecord('l1', 'k', (), 's')]))
