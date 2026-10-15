"""kbcorrelation/1 records, limits, errors and the K0 import rules (KB-integration-plan 7.2, 7.4, 9)."""
from __future__ import annotations

import ast
import dataclasses
import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.enrichment.identity import domain_id
from patchtrace.kbcorrelation import contracts as c
from patchtrace.kbcorrelation import errors as e
from patchtrace.kbcorrelation import limits, ports

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / 'src' / 'patchtrace' / 'kbcorrelation'
A, B, C = 'a' * 64, 'b' * 64, 'c' * 64


def _gen():
    spec = importlib.util.spec_from_file_location('generate_kbc_schemas', ROOT / 'tools' / 'generate_kbc_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _gen()
RECORDS = GEN.valid_records()
NESTED = {'SourceRef', 'SearchScope'}


def clone(name, **changes):
    data = json.loads(RECORDS[name].model_dump_json()) | changes
    return type(RECORDS[name]).model_validate_json(json.dumps(data))


def fails(name, **changes):
    with pytest.raises(ValidationError):
        clone(name, **changes)


# ------------------------------------------------------------------------------------------------ all records

@pytest.mark.parametrize('name', GEN.CONTRACTS)
def test_round_trip_is_stable(name):
    record = RECORDS[name]
    again = type(record).model_validate_json(record.model_dump_json())
    assert again == record
    assert again.model_dump_json() == record.model_dump_json()


@pytest.mark.parametrize('name', GEN.CONTRACTS)
def test_strict_frozen_forbid_extra(name):
    record = RECORDS[name]
    with pytest.raises(ValidationError):
        setattr(record, next(iter(type(record).model_fields)), None)
    fails(name, unexpected_field=1)
    if name in NESTED:  # value records embedded in contracts carry no version of their own
        assert not hasattr(record, 'contract')
    else:
        assert record.contract == 'kbcorrelation/1'
        fails(name, contract='kbcorrelation/2')


def test_every_contract_is_exported_by_the_generator():
    public = {n for n, v in vars(c).items() if isinstance(v, type) and issubclass(v, c.Contract) and v is not c.Contract
              and v.__module__ == c.__name__}
    assert public <= set(GEN.CONTRACTS), public - set(GEN.CONTRACTS)


def test_literal_tables_match_their_tuples():
    from typing import get_args
    assert get_args(c.State) == c.STATES
    assert get_args(c.Hook) == c.HOOKS
    assert get_args(e.ErrorCode) == e.CODES
    assert set(e.EXIT_CODES) == set(e.CODES)


# ------------------------------------------------------------------------------------------------ SourceDoc

def test_source_doc_id_derives_from_kind_and_hash():
    fails('SourceDoc', doc_id=C)
    expected = domain_id('kbc.source', 1, {'kind': 'cvrf-month', 'sha256': A})
    assert RECORDS['SourceDoc'].doc_id == expected


@pytest.mark.parametrize('path', ['/abs/x.gz', '../x.gz', 'a/../x.gz', 'a\\b.gz', 'C:/x.gz', 'a//b.gz'],
                         ids=['abs', 'up', 'mid-up', 'backslash', 'drive', 'empty-part'])
def test_source_doc_object_path_stays_inside_workspace(path):
    fails('SourceDoc', object_path=path)


def test_source_doc_origin_rules():
    fails('SourceDoc', uri='https://example.invalid/x')  # local import never has a URI
    fails('SourceDoc', origin='https-fetch', uri='http://example.invalid/x', authenticity='tls-allowlisted-host')
    fails('SourceDoc', origin='https-fetch', uri='https://example.invalid/x')  # still unverified-local-file
    ok = clone('SourceDoc', origin='https-fetch', uri='https://example.invalid/x', authenticity='tls-allowlisted-host')
    assert ok.authenticity == 'tls-allowlisted-host'
    fails('SourceDoc', release_id=None)  # cvrf-month needs a release


# ------------------------------------------------------------------------------------------------ Coverage

def _cov(state, requested=('m1', 'm2'), inspected=('m1', 'm2'), failed=(), unfetchable=()):
    scope = {'kind': 'selected_months', 'months': ['2099-Mar'], 'doc_ids': [], 'corpus_digest': None}
    return dict(coverage_id=A, source_kind='cvrf-month', scope=scope, state=state, requested_ids=list(requested),
                inspected_ids=list(inspected), failed=[{'id': i, 'reason': r} for i, r in failed],
                unfetchable_ids=list(unfetchable), retrieved_at='2099-03-01T00:00:00Z')


def _make_cov(**kw):
    return c.Coverage.model_validate_json(json.dumps(_cov(**kw)))


def test_complete_in_scope_when_requested_equals_inspected():
    cov = _make_cov(state='complete_in_scope')
    assert cov.is_complete and cov.exhaustive_for_history is False


@pytest.mark.parametrize('kw', [
    dict(requested=(), inspected=()),
    dict(inspected=('m1',)),
    dict(failed=(('m2', 'unreadable'),), inspected=('m1',)),
    dict(unfetchable=('m2',)),
    dict(inspected=('m1', 'm2', 'm3')),
], ids=['none-requested', 'subset', 'failed', 'unfetchable', 'extra'])
def test_complete_in_scope_is_refused_otherwise(kw):
    with pytest.raises(ValidationError):
        _make_cov(state='complete_in_scope', **kw)


def test_partial_and_not_searched_rules():
    assert _make_cov(state='partial_in_scope', inspected=('m1',)).state == 'partial_in_scope'
    with pytest.raises(ValidationError):
        _make_cov(state='partial_in_scope')  # everything inspected is complete, not partial
    with pytest.raises(ValidationError):
        _make_cov(state='not_searched')  # inspected something
    assert _make_cov(state='not_searched', inspected=()).state == 'not_searched'
    assert _make_cov(state='unknown_scope', requested=(), inspected=()).state == 'unknown_scope'


def test_exhaustive_for_history_is_constant_false():
    data = _cov('complete_in_scope') | {'exhaustive_for_history': True}
    with pytest.raises(ValidationError):
        c.Coverage.model_validate_json(json.dumps(data))


def test_coverage_ids_sorted_unique_and_failed_not_inspected():
    with pytest.raises(ValidationError):
        _make_cov(state='partial_in_scope', requested=('m2', 'm1'), inspected=('m1',))
    with pytest.raises(ValidationError):
        _make_cov(state='partial_in_scope', requested=('m1', 'm2'), inspected=('m1',), failed=(('m1', 'x'),))


def test_search_scope_is_finite_and_explicit():
    base = dict(kind='selected_months', months=[], doc_ids=[], corpus_digest=None)
    for bad in (base, base | {'kind': 'provided_files'}, base | {'kind': 'cached_corpus'},
                base | {'months': ['2099-Mar'], 'corpus_digest': A},
                base | {'months': [f'20{y:02d}-Jan' for y in range(10, 36)]}, base | {'months': ['2099-March']}):
        with pytest.raises(ValidationError):
            c.SearchScope.model_validate_json(json.dumps(bad))
    two_years = [f'20{y:02d}-{m}' for y in (97, 98) for m in
                 ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')]
    assert len(c.SearchScope.model_validate_json(json.dumps(base | {'months': sorted(two_years)})).months) == 24


# ------------------------------------------------------------------------------------------------ edges, scopes

@pytest.mark.parametrize('kb', ['KB123', 'kb5099001', '5099001', 'KB12345678901', 'KB٥٠٩٩٠٠١'],
                         ids=['short', 'lower', 'bare', 'long', 'arabic'])
def test_edge_requires_canonical_kb(kb):
    fails('KbCveEdge', kb=kb)


def test_edge_id_and_relation_rules():
    fails('KbCveEdge', edge_id=A)
    fails('KbCveEdge', supersedes=['KB5099001'])
    fails('KbCveEdge', supersedes=['KB5098000', 'KB5097000'])  # unsorted
    fails('KbCveEdge', lineage='nvd')
    ref = dict(RECORDS['KbCveEdge'].ref.model_dump(), assertion='index_claim')
    fails('KbCveEdge', ref=ref)  # vendor-remediation must cite an advisory_fact
    fails('KbCveEdge', cve='CVE-99-1')
    fails('KbCveEdge', fixed_build='26100')


def test_disputed_edge_needs_its_evidence():
    key = RECORDS['KbCveEdge']
    payload = {'kb': key.kb, 'cve': key.cve, 'scope_id': key.scope_id, 'relation': 'disputed',
               'doc_id': key.ref.doc_id, 'pointer': key.ref.pointer}
    edge_id = domain_id('kbc.edge', 1, payload)
    fails('KbCveEdge', relation='disputed', edge_id=edge_id)
    ok = clone('KbCveEdge', relation='disputed', edge_id=edge_id,
               product_status={'value': 'Known Not Affected', 'pointer': '/ProductTree/0'})
    assert ok.relation == 'disputed'


def test_string_derived_scope_is_never_verified():
    fails('ProductScope', mapping='verified')
    ok = clone('ProductScope', mapping='verified', winbindex_key='11-24H2')
    assert ok.mapping == 'verified'


def test_component_hint_and_build_row_names_are_validated():
    for bad in ('Examplesvc.dll', '../x.dll', 'x.txt', 'a b.dll', 'x'):
        fails('ComponentHint', basename=bad)
        fails('BuildRow', file_name=bad)
    fails('BuildRow', download='http://example.invalid/x.dll')
    fails('BuildRow', shared_with=['KB5099002', 'KB5099001'])


# ------------------------------------------------------------------------------------------------ pairs and plans

def _pair(**changes):
    base = json.loads(RECORDS['PairProposal'].model_dump_json())
    data = base | changes
    key = {'older': data['older']['sha256'], 'newer': data['newer']['sha256'], 'scope_id': data['scope_id'],
           'window_id': data['window_id']}
    data['pair_id'] = domain_id('kbc.pair', 1, key)
    return c.PairProposal.model_validate_json(json.dumps(data))


def test_pair_id_derives_from_its_inputs():
    fails('PairProposal', window_id='w2')


@pytest.mark.parametrize('reason', sorted(c.HARD_BLOCKS))
def test_every_hard_block_forces_grade_x(reason):
    with pytest.raises(ValidationError):
        _pair(reason_codes=[reason])
    assert _pair(reason_codes=[reason], grade='X').grade == 'X'


@pytest.mark.parametrize('reason', ['ORDER_UNVERIFIED', 'WINDOW_CONFOUNDED', 'INDEX_GAP'])
def test_soft_reasons_do_not_force_x(reason):
    assert _pair(reason_codes=[reason], grade='B', bytes_state='verified').grade == 'B'
    with pytest.raises(ValidationError):
        _pair(reason_codes=[reason], grade='X')


def test_grade_a_needs_adjacent_lineage_and_bytes():
    with pytest.raises(ValidationError):
        _pair(lineage_state='user-asserted')
    with pytest.raises(ValidationError):
        _pair(lineage_state='compatible-branch', grade='A')
    with pytest.raises(ValidationError):
        _pair(bytes_state='mismatch')
    assert _pair(bytes_state='mismatch', grade='X').grade == 'X'
    assert _pair(lineage_state='incompatible', grade='X').grade == 'X'
    assert _pair(lineage_state='user-asserted', bytes_state='verified', grade='B').grade == 'B'
    with pytest.raises(ValidationError):
        _pair(lineage_state='user-asserted', grade='B')  # pending bytes cannot be grade B


def test_identical_content_is_flagged():
    same = json.loads(RECORDS['PairProposal'].model_dump_json())['older']
    with pytest.raises(ValidationError):
        _pair(newer=same, grade='X')
    assert _pair(newer=same, grade='X', reason_codes=['IDENTICAL_CONTENT']).grade == 'X'


def test_plan_is_https_only_and_hosts_equal_request_hosts():
    fails('PairPlan', hosts=['a.invalid', 'example.invalid'])
    fails('PairPlan', hosts=[])
    fails('PairPlan', requests=[])
    plain = {'method': 'GET', 'url': 'http://example.invalid/x.dll', 'bytes': 1, 'why': 'x'}
    fails('PairPlan', requests=[plain])
    fails('PairPlan', requests=[plain | {'url': 'https:///x.dll'}])
    fails('PairPlan', requests=[plain | {'url': 'https://example.invalid/x', 'method': 'POST'}])


def test_attempt_and_decision_rules():
    fails('Attempt', result='error')
    fails('Attempt', code='PT-KBC-SOURCE')  # ok with a code
    fails('Attempt', created_at='yesterday')
    assert clone('Attempt', result='error', code='PT-KBC-ACQUIRE').code == 'PT-KBC-ACQUIRE'
    fails('Attempt', result='error', code='PT-UNIFIED-INPUT')
    fails('AnalystDecision', reason='x' * 501)


def test_investigation_revision_chain_and_link_rules():
    fails('InvestigationRevision', parent=None)
    fails('InvestigationRevision', parent=2)
    fails('InvestigationRevision', revision=1, parent=1)
    assert clone('InvestigationRevision', revision=1, parent=None).revision == 1
    fails('InvestigationRevision', state='DONE')
    fails('InvestigationRevision', investigation_id='not-a-uuid')
    fails('InvestigationRevision', selected_scope_id=A)  # not one of scope_ids
    fails('InvestigationRevision', lead={'kind': 'kb', 'value': 'KB5099001', 'raw': 'x' * 201})
    fails('ProjectLink', state='stale')
    fails('ProjectLink', stale_reasons=['older file changed'])
    assert clone('ProjectLink', state='stale', stale_reasons=['older file changed']).state == 'stale'


def test_context_and_lead_rows_stay_in_words():
    fails('LeadRow', group='not a cve')
    fails('LeadRow', hooks=['kb.next.unknown'])
    chip = json.loads(RECORDS['LeadRow'].model_dump_json())['chips'][0]
    fails('LeadRow', chips=[chip, chip])  # one chip per channel
    fails('LeadRow', chips=[chip | {'state': 'confirmed'}])
    assert clone('LeadRow', group='unattributed').group == 'unattributed'
    assert clone('LeadRow', group='not-applicable').group == 'not-applicable'
    fails('ContextReport', hooks=['kb.next.run_comparison', 'kb.meaning.coverage'])  # unsorted
    cards = json.loads(RECORDS['ContextReport'].model_dump_json())['cards']
    fails('ContextReport', cards=cards + cards)
    fails('ContextReport', cards=[cards[0] | {'kev': 'exploited'}])


# ------------------------------------------------------------------------------------------------ errors, limits

def test_issue_and_result_rules():
    with pytest.raises(ValidationError):
        e.KbcIssue(code='PT-KBC-OTHER', message='x')
    with pytest.raises(ValidationError):
        e.KbcIssue(code='PT-KBC-INPUT', message='x' * 501)
    with pytest.raises(ValidationError):
        e.KbcIssue(code='PT-KBC-INPUT', message='')
    issue = e.KbcIssue(code='PT-KBC-CANCEL', message='cancelled')
    assert issue.exit_code == 5
    assert e.KbcIssue(code='PT-KBC-CONSENT', message='x', details={'acq': 'PT-ACQ-INPUT'}).exit_code == 2
    for status in ('error', 'unsupported', 'cancelled'):
        with pytest.raises(ValidationError):
            e.OperationResult(status=status)
        with pytest.raises(ValidationError):
            e.OperationResult(status=status, issues=(issue,), value=1)
    with pytest.raises(ValidationError):
        e.OperationResult(status='ok', issues=(issue,))
    assert e.OperationResult(status='ok', value=1).exit_code == 0
    assert e.OperationResult(status='partial', value=1).exit_code == 3
    assert e.OperationResult(status='unknown').exit_code == 4
    assert e.OperationResult(status='cancelled', issues=(issue,)).exit_code == 5
    assert e.OperationResult(status='unsupported',
                             issues=(e.KbcIssue(code='PT-KBC-UNSUPPORTED', message='x'),)).exit_code == 2


def test_limits_are_the_plan_numbers_and_validated():
    lim = limits.DEFAULT_LIMITS
    assert lim.cvrf_doc_bytes == 32 * 1024 ** 2 and lim.cvrf_depth == 64 and lim.cvrf_json_nodes == 5_000_000
    assert lim.cvrf_edges_per_doc == 500_000 and lim.docs_per_plan == 24 and lim.index_months == 60
    assert lim.fetch_concurrency == 1 and lim.request_timeout_s == 60 and lim.plan_timeout_s == 900
    assert lim.attempts == 3 and lim.retry_after_max_s == 60 and lim.text_field_bytes == 64 * 1024
    assert lim.hints == 5_000 and lim.pairs_per_file == 1_000 and lim.files_per_investigation == 20
    assert lim.investigations == 500 and lim.project_sources_bytes == 256 * 1024 ** 2
    assert lim.workspace_objects_bytes == 4 * 1024 ** 3
    assert limits.MAX_SEARCH_MONTHS == 24
    with pytest.raises(ValueError):
        limits.KbcLimits(hints=0)
    with pytest.raises(ValueError):
        limits.KbcLimits(hints=True)
    with pytest.raises(ValueError):
        limits.KbcLimits(docs_per_plan=61)
    with pytest.raises(dataclasses.FrozenInstanceError):
        lim.hints = 1  # frozen


def test_ports_are_protocols_without_default_behaviour():
    class Clock:
        def now_utc(self):
            return '2099-03-01T00:00:00Z'
    assert isinstance(Clock(), ports.ClockPort)
    assert not isinstance(object(), ports.ClockPort)


# ------------------------------------------------------------------------------------------------ import rules

FORBIDDEN = {'PySide6', 'PyQt5', 'PyQt6', 'urllib', 'http', 'socket', 'sqlite3', 'requests', 'ssl'}
SIBLINGS = {'acquisition', 'enrichment', 'intelligence', 'unified', 'secondary', 'ui', 'backend', 'cli', 'jobs'}
ALLOWED_FORBIDDEN = {'store.py': {'sqlite3'}, 'recovery.py': {'sqlite3'}}  # K2 owns the workspace database
# context.py reads the reused intelligence contract types (CweProfile, HypothesisSet); wiring.py is the composition root
# and the only module that binds sibling behaviour (plan section 9).
ALLOWED_SIBLINGS = {'contracts.py': {'acquisition', 'enrichment', 'intelligence'}, 'context.py': {'intelligence'},
                    'wiring.py': SIBLINGS | {'service'},
                    'cli_leads.py': {'enrichment', 'service'}}  # RealEngine moves to adapters/engine.py in K8


def _imports(path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield 0, alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.level, node.module or ''


@pytest.mark.parametrize('path', sorted(PKG.glob('*.py')), ids=lambda p: p.name)
def test_domain_modules_import_no_qt_network_or_database(path):
    sibling_ok = ALLOWED_SIBLINGS.get(path.name, set())
    for level, module in _imports(path):
        top = module.split('.')[0]
        if level == 0:
            assert top not in FORBIDDEN - ALLOWED_FORBIDDEN.get(path.name, set()), f'{path.name} imports {module}'
            assert top != 'patchtrace', f'{path.name} must use relative imports'
        elif level == 2:  # `..x` is a sibling package
            assert top in sibling_ok, f'{path.name} imports sibling {module}'
        # `.x` inside kbcorrelation is fine


def test_init_is_empty_and_ports_and_ids_import_no_sibling():
    assert (PKG / '__init__.py').read_text(encoding='utf-8') == ''
    for name in ('ports.py', 'ids.py', 'limits.py', 'errors.py'):
        assert not [m for lvl, m in _imports(PKG / name) if lvl == 2], name
