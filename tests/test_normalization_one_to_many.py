"""SPEC-31 A-28 (SPEC-01 `normalize_ghidriff`): one upstream function in several `modified` pairs.

Every document here is SYNTHETIC, built in code from `patchtrace.sample.sample_diff`; no Ghidriff, Ghidra or target
binary was run. The shapes mirror what pinned Ghidriff 4f5d895 writes for a one-to-many match (one memoised record,
serialised again in each pair); they are not live evidence that it does.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from patchtrace.enrichment import pipeline
from patchtrace.enrichment.views import build_views
from patchtrace.evidence import build_context
from patchtrace.kbcorrelation.cli_leads import _change
from patchtrace.models import AnalysisRun, Artifact, ComparisonProject, FunctionMatch, FunctionRecord
from patchtrace.normalization import normalize_ghidriff
from patchtrace.nway.graph import _shape_event
from patchtrace.persistence import validate_project
from patchtrace.sample import NEW_CODE, OLD_CODE, sample_diff, synthetic_pe
from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet
from patchtrace.secondary.reconcile import reconcile
from patchtrace.service import ProjectService

FAST_CODE = NEW_CODE.replace('read_item(', 'read_item_fast(', 1)
RESERVED = ('upstream_similarity', 'diff_types', 'upstream_name', 'instructions_hash', 'assembly_unavailable',
            'upstream_one_to_many')
# sha256 of the id-free normalized sample (`_view`), taken on the branch BEFORE A-28: zero blast radius.
GOLDEN_SAMPLE = 'aeef282c852bffdc6dea3af4966d15ea9f8c5c42c2e3e5c1ea81caf1b3d7a4f6'


def upstream(name, address, code=FAST_CODE):
    """One enhanced record in the shape `sample_diff` uses."""
    return {'name': name, 'fullname': name, 'address': address, 'code': code, 'calling': [], 'called': [],
            'instructions': -17200333, 'sig': f'int {name}(...)', 'sym_type': 'FUNCTION', 'external': False}


@pytest.fixture
def pure():
    run = AnalysisRun(status='completed')
    project = ComparisonProject(name='p', runs=[run], artifacts=[
        Artifact(side='older', name='o.dll', sha256='a' * 64, size=1, relative_path='artifacts/o.bin'),
        Artifact(side='newer', name='n.dll', sha256='b' * 64, size=1, relative_path='artifacts/n.bin')])
    return project, run.id


def normalize(raw, pure):
    return normalize_ghidriff(raw, *pure)


# --- the synthetic documents ---------------------------------------------------------------------------------------

def d1(project):
    """1:N: read_item@180001000 is paired with read_item@180001080 (entry 0) and read_item_fast@180001900 (entry 2)."""
    raw = sample_diff(project)
    modified = raw['functions']['modified']
    modified.append({'old': copy.deepcopy(modified[0]['old']), 'new': upstream('read_item_fast', '180001900'),
                     'diff_type': ['code', 'address', 'name'], 'ratio': 0.41, 'match_types': ['StructuralGraphHash']})
    return raw


def d2(project):
    """N:1: read_item@180001000 and read_item_v0@180001900 are both paired with read_item@180001080."""
    raw = sample_diff(project)
    modified = raw['functions']['modified']
    modified.append({'old': upstream('read_item_v0', '180001900', OLD_CODE), 'new': copy.deepcopy(modified[0]['new']),
                     'diff_type': ['code', 'name'], 'ratio': 0.37, 'match_types': ['BulkInstructionHash']})
    return raw


def d3(project):
    """N:M chain A-B1, A-B2, A2-B2: one group although A2 and B1 each look 1:1 on their own."""
    raw = d1(project)
    modified = raw['functions']['modified']
    modified.append({'old': upstream('read_item_v2', '180001a00', OLD_CODE), 'new': copy.deepcopy(modified[2]['new']),
                     'diff_type': ['code'], 'ratio': None, 'match_types': ['SigCallingCalledHasher']})
    return raw


def rows(out, category):
    return [m for m in out if m.category == category]


def only(match: FunctionMatch) -> FunctionRecord:
    assert len(match.older) + len(match.newer) == 1
    return (match.older or match.newer)[0]


def side_of(match):
    return 'older' if match.older else 'newer'


def _view(out):
    views = []
    for match in out:
        data = match.model_dump(mode='json')
        data.pop('id')
        data.pop('run_id')
        for side in ('older', 'newer'):
            for function in data[side]:
                for key in ('id', 'artifact_id', 'run_id'):
                    function.pop(key)
        views.append(data)
    return views


# --- zero blast radius --------------------------------------------------------------------------------------------

def test_no_repeat_output_unchanged(pure):
    """D0: a document without repeats normalizes exactly as before A-28 (ids aside)."""
    out = normalize(sample_diff(pure[0]), pure)
    digest = hashlib.sha256(json.dumps(_view(out), sort_keys=True).encode()).hexdigest()
    assert digest == GOLDEN_SAMPLE
    assert [m.category for m in out] == ['added', 'removed', 'modified', 'modified']
    assert all(not m.manual and m.review == 'unreviewed' and m.reason == '' for m in out)


# --- accepted repeat shapes ---------------------------------------------------------------------------------------

def test_one_to_many_abstains_group_not_document(pure):
    out = normalize(d1(pure[0]), pure)
    [modified] = rows(out, 'modified')
    assert [f.name for f in modified.older + modified.newer] == ['get_version', 'get_version']
    ambiguous = rows(out, 'ambiguous')
    assert [(side_of(m), only(m).name, only(m).address) for m in ambiguous] == [
        ('older', 'read_item', '180001000'), ('newer', 'read_item', '180001080'),
        ('newer', 'read_item_fast', '180001900')]
    assert [m.category for m in out] == ['added', 'removed', 'modified', 'ambiguous', 'ambiguous', 'ambiguous']
    for match in ambiguous:
        assert (match.manual, match.review, match.quality, match.match_types) == (False, 'needs-review', 'unknown', [])
        assert 'one-to-many' in match.reason and 'Correct match' in match.reason
    every = [f for m in out for f in m.older + m.newer]
    assert sum((f.name, f.address) == ('read_item', '180001000') for f in every) == 1
    a = only(ambiguous[0])
    claim = a.metadata['upstream_one_to_many']
    assert [p['entry'] for p in claim['pairings']] == [0, 2]
    assert [p['pointer'] for p in claim['pairings']] == ['/functions/modified/0', '/functions/modified/2']
    assert [p['ratio'] for p in claim['pairings']] == [0.58, 0.41]
    assert [p['match_types'] for p in claim['pairings']] == [['Symbols', 'StructuralGraph'], ['StructuralGraphHash']]
    assert [p['diff_types'] for p in claim['pairings']] == [['code', 'address', 'called'], ['code', 'address', 'name']]
    assert [p['counterpart'] for p in claim['pairings']] == [
        {'name': 'read_item', 'fullname': 'read_item', 'address': '180001080'},
        {'name': 'read_item_fast', 'fullname': 'read_item_fast', 'address': '180001900'}]
    assert 'upstream_similarity' not in a.metadata and 'diff_types' not in a.metadata
    assert a.metadata['upstream_name'] == 'read_item' and a.code == OLD_CODE
    groups = {only(m).metadata['upstream_one_to_many']['group'] for m in ambiguous}
    assert len(groups) == 1 and next(iter(groups)).startswith('g1n-') and len(next(iter(groups))) == 20
    assert all(next(iter(groups)) in m.reason for m in ambiguous)
    b1 = only(ambiguous[1]).metadata['upstream_one_to_many']['pairings']
    assert [(p['entry'], p['counterpart']['address'], p['ratio']) for p in b1] == [(0, '180001000', 0.58)]
    for match in ambiguous:  # side-relative: swap_orientation moves records without rewriting metadata
        text = json.dumps(only(match).metadata['upstream_one_to_many'])
        assert 'older' not in text and 'newer' not in text
    clean = normalize(sample_diff(pure[0]), pure)
    assert _view(rows(out, 'added') + rows(out, 'removed')) == _view(rows(clean, 'added') + rows(clean, 'removed'))
    assert _view([modified]) == _view([rows(clean, 'modified')[1]])


def test_many_to_one_symmetric(pure):
    out = normalize(d2(pure[0]), pure)
    assert [[f.name for f in m.older] for m in rows(out, 'modified')] == [['get_version']]
    ambiguous = rows(out, 'ambiguous')
    assert [(side_of(m), only(m).name, only(m).address) for m in ambiguous] == [
        ('older', 'read_item', '180001000'), ('older', 'read_item_v0', '180001900'),
        ('newer', 'read_item', '180001080')]
    b = only(ambiguous[2]).metadata['upstream_one_to_many']
    assert [(p['entry'], p['counterpart']['name'], p['ratio']) for p in b['pairings']] == [
        (0, 'read_item', 0.58), (2, 'read_item_v0', 0.37)]
    assert [p['match_types'] for p in b['pairings']] == [['Symbols', 'StructuralGraph'], ['BulkInstructionHash']]
    every = [f for m in out for f in m.older + m.newer]
    assert sum((f.name, f.address) == ('read_item', '180001080') for f in every) == 1
    assert len({only(m).metadata['upstream_one_to_many']['group'] for m in ambiguous}) == 1


def test_n_to_m_chain_is_one_group(pure):
    out = normalize(d3(pure[0]), pure)
    ambiguous = rows(out, 'ambiguous')
    assert [(side_of(m), only(m).name) for m in ambiguous] == [
        ('older', 'read_item'), ('older', 'read_item_v2'), ('newer', 'read_item'), ('newer', 'read_item_fast')]
    assert len({only(m).metadata['upstream_one_to_many']['group'] for m in ambiguous}) == 1
    touched = {('read_item', '180001000'), ('read_item_v2', '180001a00'), ('read_item', '180001080'),
               ('read_item_fast', '180001900')}
    assert not any((f.name, f.address) in touched for m in rows(out, 'modified') for f in m.older + m.newer)
    a2 = only(ambiguous[1]).metadata['upstream_one_to_many']['pairings']
    assert [(p['entry'], p['counterpart']['name'], p['ratio']) for p in a2] == [(3, 'read_item_fast', None)]
    assert '1 counterpart function ' in ambiguous[1].reason and '4 functions' in ambiguous[1].reason


def _summary(out):
    found = set()
    for match in rows(out, 'ambiguous'):
        record = only(match)
        claim = record.metadata['upstream_one_to_many']
        counterparts = tuple(sorted((p['counterpart']['name'], p['counterpart']['address'], p['ratio'])
                                    for p in claim['pairings']))
        found.add((side_of(match), record.name, record.address, counterparts, claim['group']))
    return found


def test_one_to_many_order_independent(pure):
    raw = d3(pure[0])
    reference = normalize(raw, pure)
    reversed_raw = copy.deepcopy(raw)
    reversed_raw['functions']['modified'].reverse()
    other = normalize(reversed_raw, pure)
    assert _summary(other) == _summary(reference) and len(_summary(reference)) == 4
    assert [(side_of(m), only(m).name) for m in rows(other, 'ambiguous')] == [
        (side_of(m), only(m).name) for m in rows(reference, 'ambiguous')]


def test_addressless_repeat(pure):
    raw = sample_diff(pure[0])
    modified = raw['functions']['modified']
    modified[0]['old']['address'] = modified[0]['new']['address'] = None
    modified.append({'old': copy.deepcopy(modified[0]['old']), 'new': upstream('read_item_fast', '180001900'),
                     'diff_type': ['code'], 'ratio': 0.4, 'match_types': ['BSIM']})
    out = normalize(raw, pure)
    older = [only(m) for m in rows(out, 'ambiguous') if m.older]
    assert [(f.name, f.address, f.address_space) for f in older] == [('read_item', None, 'unknown')]
    assert [p['entry'] for p in older[0].metadata['upstream_one_to_many']['pairings']] == [0, 2]
    raw['functions']['modified'][2]['old']['code'] = 'int read_item(void) { return 0; }'
    with pytest.raises(ValueError, match='PT-SCHEMA: .*repeated with conflicting content'):
        normalize(raw, pure)


# --- rejections that stay -----------------------------------------------------------------------------------------

def test_identical_pair_repeat_is_still_rejected(pure):
    """CORE-2 (tests/test_core.py keeps its own assertion unchanged): a copied entry claims the same pair twice."""
    raw = sample_diff(pure[0])
    raw['functions']['modified'].append(copy.deepcopy(raw['functions']['modified'][0]))
    with pytest.raises(ValueError, match='^PT-SCHEMA: upstream pair is repeated; shared evidence counts once$'):
        normalize(raw, pure)
    raw['functions']['modified'][2]['ratio'] = 0.99  # a different score for the same pair is still the same pair
    with pytest.raises(ValueError, match='^PT-SCHEMA: upstream pair is repeated'):
        normalize(raw, pure)


def test_repeated_identity_with_conflicting_content_rejected(pure):
    raw = d1(pure[0])
    raw['functions']['modified'][2]['old']['code'] = OLD_CODE + '\n'
    with pytest.raises(ValueError, match='PT-SCHEMA: .*repeated.*conflicting'):
        normalize(raw, pure)
    raw = d1(pure[0])
    raw['functions']['modified'][2]['old']['external'] = 0  # JSON 0 is not false: canonical JSON, not ==
    with pytest.raises(ValueError, match='PT-SCHEMA: .*repeated.*conflicting'):
        normalize(raw, pure)


@pytest.mark.parametrize('where', ['deleted-and-paired', 'deleted-twice', 'added-twice'],
                         ids=['contradiction', 'deleted', 'added'])
def test_one_sided_and_matched_contradiction_rejected(pure, where):
    raw = sample_diff(pure[0])
    functions = raw['functions']
    if where == 'deleted-and-paired':
        functions['deleted'].append(copy.deepcopy(functions['modified'][0]['old']))
    elif where == 'deleted-twice':
        functions['deleted'].append(copy.deepcopy(functions['deleted'][0]))
    else:
        functions['added'].append(copy.deepcopy(functions['added'][0]))
    with pytest.raises(ValueError, match='^PT-SCHEMA: upstream function is repeated; shared evidence counts once$'):
        normalize(raw, pure)


@pytest.mark.parametrize('key', RESERVED, ids=['sim', 'diff', 'uname', 'ihash', 'asm', 'one2n'])
@pytest.mark.parametrize('where', ['modified', 'group', 'deleted'], ids=['mod', 'group', 'del'])
def test_reserved_metadata_key_rejected(pure, key, where):
    """Graft 1: an upstream record cannot plant a value PatchTrace derives (calibration, unified and tier-R read
    `upstream_similarity`; a planted one survived whenever the entry had no ratio)."""
    raw = d1(pure[0]) if where == 'group' else sample_diff(pure[0])
    if where == 'deleted':
        target = raw['functions']['deleted'][0]
    else:
        target = raw['functions']['modified'][1 if where == 'modified' else 2]['new']
    target[key] = {} if key == 'upstream_one_to_many' else 0.99
    if where == 'modified':
        raw['functions']['modified'][1]['ratio'] = None
    with pytest.raises(ValueError, match=f'^PT-SCHEMA: upstream function carries the PatchTrace-reserved metadata '
                                         f'key {key}$'):
        normalize(raw, pure)


def test_grouped_shape_raises_only_value_error_under_mutation(pure):
    """Graft (judge 2): the hostile-input harness over the grouped shapes; only ValueError may escape."""
    tool = Path(__file__).resolve().parents[1] / 'tools' / 'fuzz_parsers.py'
    spec = importlib.util.spec_from_file_location('fuzz_parsers_1ton', tool)
    fuzz = importlib.util.module_from_spec(spec)
    sys.modules['fuzz_parsers_1ton'] = fuzz
    spec.loader.exec_module(fuzz)
    seeds = [json.dumps(build(pure[0])).encode() for build in (d1, d2, d3)]
    target = fuzz.Target('ghidriff-1ton', lambda _stack, _tmp: lambda data: normalize_ghidriff(
        fuzz_json(data), *pure), lambda: seeds, (ValueError,))
    report = fuzz.run_target(target, iterations=150, seed=3, time_budget=None, crash_dir=None)
    assert report.iterations == 150 and [(f.kind, f.detail) for f in report.findings] == []


def fuzz_json(data: bytes):
    from patchtrace.persistence import strict_json
    return strict_json(data.decode('utf-8', 'replace'))


# --- service level ------------------------------------------------------------------------------------------------

@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    project = ProjectService.create(older, newer, 'Comparison', tmp_path / 'project')
    yield project
    project.close()


def imported(service, tmp_path, builder=d1):
    path = tmp_path / 'diff.ghidriff.json'
    path.write_text(json.dumps(builder(service.project)), encoding='utf-8', newline='\n')
    service.import_diff(path)
    return rows(service.project.matches, 'ambiguous')


def test_service_imports_corrects_and_restores_one_to_many(service, tmp_path):
    ambiguous = imported(service, tmp_path)
    assert len(ambiguous) == 3
    assert service.store.load() == service.project
    validate_project(service.project)
    a, b1, b2 = (only(m) for m in ambiguous)
    context = build_context(service.project, [m.id for m in ambiguous])
    assert {e.function_id for e in context.evidence if e.side == 'older'} == {a.id}
    assert context.payload.count('return buffer[index];') == 3  # A once, B1 once, B2 once
    assert not [o for o in context.omitted if 'read_item' in o and 'unavailable' in o]
    service.correct_match(ambiguous[0].id, [a.id], [b1.id], 'modified', 'analyst choice')
    manual = [m for m in service.project.matches if m.manual]
    assert [(m.category, [f.id for f in m.older], [f.id for f in m.newer]) for m in manual] == [
        ('modified', [a.id], [b1.id])]
    assert [only(m).id for m in rows(service.project.matches, 'ambiguous')] == [b2.id]
    annotation = next(x for x in service.project.annotations if x.kind == 'match-override' and not x.stale)
    service.restore_match_override(annotation.id)
    restored = sorted((m.id, m.category, only(m).id) for m in rows(service.project.matches, 'ambiguous'))
    assert restored == sorted((m.id, m.category, only(m).id) for m in ambiguous)
    assert not any(m.manual for m in service.project.matches)


def test_swap_orientation_keeps_abstention_and_metadata(service, tmp_path):
    before = {only(m).id: (m.category, only(m).metadata) for m in imported(service, tmp_path)}
    service.swap_orientation()
    after = {only(m).id: (m.category, only(m).metadata) for m in rows(service.project.matches, 'ambiguous')}
    assert after == before
    assert {side_of(m) for m in rows(service.project.matches, 'ambiguous')} == {'older', 'newer'}
    validate_project(service.project)


def test_enrichment_and_leads_see_each_function_once(service, tmp_path):
    """Graft (judge 2): enrichment pairing ids stay unique (no 'duplicate pairing' raise), the abstained rows give no
    change signal, get_version is still ranked, and kbcorrelation never calls a matched function 'removed'."""
    ambiguous = {m.id for m in imported(service, tmp_path)}
    result = pipeline.run(service.project)
    assert result.ranking is not None
    ranked = {v.match_id for v in result.views.matches if v.pairing_id in {e.pairing_id for e in
                                                                           result.ranking.entries}}
    get_version = next(m.id for m in rows(service.project.matches, 'modified'))
    assert get_version in ranked
    assert not [s for s in result.signal_sets if s.match_id in ambiguous and s.signals]
    views = [v for v in build_views(service.project).matches if v.match_id in ambiguous]
    assert len(views) == 3 and {_change(v) for v in views} == {'ambiguous'}
    assert {_change(v) for v in build_views(service.project).matches if v.match_id not in ambiguous} == {
        'added', 'removed', 'modified'}


# --- consumers ----------------------------------------------------------------------------------------------------

def _secondary(*pairs):
    return SecondaryMatchSet(engine='rz-diff', engine_version='0.9.1', older_sha256='a' * 64, newer_sha256='b' * 64,
                             file_sha256='c' * 64, limitations=(), matches=tuple(
                                 SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=o,
                                                newer_address=n, older_name=None, newer_name=None,
                                                similarity_milli=500, similarity_text='0.5', confidence_milli=None,
                                                confidence_text=None, flags=(), algorithm='levenshtein-bytes')
                                 for o, n in pairs))


def test_reconcile_abstained_row_is_not_comparable(pure):
    out = normalize(d1(pure[0]), pure)
    report = reconcile(out, _secondary((0x180001000, 0x180001080), (0x180001600, 0x180001700)))
    status = {row.match_id: (row.status, row.note) for row in report.rows}
    for match in rows(out, 'ambiguous'):
        assert status[match.id] == ('not-comparable', 'Ghidriff abstained: one-to-many')
    assert status[rows(out, 'modified')[0].id][0] == 'agreement'
    assert [(m.older_address, m.newer_address) for m in report.secondary_only] == [(0x180001000, 0x180001080)]


def test_features_and_nway_abstain_on_the_rows(pure):
    from patchtrace.calibration.features import extract
    out = normalize(d1(pure[0]), pure)
    report = reconcile(out, _secondary((0x180001000, 0x180001080)))
    for match in rows(out, 'ambiguous'):
        assert _shape_event([match]) == 'ambiguous'
        row = extract(match, [report])
        assert row.status == 'not-comparable' and row.values == ()
        alone = extract(match, [])
        assert alone.status == 'one-sided' and 'added/removed' not in alone.reason and 'ambiguous' in alone.reason
