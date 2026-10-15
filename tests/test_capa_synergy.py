"""CAP-2 synergy: what the capa pair delta adds over the Ghidriff pairing and over the whole-file capa inventory.

Inputs are REAL capa 9.4.0 output on the SYNTHETIC `capa-api` / `capa-control` pairs plus DERIVED variants (labelled in
`fixtures/intel_tools/capa/MANIFEST.capa-v2.json`). Pairing RVAs follow the CAP plan section 5. A plumbing proof, not
accuracy evidence: the value gate stays `unvalidated`. The hypothesis-context leg belongs to CAP-7."""
from __future__ import annotations

import json
import os

import pytest
from intel_tools_support import FIXTURES, golden, image_getter
from test_capa_pairs import group, pairs, run_for

from patchtrace.intelligence.tools import capa, delta
from patchtrace.intelligence.tools.capa_pairs import groups_from_project
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.models import FunctionMatch, FunctionRecord

BASE = 0x140000000
EXPECTED = FIXTURES / 'expected-pairs-capa-api.json'


@pytest.fixture
def images(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


def parsed(images, pair, side, name=None):
    copy, _reader, pe = images(pair, side)
    ctx = capa.ParseContext(f'run-{side}', side, copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
    return capa.parse(golden(f'capa/{name or f"{pair}-{side}"}.json'), ctx)


def record(address: int, name: str) -> FunctionRecord:
    return FunctionRecord(id=f'fn-{address:x}', artifact_id='a', run_id='r', name=name, address=f'{BASE + address:x}',
                          address_space='virtual')


def match(mid: str, category: str, older=(), newer=()) -> FunctionMatch:
    return FunctionMatch(id=mid, run_id='r', category=category, older=[record(a, f'o_{a:x}') for a in older],
                         newer=[record(a, f'n_{a:x}') for a in newer])


# Ghidriff's view of capa-api: four changed pairs, and three unchanged pairs that only the raw address table lists.
CHANGED = [match('main', 'modified', [0x1000], [0x1000]), match('log', 'modified', [0x108b], [0x1096]),
           match('env', 'added', newer=[0x1030]), match('term', 'removed', older=[0x104d])]
UNCHANGED_RAW = {'address_matches': {f'{BASE + o:x}': [[f'{BASE + n:x}', ['SymbolsHash']]]
                                     for o, n in ((0x1030, 0x1053), (0x1065, 0x1070), (0x108e, 0x10bc))}}


def api_delta(images, **kw):
    older, newer = parsed(images, 'capa-api', 'older'), parsed(images, 'capa-api', 'newer')
    groups = groups_from_project(CHANGED, UNCHANGED_RAW, (BASE, BASE))
    return older, newer, groups, pairs(older, newer, groups, **kw)


def test_pair_delta_equals_the_committed_golden(images):
    *_unused, result = api_delta(images, include_unchanged=True)
    text = json.dumps(result.model_dump(mode='json'), indent=2, sort_keys=True) + '\n'
    if os.environ.get('PATCHTRACE_REGENERATE_GOLDENS') == '1':
        EXPECTED.write_text(text, encoding='utf-8', newline='\n')
    assert text == EXPECTED.read_text(encoding='utf-8')


def test_the_combined_channel_names_four_changes_and_two_unplaced_behaviours(images):
    *_unused, result = api_delta(images)
    changed = {(c.rule_id, c.group_id.split(':')[1][:4], c.change) for c in result.changes if c.kind == 'capability'}
    assert changed == {('write file on Windows', 'log', 'gained'), ('query environment variable', 'env', 'gained'),
                       ('terminate process', 'term', 'lost')}
    assert result.counts == {'gained': 2, 'lost': 1, 'moved': 0, 'unchanged': 2, 'not-compared': 0,
                             'detection-difference': 0}
    assert {(u.rule_id, u.reason, u.change) for u in result.unattributed} == {
        ('link function at runtime on Windows', 'instruction-scope', 'unchanged'),
        ('contain a thread local storage (.tls) section', 'file-scope', 'gained')}
    assert result.coverage.matched_groups == 5 and result.coverage.both_evaluated == 5
    log = next(c for c in result.changes if c.rule_id == 'write file on Windows')
    assert log.match_id == 'log' and (log.newer.links[0].rva, log.older.state) == (0x1096, 'absent')
    assert any(f.kind == 'api' for f in log.newer.features)


def test_whole_file_inventory_has_no_pair_unknown_or_moved_state(images):
    older, newer, groups, result = api_delta(images)
    pairing = FunctionPairing.from_project(CHANGED, UNCHANGED_RAW, older_base=BASE, newer_base=BASE)
    inventory = delta.compute(run_for('older', older), older, run_for('newer', newer), newer, pairing=pairing)
    assert all(not hasattr(c, 'group_id') for c in inventory.capabilities)
    assert sum(1 for c in inventory.capabilities if c.change != 'unchanged') >= 4
    assert result.pairing == 'available' and {c.group_id for c in result.changes} >= {'m:log', 'm:env', 'm:term'}


def test_control_pair_has_no_pair_changes(images):
    older, newer = parsed(images, 'capa-control', 'older'), parsed(images, 'capa-control', 'newer')
    assert older.coverage.evaluated and len(older.coverage.evaluated) == len(newer.coverage.evaluated)
    groups = [group(f'u:{o}:{n}', 'unchanged', [o], [n])
              for o, n in zip(older.coverage.evaluated, newer.coverage.evaluated, strict=True)]
    result = pairs(older, newer, groups)
    assert result.comparable and result.changes == () and result.unattributed == tuple(
        u for u in result.unattributed if u.change == 'unchanged')
    assert result.counts['gained'] == result.counts['lost'] == result.counts['moved'] == 0


def test_moved_capability_is_candidate_not_gain_or_loss(images):
    older = parsed(images, 'capa-api', 'older')
    newer = parsed(images, 'capa-api', 'newer', 'capa-move-derived-newer')
    groups = [group('m:host', 'modified', [0x1030], [0x1053]), group('m:helper', 'added', newer=[0x1070])]
    result = pairs(older, newer, groups)
    moved = {(c.rule_id, c.group_id, c.change, c.relocation) for c in result.changes if c.rule_id == 'get hostname'}
    assert moved == {('get hostname', 'm:host', 'moved', 'candidate'),
                     ('get hostname', 'm:helper', 'moved', 'candidate')}
    assert result.counts['moved'] == 1 and result.counts['gained'] == result.counts['lost'] == 0


def test_the_same_relocation_between_unchanged_pairs_is_detection_noise(images):
    older = parsed(images, 'capa-api', 'older')
    newer = parsed(images, 'capa-api', 'newer', 'capa-move-derived-newer')
    groups = [group('u:1', 'unchanged', [0x1030], [0x1053]), group('u:2', 'unchanged', [0x1065], [0x1070])]
    result = pairs(older, newer, groups)
    host = [c for c in result.changes if c.rule_id == 'get hostname']
    assert {(c.change, c.noise) for c in host} == {('lost', 'detection-difference'),
                                                   ('gained', 'detection-difference')}
    assert result.counts['moved'] == 0 and result.counts['detection-difference'] == 2


def test_library_function_is_not_a_lost_capability(images):
    older = parsed(images, 'capa-api', 'older', 'capa-library-derived-older')
    newer = parsed(images, 'capa-api', 'newer', 'capa-library-derived-newer')
    result = pairs(older, newer, [group('m:host', 'modified', [0x1030], [0x1053])])
    host = next(c for c in result.changes if c.rule_id == 'get hostname')
    assert host.change == 'not-compared' and host.older.reason == 'library-function'
    assert host.older.state == 'not-evaluated' and host.newer.state == 'present'
    assert result.counts['gained'] == 0 and result.coverage.older_library == 1


def test_unrecovered_function_is_not_compared(images):
    older = parsed(images, 'capa-api', 'older', 'capa-library-derived-older')   # derived: 0x1065 not recovered
    newer = parsed(images, 'capa-api', 'newer')
    # a hand-made pair: the unrecovered older function against the newer function that holds a match
    result = pairs(older, newer, [group('m:dyn', 'modified', [0x1065], [0x1096])])
    row = next(c for c in result.changes if c.rule_id == 'write file on Windows')
    assert row.change == 'not-compared' and row.older.reason == 'function-not-recovered'
    assert result.coverage.older_not_recovered == 1 and result.counts['gained'] == 0


def test_swapping_orientation_swaps_gained_and_lost(images):
    older, newer, groups, straight = api_delta(images)
    flipped = [group(g.group_id, g.category, g.newer_rvas, g.older_rvas) for g in groups]
    swapped = pairs(newer, older, flipped)
    flip = {'gained': 'lost', 'lost': 'gained'}
    assert {(c.rule_id, c.group_id, c.change) for c in swapped.changes} == {
        (c.rule_id, c.group_id, flip.get(c.change, c.change)) for c in straight.changes}
    assert (swapped.counts['gained'], swapped.counts['lost']) == (straight.counts['lost'], straight.counts['gained'])


def test_absence_never_contradicts(images):
    older = parsed(images, 'capa-api', 'older', 'capa-library-derived-older')
    newer = parsed(images, 'capa-api', 'newer', 'capa-library-derived-newer')
    groups = [group('m:host', 'modified', [0x1030], [0x1053]), group('m:dyn', 'unchanged', [0x1065], [0x1070])]
    result = pairs(older, newer, groups, include_unchanged=True)
    assert not [c for c in result.changes if c.change in ('lost', 'gained') and c.older.state == 'not-evaluated']
    assert 'dyn' not in {c.group_id for c in result.changes}   # no match there: nothing is said about it
