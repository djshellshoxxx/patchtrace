"""LBL-22: Tier-W symbol-derived truth, candidate labels, tags and detail records (SPEC-33 s6). Synthetic symbol maps only."""
from __future__ import annotations

import sys

import pytest
from tier_w_builders import ROOT

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import labels as L  # noqa: E402
from tools.calibration.tier_w.contracts import MatchLine, Symbol, SymbolMap  # noqa: E402

SHA = 'ab' * 32


def sym(name, rva, size=100, aliases=0, thunk=False):
    return Symbol(name=name, rva=rva, size=size, size_source=None if size is None else 'pdb-proc', kind='private',
                  aliases=aliases, thunk=thunk, ranges=())


def smap(*symbols):
    return SymbolMap(contract='symbol-map/1', tier='test',
                     image={'file_name': 'x.dll', 'sha256': SHA, 'image_base': 0, 'size_of_image': None, 'machine': 'x64'},
                     pdb={}, producer={'tool': 'msf', 'version': '1'}, symbols=tuple(sorted(symbols, key=lambda s: s.rva)),
                     stats={'functions': len(symbols), 'unnamed': 0, 'dropped': 0})


OLDER = smap(sym('A', 0x1000), sym('B', 0x2000, aliases=1), sym('C', 0x3000), sym('D', 0x4000, size=None),
             sym('E', 0x5000), sym('F', 0x6000), sym('F', 0x7000), sym('G', 0x8000), sym('K', 0xA000, size=100))
NEWER = smap(sym('A', 0x1100, size=90), sym('B', 0x2100), sym('C', 0x3100, size=20), sym('D', 0x4100),
             sym('F', 0x6100), sym('H', 0x9000, size=50), sym('K', 0xA100, size=33))


def match(o, n, condition='symbols-hidden', mid=None, engine='ghidriff'):
    return MatchLine(contract='tier-w-matches/1', tier='test', pair='tw.x.1', engine=engine, condition=condition,
                     match_id=mid or f'm{o}-{n}', older_rva=o, newer_rva=n)


def test_truth_and_exclusions():
    truth, excluded = L.derive_truth(OLDER, NEWER)
    assert [(t.name, t.match_id) for t in truth] == [('A', 'sym:1000-1100'), ('K', 'sym:a000-a100')]
    assert {e.reason for e in excluded} == {'alias', 'size-ratio', 'no-size', 'absent-in-newer', 'non-unique',
                                            'absent-in-older'}
    by_reason = {e.reason: sorted(s.name for s in e.older + e.newer) for e in excluded}
    assert by_reason['non-unique'] == ['F', 'F', 'F'] and by_reason['absent-in-older'] == ['H']
    assert by_reason['alias'] == ['B', 'B'] and by_reason['size-ratio'] == ['C', 'C']
    assert [e.reason for e in excluded] == sorted(e.reason for e in excluded)


@pytest.mark.parametrize('ratio_min,names', [(0.33, ['A', 'K']), (0.34, ['A']), (1.0, [])],
                         ids=['default', 'k-drops', 'strict'])
def test_ratio_boundary(ratio_min, names):
    # A is 90/100 = 0.9; K is 33/100 = 0.33 exactly: kept at 0.33, dropped above it
    truth, _ = L.derive_truth(OLDER, NEWER, ratio_min)
    assert [t.name for t in truth] == names


def test_ratio_min_validated():
    with pytest.raises(ValueError):
        L.derive_truth(OLDER, NEWER, 0)


def test_candidate_labelling():
    truth, _ = L.derive_truth(OLDER, NEWER)
    matches = [match(0x1000, 0x1100), match(0x1000, 0x2100), match(0x2000, 0x1100), match(0x3000, 0x4100),
               match(0x1000, None), match(0x5000, 0x9000, 'symbols-visible')]
    got = {(c.older_rva, c.newer_rva): (c.answer, c.rule) for c in L.label_candidates(truth, matches)}
    assert got == {(0x1000, 0x1100): ('same', 'truth-pair'), (0x1000, 0x2100): ('different', 'truth-conflict'),
                   (0x2000, 0x1100): ('different', 'truth-conflict'), (0x3000, 0x4100): (None, 'no-truth')}
    assert len(L.candidate_records('tw.x.1', L.label_candidates(truth, matches))) == 3  # unlabelled never written


@pytest.mark.parametrize('name,thunk,exported,tags', [
    ('memcpy', False, False, ('N3',)), ('NtOpen', False, True, ('exported',)), ('__imp_NtOpen', False, False, ('N2',)),
    ('anything', True, True, ('exported', 'N2')), ('j_foo', False, False, ('N2',)),
    ('__security_check_cookie', False, False, ('N9',)), ('??_Efoo@@', False, False, ('N9',)),
    ('foo?dtor$0@@', False, False, ('N9',)), ('foo.cold', False, False, ('N10',)), ('foo_cold_3', False, False, ('N10',)),
    ('foo.part.2', False, False, ('N10',)), ('__acrt_x', False, False, ('N3',)), ('f@std@@', False, False, ('N3',)),
    ('__imp_memcpy.cold', False, False, ('N2',)), ('_RTC_x.part.1', False, False, ('N9',)),
    ('StringCchCopyW', False, False, ('N3',)), ('Mcfoo', False, False, ())],
    ids=['crt', 'export', 'imp', 'thunk-flag', 'j', 'cookie', 'dyn-init', 'funclet', 'cold', 'cold-n', 'part', 'acrt',
         'std', 'n2-over-n10', 'n9-over-n10', 'strsafe', 'mc-prefix-narrow'])
def test_tags(name, thunk, exported, tags):
    assert L.tags_for(name, thunk=thunk, exported=exported) == tags


def test_detail_records():
    truth, excluded = L.derive_truth(OLDER, NEWER)
    cands = L.label_candidates(truth, [match(0x1000, 0x1100), match(0x3000, 0x4100)])
    details = L.detail_records('tw.x.1', truth, excluded, cands, OLDER, NEWER, older_exports={0x1000})
    first = details[0]
    assert (first.match_id, first.A, first.rule, first.older.exported, first.older.tags) == (
        'sym:1000-1100', 'same', 'name+size', True, ('exported',))
    assert first.size_change == pytest.approx(-0.1)
    rules = {d.match_id: d.rule for d in details}
    assert rules['sym:6000-none'] == 'non-unique' and rules['sym:7000-none'] == 'non-unique'
    assert rules['sym:none-9000'] == 'absent-in-older' and rules['m12288-16640'] == 'no-truth'
    assert len({(d.kind, d.match_id) for d in details}) == len(details)
    assert all(d.tier == 'W' for d in details)


def test_truth_records_are_guard_shaped():
    from tools.calibration.tier_w.guard import LABEL_KEYS
    truth, _ = L.derive_truth(OLDER, NEWER)
    doc = L.truth_records('tw.x.1', truth)[0].model_dump()
    assert LABEL_KEYS <= set(doc) and doc['source'] == 'symbol-derived' and doc['p_incl'] == 1.0
