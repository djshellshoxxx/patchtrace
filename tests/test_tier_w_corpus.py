"""SPEC-33 s3: Winbindex catalogue, resolve and pair/manifest builder. Recorded afd.sys fixture + synthetic
Winbindex-shaped documents only (no network, no Microsoft binaries)."""
from __future__ import annotations

import json
import sys

import pytest
from tier_w_builders import AFD, ROOT, gz, monthly_line, sha, wb_doc, wb_entry

from patchtrace.acquisition.contracts import AcquisitionError, symbol_server_url

sys.path.insert(0, str(ROOT))
from tools.calibration.contracts import load_manifest  # noqa: E402
from tools.calibration.tier_w import catalogue as C  # noqa: E402
from tools.calibration.tier_w import pairs as P  # noqa: E402
from tools.calibration.tier_w.contracts import load_catalogue, load_pairs  # noqa: E402
from tools.calibration.tier_w.paths import TierWError, dumps  # noqa: E402

DIRECT = '7f145acc6cd255c5b21b64c6e0f84c487738bacbc7a8e5f812bc40368e6d70eb'
DELTA = 'a151f2258bf5d5748f1cd25b536dc5412e72a5418b319bfd01bc033c5225236a'
OLD1 = '6df5003f77eaa67ff27abe66711b65a7d837860e1f5ac590c4175e82b1c3dfb2'
OLD2 = 'b15c7e83e6d0'


def afd() -> C.Catalogue:
    return C.build_catalogue(gz(json.loads(AFD.read_text(encoding='utf-8'))), 'afd.sys', '2026-10-12',
                             retrieved_at='2026-10-12T00:00:00Z')


def cat_of(name: str, *entries, family=None) -> C.Catalogue:
    return C.build_catalogue(gz(wb_doc(*entries)), name, '2026-10-01', family=family)


def test_afd_catalogue_lines_and_roundtrip():
    cat = afd()
    assert cat.family == 'driver' and cat.skipped == 0 and cat.non_x64 == 0 and len(cat.builds) == 4
    by = {b.sha256: b for b in cat.builds}
    assert by[DIRECT].lines['11-26H1'][0].kind == 'preview' and by[DIRECT].lines['11-26H1'][0].date == '2026-09-22'
    old = by[OLD1].lines['1507']
    assert [k.kb for k in old][:2] == ['KB5005569', 'KB5006675'] and old[0].release == '10240.19060'
    assert by[DELTA].download == 'candidates' and by[DELTA].size_of_image is None
    assert load_catalogue(dumps(cat.model_dump(mode='json'))) == cat


def test_catalogue_strict_and_bounded():
    good = wb_entry('a', lines={'11-24H2': [('KB1', '2025-01-14', '26100.1', 'x')]})
    bad_line = wb_entry('b', lines={'bad line!': [('KB2', '2025-01-14', '26100.2', 'x')]})
    odd = wb_entry('c', lines={'11-24H2': [('KB3', '14/01/2025', 'v', None)]})
    arm = wb_entry('d', machine=43620, lines={'11-24H2': [('KB4', '2025-01-14', '26100.4', 'x')]})
    cat = cat_of('afd.sys', good, bad_line, odd, arm)
    by = {b.sha256: b for b in cat.builds}
    assert cat.non_x64 == 1 and cat.dropped_kbs == 1 and set(by) == {sha('a'), sha('b'), sha('c')}
    assert by[sha('c')].lines['11-24H2'][0].date is None and by[sha('c')].lines['11-24H2'][0].release is None
    assert C.kb_kind('KB9', 'March 1, 2026 Out-of-band') == 'oob' and C.kb_kind('BASE', None) == 'base'
    with pytest.raises(TierWError):
        C.build_catalogue(b'not gzip', 'afd.sys', '2026-10-01')
    with pytest.raises(TierWError):
        C.family_of('foo.dll')
    assert C.family_of('foo.dll', {'foo.dll': 'usermode-dll'}) == 'usermode-dll'


def test_resolve_uses_probe_and_budget():
    cat = afd()
    urls_seen = []

    def probe(urls):
        urls_seen.append(urls)
        return urls[2]
    resolved, stats = C.resolve_candidates(cat, probe, max_probes=256)
    by = {b.sha256: b for b in resolved.builds}
    assert stats['resolved'] == 1 and len(urls_seen) == 1
    size = by[DELTA].resolved_virtual_size
    assert urls_seen[0][2] == symbol_server_url('afd.sys', by[DELTA].timestamp, size)
    _, stats = C.resolve_candidates(cat, probe, max_probes=1)
    assert stats['over-budget'] == 1

    def missing(urls):
        raise AcquisitionError('PT-ACQ-NOTFOUND', 'no')
    assert C.resolve_candidates(cat, missing, max_probes=256)[1]['not-found'] == 1


def test_afd_pairs_lines_and_cross():
    cat = afd()
    plan = P.plan_file(cat, P.PairParams())
    assert plan.lines == ('1507',) and plan.exclusions['download-candidates'] == 1
    assert [(p['older'].sha256, p['newer'].sha256[:12]) for p in plan.pairs] == [(OLD1, OLD2)]
    both = P.plan_file(cat, P.PairParams(lines=('1507', '11-26H1')))
    kinds = {(p['kind'], p['newer'].sha256) for p in both.pairs}
    assert ('cross-version', DIRECT) in kinds
    cross = next(p for p in both.pairs if p['kind'] == 'cross-version')
    assert cross['older'].sha256.startswith(OLD2) and 'stratum:large-rewrite' in cross['tags']
    resolved, _ = C.resolve_candidates(cat, lambda urls: urls[0], max_probes=256)
    plan2 = P.plan_file(resolved, P.PairParams(lines=('11-26H1',)))
    assert [(p['older'].sha256, p['newer'].sha256) for p in plan2.pairs] == [(DELTA, DIRECT)]
    assert plan2.pairs[0]['newer_kbs'][0].kb == 'KB5124006'


def test_adjacent_window_since_security_and_dedupe():
    shared = {i: {'11-23H2': [(f'KB2{i}', f'2024-{i + 1:02d}-10', f'22631.{100 + i}', 'x')]} for i in range(5)}
    entries = monthly_line('n', '11-22H2', 22621, 5, shared=shared)
    entries[3] = wb_entry('n3', ts=1003, version='10.0.22621.103 (x)', lines={
        '11-22H2': [('KB2262103', '2024-04-23', '22621.103', 'April 23, 2024 Preview')],
        '11-23H2': [('KB23', '2024-04-23', '22631.103', 'Preview')]})
    cat = cat_of('afd.sys', *entries)
    plan = P.plan_file(cat, P.PairParams(max_adjacent=2, cross=False))
    assert set(plan.lines) == {'11-22H2', '11-23H2'}
    assert len(plan.pairs) == 2  # identical pairs from both lines merged
    assert all(set(p['lines']) == {'11-22H2', '11-23H2'} for p in plan.pairs)
    assert [p['newer'].sha256 for p in plan.pairs] == [sha('n3'), sha('n4')]
    sec = P.plan_file(cat, P.PairParams(lines=('11-22H2',), security_only=True, max_adjacent=10))
    assert sha('n3') not in {p['newer'].sha256 for p in sec.pairs}
    late = P.plan_file(cat, P.PairParams(lines=('11-22H2',), since='2024-04-01', max_adjacent=10))
    assert [p['newer'].sha256 for p in late.pairs] == [sha('n3'), sha('n4')]
    assert P.plan_file(cat, P.PairParams(lines=('11-22H2',), max_adjacent=0)).pairs == []


def test_cross_version_by_build_number():
    old = monthly_line('o', '22H2', 19045, 3)
    new = monthly_line('w', '11-21H2', 22000, 2, start_month=6)
    plan = P.plan_file(cat_of('afd.sys', *old, *new), P.PairParams(max_adjacent=1))
    cross = [p for p in plan.pairs if p['kind'] == 'cross-version']
    assert plan.lines == ('22H2', '11-21H2')
    assert [(p['older'].sha256, p['newer'].sha256) for p in cross] == [(sha('o2'), sha('w0'))]


def corpus(names=None):
    names = names or list(C.FAMILIES)[:6] + ['ntdll.dll']
    cats = []
    for i, name in enumerate(dict.fromkeys(names)):
        cats.append(cat_of(name, *monthly_line(f'{name}-', '11-24H2', 26100, 3 + i % 2)))
    return cats


def test_manifest_and_sidecar_valid_and_stable():
    cats = corpus()
    manifest, side = P.build_corpus(cats, P.PairParams(), corpus_id='tier-w-test', created='2026-10-14')
    m = load_manifest(json.dumps(manifest).encode())
    assert {b.tier for b in m.binaries} == {'W'} and all(b.redistribution == 'none' for b in m.binaries)
    assert all(p.id.startswith('tw.') and p.role in ('dev', 'locked-test', 'shift-test') for p in m.pairs)
    assert {lin.cluster_rule for lin in m.lineages} == {'file-name'}
    assert side.coverage.complete and set(side.coverage.classes) == {'kernel', 'driver', 'usermode-dll'}
    assert load_pairs(dumps(side.model_dump(mode='json'))) == side
    again, _ = P.build_corpus(list(reversed(cats)), P.PairParams(), corpus_id='tier-w-test', created='2026-10-14')
    assert again == manifest
    first = m.pairs[0]
    older = next(b for b in m.binaries if b.id == first.older)
    assert first.id == P.pair_id(older.file_name, older.sha256, next(b for b in m.binaries
                                                                     if b.id == first.newer).sha256)


def test_coverage_rule_and_ids():
    few = corpus(['afd.sys', 'clfs.sys', 'ntdll.dll'])
    with pytest.raises(TierWError, match='coverage'):
        P.build_corpus(few, P.PairParams(), corpus_id='tier-w-x', created='2026-10-14')
    _, side = P.build_corpus(few, P.PairParams(), corpus_id='tier-w-x', created='2026-10-14', allow_incomplete=True)
    assert not side.coverage.complete and 'class:kernel' in side.coverage.missing
    with pytest.raises(TierWError):
        P.build_corpus(few, P.PairParams(), corpus_id='calib-x', created='2026-10-14', allow_incomplete=True)
    with pytest.raises(TierWError):
        P.PairParams(recent_lines=0)
