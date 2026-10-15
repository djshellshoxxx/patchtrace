"""Synergy of the two channels and the noise map on a toolchain swap (DIE plan s5). Behaviour on synthetic data:
annotation, counts and ordering rules, not effectiveness (that is gate G-DIE-1)."""
from __future__ import annotations

import hashlib
import json

import pytest
from pe_build_fixtures import BuildSpec, build_with_facts
from pe_builder import CODE, PeSpec, SectionSpec, build_pe
from test_buildenv_support import FIXTURES, fingerprint_of, pair_fingerprints

from patchtrace.buildenv.delta import compute_delta
from patchtrace.buildenv.noise_map import RowFacts, order_rows, summary_counts, tag_rows
from patchtrace.buildenv.view_model import build_view


def load_rows() -> list[RowFacts]:
    data = json.loads((FIXTURES / 'rows-toolchain-swap.json').read_text(encoding='utf-8'))
    return [RowFacts(r['row_id'], r['group'], r['verdict'], tuple(r['classes']), r['deltas_omitted'],
                     tuple(r['limits_hit'])) for r in data['rows']]


NAMES = {r['row_id']: r['name'] for r in json.loads((FIXTURES / 'rows-toolchain-swap.json')
                                                       .read_text(encoding='utf-8'))['rows']}


def names(ids: list[str]) -> list[str]:
    return [NAMES[i] for i in ids]


@pytest.fixture
def swap(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    return older, newer, compute_delta(older, newer)


def test_toolchain_swap_explains_shape_only_rows(swap):
    older, newer, delta = swap
    assert delta.toolchain == 'differs' and delta.toolchain_corroborated
    assert set(next(c for c in delta.changes if c.key == 'compiler').basis) == {'diec'}
    assert {s for w in delta.preflight if w.code == 'toolchain-differs' for s in w.basis} == {
        'diec', 'rich-header', 'pe-header'}
    assert 'linker-version-sources-disagree' in older.anomalies  # a row status, not a notice-bar entry
    assert all('disagree' not in w.summary for w in delta.preflight)

    rows = load_rows()
    tags = tag_rows(rows, delta.toolchain)
    assert {NAMES[k]: v for k, v in tags.items()} == {'CopyBuf': 'order', 'LogMessage': 'order',
                                                      'Crc32Update': 'tag'}
    assert summary_counts(rows, tags) == (3, 5)

    engine_order = [r.row_id for r in rows]
    default = order_rows(rows, tags)
    assert names(default)[:7] == ['Init', 'ParseHeader', 'ValidateLen', 'Crc32Update', 'BuildMessage',
                                  'LogMessage', 'CopyBuf']
    grouped = order_rows(rows, tags, group_tagged_last=True)
    assert names(grouped)[:7] == ['Init', 'ParseHeader', 'ValidateLen', 'BuildMessage', 'Crc32Update',
                                  'LogMessage', 'CopyBuf']
    assert sorted(default) == sorted(grouped) == sorted(engine_order)  # all eight rows stay listed
    assert order_rows(rows, {}) == engine_order  # no tags: engine order, byte for byte


def test_each_channel_alone_explains_nothing(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain')  # PE facts alone: forgeable fields
    delta = compute_delta(older, newer)
    assert delta.toolchain == 'unknown' and 'header-only' in delta.reasons
    assert tag_rows(load_rows(), delta.toolchain) == {}
    assert delta.noise == ()
    assert {c.key for c in delta.changes if c.change == 'changed'} >= {'rich_signature', 'linker_field'}


def test_same_toolchain_controls_tag_nothing(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-same', 'same')
    delta = compute_delta(older, newer)
    assert delta.toolchain == 'same'
    rows = load_rows()
    assert tag_rows(rows, delta.toolchain) == {}
    assert order_rows(rows, {}) == [r.row_id for r in rows]
    assert build_view(older, newer, delta).state == 'B3'


def test_unknown_pair_tags_nothing(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-unknown', 'unknown')
    delta = compute_delta(older, newer)
    assert delta.toolchain == 'unknown'
    assert tag_rows(load_rows(), delta.toolchain) == {}
    assert build_view(older, newer, delta).state == 'B5'


def test_die_not_configured_tags_nothing_and_says_so(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain')
    delta = compute_delta(older, newer)
    view = build_view(older, newer, delta)
    assert view.state == 'B2' and 'not set up' in view.state_text
    assert any(w.code == 'tool-unavailable' for w in delta.preflight)
    assert tag_rows(load_rows(), delta.toolchain) == {}


def test_opt_level_pair_is_not_explained(tmp_path):
    """Same toolchain, rows differ only in shape (the -O0 versus -O2 situation): zero tags, and B3 says so."""
    older, newer = pair_fingerprints(tmp_path, 'diec-same', 'same')
    view = build_view(older, newer, compute_delta(older, newer))
    assert view.state == 'B3' and 'code can still differ' in view.state_text


def test_synergy_packed_newer_raises_one_sided_warning(tmp_path):
    """PE-facts leg only: the DiE golden for a UPX image is captured by the live gate (blocked until then)."""
    plain = build_with_facts(BuildSpec(rich=None))
    noise = b''.join(hashlib.sha256(bytes([i])).digest() for i in range(64))
    packed = build_pe(PeSpec(sections=[SectionSpec('UPX0', b'', CODE, virtual_size=0x4000, raw_size=0),
                                       SectionSpec('UPX1', noise, CODE)]))
    older, newer = fingerprint_of(tmp_path, plain, 'older'), fingerprint_of(tmp_path, packed, 'newer')
    delta = compute_delta(older, newer)
    codes = {(w.code, w.side, w.severity) for w in delta.preflight}
    assert ('packed', 'newer', 'caution') in codes and ('packed-one-side', 'newer', 'caution') in codes
    assert not any(w.side == 'older' and w.code.startswith('packed') for w in delta.preflight)
    assert delta.toolchain == 'unknown'
