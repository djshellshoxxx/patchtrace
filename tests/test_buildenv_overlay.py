"""Row overlay over the noise map: tags, order, summary, pair guard and scale (DIE plan s6, s7, s9 D6)."""
from __future__ import annotations

import time

import pytest

from patchtrace.buildenv.contracts import BuildEnvDelta
from patchtrace.buildenv.copy import ROW_CHIP, SUMMARY_TEXT
from patchtrace.buildenv.noise_map import RowFacts
from patchtrace.buildenv.overlay import build_overlay, chip_detail

OLD, NEW = 'a' * 64, 'b' * 64


def delta(toolchain='differs', *, older=OLD, newer=NEW, comparable=True) -> BuildEnvDelta:
    return BuildEnvDelta(delta_id='c' * 64, older_sha256=older, newer_sha256=newer, comparable=comparable,
                         reasons=(), toolchain=toolchain, toolchain_corroborated=toolchain == 'differs',
                         options_changed=(), changes=(), preflight=(), noise=(), limits_hit=(), counts={})


def rows() -> list[RowFacts]:
    return [RowFacts('m1', 'material', 'material', ('constant',)),
            RowFacts('r1', 'review', 'review', ('frame',)),
            RowFacts('r2', 'review', 'review', ('cfg',)),
            RowFacts('r3', 'review', 'review', ('callee',)),
            RowFacts('r4', 'review', 'review', ('eh', 'size-only'))]


def overlay(d=None, **kw):
    return build_overlay(rows(), d if d is not None else delta(), older_sha256=OLD, newer_sha256=NEW, **kw)


def test_tags_and_order_for_a_differing_toolchain():
    result = overlay()
    assert dict(result.tags) == {'r1': 'order', 'r2': 'tag', 'r4': 'order'}
    assert result.order == ('m1', 'r2', 'r3', 'r1', 'r4')
    assert (result.tagged, result.review) == (3, 4)
    assert result.summary == SUMMARY_TEXT.format(n=3, total=4)
    assert result.chip('r1') == ROW_CHIP and result.chip('r3') == ''


def test_group_tagged_last_moves_tag_rows_too():
    assert overlay(group_tagged_last=True).order == ('m1', 'r3', 'r1', 'r2', 'r4')


def test_material_and_contested_never_tagged():
    result = overlay()
    assert 'm1' not in result.tags and 'r3' not in result.tags


def test_rows_with_omitted_deltas_never_tagged():
    cut = [RowFacts('x', 'review', 'review', ('frame',), deltas_omitted=2),
           RowFacts('y', 'review', 'review', ('frame',), limits_hit=('cap',))]
    result = build_overlay(cut, delta(), older_sha256=OLD, newer_sha256=NEW)
    assert not result.active and result.order == ('x', 'y')


@pytest.mark.parametrize('d', [None, delta('same'), delta('unknown'), delta(older=NEW, newer=OLD),
                               delta(older='d' * 64), delta(newer='d' * 64)],
                         ids=['none', 'same', 'unknown', 'swapped', 'other-older', 'other-newer'])
def test_no_tags_without_a_matching_differing_delta(d):
    result = build_overlay(rows(), d, older_sha256=OLD, newer_sha256=NEW)
    assert not result.active and result.summary == ''
    assert result.order == tuple(row.row_id for row in rows()) and result.chip('r1') == ''


def test_not_comparable_delta_gives_no_tags():
    assert not overlay(delta('unknown', comparable=False)).active


def test_order_is_a_permutation_and_tagged_is_a_subset_of_review_rows():
    result = overlay()
    assert sorted(result.order) == sorted(row.row_id for row in rows())
    assert set(result.tags) <= {row.row_id for row in rows() if row.verdict == 'review'}


def test_overlay_is_a_pure_function_of_its_inputs():
    assert overlay() == overlay()


def test_tags_are_read_only():
    with pytest.raises(TypeError):
        overlay().tags['m1'] = 'tag'  # type: ignore[index]


def test_chip_detail_lists_classes_and_says_context_only():
    text = chip_detail(rows()[4])
    assert 'eh, size-only' in text and 'not hidden' in text


def test_hundred_thousand_rows_within_budget():
    big = [RowFacts(f'r{i}', 'review' if i % 2 else 'material', 'review', ('frame',) if i % 3 else ('callee',))
           for i in range(100_000)]
    start = time.perf_counter()
    result = build_overlay(big, delta(), older_sha256=OLD, newer_sha256=NEW)
    elapsed = time.perf_counter() - start
    assert len(result.order) == 100_000 and result.active
    assert elapsed < 2.0  # 50 ms budget (plan s8) with a wide margin for shared CI machines
