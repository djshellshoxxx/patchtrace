"""RD-F03: original-byte reconstruction, conservative ambiguity and deterministic operation bounds."""
from __future__ import annotations

import hashlib
import random
from dataclasses import replace

import pytest

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.representations import (
    MAX_PAGE_SIZE,
    AlignmentLimits,
    Segment,
    align_bytes,
    align_pages,
    byte_diff_mask,
    file_range,
    function_rva,
    read_page,
)
from patchtrace.representations.scope import MAX_INT


def exact(result, older, newer, old_base=0, new_base=0):
    """Independent byte/range oracle, also valid for incomplete outcomes."""
    assert b''.join(s.older for s in result.spans) == older
    assert b''.join(s.newer for s in result.spans) == newer
    o, n = old_base, new_base
    for span in result.spans:
        assert (span.older_offset, span.newer_offset) == (o, n)
        assert span.older or span.newer
        if span.kind == 'equal':
            assert span.older == span.newer
        if span.kind == 'insert':
            assert span.older == b'' and span.newer
        if span.kind == 'delete':
            assert span.newer == b'' and span.older
        o, n = o + len(span.older), n + len(span.newer)
    assert (o, n) == (old_base + len(older), new_base + len(newer))


@pytest.mark.parametrize('insertion', [True, False], ids=['insert', 'delete'])
def test_shift_resynchronizes_exact_original_file_offsets(insertion):
    plain = bytes(range(96))
    edited = plain[:32] + b'\xfa\xfb\xfc' + plain[32:]
    older, newer = (plain, edited) if insertion else (edited, plain)
    bases = (0x1_0000_0010, 0x280)
    result = align_bytes(older, newer, older_offset=bases[0], newer_offset=bases[1])
    assert result.status == 'complete' and result.reason is None
    assert [s.kind for s in result.spans] == ['equal', 'insert' if insertion else 'delete', 'equal']
    gap = result.spans[1]
    assert (gap.older_offset, gap.newer_offset) == (bases[0] + 32, bases[1] + 32)
    assert gap.newer == b'\xfa\xfb\xfc' if insertion else gap.older == b'\xfa\xfb\xfc'
    exact(result, older, newer, *bases)
    assert len(byte_diff_mask(older, newer)) > 3  # Legacy positional behavior deliberately remains unchanged.


@pytest.mark.parametrize('older,newer,kinds', [
    (b'', b'', []), (b'', b'abc', ['insert']), (b'abc', b'', ['delete']),
    (b'abc', b'abc', ['equal']), (b'abX', b'abY', ['equal', 'replace']),
    (bytes(range(80)), bytes(range(32)) + b'XXXX' + bytes(range(36, 80)), ['equal', 'replace', 'equal']),
], ids=['empty', 'empty-old', 'empty-new', 'identical', 'short-replace', 'replace'])
def test_positional_cases_do_not_need_a_guessed_shift(older, newer, kinds):
    result = align_bytes(older, newer)
    assert result.status == 'complete'
    assert [s.kind for s in result.spans] == kinds
    exact(result, older, newer)


@pytest.mark.parametrize('older,newer', [
    (b'prefixX' + b'A' * 80, b'prefixY' + b'A' * 80),
    (b'A' * 32, b'A' * 33),
    (b'ABCD' * 8 + bytes(range(32)), b'ABCD' * 9 + bytes(range(32))),
], ids=['repeated-window', 'sliding-tail', 'sliding-block'])
def test_repeated_bytes_do_not_get_an_arbitrary_unique_alignment(older, newer):
    for a, b in ((older, newer), (newer, older)):
        result = align_bytes(a, b)
        assert result.status == 'ambiguous'
        assert result.reason in ('repeated-anchor', 'repeat-boundary')
        assert result.spans[-1].kind == 'unresolved'
        exact(result, a, b)


def test_conflicting_displacements_do_not_silently_choose_a_function_like_block():
    old = bytes(range(128))
    new = old[:20] + b'\xfa' + old[20:80] + b'\xfb' + old[80:]
    result = align_bytes(old, new)
    assert (result.status, result.reason) == ('ambiguous', 'conflicting-shifts')
    exact(result, old, new)


@pytest.mark.parametrize('old,new,limit', [
    (bytes(range(64)), bytes(range(192, 256)), 4096),
    (bytes(range(64)), b'\xff' * 9 + bytes(range(64)), 8),
    (bytes(range(64)), b'\xff' + bytes(range(64)), 0),
], ids=['unrelated', 'beyond-window', 'zero-window'])
def test_no_anchor_is_explicit_and_keeps_every_unresolved_byte(old, new, limit):
    result = align_bytes(old, new, limits=AlignmentLimits(max_shift=limit))
    assert (result.status, result.reason) == ('unaligned', 'no-anchor-in-window')
    assert result.spans[-1].kind == 'unresolved'
    exact(result, old, new)


def test_budget_and_span_limits_retain_the_original_tail():
    old, new = bytes(range(80)), bytes(range(32)) + b'\xff' + bytes(range(32, 80))
    for limits, reason in ((AlignmentLimits(max_work=5), 'work-limit'),
                           (AlignmentLimits(max_spans=1), 'span-limit'),
                           (AlignmentLimits(max_spans=2), 'span-limit')):
        result = align_bytes(old, new, limits=limits)
        assert (result.status, result.reason) == ('limited', reason)
        assert result.work_used <= limits.max_work and len(result.spans) <= limits.max_spans
        exact(result, old, new)
    result = align_bytes(b'A' * MAX_PAGE_SIZE, b'A' * MAX_PAGE_SIZE)
    assert result.status == 'complete' and len(result.spans) == 1
    assert result.work_used == MAX_PAGE_SIZE


def test_cancel_before_and_during_search_never_publishes_a_pending_anchor():
    old, new = bytes(range(80)), bytes(range(32)) + b'\xff' + bytes(range(32, 80))
    result = align_bytes(old, new, cancel=lambda: True)
    assert result.status == 'cancelled' and result.work_used == 0
    exact(result, old, new)
    polls = 0

    def cancel():
        nonlocal polls
        polls += 1
        return polls == 40

    result = align_bytes(old, new, cancel=cancel)
    assert result.status == 'cancelled' and result.work_used > 0
    assert [s.kind for s in result.spans] == ['equal', 'unresolved']
    exact(result, old, new)


def test_callback_failure_is_not_misreported_as_a_comparison():
    def broken():
        raise RuntimeError('callback broke')
    with pytest.raises(RuntimeError, match='callback broke'):
        align_bytes(b'a', b'b', cancel=broken)


@pytest.mark.parametrize('kwargs', [
    {'older_offset': True}, {'newer_offset': -1}, {'older_offset': 1.5}, {'newer_offset': MAX_INT},
    {'older_offset': MAX_INT + 1},
])
def test_file_offsets_are_strict_and_overflow_checked(kwargs):
    with pytest.raises(ValueError):
        align_bytes(b'abc', b'def', **kwargs)


@pytest.mark.parametrize('kwargs', [
    {'max_work': 0}, {'max_work': 2_000_001}, {'max_shift': 4097}, {'anchor_size': 7},
    {'anchor_size': 65}, {'max_spans': 0}, {'max_spans': 4097}, {'max_shift': True},
])
def test_resource_limits_cannot_disable_the_hard_bounds(kwargs):
    with pytest.raises(ValueError):
        AlignmentLimits(**kwargs)


def test_input_type_and_page_cap_are_checked_before_work():
    with pytest.raises(TypeError):
        align_bytes(bytearray(b'abc'), b'abc')
    with pytest.raises(ValueError):
        align_bytes(b'A' * (MAX_PAGE_SIZE + 1), b'')


def test_verified_pages_keep_physical_bases_and_refuse_noncontiguous_or_malformed_pages(tmp_path):
    pages = []
    for i, (prefix, data) in enumerate(((b'P' * 64, bytes(range(80))),
                                      (b'Q' * 96, bytes(range(32)) + b'\xff' + bytes(range(32, 80))))):
        path = tmp_path / f'{i}.bin'
        path.write_bytes(prefix + data)

        class Mapping:
            def __init__(self, offset):
                self.offset = offset

            def rva_to_file_ranges(self, rva, length):
                assert rva == 0x7000_0000
                return (Segment(self.offset, length),)

        with VerifiedArtifactReader.open_path(path) as reader:
            scope = function_rva(Mapping(len(prefix)), 0x7000_0000, len(data)) if i == 0 else file_range(
                reader.size, len(prefix), len(data))
            pages.append(read_page(reader, scope, 0, 128))
    result = align_pages(*pages)
    assert result.status == 'complete'
    exact(result, pages[0].data, pages[1].data, 64, 96)
    for bad in (replace(pages[0], chunks=((64, b'a'), (800, b'b')), byte_count=2,
                        sha256=hashlib.sha256(b'ab').hexdigest()),
                replace(pages[0], chunks=()), replace(pages[0], byte_count=79),
                replace(pages[0], sha256='0' * 64),
                replace(pages[0], scope=replace(pages[0].scope, available=False)),
                replace(pages[0], chunks=((pages[0].scope.rva, pages[0].data),)),
                replace(pages[0], logical_start=99), replace(pages[0], page_index=-1),
                replace(pages[0], page_count=99), replace(pages[0], scope=None),
                replace(pages[0], scope=replace(pages[0].scope, total_length=81))):
        with pytest.raises(ValueError):
            align_pages(bad, pages[1])


def test_page_adapter_validates_later_page_coordinates_and_bounded_scope_metadata(tmp_path):
    path = tmp_path / 'paged.bin'
    path.write_bytes(bytes(range(128)))
    with VerifiedArtifactReader.open_path(path) as reader:
        scope = file_range(reader.size, 32, 67)
        page = read_page(reader, scope, 1, 32)
        last = read_page(reader, scope, 2, 32)
    assert align_pages(page, page).spans[0].older_offset == 64
    assert align_pages(last, last).spans[0].older == bytes(range(96, 99))
    for bad in (replace(page, logical_start=31), replace(page, page_index=True),
                replace(page, page_count=4), replace(page, byte_count=True),
                replace(page, scope=replace(scope, segments=(Segment(32, 40), Segment(50, 27)))),
                replace(page, scope=replace(scope, segments=(Segment(32, 0), Segment(32, 67)))),
                replace(page, scope=replace(scope, segments=(Segment(32, True),))),
                replace(page, scope=replace(scope, segments=(Segment(0, 1),) * 4097)),
                replace(page, scope=replace(scope, file_size=64))):
        with pytest.raises(ValueError):
            align_pages(bad, page)


def test_deterministic_generated_edits_reconstruct_both_sides_without_semantic_assumptions():
    rng = random.Random(381)
    for _ in range(100):
        old = rng.randbytes(rng.randrange(0, 180))
        at = rng.randrange(len(old) + 1)
        new = old[:at] + rng.randbytes(rng.randrange(0, 12)) + old[at + rng.randrange(0, 12):]
        limits = AlignmentLimits(max_work=5000, max_shift=64, max_spans=10)
        result = align_bytes(old, new, older_offset=21, newer_offset=83, limits=limits)
        assert result == align_bytes(old, new, older_offset=21, newer_offset=83, limits=limits)
        assert len(result.spans) <= 10 and result.work_used <= 5000
        exact(result, old, new, 21, 83)
