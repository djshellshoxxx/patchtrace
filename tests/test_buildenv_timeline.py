"""Series build-environment timeline: cells, hops, adjacency, tool-version guard, limits (DIE plan s8, s9 D7)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from patchtrace.buildenv.contracts import BuildEnvError, BuildFact, BuildFingerprint, BuiltFrom, DieSummary
from patchtrace.buildenv.copy import ROW_CHIP, TIMELINE_TOOLS_DIFFER, deck_texts
from patchtrace.buildenv.timeline import FAMILIES, build_timeline

DB = 'd' * 64


@dataclass(frozen=True)
class Build:
    ordinal: int
    label: str
    artifact_sha256: str


def builds(n: int) -> list[Build]:
    return [Build(i, f'b{i}', hashlib.sha256(bytes([i])).hexdigest()) for i in range(n)]


def die(side: str, version: str = '3.21') -> DieSummary:
    key = hashlib.sha256(f'{side}{version}'.encode()).hexdigest()
    return DieSummary(status='ok', run_id=f'r-{side}', tool_version=version, db_label=None, db_sha256=DB,
                      argv_version='diec/1', heuristics=False, cache_key=key)


def fact(key, value, version='', source='diec', certainty='signature') -> BuildFact:
    return BuildFact(key=key, value=value, version=version, source=source, certainty=certainty)


def fp(build: Build, side: str, facts, version: str = '3.21') -> BuildFingerprint:
    summary = die(side, version)
    built = BuiltFrom(pe_facts_version='pe-build-facts/1', die_cache_key=summary.cache_key)
    return BuildFingerprint(artifact_sha256=build.artifact_sha256, side=side, pe=None, die=summary,
                            facts=tuple(facts), anomalies=(), built_from=built)


class Reader:
    """Stored-row fake: (ordinal, side) -> facts, or (facts, diec version)."""

    def __init__(self, series: list[Build], rows: dict):
        self.series, self.rows = series, rows

    def fingerprint(self, sha256: str, side: str):
        ordinal = next(b.ordinal for b in self.series if b.artifact_sha256 == sha256)
        value = self.rows.get((ordinal, side))
        if value is None:
            return None
        facts, version = value if isinstance(value, tuple) else (value, '3.21')
        return fp(self.series[ordinal], side, facts, version)


def cl(version: str) -> list[BuildFact]:
    return [fact('compiler', 'MSVC', version), fact('linker', 'Microsoft Linker', version)]


def full(series: list[Build], versions: list[str]) -> Reader:
    return Reader(series, {(i, side): cl(v) for i, v in enumerate(versions) for side in ('older', 'newer')})


def row(view, family):
    return next(r for r in view.rows if r.family == family)


def test_cells_show_values_and_unknown():
    series = builds(3)
    view = build_timeline(series, full(series, ['19.29', '19.29', '19.38']))
    assert [b.label for b in view.builds] == ['b0', 'b1', 'b2']
    assert [c.state for c in row(view, 'toolchain').cells] == ['value'] * 3
    assert row(view, 'toolchain').cells[2].text == 'MSVC 19.38; Microsoft Linker 19.38'
    assert [c.state for c in row(view, 'packing').cells] == ['unknown'] * 3


def test_hops_mark_the_change_and_never_skip_a_build():
    series = builds(4)
    view = build_timeline(series, full(series, ['19.29', '19.29', '19.38', '19.38']))
    assert [h.verdict for h in view.hops] == ['same', 'differs', 'same']
    assert view.change_after == (1,)
    assert [h.note for h in view.hops] == ['', ROW_CHIP, '']


def test_non_adjacent_builds_are_never_compared():
    series = builds(5)
    view = build_timeline(series, full(series, ['19.29'] * 4 + ['19.38']))
    assert [(h.from_ordinal, h.to_ordinal) for h in view.hops] == [(0, 1), (1, 2), (2, 3), (3, 4)]


def test_missing_row_is_not_run_not_a_difference():
    series = builds(3)
    reader = full(series, ['19.29', '19.29', '19.38'])
    del reader.rows[(1, 'older')], reader.rows[(1, 'newer')]
    view = build_timeline(series, reader)
    assert [c.state for c in row(view, 'toolchain').cells] == ['value', 'not-run', 'value']
    assert [h.verdict for h in view.hops] == ['not-run', 'not-run']
    assert view.change_after == ()


def test_one_missing_side_of_a_hop_is_not_run():
    series = builds(3)
    reader = full(series, ['19.29', '19.38', '19.38'])
    del reader.rows[(1, 'newer')]
    view = build_timeline(series, reader)
    assert [h.verdict for h in view.hops] == ['not-run', 'same']
    assert row(view, 'toolchain').cells[1].state == 'value'  # the older-side row still fills the cell


def test_tool_version_change_shows_a_note_instead_of_a_comparison():
    series = builds(3)
    reader = full(series, ['19.29', '19.38', '19.38'])
    reader.rows[(1, 'newer')] = (cl('19.38'), '3.20')
    view = build_timeline(series, reader)
    assert view.hops[0].verdict == 'tools-differ'
    assert view.hops[0].note == TIMELINE_TOOLS_DIFFER
    assert view.change_after == ()


def test_header_only_difference_is_unknown_and_unmarked():
    series = builds(3)

    def header(v):
        return [fact('linker_field', v, source='pe-header', certainty='exact-field')]

    rows = {(i, s): header(v) for i, v in enumerate(['14.29', '14.38', '14.38']) for s in ('older', 'newer')}
    view = build_timeline(series, Reader(series, rows))
    assert [h.verdict for h in view.hops] == ['unknown', 'unknown']
    assert view.change_after == ()


def test_heuristic_facts_never_fill_a_cell():
    series = builds(3)
    reader = full(series, ['19.29'] * 3)
    reader.rows[(0, 'older')] = [fact('packer', 'UPX', certainty='heuristic')]
    reader.rows[(0, 'newer')] = [fact('packer', 'UPX', certainty='heuristic')]
    assert row(build_timeline(series, reader), 'packing').cells[0].state == 'unknown'


def test_untrusted_text_is_bounded():
    series = builds(3)
    reader = full(series, ['19.29'] * 3)
    reader.rows[(0, 'newer')] = [fact('compiler', 'x' * 200, 'y' * 120), fact('linker', 'z' * 200, 'w' * 120)]
    cell = row(build_timeline(series, reader), 'toolchain').cells[0]
    assert 0 < len(cell.text) <= 200


@pytest.mark.parametrize('count, code', [(2, 'PT-BUILD-INPUT'), (9, 'PT-BUILD-LIMIT')], ids=['short', 'long'])
def test_series_size_is_bounded(count, code):
    series = builds(count)
    with pytest.raises(BuildEnvError) as err:
        build_timeline(series, full(series, ['1'] * count))
    assert err.value.code == code


def test_family_rows_are_stable_and_texts_pass_the_sweep():
    series = builds(3)
    view = build_timeline(series, full(series, ['1', '1', '1']))
    assert [r.family for r in view.rows] == list(FAMILIES)
    assert TIMELINE_TOOLS_DIFFER in deck_texts()
