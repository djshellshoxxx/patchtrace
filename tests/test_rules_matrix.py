"""R5: the test grid (YRX-integration-plan sections 7 and 8). Real YARA-X in this process stands in for the worker child
(`rules_store_support.engine_scan`; the child itself is covered by the CLI test and `test_rules_worker.py`), over the SYNTHETIC
builds of the section 5 grid. What is pinned: row-major cells, expectations that follow the rule, a file that was not read is
never a miss, a cancel keeps what was scanned, and no path reaches a record.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

import pytest
import rules_fixtures as rf
from rules_store_support import accepted, candidate_of, engine_scan

from patchtrace.rules import matrix
from patchtrace.rules.contracts import CellResult, TargetRef
from patchtrace.rules.errors import RuleError
from patchtrace.rules.limits import RuleLimits

SERIES = ('V1', 'V1r', 'V1t', 'V2')
CLEAN = ('clean-1', 'clean-2', 'clean-3', 'clean-4')


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


class World:
    """The builds of the grid as files: `series/` (V1, V1r, V1t, V2 in this order), `clean/` and the lone images."""

    def __init__(self, bench, root: Path):
        self.builds = rf.synergy_builds(bench)
        self.root = root
        self.series, self.clean = root / 'series', root / 'clean'
        for folder, names in ((self.series, SERIES), (self.clean, CLEAN)):
            folder.mkdir()
            for index, name in enumerate(names):
                (folder / f'{index}-{name}.dll').write_bytes(self.builds[name])
        self.anchors = {side: matrix.Anchor(path, path.name) for side, path in (
            ('older', self.series / '0-V1.dll'), ('newer', self.series / '3-V2.dll'))}
        self.pair = rf.capa_pair(bench, 'term')

    def entries(self, **kw):
        return matrix.gather(self.pair, self.anchors, **kw)


@pytest.fixture
def world(bench, tmp_path):
    return World(bench, tmp_path)


@pytest.fixture
def older_rule(bench):
    return accepted(candidate_of(bench, 'term'))[1]


@pytest.fixture
def newer_rule(bench):
    return accepted(candidate_of(bench, 'env'), 'Environment added')[1]


def run(entries, versions, **kw):
    return matrix.run_matrix(entries, versions, scan=engine_scan, now=lambda: '2026-10-14T10:00:00+00:00', **kw)


def by_label(grid, column: int = 0) -> dict[str, CellResult]:
    width = len(grid.rules)
    return {t.label: grid.cells[i * width + column] for i, t in enumerate(grid.targets)}


def test_the_grid_scores_each_cell_against_what_the_rule_should_do(world, older_rule):
    entries, notes = world.entries(series=world.series, clean_dir=world.clean)
    grid = run(entries, [older_rule])
    assert notes == () and grid.status == 'complete' and grid.anomalies == ()
    assert [t.role for t in grid.targets] == ['older-anchor', 'newer-anchor', 'series', 'series'] + ['clean'] * 4
    assert [t.ordinal for t in grid.targets] == [1, 2, 3, 4, None, None, None, None]
    cells = by_label(grid)
    states = {label: (cell.state, cell.verdict) for label, cell in cells.items()}
    assert states['0-V1.dll'] == ('hit', 'as-expected') and states['3-V2.dll'] == ('no-hit', 'as-expected')
    assert states['1-V1r.dll'] == ('hit', 'unscored') and states['2-V1t.dll'] == ('hit', 'unscored')   # no expectation set
    assert all(states[f'{i}-{n}.dll'] == ('no-hit', 'as-expected') for i, n in enumerate(CLEAN))
    assert cells['0-V1.dll'].rvas == (0x104d,) and cells['0-V1.dll'].hits == 1
    count = matrix.totals(grid, 0)
    assert (count.match, count.no_match, count.not_scanned, count.unexpected_hit, count.unexpected_miss) == (3, 5, 0, 0, 0)
    assert (count.builds, count.clean) == (4, 4) and grid.engine.engine == 'yara-x'


def test_cells_are_row_major_over_builds_and_rules_and_the_anchors_follow_each_rule(world, older_rule, newer_rule):
    entries, _ = world.entries(series=world.series)
    grid = run(entries, [older_rule, newer_rule])
    assert [r.version_id for r in grid.rules] == [older_rule.version_id, newer_rule.version_id]
    assert len(grid.cells) == len(grid.targets) * 2
    older, newer = by_label(grid, 0), by_label(grid, 1)
    assert (older['0-V1.dll'].verdict, older['3-V2.dll'].verdict) == ('as-expected', 'as-expected')
    assert (newer['0-V1.dll'].state, newer['3-V2.dll'].state) == ('no-hit', 'hit')
    assert (newer['0-V1.dll'].verdict, newer['3-V2.dll'].verdict) == ('as-expected', 'as-expected')


@pytest.mark.parametrize('direction,role,expect,want', [
    pytest.param('older', 'older-anchor', 'unknown', 'hit', id='older-rule-older'),
    pytest.param('older', 'newer-anchor', 'unknown', 'no-hit', id='older-rule-newer'),
    pytest.param('newer', 'older-anchor', 'unknown', 'no-hit', id='newer-rule-older'),
    pytest.param('newer', 'newer-anchor', 'unknown', 'hit', id='newer-rule-newer'),
    pytest.param('older', 'series', 'unknown', 'unknown', id='series-unset'),
    pytest.param('older', 'series', 'no-hit', 'no-hit', id='series-set'),
    pytest.param('older', 'older-anchor', 'no-hit', 'no-hit', id='analyst-wins'),
])
def test_expectations(direction, role, expect, want):
    target = TargetRef(target_id='b1', label='x', role=role, sha256='1' * 64, size=1, ordinal=1 if role != 'clean' else None,
                       expect=expect)
    assert matrix.expected(direction, target) == want


@pytest.mark.parametrize('state,hits,wanted,verdict', [
    pytest.param('hit', 1, 'hit', 'as-expected', id='hit-hit'),
    pytest.param('no-hit', 0, 'no-hit', 'as-expected', id='miss-miss'),
    pytest.param('hit', 1, 'no-hit', 'unexpected-hit', id='hit-unwanted'),
    pytest.param('no-hit', 0, 'hit', 'unexpected-miss', id='miss-wanted'),
    pytest.param('hit', 1, 'unknown', 'unscored', id='hit-unset'),
    pytest.param('timeout', None, 'hit', 'unscored', id='timeout'),
    pytest.param('not-scanned', None, 'no-hit', 'unscored', id='unread'),
])
def test_verdict(state, hits, wanted, verdict):
    cell = CellResult(state=state, hits=hits, offsets=(1,) if state == 'hit' else (),
                      rvas=(0x1000,) if state == 'hit' else (), reason='unreadable' if state == 'not-scanned' else None)
    assert matrix.verdict(cell, wanted) == verdict


def test_an_expectations_file_turns_a_series_build_into_a_scored_row(world, older_rule, tmp_path):
    path = tmp_path / 'expect.json'
    path.write_text(json.dumps({'1-V1r.dll': 'no-hit', hashlib.sha256(world.builds['V1t']).hexdigest(): 'hit'}),
                    encoding='utf-8')
    entries, _ = world.entries(series=world.series, expect=matrix.read_expectations(path))
    cells = by_label(run(entries, [older_rule]))
    assert cells['1-V1r.dll'].verdict == 'unexpected-hit'              # the rule matches a rebuild the analyst said it must not
    assert cells['2-V1t.dll'].verdict == 'as-expected'


@pytest.mark.parametrize('text', ['[]', '{"a": "maybe"}', '{"a": 1}', 'not json', '{"x.exe": "hit", "x.exe": "hit"}',
                                  '{"x.exe": "hit", "x.exe": "unknown"}', '{"x.exe": "hit"}' + ' ' * (1 << 20),
                                  '[' * 100_000],
                         ids=['list', 'word', 'number', 'text', 'dup-same-value', 'dup-other-value', 'too-large',
                              'deep-105-rule5'])
def test_a_bad_expectations_file_is_refused(tmp_path, text):
    path = tmp_path / 'expect.json'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(RuleError) as caught:
        matrix.read_expectations(path)
    assert caught.value.code == 'PT-RULE-INPUT'
    with pytest.raises(RuleError):
        matrix.read_expectations(tmp_path / 'missing.json')


def test_a_file_that_is_gone_is_not_scanned_and_never_a_no_match(world, older_rule):
    entries, _ = world.entries(series=world.series, clean_dir=world.clean)
    (world.clean / '1-clean-2.dll').unlink()
    grid = run(entries, [older_rule])
    gone = by_label(grid)['1-clean-2.dll']
    assert (gone.state, gone.hits, gone.reason, gone.verdict) == ('not-scanned', None, 'unreadable', 'unscored')
    count = matrix.totals(grid, 0)
    assert (count.no_match, count.not_scanned, count.unexpected_miss) == (4, 1, 0)       # 3 clean + V2 only, not 4 + V2
    assert grid.status == 'partial' and grid.anomalies == ('1 cells not scanned: unreadable',)


def test_a_file_that_changed_after_it_was_hashed_is_not_scanned(world, older_rule):
    entries, _ = world.entries(series=world.series)
    (world.series / '2-V1t.dll').write_bytes(world.builds['LA'])
    cell = by_label(run(entries, [older_rule]))['2-V1t.dll']
    assert (cell.state, cell.reason) == ('not-scanned', 'file-changed')


def test_a_cancel_between_batches_keeps_what_was_scanned(world, older_rule):
    entries, _ = world.entries(series=world.series, clean_dir=world.clean)
    cancel, calls = threading.Event(), []

    def scan_once(rules, targets, **kw):
        calls.append(len(targets))
        cancel.set()                                                    # the analyst pressed Cancel during the first batch
        return engine_scan(rules, targets, **kw)
    grid = matrix.run_matrix(entries, [older_rule], scan=scan_once, cancel=cancel, batch=3,
                             now=lambda: '2026-10-14T10:00:00+00:00')
    assert calls == [3] and grid.status == 'cancelled' and len(grid.cells) == len(entries)
    states = [(c.state, c.reason) for c in grid.cells]
    assert states[:3] == [('hit', None), ('no-hit', None), ('hit', None)]
    assert set(states[3:]) == {('not-scanned', 'cancelled')} and grid.anomalies == ()


def test_a_cancel_before_anything_ran_is_a_cancel(world, older_rule):
    entries, _ = world.entries(series=world.series)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(RuleError) as caught:
        matrix.run_matrix(entries, [older_rule], scan=engine_scan, cancel=cancel)
    assert caught.value.code == 'PT-RULE-CANCEL'


def test_a_worker_failure_is_not_a_partial_grid(world, older_rule):
    entries, _ = world.entries(series=world.series)

    def broken(rules, targets, **kw):
        raise RuleError('PT-RULE-ENGINE', 'The rule worker failed', reason='worker-crash')
    with pytest.raises(RuleError) as caught:
        matrix.run_matrix(entries, [older_rule], scan=broken, batch=1)
    assert caught.value.code == 'PT-RULE-ENGINE'


def test_a_saved_rule_that_no_longer_compiles_stops_the_run(world, older_rule):
    entries, _ = world.entries(series=world.series)
    fake = older_rule.model_copy(update={'rule_text': older_rule.rule_text.replace('and $b', 'and $nothing')})
    with pytest.raises(RuleError) as caught:
        run(entries, [fake])
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-COMPILE', 'lint')


def test_a_run_needs_rules_and_files(world, older_rule):
    entries, _ = world.entries(series=world.series)
    for rules, files in (([], entries), ([older_rule], ())):
        with pytest.raises(RuleError) as caught:
            matrix.run_matrix(files, rules, scan=engine_scan)
        assert caught.value.reason == 'empty-request'


def test_a_stored_run_is_scored_again_with_new_expectations_and_the_key_ignores_them(world, older_rule):
    entries, _ = world.entries(series=world.series)
    grid = run(entries, [older_rule])
    changed = [e.target.model_copy(update={'expect': 'no-hit' if e.target.label == '1-V1r.dll' else e.target.expect})
               for e in entries]
    again = matrix.rescored(grid, changed, [older_rule])
    assert by_label(again)['1-V1r.dll'].verdict == 'unexpected-hit' and by_label(grid)['1-V1r.dll'].verdict == 'unscored'
    assert [c.state for c in again.cells] == [c.state for c in grid.cells]               # what the engine said is untouched
    assert grid.cache_key == matrix.cache_key([older_rule], changed, grid.engine.version, 30)


def test_a_stored_run_reused_in_another_order_keeps_each_result_on_its_own_file_and_rule(world, older_rule, newer_rule):
    """#105 BUG-RULE-1: the key ignores order, so a reused run must remap cells by hash, not by position."""
    entries, _ = world.entries(series=world.series)
    grid = run(entries, [older_rule, newer_rule])
    targets, versions = [e.target for e in reversed(entries)], [newer_rule, older_rule]
    assert grid.cache_key == matrix.cache_key(versions, targets, grid.engine.version, 30)
    again = matrix.rescored(grid, targets, versions)
    assert [t.target_id for t in again.targets] == [t.target_id for t in targets]
    assert [r.rule_sha256 for r in again.rules] == [v.rule_sha256 for v in versions]
    was = {(t.label, r.rule_sha256): grid.cells[i * 2 + j].state
           for i, t in enumerate(grid.targets) for j, r in enumerate(grid.rules)}
    now = {(t.label, r.rule_sha256): again.cells[i * 2 + j].state
           for i, t in enumerate(again.targets) for j, r in enumerate(again.rules)}
    assert now == was
    assert (by_label(again, 1)['0-V1.dll'].verdict, by_label(again, 0)['3-V2.dll'].verdict) == ('as-expected',) * 2


def test_no_path_reaches_the_record(world, older_rule):
    entries, _ = world.entries(series=world.series, clean_dir=world.clean)
    text = run(entries, [older_rule]).model_dump_json()
    assert str(world.root) not in text and '/series/' not in text and 'tmp' not in text.replace('timeout', '')
    assert all(e.path.startswith(str(world.root)) for e in entries)         # the paths exist, beside the records, not in them


def test_the_same_content_is_one_row_and_a_second_spelling_is_noted(world, older_rule):
    (world.series / '9-copy.dll').write_bytes(world.builds['V1r'])
    (world.clean / '9-V1.dll').write_bytes(world.builds['V1'])                 # the older anchor, listed as a clean file
    entries, notes = world.entries(series=world.series, clean_dir=world.clean)
    assert [e.target.label for e in entries].count('1-V1r.dll') == 1 and '9-copy.dll' not in [e.target.label for e in entries]
    assert notes == ('same-content:9-copy.dll', 'same-content:9-V1.dll')
    assert sorted(notes) == sorted(set(notes))
    assert len({e.target.sha256 for e in entries}) == len(entries)


def test_links_are_skipped_and_folders_are_not_followed(world):
    if os.name == 'nt':
        pytest.skip('symbolic links need a privilege on Windows')
    (world.series / 'link.dll').symlink_to(world.series / '1-V1r.dll')
    (world.series / 'sub').mkdir()
    entries, _ = world.entries(series=world.series)
    assert 'link.dll' not in [e.target.label for e in entries] and 'sub' not in [e.target.label for e in entries]


def test_the_caps_of_a_run_are_enforced_before_anything_is_scanned(world):
    for index in range(10):
        (world.series / f'extra-{index}.dll').write_bytes(bytes([index]) * 64)
    with pytest.raises(RuleError) as caught:
        world.entries(series=world.series)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-LIMIT', 'series')
    with pytest.raises(RuleError) as caught:
        world.entries(extra=[world.series / '0-V1.dll'] * 65)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-LIMIT', 'extra')
    with pytest.raises(RuleError) as caught:
        world.entries(clean_dir=world.clean, limits=RuleLimits(clean_targets=3))
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-LIMIT', 'clean')
    with pytest.raises(RuleError) as caught:                                    # the anchors and the series are all rows
        world.entries(series=world.series, limits=RuleLimits(series_targets=2))
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-LIMIT', 'series')


@pytest.mark.skipif(not Path('/dev/zero').exists(), reason='needs a character device such as /dev/zero')
def test_a_device_as_an_extra_build_is_refused_without_reading_it(world):
    """#105 BUG-RULE-6: `--extra /dev/zero` (or a FIFO) was hashed with no regular-file check and never returned."""
    outcome = []

    def gather():
        try:
            world.entries(extra=[Path('/dev/zero')])
        except RuleError as exc:
            outcome.append((exc.code, exc.reason))

    worker = threading.Thread(target=gather, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive() and outcome == [('PT-RULE-INPUT', 'not-a-file')]


def test_a_file_or_folder_that_cannot_be_read_is_a_bad_selection(world, tmp_path):
    for kw in ({'extra': [tmp_path / 'missing.dll']}, {'series': tmp_path / 'missing-folder'}):
        with pytest.raises(RuleError) as caught:
            world.entries(**kw)
        assert caught.value.code == 'PT-RULE-INPUT'


def test_rescore_keeps_distinct_versions_with_identical_rule_content(world, older_rule):
    other = older_rule.__class__.model_validate({**older_rule.model_dump(), 'version_id': 'f' * 64})
    entries, _ = world.entries(series=world.series)
    grid = run(entries, [older_rule, other])
    from patchtrace.rules.contracts import MatrixRun
    cells = (CellResult(state='timeout'), CellResult(state='no-hit', hits=0), *grid.cells[2:])
    grid = MatrixRun.model_validate({**grid.model_dump(), 'cells': cells})
    again = matrix.rescored(grid, grid.targets, [other, older_rule])
    assert [r.version_id for r in again.rules] == [other.version_id, older_rule.version_id]
    assert [c.state for c in again.cells[:2]] == ['no-hit', 'timeout']
    assert MatrixRun.model_validate(again.model_dump()) == again
    renamed = other.__class__.model_validate({**other.model_dump(), 'version_id': 'e' * 64})
    with pytest.raises(RuleError) as caught:
        matrix.rescored(grid, grid.targets, [renamed, older_rule])
    assert caught.value.reason == 'cache-identity'


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='POSIX FIFO replacement regression')
def test_regular_file_replaced_by_fifo_before_open_does_not_block(tmp_path):
    import subprocess
    import sys

    path = tmp_path / 'input.bin'
    path.write_bytes(b'regular input')
    code = '''
import os, pathlib, sys
from patchtrace.rules import matrix
from patchtrace.rules.errors import RuleError
path = pathlib.Path(sys.argv[1])
real_stat = os.stat
swapped = False
def stat_then_swap(p, *args, **kwargs):
    global swapped
    info = real_stat(p, *args, **kwargs)
    if pathlib.Path(p) == path and not swapped:
        swapped = True
        path.unlink()
        os.mkfifo(path)
    return info
matrix.os.stat = stat_then_swap
try:
    matrix._digest(path)
except RuleError as exc:
    assert exc.reason == 'not-a-file'
else:
    raise AssertionError('FIFO accepted')
'''
    result = subprocess.run([sys.executable, '-c', code, str(path)], capture_output=True, text=True, timeout=3,
                            env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
    assert result.returncode == 0, result.stderr
