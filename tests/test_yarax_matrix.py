"""R5 matrix: the synthesizer binding, gates from real scan output, target collection, verdicts, resume and cancel.

Real YARA-X in the capped worker child on SYNTHETIC images (floss-static pair); fakes only where a failure is staged.
"""
from __future__ import annotations

import dataclasses
import threading

import pytest

yara_x = pytest.importorskip('yara_x')

import yarax_fixtures as fx  # noqa: E402
from intel_tools_support import image_getter  # noqa: E402

from patchtrace.yarax import candidates, matrix  # noqa: E402
from patchtrace.yarax.adapters import tools_delta  # noqa: E402
from patchtrace.yarax.contracts import CellResult, LintFinding  # noqa: E402
from patchtrace.yarax.errors import RulesError  # noqa: E402
from patchtrace.yarax.features import included_ids  # noqa: E402
from patchtrace.yarax.limits import LIMITS  # noqa: E402
from patchtrace.yarax.synth import parse_rule  # noqa: E402

PAIR = 'floss-static'


@pytest.fixture
def images(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


def real_candidates(images):
    delta, readers = fx.floss_delta(images, PAIR)
    pair = fx.pair_source(images, PAIR, match_id='m1', category='modified')
    found = candidates.propose(pair, writer=matrix.synth_writer(), engine=fx.ENGINE,
                               strings=tools_delta.FlossStringSource(delta, readers))
    return pair, {c.direction: c for c in found}


def anchor_targets(images, pair=PAIR):
    out = {}
    for side in ('older', 'newer'):
        copy = images(pair, side)[0]
        out[side] = matrix.file_target(copy.path, f'{side}-anchor', None, sha256=copy.sha256, size=copy.size)
    return out


def worker_anchors(anchors):
    return {side: target.worker() for side, target in anchors.items()}


@pytest.fixture
def engine(tmp_path):
    return matrix.worker_engine(cancel=threading.Event(), private_dir=tmp_path)


class FakeEngine:
    """Scripted engine: `lint` returns `findings`; `scan` answers from `table[(rule, target)]` and records calls."""

    def __init__(self, findings=(), table=None, default='no-hit', fail=None):
        self.findings, self.table, self.default, self.fail, self.scans = findings, table or {}, default, fail, []
        self.engine = matrix.Engine(probe=lambda: fx.ENGINE, lint=self._lint, scan=self._scan)

    def _lint(self, rules):
        return fx.ENGINE, tuple(self.findings)

    def _scan(self, rules, targets):
        self.scans.append([t.target_id for t in targets])
        if self.fail is not None:
            exc = self.fail(len(self.scans))
            if exc is not None:
                raise exc
        cells = []
        for r in rules:
            for t in targets:
                state = self.table.get((r.name, t.target_id), self.default)
                cells.append(CellResult(rule_name=r.name, target_id=t.target_id, state=state,
                                        hits=1 if state == 'hit' else 0, rvas=(0x1000,) if state == 'hit' else ()))
        return fx.ENGINE, tuple(cells)


# ---- the RuleWriter binding ------------------------------------------------------------------------------------------

def test_synth_satisfies_the_rule_writer_protocol_with_the_real_grammar(images):
    pair, found = real_candidates(images)
    assert set(found) == {'older', 'newer'}
    for direction, candidate in found.items():
        parsed = parse_rule(candidate.rule_text)
        assert parsed.name == candidate.rule_name == f'PT_{candidate.lineage_id[:12]}_{direction}'
        assert parsed.side == direction and candidate.rule_sha256


def test_writer_rejects_a_name_that_is_not_the_candidates(images):
    pair, found = real_candidates(images)
    write = matrix.synth_writer()
    with pytest.raises(RulesError) as caught:
        write(pair, direction='older', rule_name='PT_000000000000_older', features=found['older'].features)
    assert caught.value.code == 'PT-RULE-INTEGRITY'


# ---- gates from the real scan ----------------------------------------------------------------------------------------

@pytest.mark.parametrize('direction', ['older', 'newer'], ids=['older', 'newer'])
def test_sep_and_compile_pass_on_the_real_engine(images, engine, direction):
    _pair, found = real_candidates(images)
    checked = matrix.evaluate(found[direction], worker_anchors(anchor_targets(images)), engine)
    state = {g.gate_id: g for g in checked.gates}
    assert state['compile'].state == 'pass' and state['sep'].state == 'pass'
    assert state['sep'].measured == '1/0' and state['uniq'].state == 'waived'   # text rule: no byte window
    assert checked.engine.version == '1.21.0'


def test_sep_fails_when_the_anchors_are_swapped(images, engine):
    _pair, found = real_candidates(images)
    anchors = anchor_targets(images)
    swapped = worker_anchors({'older': anchors['newer'], 'newer': anchors['older']})
    state = {g.gate_id: g for g in matrix.evaluate(found['older'], swapped, engine).gates}
    assert state['sep'].state == 'fail' and state['sep'].detail == 'no hit in the source build'


def test_a_rule_hitting_both_builds_fails_sep(images):
    _pair, found = real_candidates(images)
    fake = FakeEngine(default='hit')
    state = {g.gate_id: g for g in matrix.evaluate(found['older'], worker_anchors(anchor_targets(images)),
                                                   fake.engine).gates}
    assert state['sep'].state == 'fail' and state['sep'].detail == 'also hits the other build'


def test_a_compile_error_blocks_the_scan_and_leaves_sep_unknown(images):
    _pair, found = real_candidates(images)
    fake = FakeEngine(findings=[LintFinding(rule_name='x', code='E001', severity='error', message='bad')])
    checked = matrix.evaluate(found['older'], worker_anchors(anchor_targets(images)), fake.engine)
    state = {g.gate_id: g.state for g in checked.gates}
    assert state['compile'] == 'fail' and state['sep'] == 'unknown' and fake.scans == []
    assert checked.compile_warnings[0].code == 'E001'


@pytest.mark.parametrize('cell', ['not-scanned', 'timeout', 'error'], ids=['ns', 'to', 'err'])
def test_an_unscanned_anchor_is_unknown_never_a_failed_separation(images, cell):
    _pair, found = real_candidates(images)
    fake = FakeEngine(default=cell)
    state = {g.gate_id: g.state for g in matrix.evaluate(found['older'], worker_anchors(anchor_targets(images)),
                                                         fake.engine).gates}
    assert state['sep'] == 'unknown'


def test_revise_keeps_the_lineage_and_reruns_the_engine(images, engine):
    _pair, found = real_candidates(images)
    original = found['newer']
    ids = included_ids(original.features)
    again = matrix.revise(original, ids, worker_anchors(anchor_targets(images)), engine)
    assert again.lineage_id == original.lineage_id and again.rule_sha256 == original.rule_sha256
    assert {g.gate_id: g.state for g in again.gates}['sep'] == 'pass'


# ---- targets and expectations -----------------------------------------------------------------------------------------

@pytest.mark.parametrize('expect,state,verdict', [
    ('hit', 'hit', 'as-expected'), ('hit', 'no-hit', 'unexpected-miss'), ('no-hit', 'hit', 'unexpected-hit'),
    ('no-hit', 'no-hit', 'as-expected'), ('unknown', 'hit', 'unscored'), ('unknown', 'no-hit', 'unscored'),
    ('hit', 'not-scanned', 'unscored'), ('no-hit', 'timeout', 'unscored'), ('hit', 'error', 'unscored')],
    ids=['hh', 'hn', 'nh', 'nn', 'uh', 'un', 'hns', 'nto', 'her'])
def test_verdicts(expect, state, verdict):
    assert matrix.verdict_of(expect, state) == verdict


def test_anchors_follow_the_rule_direction_and_others_keep_the_analysts_expectation(tmp_path):
    for role, direction, want in [('older-anchor', 'older', 'hit'), ('newer-anchor', 'older', 'no-hit'),
                                  ('older-anchor', 'newer', 'no-hit'), ('newer-anchor', 'newer', 'hit')]:
        made = matrix.file_target(_file(tmp_path, 'a.bin', b'MZ'), role, None)
        assert matrix.expectation(direction, made.ref) == want
    series = matrix.file_target(_file(tmp_path, 'b.bin', b'MZ'), 'series', 1, expect='hit')
    assert matrix.expectation('older', series.ref) == matrix.expectation('newer', series.ref) == 'hit'


def _file(directory, name, data=b'MZ'):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_collect_orders_roles_and_ids_carry_no_paths(tmp_path, images):
    anchors = anchor_targets(images)
    for name in ('b.dll', 'a.dll'):
        _file(tmp_path / 'series', name)
    _file(tmp_path / 'clean' / 'sub', 'z.dll')
    _file(tmp_path / 'clean', 'y.dll')
    extra = _file(tmp_path, 'extra.dll')
    got = matrix.collect_targets(tuple(anchors.values()), series_dir=tmp_path / 'series', extra=[extra, extra],
                                 clean_dir=tmp_path / 'clean')
    refs = [t.ref for t in got.targets]
    assert [r.role for r in refs] == ['older-anchor', 'newer-anchor', 'series', 'series', 'extra', 'clean', 'clean']
    assert [r.label for r in refs[2:]] == ['a.dll', 'b.dll', 'extra.dll', 'z.dll', 'y.dll']   # clean: by relative path, sub/z before y
    assert {r.expect for r in refs if r.role == 'clean'} == {'no-hit'}
    assert all(str(tmp_path) not in r.target_id and str(tmp_path) not in r.label for r in refs)


def test_analyst_expectations_apply_by_hash(tmp_path, images):
    series = _file(tmp_path / 'series', 'a.dll', b'MZ-one')
    sha = matrix.file_target(series, 'series', 1).ref.sha256
    got = matrix.collect_targets((), series_dir=series.parent, expected={sha: 'hit'})
    assert got.targets[0].ref.expect == 'hit'


@pytest.mark.parametrize('field,role', [('series_targets', 'series'), ('extra_targets', 'extra'),
                                        ('clean_targets', 'clean')], ids=['series', 'extra', 'clean'])
def test_caps_are_enforced_before_hashing(tmp_path, field, role):
    limits = dataclasses.replace(LIMITS, **{field: 1})
    files = [_file(tmp_path / role, f'{n}.dll') for n in 'ab']
    kwargs = {'series': {'series_dir': tmp_path / 'series'}, 'extra': {'extra': files},
              'clean': {'clean_dir': tmp_path / 'clean'}}[role]
    with pytest.raises(RulesError) as caught:
        matrix.collect_targets((), limits=limits, **kwargs)
    assert caught.value.code == 'PT-RULE-LIMIT'


def test_oversize_and_unreadable_files_are_reported_never_dropped_silently(tmp_path):
    big = _file(tmp_path / 'clean', 'big.dll', b'M' * 64)
    ok = _file(tmp_path / 'clean', 'ok.dll', b'MZ')
    limits = dataclasses.replace(LIMITS, target_file_bytes=16)
    got = matrix.collect_targets((), clean_dir=big.parent, limits=limits)
    assert [t.ref.label for t in got.targets] == [ok.name]
    assert got.skipped == ('big.dll: file is larger than the limit',)
    gone = matrix.file_target(tmp_path / 'missing.dll', 'extra', 1)
    assert gone == 'missing.dll: file could not be read'


# ---- the grid on the real engine ---------------------------------------------------------------------------------------

def matrix_rule(candidate, version_id='v' * 64):
    return matrix.MatrixRule(name=candidate.rule_name, text=candidate.rule_text, direction=candidate.direction,
                             version_id=version_id, rule_sha256=candidate.rule_sha256)


def run(rules, targets, engine, **kwargs):
    return matrix.run_matrix(rules, targets, engine=engine, stamp=fx.ENGINE, cancel=kwargs.pop('cancel', threading.Event()),
                             run_id='run-1', **kwargs)


def test_real_grid_assigns_verdicts_and_keeps_unscanned_cells_unknown(tmp_path, images, engine):
    _pair, found = real_candidates(images)
    anchors = anchor_targets(images)
    clean_pe = images('capa-api', 'older')[0]
    clean = tmp_path / 'clean'
    clean.mkdir()
    (clean / 'pe.dll').write_bytes(clean_pe.path.read_bytes())
    (clean / 'notes.txt').write_bytes(b'not an executable')
    collected = matrix.collect_targets(tuple(anchors.values()), clean_dir=clean)
    result = run([matrix_rule(found['older'])], collected.targets, engine, skipped=collected.skipped)
    by_label = {t.target_id: t for t in result.targets}
    cells = {by_label[c.target_id].label: c for c in result.cells}
    assert result.status == 'partial' and len(result.cells) == 4   # an unscanned file never completes the run
    names = [t.label for t in result.targets]
    older, newer = cells[names[0]], cells[names[1]]
    assert (older.state, older.verdict) == ('hit', 'as-expected') and older.rvas
    assert (newer.state, newer.verdict) == ('no-hit', 'as-expected')
    assert cells['pe.dll'].state == 'no-hit' and cells['pe.dll'].verdict == 'as-expected'
    unscanned = cells['notes.txt']
    assert unscanned.state == 'not-scanned' and unscanned.reason == 'not a PE image' and unscanned.verdict == 'unscored'
    # the engine produced a "not a PE image" cell: a run with an unscanned file is partial, not complete
    assert matrix.summarize(result, found['older'].rule_name).not_scanned == 1


def test_grid_json_is_independent_of_the_machine_apart_from_timing(tmp_path, images, engine):
    _pair, found = real_candidates(images)
    collected = matrix.collect_targets(tuple(anchor_targets(images).values()))
    first = run([matrix_rule(found['older'])], collected.targets, engine)
    second = run([matrix_rule(found['older'])], collected.targets, engine)

    def stable(r):
        return [c.model_copy(update={'elapsed_ms': 0}).model_dump(mode='json') for c in r.cells]
    assert stable(first) == stable(second) and first.cache_key == second.cache_key


def test_skipped_files_make_the_run_partial_with_a_reason(images):
    _pair, found = real_candidates(images)
    fake = FakeEngine()
    collected = matrix.collect_targets(tuple(anchor_targets(images).values()))
    result = run([matrix_rule(found['older'])], collected.targets, fake.engine, skipped=('big.dll: file is larger than the limit',))
    assert result.status == 'partial' and result.anomalies == ('Not scanned: big.dll: file is larger than the limit',)


# ---- chunks, resume, cancel, failures ---------------------------------------------------------------------------------

def many_targets(tmp_path, count):
    return tuple(matrix.file_target(_file(tmp_path, f'f{n}.dll', f'MZ{n}'.encode()), 'extra', n) for n in range(count))


def test_resume_scans_only_what_the_crashed_run_did_not_finish(tmp_path, images, monkeypatch):
    monkeypatch.setattr(matrix, 'CHUNK_TARGETS', 2)
    _pair, found = real_candidates(images)
    rules, targets = [matrix_rule(found['older'])], many_targets(tmp_path, 5)
    saved: list[tuple[CellResult, ...]] = []

    def crash_on_third(call):
        return RulesError('PT-RULE-CANCEL', 'stop') if call == 3 else None
    first = FakeEngine(fail=crash_on_third)
    partial = run(rules, targets, first.engine, on_chunk=saved.append)
    assert partial.status == 'cancelled' and len(saved) == 2
    assert [c.reason for c in partial.cells if c.state == 'not-scanned'] == ['run was cancelled']
    second = FakeEngine()
    resumed = run(rules, targets, second.engine, known=[c for chunk in saved for c in chunk])
    assert second.scans == [[targets[4].ref.target_id]] and resumed.status == 'complete'
    assert [c.target_id for c in resumed.cells] == [t.ref.target_id for t in targets]


def test_cancel_leaves_every_cell_not_scanned_never_no_hit(tmp_path, images):
    _pair, found = real_candidates(images)
    event = threading.Event()
    event.set()
    fake = FakeEngine()
    result = run([matrix_rule(found['older'])], many_targets(tmp_path, 3), fake.engine, cancel=event)
    assert result.status == 'cancelled' and fake.scans == []
    assert {c.state for c in result.cells} == {'not-scanned'} and {c.verdict for c in result.cells} == {'unscored'}


@pytest.mark.parametrize('code,state', [('PT-RULE-ENGINE', 'error'), ('PT-RULE-TIMEOUT', 'timeout')],
                         ids=['engine', 'timeout'])
def test_a_failed_chunk_is_unknown_cells_and_the_run_goes_on(tmp_path, images, monkeypatch, code, state):
    monkeypatch.setattr(matrix, 'CHUNK_TARGETS', 2)
    _pair, found = real_candidates(images)
    fake = FakeEngine(fail=lambda call: RulesError(code, 'child failed') if call == 1 else None)
    result = run([matrix_rule(found['older'])], many_targets(tmp_path, 4), fake.engine)
    assert [c.state for c in result.cells] == [state, state, 'no-hit', 'no-hit'] and result.status == 'partial'
    assert all(c.verdict == 'unscored' for c in result.cells[:2])


@pytest.mark.parametrize('code', ['PT-RULE-COMPILE', 'PT-RULE-UNAVAILABLE'], ids=['compile', 'unavailable'])
def test_compile_and_availability_failures_abort_the_run(tmp_path, images, code):
    _pair, found = real_candidates(images)
    fake = FakeEngine(fail=lambda call: RulesError(code, 'no'))
    with pytest.raises(RulesError) as caught:
        run([matrix_rule(found['older'])], many_targets(tmp_path, 2), fake.engine)
    assert caught.value.code == code


def test_run_input_checks(tmp_path, images):
    _pair, found = real_candidates(images)
    rule = matrix_rule(found['older'])
    fake = FakeEngine()
    with pytest.raises(RulesError) as dup:
        run([rule, rule], many_targets(tmp_path, 1), fake.engine)
    assert dup.value.code == 'PT-RULE-INPUT'
    tight = dataclasses.replace(LIMITS, cells=3)
    with pytest.raises(RulesError) as big:
        run([rule], many_targets(tmp_path, 4), fake.engine, limits=tight)
    assert big.value.code == 'PT-RULE-LIMIT' and fake.scans == []


# ---- cache key and summary ---------------------------------------------------------------------------------------------

def test_cache_key_is_order_independent_and_changes_with_inputs(tmp_path, images):
    _pair, found = real_candidates(images)
    rules = [matrix_rule(found['older']), matrix_rule(found['newer'])]
    targets = many_targets(tmp_path, 3)
    key = matrix.cache_key(rules, targets, fx.ENGINE)
    assert key == matrix.cache_key(rules[::-1], targets[::-1], fx.ENGINE)
    assert key != matrix.cache_key(rules[:1], targets, fx.ENGINE)
    assert key != matrix.cache_key(rules, targets[:2], fx.ENGINE)
    assert key != matrix.cache_key(rules, targets, fx.ENGINE.model_copy(update={'version': '1.22.0'}))
    assert key != matrix.cache_key(rules, targets, fx.ENGINE, dataclasses.replace(LIMITS, target_timeout_s=60))


def test_summary_counts_are_raw_numbers(tmp_path, images):
    _pair, found = real_candidates(images)
    clean = tuple(matrix.file_target(_file(tmp_path, f'c{n}.dll', f'MZ{n}'.encode()), 'clean', n, expect='no-hit')
                  for n in range(3))
    anchors = tuple(anchor_targets(images).values())
    name = found['older'].rule_name
    fake = FakeEngine(table={(name, clean[0].ref.target_id): 'hit', (name, clean[1].ref.target_id): 'not-scanned',
                             (name, anchors[0].ref.target_id): 'hit'})
    result = run([matrix_rule(found['older'])], anchors + clean, fake.engine)
    summary = matrix.summarize(result, name)
    assert (summary.builds, summary.clean, summary.unexpected_hits, summary.unexpected_misses,
            summary.not_scanned) == (2, 2, 1, 0, 1)


def test_matrix_never_imports_the_engine():
    import ast
    from pathlib import Path
    tree = ast.parse(Path(matrix.__file__).read_text(encoding='utf-8'))
    names = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not names & {'yara_x', 'iced_x86', 'PySide6'}
