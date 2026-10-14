"""SPEC-09b sections 3, 5, 9: pair access and the pure Series view-model (no Qt)."""
import threading

import pytest
from test_nway_series import builds, create, populated  # noqa: F401, F811  (fixture and helper reuse)

from patchtrace import cli
from patchtrace.enrichment.contracts import RankingEntry, RankingResult
from patchtrace.nway import series as store
from patchtrace.nway import view_model as vm
from patchtrace.nway.contracts import NwayError
from patchtrace.nway.pair_access import DiskPairReader, PairSnapshot
from patchtrace.service import ProjectService

SHA = '0' * 64


def ranking(scores: dict[str, int]) -> RankingResult:
    entries = tuple(RankingEntry(pairing_id=f'{i:064x}', match_id=mid, rank=rank, score=score, raw=0,
                                 strong_groups=0, evidence='complete')
                    for rank, (i, (mid, score)) in enumerate(enumerate(scores.items()), 1))
    return RankingResult(config_digest=SHA, input_digest=SHA, entries=entries, status='complete')


class FakeReader:
    def __init__(self, snapshots):
        self.snapshots, self.calls = snapshots, 0

    def read(self, root, ref, older_sha, newer_sha, wanted):
        self.calls += 1
        snap = self.snapshots[ref.from_ordinal]
        return snap(wanted) if callable(snap) else snap


@pytest.fixture
def series_file(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    populated(capsys, builds, root)
    path = root / 'series.json'
    return path, store.load(path)


def ids(series):
    [chain] = series.chains
    return [e.match_id for e in chain.edges]


def ok(scores=None, **kw):
    return PairSnapshot('ok', ranking=ranking(scores) if scores is not None else None, **kw)


def load(path, snapshots):
    return vm.load_view(path, FakeReader(snapshots), threading.Event())


def test_every_hop_scored_state_ready(series_file):
    path, series = series_file
    first, second = ids(series)
    loaded = load(path, {0: ok({first: 70}), 1: ok({second: 40})})
    view = vm.apply_query(loaded, vm.ViewQuery())
    [row] = view.rows
    assert view.state == 'ready' and view.message == ''
    assert [h.score_state for h in row.hops] == ['scored', 'scored']
    assert (row.max_score, row.sum_score, row.scored_hops, row.total_hops, row.degraded) == (70, 110, 2, 2, False)
    assert row.hops[0].rank == 1 and row.hops[0].of == 1 and row.hops[0].label.endswith('b1.dll')
    assert row.hops[0].from_name == 'f' and not row.stale


def test_score_states_for_each_snapshot_condition(series_file):
    path, series = series_file
    first, second = ids(series)
    cases = [
        (PairSnapshot('ok', ranking=None, ranking_note='no stored ranking'), 'no-ranking'),
        (PairSnapshot('ok', ranking=None, ranking_note='stored ranking is stale'), 'stale-ranking'),
        (ok({'other': 5}), 'not-ranked'),
        (PairSnapshot('locked', 'locked by another PatchTrace window'), 'pair-unavailable'),
        (PairSnapshot('missing', 'gone'), 'pair-unavailable'),
        (PairSnapshot('no-run', 'no run'), 'no-ranking'),
    ]
    for snap, expected in cases:
        if snap.state == 'no-run':
            snap = PairSnapshot('no-run', 'no run', ranking=None, ranking_note='no completed run')
        row = vm.apply_query(load(path, {0: snap, 1: ok({second: 1})}), vm.ViewQuery()).rows[0]
        assert row.hops[0].score_state == expected, snap
        assert row.degraded == (expected != 'not-ranked') and row.hops[1].score_state == 'scored'
    del first


def test_locked_pair_leaves_other_hops_scored_and_is_partial_not_stale(series_file):
    path, series = series_file
    _, second = ids(series)
    view = vm.apply_query(load(path, {0: PairSnapshot('locked', 'locked by another PatchTrace window'),
                                      1: ok({second: 33})}), vm.ViewQuery())
    assert view.state == 'partial' and 'pair 0->1: locked by another PatchTrace window' in view.message
    [row] = view.rows
    assert row.max_score == 33 and row.scored_hops == 1 and not row.stale


def test_max_score_none_when_nothing_scored(series_file):
    path, _ = series_file
    snap = PairSnapshot('ok', ranking=None, ranking_note='no stored ranking')
    [row] = vm.apply_query(load(path, {0: snap, 1: snap}), vm.ViewQuery()).rows
    assert row.max_score is None and row.sum_score is None and row.scored_hops == 0
    assert vm.apply_query(load(path, {0: snap, 1: snap}), vm.ViewQuery(only_scored=True)).hidden_by_filter == 1


def test_all_pairs_changed_is_stale_and_state_precedence(series_file, builds, tmp_path):  # noqa: F811
    path, series = series_file
    bad = PairSnapshot('changed', 'project changed since the series was computed')
    # Staleness reasons exist only when projects really drifted; fake it by renaming both pairs away.
    for ref in series.pair_projects:
        (path.parent / ref.path).rename(tmp_path / f'moved-{ref.from_ordinal}')
    loaded = load(path, {0: PairSnapshot('missing', 'pair project is missing'), 1: bad})
    assert loaded.state == 'stale' and 'out of date' in loaded.message
    assert all(r.stale for r in loaded.rows)
    # Failed beats everything.
    path.write_text('{')
    failed = load(path, {})
    assert failed.state == 'failed' and 'PT-NWAY-STORAGE' in failed.message and failed.rows == ()


def test_empty_series_state(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    snap = PairSnapshot('no-run', 'pair has no completed run')
    view = vm.apply_query(load(root / 'series.json', {0: snap, 1: snap}), vm.ViewQuery())
    assert view.state == 'empty' and view.message.startswith('No 1:1 chain') and view.rows == ()


def test_cancel_mid_load_raises_and_stops_reading(series_file):
    path, _ = series_file
    cancel = threading.Event()

    class Cancelling(FakeReader):
        def read(self, *args):
            cancel.set()
            return super().read(*args)

    reader = Cancelling({0: ok({}), 1: ok({})})
    with pytest.raises(NwayError, match='PT-NWAY-CANCEL'):
        vm.load_view(path, reader, cancel)
    assert reader.calls == 1


def row(chain_id, max_score, total=None, title='t', status='inferred', stale=False, events=(), search=''):
    return vm.ChainRow(chain_id=chain_id, title=title, hops=(), status=status, stale=stale,
                       weakest_match_type='x', gaps=(), events=events, max_score=max_score,
                       sum_score=total if total is not None else max_score, scored_hops=1 if max_score is not None else 0,
                       total_hops=2, degraded=False, search=(search or title).casefold())


def loaded_of(*rows):
    return vm.LoadedSeries('ready', '', rows=tuple(rows))


def test_sort_ties_and_unscored_last_and_deterministic():
    data = loaded_of(row('c', 50, 60), row('a', 50, 60), row('b', 50, 90), row('z', None), row('d', 80, 80),
                     row('e', None))
    order = [r.chain_id for r in vm.apply_query(data, vm.ViewQuery()).rows]
    assert order == ['d', 'b', 'a', 'c', 'e', 'z']
    again = [r.chain_id for r in vm.apply_query(loaded_of(*reversed(data.rows)), vm.ViewQuery()).rows]
    assert again == order
    asc = [r.chain_id for r in vm.apply_query(data, vm.ViewQuery(descending=False)).rows]
    assert asc == ['a', 'c', 'b', 'd', 'e', 'z']
    by_sum = [r.chain_id for r in vm.apply_query(data, vm.ViewQuery(sort='sum-score')).rows]
    assert by_sum == ['b', 'd', 'a', 'c', 'e', 'z']
    assert [r.chain_id for r in vm.apply_query(data, vm.ViewQuery(sort='chain-id', descending=False)).rows] == [
        'a', 'b', 'c', 'd', 'e', 'z']


def test_filters_combine_and_count_hidden():
    from patchtrace.nway.contracts import ChainEvent
    split = (ChainEvent(kind='split', ordinal=1),)
    data = loaded_of(row('a', 90, title='Alpha', stale=True, events=split, status='confirmed'),
                     row('b', 20, title='Beta'), row('c', None, title='Gamma'))
    q = vm.ViewQuery
    assert [r.chain_id for r in vm.apply_query(data, q(text=' ALP ')).rows] == ['a']
    assert [r.chain_id for r in vm.apply_query(data, q(status=frozenset({'confirmed'}))).rows] == ['a']
    assert [r.chain_id for r in vm.apply_query(data, q(event=frozenset({'split'}))).rows] == ['a']
    assert [r.chain_id for r in vm.apply_query(data, q(only_stale=True)).rows] == ['a']
    assert [r.chain_id for r in vm.apply_query(data, q(only_scored=True)).rows] == ['a', 'b']
    view = vm.apply_query(data, q(min_score=50))
    assert [r.chain_id for r in view.rows] == ['a'] and view.hidden_by_filter == 2 and view.total_chains == 3
    assert vm.apply_query(data, q(text='alp', min_score=95)).rows == ()


def test_row_cap_sets_truncated():
    data = loaded_of(*(row(f'{i:05d}', 1) for i in range(vm.MAX_ROWS + 3)))
    view = vm.apply_query(data, vm.ViewQuery())
    assert len(view.rows) == vm.MAX_ROWS and view.truncated and view.total_chains == vm.MAX_ROWS + 3


def test_untrusted_strings_are_kept_verbatim_in_the_model():
    nasty = '<b>x</b>\x1b[31m'
    [r] = vm.apply_query(loaded_of(row('a', 1, title=nasty)), vm.ViewQuery()).rows
    assert r.title == nasty


def rank_pairs(plan, capsys):
    for path in plan:
        assert cli.main(['rank', str(path)]) == 0
    capsys.readouterr()


def test_disk_reader_reads_stored_ranking_read_only(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    rank_pairs(plan, capsys)
    assert create(capsys, builds[:3], root)[0] == 0
    revisions = []
    for path in plan:
        with ProjectService.open(path) as service:
            revisions.append(service.project.revision)
    loaded = vm.load_view(root / 'series.json', DiskPairReader(), threading.Event())
    assert loaded.state == 'ready', loaded.message
    [r] = loaded.rows
    assert [h.score_state for h in r.hops] == ['scored', 'scored'] and r.max_score is not None
    assert all(h.pair_state == 'ok' for h in r.hops)
    for path, revision in zip(plan, revisions, strict=True):
        with ProjectService.open(path) as service:  # lock released; nothing changed
            assert service.project.revision == revision


def test_disk_reader_classifies_locked_missing_garbage_and_unranked(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    series = store.load(root / 'series.json')
    hashes = [b.artifact_sha256 for b in series.builds]
    reader = DiskPairReader()

    def read(i):
        return reader.read(root, series.pair_projects[i], hashes[i], hashes[i + 1], frozenset(ids(series)))

    snap = read(0)
    assert snap.state == 'ok' and snap.ranking is None and snap.ranking_note == 'no stored ranking'
    assert set(snap.match_names.values()) == {'f'}
    with ProjectService.open(plan[0]):
        locked = read(0)
    assert locked.state == 'locked' and str(root) not in locked.reason
    (plan[1] / 'project.sqlite3').write_bytes(b'x' * 64)
    assert read(1).state == 'unreadable'
    plan[0].rename(tmp_path / 'away')
    assert read(0).state == 'missing'


def test_disk_reader_wrong_pair_and_changed(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    series = store.load(root / 'series.json')
    hashes = [b.artifact_sha256 for b in series.builds]
    reader = DiskPairReader()
    assert reader.read(root, series.pair_projects[0], hashes[1], hashes[0], frozenset()).state == 'mismatch'
    with ProjectService.open(plan[0]) as service:
        match = next(m for m in service.project.matches if m.category == 'modified')
        service.correct_match(match.id, [match.older[0].id], [match.newer[0].id], 'modified', 'analyst check')
    snap = reader.read(root, series.pair_projects[0], hashes[0], hashes[1], frozenset())
    assert snap.state == 'changed'
    loaded = vm.load_view(root / 'series.json', reader, threading.Event())
    assert loaded.state == 'partial' and loaded.rows[0].stale and loaded.rows[0].degraded
