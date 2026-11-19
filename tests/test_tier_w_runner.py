"""SPEC-33 s9 Tier-W runner: PatchTrace projects per pair and condition, 1:1 match extraction with RVA bounds, the
secondary-engine image-base rule, resume, partial and cancelled runs, deterministic `tier-w-matches/1` output.
Hermetic: synthetic PEs from tests/pe_builder.py, real PatchTrace project stores, fake engine invokers that store
FunctionMatch records; no Ghidra, network or Microsoft data, and nothing is executed."""
from __future__ import annotations

import hashlib
import sys
import threading
from pathlib import Path

import pytest
from pe_builder import PeSpec, SectionSpec, build_pe

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchtrace.models import AnalysisRun, FunctionMatch, FunctionRecord  # noqa: E402
from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet  # noqa: E402
from patchtrace.service import ProjectService  # noqa: E402
from tools.calibration.tier_w import runner as R  # noqa: E402
from tools.calibration.tier_w.contracts import (  # noqa: E402
    Coverage,
    MatchLine,
    PairBinary,
    PairEntry,
    PairsDoc,
    RunRecord,
    load_jsonl,
    load_run_record,
)
from tools.calibration.tier_w.paths import Layout, TierWError, dumps  # noqa: E402

CID = 'tier-w-t'
BASE = 0x180000000
SIZE = 0x3000  # one 0x2000-byte section at RVA 0x1000
H, V = 'symbols-hidden', 'symbols-visible'
ONE_TO_ONE = (([BASE + 0x1000], [BASE + 0x1010], 'modified'), ([BASE + 0x1100], [BASE + 0x1100], 'unchanged'))


def pe(fill: int, base: int = BASE) -> bytes:
    return build_pe(PeSpec(kind='dll', image_base=base, sections=[SectionSpec(data=bytes([fill]) * 0x2000)]))


def corpus(root: Path, names=('a', 'b'), *, missing=(), bases=None) -> PairsDoc:
    """Synthetic pairs sidecar; binaries placed at <root>/binaries/<sha>/<name> unless listed in `missing`."""
    binaries, pairs = [], []
    for i, name in enumerate(names):
        file_name = f'{name}.dll'
        ids = []
        for side, fill in (('older', 0x90 + 2 * i), ('newer', 0x91 + 2 * i)):
            data = pe(fill, (bases or {}).get(side, BASE))
            sha = hashlib.sha256(data).hexdigest()
            if (name, side) not in missing:
                target = root / 'binaries' / sha / file_name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            ids.append(f'w-{sha[:16]}')
            binaries.append(PairBinary(id=ids[-1], file_name=file_name, sha256=sha, record_sha256=sha,
                                       family='usermode-dll'))
        pairs.append(PairEntry(id=f'tw.{name}.dll.{i:010x}', older=ids[0], newer=ids[1], kind='adjacent-patch',
                               file_name=file_name, lines=('l1',), older_kbs=(), newer_kbs=(), older_date=None,
                               newer_date=None, tags=()))
    return PairsDoc(contract='tier-w-pairs/1', tier='W', corpus_id=CID, created='', params={},
                    binaries=tuple(binaries), pairs=tuple(pairs), exclusions={},
                    coverage=Coverage(classes=('usermode-dll',), files_with_pairs=(), complete=False,
                                      allow_incomplete=True))


def store_matches(project_dir: Path, rows, version: str = 'ghidriff-test') -> None:
    """What a completed Ghidriff import leaves behind: one completed run plus its FunctionMatch records."""
    service = ProjectService.open(project_dir, maintenance=False)
    try:
        project = service.project.model_copy(deep=True)
        run = AnalysisRun(status='completed', backend='ghidriff', backend_version=version)
        ids = {a.side: a.id for a in project.artifacts}

        def fn(side, va, n):
            return FunctionRecord(artifact_id=ids[side], run_id=run.id, name=f'{side}{n}',
                                  address=None if va is None else hex(va),
                                  address_space='unknown' if va is None else 'virtual')
        project.runs.append(run)
        for n, (older, newer, category) in enumerate(rows):
            project.matches.append(FunctionMatch(run_id=run.id, category=category,
                                                 older=[fn('older', va, n) for va in older],
                                                 newer=[fn('newer', va, n) for va in newer]))
        service.store.save(project)
    finally:
        service.close()


class FakeGhidriff:
    """PairInvoker that records each call and stores FunctionMatch rows the way `_run_pair` + import would."""

    def __init__(self, rows=None, *, raises=(), after=None):
        self.rows = rows or {}
        self.raises = set(raises)
        self.after = after
        self.calls: list[tuple[str, str, object, Path]] = []

    def __call__(self, config, project_dir: Path, cancel) -> str | None:
        pair, condition = project_dir.parent.parent.name, project_dir.parent.name
        self.calls.append((pair, condition, config, project_dir))
        if pair in self.raises:
            raise RuntimeError('ghidriff crashed \x1b[31mred\x1b[0m')
        store_matches(project_dir, self.rows.get(pair, ONE_TO_ONE))
        if self.after:
            self.after(cancel)
        return None


def configs(condition: str) -> dict:
    return {'condition': condition}


def run(root: Path, doc: PairsDoc, invoker=None, **kw) -> RunRecord:
    kw.setdefault('config_factory', configs)
    return R.run_corpus(Layout(root), doc, corpus_id=CID, invoker=invoker or FakeGhidriff(),
                        matches_path=root / 'tier-w' / 'runs' / CID / 'matches.jsonl', **kw)


def lines(root: Path) -> list[MatchLine]:
    data = (root / 'tier-w' / 'runs' / CID / 'matches.jsonl').read_bytes()
    return load_jsonl(MatchLine, data, 'matches')


def cell(record: RunRecord, engine: str = 'ghidriff', condition: str = H):
    return next(c for c in record.cells if (c.engine, c.condition) == (engine, condition))


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path / 'ptcal'


def test_hidden_disallows_and_visible_allows_symbol_downloads(root):
    doc = corpus(root, names=('a',))
    fake = FakeGhidriff()
    record = run(root, doc, fake, conditions=(H, V), config_factory=R.backend_configs('py', 'ghidra', 600))
    seen = {condition: config for _pair, condition, config, _dir in fake.calls}
    assert seen['h'].allow_symbol_downloads is False and seen['v'].allow_symbol_downloads is True
    assert seen['h'].python_executable == 'py' and seen['h'].ghidra_dir == 'ghidra' and seen['h'].timeout_seconds == 600
    layout = Layout(root)
    assert sorted(d for *_, d in fake.calls) == sorted(layout.run_dir(CID, doc.pairs[0].id, c) / 'project'
                                                       for c in (H, V))
    assert record.status == 'ok' and {(c.condition, c.ok) for c in record.cells} == {(H, 1), (V, 1)}
    assert {line.condition for line in lines(root)} == {H, V}


def test_completed_project_is_reused(root):
    doc = corpus(root)
    fake = FakeGhidriff()
    first = run(root, doc, fake)
    data = (root / 'tier-w' / 'runs' / CID / 'matches.jsonl').read_bytes()
    second = run(root, doc, fake)
    assert len(fake.calls) == 2  # one invocation per pair across both runs
    assert first == second and cell(second).ok == 2
    assert (root / 'tier-w' / 'runs' / CID / 'matches.jsonl').read_bytes() == data


def test_va_to_rva_uses_each_side_image_base_and_rejects_out_of_image(root):
    newer_base = 0x10000000
    doc = corpus(root, names=('a',), bases={'newer': newer_base})
    rows = {doc.pairs[0].id: (([BASE + 0x1000], [newer_base + 0x1020], 'modified'),
                              ([BASE + SIZE], [newer_base + 0x1000], 'modified'),
                              ([BASE - 0x10], [newer_base + 0x1000], 'modified'),
                              ([BASE + SIZE - 1], [newer_base], 'unchanged'))}
    record = run(root, doc, FakeGhidriff(rows))
    got = [(line.older_rva, line.newer_rva, line.match_id, line.engine, line.engine_version) for line in lines(root)]
    assert got == [(0x1000, 0x1020, 'sym:1000-1020', 'ghidriff', 'ghidriff-test'),
                   (SIZE - 1, 0, 'sym:2fff-0', 'ghidriff', 'ghidriff-test')]
    assert cell(record).matches == 2 and cell(record).skipped == {'out-of-image': 2}


def test_one_to_many_split_and_ambiguous_are_skipped_and_counted(root):
    doc = corpus(root, names=('a',))
    rows = {doc.pairs[0].id: (([BASE + 0x1000], [BASE + 0x1000], 'modified'),
                              ([BASE + 0x1100], [BASE + 0x1100, BASE + 0x1200], 'modified'),
                              ([BASE + 0x1300], [BASE + 0x1300, BASE + 0x1400], 'split'),
                              ([BASE + 0x1500], [], 'ambiguous'),
                              ([], [BASE + 0x1600], 'added'),
                              ([None], [BASE + 0x1700], 'modified'),
                              ([BASE + 0x1000], [BASE + 0x1000], 'unchanged'))}
    record = run(root, doc, FakeGhidriff(rows))
    assert [(line.older_rva, line.newer_rva) for line in lines(root)] == [(0x1000, 0x1000)]
    assert cell(record).skipped == {'not-one-to-one': 1, 'split': 1, 'ambiguous': 1, 'added': 1, 'no-address': 1,
                                    'duplicate': 1}


def rz_set(doc: PairsDoc, pair_index: int, subtracted: str, rows) -> SecondaryMatchSet:
    by_id = {b.id: b for b in doc.binaries}
    pair = doc.pairs[pair_index]
    matches = tuple(SecondaryMatch(engine='rz-diff', engine_version='rz-test', older_address=o, newer_address=n,
                                   older_name=None, newer_name=None, similarity_milli=900, similarity_text='0.9',
                                   confidence_milli=None, confidence_text=None, flags=(),
                                   algorithm='levenshtein-bytes') for o, n in rows)
    return SecondaryMatchSet(engine='rz-diff', engine_version='rz-test', older_sha256=by_id[pair.older].sha256,
                             newer_sha256=by_id[pair.newer].sha256, file_sha256='0' * 64,
                             image_base_subtracted=subtracted, matches=matches)


@pytest.mark.parametrize('subtracted, rows, want, skipped', [
    ('yes', [(0x1000, 0x1010), (0x1000, None), (SIZE, 0x1000)], [(0x1000, 0x1010)],
     {'one-sided': 1, 'out-of-image': 1}),
    ('no', [(BASE + 0x1000, BASE + 0x1010), (0x1000, 0x1010)], [(0x1000, 0x1010)], {'out-of-image': 1}),
    ('unknown', [(0x1000, 0x1010), (BASE + 0x1000, BASE + 0x1010)], [], {'image-base-unknown': 2}),
], ids=['yes', 'no', 'unknown'])
def test_secondary_image_base_rule(root, subtracted, rows, want, skipped):
    doc = corpus(root, names=('a',))
    projects = []

    def secondary(project_dir):
        projects.append(project_dir)
        return rz_set(doc, 0, subtracted, rows)
    record = run(root, doc, conditions=(V,), secondary_engines=('rz-diff',), secondary={'rz-diff': secondary})
    assert projects == [Layout(root).run_dir(CID, doc.pairs[0].id, H) / 'project']
    rz = [line for line in lines(root) if line.engine == 'rz-diff']
    assert [(line.older_rva, line.newer_rva) for line in rz] == want
    assert all(line.condition == 'n/a' and line.engine_version == 'rz-test' for line in rz)
    assert cell(record, 'rz-diff', 'n/a').skipped == skipped and cell(record, 'rz-diff', 'n/a').ok == 1


def test_secondary_with_swapped_orientation_or_no_invoker_never_yields_rows(root):
    doc = corpus(root)

    def swapped(project_dir):
        good = rz_set(doc, 0, 'yes', [(0x1000, 0x1000)])
        return good.model_copy(update={'older_sha256': good.newer_sha256, 'newer_sha256': good.older_sha256})
    record = run(root, doc, secondary_engines=('rz-diff', 'bindiff'), secondary={'rz-diff': swapped})
    assert cell(record, 'rz-diff', 'n/a').failed == 2 and cell(record, 'bindiff', 'n/a').blocked == 2
    assert not [line for line in lines(root) if line.engine != 'ghidriff']
    assert record.status == 'partial' and cell(record).ok == 2


def test_raising_invoker_gives_partial_and_the_next_pair_still_runs(root):
    doc = corpus(root)
    fake = FakeGhidriff(raises={doc.pairs[0].id})
    record = run(root, doc, fake)
    assert [c[0] for c in fake.calls] == [p.id for p in doc.pairs]
    assert record.status == 'partial'
    assert (cell(record).attempted, cell(record).ok, cell(record).failed) == (2, 1, 1)
    assert {line.pair for line in lines(root)} == {doc.pairs[1].id}
    problem = record.problems[0]
    assert (problem.pair, problem.outcome) == (doc.pairs[0].id, 'failed')
    assert '\x1b' not in problem.message and '\\x1b[31m' in problem.message


def test_missing_binary_blocks_only_that_pair(root):
    doc = corpus(root, missing={('a', 'newer')})
    fake = FakeGhidriff()
    record = run(root, doc, fake)
    assert [c[0] for c in fake.calls] == [doc.pairs[1].id]
    assert (cell(record).blocked, cell(record).ok, record.status) == (1, 1, 'partial')
    every = corpus(root / 'other', missing={('a', 'older'), ('b', 'older')})
    assert run(root / 'other', every).status == 'blocked'


def test_binary_that_fails_its_hash_is_never_run(root):
    doc = corpus(root, names=('a',))
    older = next(b for b in doc.binaries if b.id == doc.pairs[0].older)
    path = root / 'binaries' / older.sha256 / older.file_name
    path.write_bytes(pe(0x55))
    fake = FakeGhidriff()
    record = run(root, doc, fake)
    assert not fake.calls and (cell(record).failed, record.status) == (1, 'partial')
    assert not (Layout(root).run_dir(CID, doc.pairs[0].id, H) / 'project').exists()


def cancel_file(root):
    return lambda _event: Layout(root).cancel_file.touch()


@pytest.mark.parametrize('how', ['file', 'event'])
def test_cancel_between_pairs(root, how):
    doc = corpus(root)
    root.joinpath('tier-w').mkdir(parents=True)
    trip = cancel_file(root) if how == 'file' else (lambda event: event.set())
    fake = FakeGhidriff(after=trip)
    record = run(root, doc, fake, secondary_engines=('rz-diff',), cancel=threading.Event())
    assert len(fake.calls) == 1 and record.status == 'cancelled'
    assert (cell(record).ok, cell(record).cancelled) == (1, 1)
    assert cell(record, 'rz-diff', 'n/a').cancelled == 2  # the secondary of the first pair comes after the trip
    assert {line.pair for line in lines(root)} == {doc.pairs[0].id}  # completed results are preserved


def test_output_is_byte_identical_across_reruns_and_pair_order(tmp_path):
    outputs = []
    for name, reverse in (('one', False), ('two', True)):
        root = tmp_path / name
        doc = corpus(root, names=('a', 'b', 'c', 'd'))
        if reverse:
            doc = doc.model_copy(update={'pairs': doc.pairs[::-1]})
        rows = {p.id: (([BASE + 0x1200], [BASE + 0x1200], 'unchanged'), *ONE_TO_ONE) for p in doc.pairs}
        failing = {p.id for p in doc.pairs if p.file_name in ('a.dll', 'c.dll')}  # problems must be ordered too
        for _ in range(2):
            run(root, doc, FakeGhidriff(rows, raises=failing))
            runs = root / 'tier-w' / 'runs' / CID
            outputs.append(((runs / 'matches.jsonl').read_bytes(), (runs / 'run.json').read_bytes()))
    assert len(set(outputs)) == 1
    matches, record = outputs[0]
    keys = [(m.pair, m.engine, m.condition, m.older_rva, m.newer_rva) for m in load_jsonl(MatchLine, matches, 'm')]
    assert keys == sorted(keys) and len(keys) == 6 and len({k[0] for k in keys}) == 2
    assert [p.pair for p in load_run_record(record).problems] == sorted(failing)


def test_every_line_is_a_match_line_and_the_record_is_strict(root):
    doc = corpus(root)
    record = run(root, doc, secondary_engines=('rz-diff',),
                 secondary={'rz-diff': lambda p: rz_set(doc, int(p.parent.parent.name[-1]), 'yes', [(0x1000, 0x1000)])})
    runs = root / 'tier-w' / 'runs' / CID
    loaded = lines(root)
    assert len(loaded) == 6 and all(m.contract == 'tier-w-matches/1' and m.tier == 'W' for m in loaded)
    stored = load_run_record((runs / 'run.json').read_bytes())
    assert stored == record and stored.contract == 'tier-w-run/1' and stored.tier == 'W' and stored.corpus_id == CID
    assert stored.matches_sha256 == hashlib.sha256((runs / 'matches.jsonl').read_bytes()).hexdigest()
    assert sum(c.matches for c in stored.cells) == 6
    bad = record.model_dump(mode='json')
    bad['cells'][0]['ok'] += 1
    with pytest.raises(TierWError):
        load_run_record(dumps(bad))
    bad = record.model_dump(mode='json') | {'extra': 1}
    with pytest.raises(TierWError):
        load_run_record(dumps(bad))


def test_every_write_stays_under_the_root(root, tmp_path):
    doc = corpus(root)
    outside = lambda: sorted(p for p in tmp_path.rglob('*') if p.is_file() and root not in p.parents)  # noqa: E731
    before = outside()
    run(root, doc, conditions=(H, V), secondary_engines=('rz-diff',),
        secondary={'rz-diff': lambda p: rz_set(doc, int(p.parent.parent.name[-1]), 'yes', [(0x1000, 0x1000)])})
    assert outside() == before == []
    with pytest.raises(TierWError) as caught:
        R.run_corpus(Layout(root), doc, corpus_id=CID, config_factory=configs, invoker=FakeGhidriff(),
                     matches_path=tmp_path / 'matches.jsonl')
    assert caught.value.code == 'PT-TIERW-CONFIG' and not (tmp_path / 'matches.jsonl').exists()


@pytest.mark.parametrize('change', ['pair-id', 'corpus-id', 'binary-ref', 'condition', 'engine'])
def test_malformed_input_is_refused_before_any_work(root, change):
    doc = corpus(root)
    kw: dict = {}
    if change == 'pair-id':
        doc = doc.model_copy(update={'pairs': (doc.pairs[0].model_copy(update={'id': '..'}),)})
    elif change == 'corpus-id':
        doc = doc.model_copy(update={'corpus_id': 'tier-w-other'})
    elif change == 'binary-ref':
        doc = doc.model_copy(update={'pairs': (doc.pairs[0].model_copy(update={'older': 'w-missing'}),)})
    elif change == 'condition':
        kw['conditions'] = ('symbols-maybe',)
    else:
        kw['secondary_engines'] = ('diaphora',)
    fake = FakeGhidriff()
    with pytest.raises(TierWError) as caught:
        run(root, doc, fake, **kw)
    assert caught.value.code == 'PT-TIERW-INPUT' and not fake.calls and not (root / 'tier-w').exists()
