"""p7 (A-29): the ladder's leftovers reach fusion as one-sided `pt-ladder` atoms, so an IR-only result (no `ghidriff`
source) shows `older-only`/`newer-only` rows. Synthetic only: the sidecars of tests/unified_wire_support.py (`debug_dump`
exists only in the older image, `report_invalid_index` only in the newer one) and hand-built correspondences.

What the row model carries: a stored `UnifiedMatch` keeps the atoms of the row (the leftover reason is the atom's
`native` pair ('reason', <reason>)) and `hints` (`one-sided-by:<source>`); the tests assert both."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

from patchtrace.unified import pipeline, store
from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.ir import schema
from patchtrace.unified.ladder.types import Correspondence, Leftover
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.sources.ladder import ladder_output


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def run_rows(service, sources):
    options = UnifiedOptions(isolate=False, sources=sources, refresh=True)
    pipeline.run_unified(service, options)
    loaded = pipeline.load_current(service, pipeline.make_plan(service, sources))
    assert loaded.state == 'current'
    return list(store.read_rows(loaded.directory, loaded.manifest))


def one_sided(rows, decision):
    return [r for r in rows if r.decision == decision]


def pairs_of(rows):
    return sorted((r.older[0].rva, r.newer[0].rva, r.decision) for r in rows if r.older and r.newer)


def ladder_atoms(row):
    return [a for a in row.atoms if a.source == 'pt-ladder' and a.step == 'leftover']


# --- (a) IR only ------------------------------------------------------------------------------------------------------------------

def test_ir_only_result_shows_the_ladders_one_sided_functions(project, tmp_path):
    place_pair(project, scratch=tmp_path)
    rows = run_rows(project, ('manual',))
    (old,) = one_sided(rows, 'older-only')
    (new,) = one_sided(rows, 'newer-only')
    assert (old.older[0].name, old.older[0].kind) == ('debug_dump', 'function')
    assert (new.newer[0].name, new.newer[0].kind) == ('report_invalid_index', 'function')
    for row in (old, new):
        assert 'one-sided-by:pt-ladder' in row.hints
        (atom,) = ladder_atoms(row)
        assert (atom.tier, atom.cls, atom.cardinality) == ('W', 'E-UNKNOWN', '1:1')
        assert dict(atom.native)['reason']                       # the leftover reason is display text in `native`
    assert (ladder_atoms(old)[0].newer_rva, ladder_atoms(new)[0].older_rva) == (None, None)


# --- (b) with Ghidriff -------------------------------------------------------------------------------------------------------------

def test_with_ghidriff_the_pairs_are_the_same_and_both_observations_are_hints(project, tmp_path):
    place_pair(project, scratch=tmp_path)
    ir_only = run_rows(project, ('manual',))
    both = run_rows(project, ('ghidriff', 'manual'))
    assert [(a, b) for a, b, _ in pairs_of(ir_only)] == [(a, b) for a, b, _ in pairs_of(both)]
    for decision in ('older-only', 'newer-only'):
        (row,) = one_sided(both, decision)
        assert row.hints.count('one-sided-by:pt-ladder') == 1
        assert row.hints.count('one-sided-by:ghidriff') == 1
        assert len(ladder_atoms(row)) == 1


# --- (c) fusion: a leftover never contests -----------------------------------------------------------------------------------------

def test_a_leftover_never_contests_a_pair_of_another_source():
    leftover = Atom(source='pt-ladder', step='leftover', tier='W', cardinality='1:1', cls='E-UNKNOWN',
                    older_rva=0x1000, newer_rva=None, native=(('reason', 'no-unique-evidence'),))
    pair = Atom(source='ghidriff', step='SymbolsHash', tier='A', cardinality='1:1', cls='E-NAME',
                older_rva=0x1000, newer_rva=0x2000)
    rows = arbiter.decide([leftover, pair], [])
    assert len(rows) == 1
    (row,) = rows
    assert (row.older, row.newer, row.decision, row.contest) == ((0x1000,), (0x2000,), 'matched', None)
    assert 'one-sided-by:pt-ladder' in row.hints and leftover in row.atoms


# --- (d), (e) ladder_output over stub readers --------------------------------------------------------------------------------------

class _Table:
    def __init__(self, rows):
        self.rows, self.name = rows, [r[3] for r in rows]

    def get(self, column, fid):
        rva, kind, flags, _ = self.rows[fid]
        return {'rva': rva, 'kind': kind, 'flags': flags}[column]


def reader(*rows):
    return SimpleNamespace(functions=_Table(rows))


NORMAL, EXTERNAL = schema.KIND_CODES['normal'], schema.KIND_CODES['external']
IMPORT = schema.FN_FLAGS['import']


def correspondence(older_only, newer_only):
    return Correspondence(pairs=(), groups=(), older_only=older_only, newer_only=newer_only, status='complete',
                          stop_reason=None, passes_completed=(), limits_hit=(), stats=(), older_rva=(0x10, 0x20, 0x30),
                          newer_rva=(0x40, 0x50))


OLDER = reader((0x10, NORMAL, 0, 'a'), (0x20, NORMAL, IMPORT, 'imp'), (0x30, EXTERNAL, 0, 'ext'))
NEWER = reader((0x40, NORMAL, 0, 'b'), (0x50, NORMAL, 0, 'c'))


def test_imports_and_externals_are_counted_never_rows():
    corr = correspondence((Leftover(0, 'tiny'), Leftover(1, 'tiny'), Leftover(2, 'oversize')), ())
    out = ladder_output(corr, OLDER, NEWER)
    assert [(a.older_rva, a.newer_rva, a.step) for a in out.atoms] == [(0x10, None, 'leftover')]
    assert [(n.side, n.rva, n.kind) for n in out.nodes] == [('older', 0x10, 'function')]
    assert 'ladder-leftovers-not-shown:import' in out.limitations or any(
        s.startswith('ladder-leftovers-not-shown:import') for s in out.limitations)
    assert any(s.startswith('ladder-leftovers-not-shown:external') for s in out.limitations)
    assert not arbiter.decide(out.atoms, ())[0].newer


def test_the_leftover_output_is_deterministic_and_sorted():
    corr = correspondence((Leftover(0, 'tiny', ('b', 'a')),), (Leftover(1, 'unfinished'), Leftover(0, 'tiny')))
    first = ladder_output(corr, OLDER, NEWER)
    second = ladder_output(corr, OLDER, NEWER)
    assert first == second
    assert [(a.older_rva, a.newer_rva) for a in first.atoms] == [(0x10, None), (None, 0x40), (None, 0x50)]
    assert [(r.older, r.newer, r.decision) for r in arbiter.decide(first.atoms, ())] == [
        ((0x10,), (), 'older-only'), ((), (0x40,), 'newer-only'), ((), (0x50,), 'newer-only')]


def test_two_pipeline_runs_give_identical_rows(project, tmp_path):
    place_pair(project, scratch=tmp_path)
    first = [r.model_dump_json() for r in run_rows(project, ('manual',))]
    second = [r.model_dump_json() for r in run_rows(project, ('manual',))]
    assert first == second
