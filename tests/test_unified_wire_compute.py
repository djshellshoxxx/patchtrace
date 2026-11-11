"""SPEC-31 wiring of the finished slices into `compute` (S3 channels, S2 ladder, S5 residual stage): the compute step
reads two placed ProgramIR sidecars, runs the ladder with the residual passes, feeds its atoms to fusion, judges every
pair with the IR channels and stores the row flags, the IR references and the identity. The IR is the RECORDED real
Ghidra 12.0.4 output of the clang probe pair (tests/fixtures/unified/PROVENANCE.json) or hand-assembled x86-64 through
the real ingest; the Ghidriff, BinDiff and rz-diff inputs are empty or synthetic, so nothing here is live evidence for
those engines."""
from __future__ import annotations

import dataclasses
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_unified_gu_mutants import recorded
from unified_facts_builder import BASE, NEW_SHA, OLD_SHA, SIZE, build_reader, function
from unified_s0_fixtures import RAW_SHA, func, match

from patchtrace.unified import compute, keys, store
from patchtrace.unified.addressing import AddressMap, PeLayout
from patchtrace.unified.compute import IrInputs, compute_config_digest, compute_result, plan_identity
from patchtrace.unified.contracts import Atom, Support
from patchtrace.unified.exchange import ALL_SOURCES
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.ir.ladder_port import ReaderSide
from patchtrace.unified.ladder import residual
from patchtrace.unified.ladder.engine import run_ladder
from patchtrace.unified.ladder.types import CorrGroup
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted
from patchtrace.unified.registry import REGISTRY
from patchtrace.unified.sources import GhidriffRun, RawGhidriff, SourceInputs
from patchtrace.unified.sources.ladder import anchor_pairs, ladder_output

FIXED = '2026-01-01T00:00:00+00:00'
RAW = RawGhidriff(status='ok', address_matches={}, sha256=RAW_SHA)


def sections(tables) -> tuple[tuple[int, int], ...]:
    return tuple((s.start, s.end) for s in tables.sections)


def probe(tmp_path, *, matches=(), same=False):
    """The recorded clang pair as compute inputs `(SourceInputs, AddressMap, IrInputs)`; `same` = the older build on
    both sides (X versus X)."""
    old, tables_old, data_old = recorded(tmp_path, 'probe_old')
    new, tables_new, data_new = (old, tables_old, data_old) if same else recorded(tmp_path, 'probe_new')
    layout = PeLayout(image_base=old.manifest.image_base, size_of_image=old.manifest.size_of_image)
    inputs = SourceInputs(older_sha256=data_old['sha256'], newer_sha256=data_new['sha256'],
                          run=GhidriffRun('run-1', '1', RAW), matches=tuple(matches))
    return inputs, AddressMap(layout, layout), IrInputs(old, new, sections(tables_old), sections(tables_new))


def run(tmp_path, inputs, addr, name='out', **kw):
    directory = tmp_path / name
    directory.mkdir()
    kw.setdefault('created_utc', FIXED)
    return compute_result(inputs, addr, result_dir=directory, **kw), directory


def rows_of(directory: Path, manifest) -> dict:
    """older name -> (row, facts) of a result."""
    facts = {f.row_id: f for f in store.read_facts(directory, manifest)}
    return {r.older[0].name: (r, facts.get(r.row_id)) for r in store.read_rows(directory, manifest) if r.older}


def verdicts(rows: dict) -> dict:
    return {name: (f.verdict, f.proof) for name, (_r, f) in rows.items()}


def files_of(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


# --- identity ---------------------------------------------------------------------------------------------------------------

def test_the_config_digest_covers_the_ladder_table_the_residual_switch_and_the_registry_rows(monkeypatch):
    base = compute_config_digest()
    assert base == compute_config_digest(REGISTRY, DEFAULT_LIMITS, residual=True)
    assert compute_config_digest(residual=False) != base                      # backup B-07 is another configuration
    monkeypatch.setattr(residual, 'RESIDUAL_VERSION', 'residual/9')
    assert compute_config_digest() != base                                    # `table_digest()` feeds the digest ...
    monkeypatch.undo()
    assert compute_config_digest(dataclasses.replace(REGISTRY, passes=REGISTRY.passes[:-1])) != base   # ... and the rows


def test_the_result_id_is_planned_before_the_run_and_covers_the_ir_digests(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    manifest, _ = run(tmp_path, inputs, addr, ir=ir)
    older, newer = ir.digests()
    planned = plan_identity(inputs, addr, ALL_SOURCES, ir=(older, newer))
    assert planned.result_id == manifest.result_id
    assert (planned.key_inputs.ir_older_digest, planned.key_inputs.ir_newer_digest) == (older, newer)
    assert manifest.ir_older.content_digest == older and manifest.ir_newer.content_digest == newer
    assert plan_identity(inputs, addr, ALL_SOURCES).result_id != planned.result_id           # S0 mode is another result
    assert plan_identity(inputs, addr, ALL_SOURCES, ir=(newer, older)).result_id != planned.result_id
    assert plan_identity(inputs, addr, ALL_SOURCES, ir=(older, newer), residual=False).result_id != planned.result_id
    assert keys.result_key(keys.result_key_inputs(manifest)) == manifest.result_id


# --- the recorded real pair through the whole step ---------------------------------------------------------------------------

def test_the_recorded_probe_pair_runs_through_ladder_fusion_and_the_ir_facts(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    events = []
    manifest, directory = run(tmp_path, inputs, addr, ir=ir, emit=events.append)
    assert [(e.stage, e.done, e.total) for e in events] == [('sources', 0, 4), ('ladder', 1, 4), ('fusion', 2, 4),
                                                           ('facts', 3, 4), ('write', 4, 4)]
    assert manifest.status == 'complete' and 'ir-not-extracted' not in manifest.limitations
    assert manifest.ir_older.functions == manifest.ir_newer.functions == 7
    assert manifest.ir_older.producer_mode == 'analyze' and manifest.ir_older.ir_key == ir.older.manifest.ir_key
    rows = rows_of(directory, manifest)
    assert set(rows) == {'add_clamped', 'dispatch', 'use_data', 'say', 'tick', 'loop_sum', 'limit_check'}
    for name, (row, _facts) in rows.items():                       # every pair came from the ladder, not from a name
        assert row.decision == 'matched' and {a.source for a in row.atoms} == {'pt-ladder'}, name
        assert [(a.step, a.tier) for a in row.atoms] == [('P03-name-exact', 'A')], name
    got = verdicts(rows)
    assert got['loop_sum'] == got['limit_check'] == ('unchanged', 'UNCH/1')          # moved, equal bytes, targets mapped
    assert got['tick'] == ('cosmetic', 'COS-ADDR/1')                                  # a call to the moved add_clamped
    for name in ('add_clamped', 'dispatch'):
        assert got[name][0] == 'review' and {d.cls for d in rows[name][1].deltas} == {'constant'}
    assert got['say'][0] == 'review' and 'string' in {d.cls for d in rows['say'][1].deltas}
    assert got['use_data'][0] in ('material', 'review')
    assert rows['say'][0].flags == rows['tick'][0].flags == ('tiny',) and rows['loop_sum'][0].flags == ()


def test_the_step_is_deterministic_and_the_same_build_against_itself_is_all_unchanged(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    first, a = run(tmp_path, inputs, addr, 'a', ir=ir)
    again, b = run(tmp_path, inputs, addr, 'b', ir=ir)
    assert files_of(a) == files_of(b) and first.result_id == again.result_id
    (tmp_path / 'same').mkdir()
    same_inputs, same_addr, same_ir = probe(tmp_path / 'same', same=True)
    manifest, directory = run(tmp_path, same_inputs, same_addr, 'xvx', ir=same_ir)
    rows = rows_of(directory, manifest)
    assert len(rows) == 7 and set(verdicts(rows).values()) == {('unchanged', 'UNCH/1')}     # G-U1 through the whole step
    assert manifest.counts.decisions.matched == 7 and manifest.counts.materiality.unchanged == 7


def test_without_ir_the_step_stays_in_s0_mode(tmp_path):
    inputs, addr, _ir = probe(tmp_path)
    manifest, directory = run(tmp_path, inputs, addr)
    assert manifest.ir_older is None and manifest.ir_newer is None and manifest.limitations == ('ir-not-extracted',)
    assert manifest.counts.total() == 0 and [p.name for p in manifest.parts] == ['facts.jsonl.gz', 'rows.jsonl.gz']
    assert sorted(p.name for p in directory.iterdir()) == ['facts.jsonl.gz', 'manifest.json', 'rows.jsonl.gz']


# --- the residual stage and backup B-07 ----------------------------------------------------------------------------------------

ALPHA = [('mov_ri', 'EAX', 0x2001), ('add_ri', 'EAX', 3), ('xor_rr', 'ECX', 'ECX'), ('test_rr', 'EAX', 'EAX'),
         ('mov_rr', 'EDX', 'EAX'), ('mov_ri', 'ECX', 0x77), ('ret',)]
BETA = [('mov_ri', 'EAX', 0x3001), ('sub_ri', 'EAX', 5), ('xor_rr', 'EDX', 'EDX'), ('test_rr', 'ECX', 'ECX'),
        ('mov_rr', 'ECX', 'EAX'), ('mov_ri', 'EDX', 0x99), ('ret',)]
GAMMA_OLD = [('mov_ri', 'EAX', 11), ('cmp_ri', 'ECX', 3), ('jcc', 'Z', 'out'), ('add_ri', 'EAX', 1), ('label', 'out'),
             ('mov_rr', 'EDX', 'EAX'), ('ret',)]
GAMMA_NEW = [('mov_ri', 'ECX', 99), ('sub_ri', 'ECX', 2), ('test_rr', 'EDX', 'EDX'), ('xor_rr', 'EAX', 'EAX'),
             ('mov_rr', 'EBX', 'ECX'), ('mov_ri', 'EAX', 5), ('add_ri', 'EAX', 4), ('ret',)]


def gap_world(tmp_path):
    """alpha and beta match by name; the unnamed function between them was rewritten completely, so no content key
    agrees: only the layout gap between two anchors (P18, tier C) can pair it."""
    def image(gamma):
        return [function(0x1000, ALPHA, name='alpha', sym={}),
                function(0x1100, gamma, name='FUN_180001100', sym={}, name_src='DEFAULT'),
                function(0x1200, BETA, name='beta', sym={})]
    old = build_reader(tmp_path, 'gap-old', image(GAMMA_OLD), sha=OLD_SHA)
    new = build_reader(tmp_path, 'gap-new', image(GAMMA_NEW), sha=NEW_SHA)
    inputs = SourceInputs(older_sha256=OLD_SHA, newer_sha256=NEW_SHA, run=GhidriffRun('run-1', '1', RAW), matches=())
    data = ((0x2000, 0x3000), (0x3000, 0x4000))
    return inputs, AddressMap(PeLayout(BASE, SIZE), PeLayout(BASE, SIZE)), IrInputs(old, new, data, data)


def test_the_residual_stage_runs_and_backup_b07_switches_it_off(tmp_path):
    inputs, addr, ir = gap_world(tmp_path)
    full, full_dir = run(tmp_path, inputs, addr, 'full', ir=ir)
    skipped, skipped_dir = run(tmp_path, inputs, addr, 'skip', ir=ir, residual=False)
    gap = [r for r in store.read_rows(full_dir, full) if r.older[0].rva == 0x1100]
    assert len(gap) == 1 and gap[0].decision == 'candidate'
    assert [(a.source, a.step, a.tier) for a in gap[0].atoms] == [('pt-ladder', 'P18-layout-gap', 'C')]
    assert full.counts.decisions.candidate == 1 and skipped.counts.decisions.candidate == 0
    assert [r.older[0].rva for r in store.read_rows(skipped_dir, skipped)] == [0x1000, 0x1200]
    assert full.result_id != skipped.result_id and full.config_digest != skipped.config_digest


# --- the analyst's corrections are the ladder's P00 anchors ------------------------------------------------------------------------

def test_a_one_to_one_correction_anchors_the_ladder_and_wins_over_every_pass(tmp_path):
    """The analyst pairs `say` (older) with `tick` (newer): tier M, P00, whatever the names and bytes say."""
    correction = match('m1', 'modified', older=[func('say', 0x1080)], newer=[func('tick', 0x10c0)], manual=True)
    inputs, addr, ir = probe(tmp_path, matches=[correction])
    manifest, directory = run(tmp_path, inputs, addr, ir=ir)
    rows = {(r.older[0].rva, r.newer[0].rva): r for r in store.read_rows(directory, manifest) if r.older and r.newer}
    row = rows[(0x1080, 0x10c0)]
    assert row.decision == 'matched' and any(a.tier == 'M' for a in row.atoms)
    assert not [k for k in rows if k[0] == 0x1080 and k != (0x1080, 0x10c0)]          # no other pairing of `say`
    assert 'ladder-anchors-outside-ir' not in ' '.join(manifest.limitations)


def test_a_correction_that_names_no_function_entry_of_the_ir_is_counted_not_hidden(tmp_path):
    odd = match('m2', 'modified', older=[func('nowhere', 0x1ff0)], newer=[func('nowhere', 0x1ff8)], manual=True)
    inputs, addr, ir = probe(tmp_path, matches=[odd])
    manifest, directory = run(tmp_path, inputs, addr, ir=ir)
    assert 'ladder-anchors-outside-ir:1' in manifest.limitations and manifest.status == 'complete'
    assert (0x1ff0, 0x1ff8) in {(r.older[0].rva, r.newer[0].rva) for r in store.read_rows(directory, manifest)
                                if r.older and r.newer}                   # fusion still has the analyst's pairing


def test_anchor_pairs_take_only_tier_m_one_to_one_atoms_whose_functions_exist(tmp_path):
    _inputs, _addr, ir = probe(tmp_path)

    def atom(older, newer, *, tier='M', card='1:1'):
        return Atom(source='manual', step='manual-correction', tier=tier, cardinality=card, cls='E-MANUAL',
                    older_rva=older, newer_rva=newer)
    pairs, outside = anchor_pairs([atom(0x1080, 0x10c0), atom(0x1000, None), atom(0x1000, 0x1000, tier='A'),
                                   atom(0x1000, 0x1000, card='1:N'), atom(0x1ff0, 0x1000)], ir.older, ir.newer)
    assert pairs == ((3, 4),) and outside == 1


# --- limits and the partial ladder ------------------------------------------------------------------------------------------------

def test_a_ladder_that_the_budget_stopped_is_a_degrading_limitation(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    cancelled = threading.Event()
    cancelled.set()
    stopped = run_ladder(ReaderSide(ir.older), ReaderSide(ir.newer), budget=Budget(cancel=cancelled, check_every=1))
    assert stopped.status == 'partial'
    output = ladder_output(stopped, ir.older, ir.newer)
    assert 'ladder-partial:cancelled' in output.limitations and compute.is_degrading('ladder-partial:cancelled')
    assert not compute.is_degrading('ladder-limit-neighbour-cap:3')


def test_the_ladders_groups_and_limits_are_counted_in_the_limitations(tmp_path):
    _inputs, _addr, ir = probe(tmp_path)
    done = run_ladder(ReaderSide(ir.older), ReaderSide(ir.newer))
    assert ladder_output(done, ir.older, ir.newer).limitations == ()
    duplicates = (CorrGroup('duplicate', (0,), (1,), 'content-identical'), CorrGroup('icf', (2,), (3,), 'alias-fold'))
    grouped = dataclasses.replace(done, groups=duplicates, limits_hit=(('neighbour-cap', 3), ('block-cap', 1)))
    assert ladder_output(grouped, ir.older, ir.newer).limitations == (
        'ladder-groups-not-shown:2', 'ladder-limit-block-cap:1', 'ladder-limit-neighbour-cap:3')


# --- the row flags -----------------------------------------------------------------------------------------------------------------

def test_to_match_stores_the_row_flags_sorted_without_repeats_and_only_valid_ones():
    atom = Atom(source='ghidriff', step='SymbolsHash', tier='A', cardinality='1:1', cls='E-NAME', older_rva=0x1000,
                newer_rva=0x2000)
    d = arbiter.Decided(older=(0x1000,), newer=(0x2000,), decision='matched',
                        support=(Support(component='K1', tier='A', atom_index=0),), contest=None, atoms=(atom,),
                        hints=(), pair=(0x1000, 0x2000), mapped=True)
    row = arbiter.to_match(d, {}, OLD_SHA, NEW_SHA, flags=('tiny', 'pdata-confirmed', 'tiny'))
    assert row.flags == ('pdata-confirmed', 'tiny') and arbiter.to_match(d, {}, OLD_SHA, NEW_SHA).flags == ()
    with pytest.raises(ValidationError):
        arbiter.to_match(d, {}, OLD_SHA, NEW_SHA, flags=('not-a-flag',))


# --- U7-06: a deadline that passes during the ladder keeps the partial result -----------------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def _expire_at_fusion(clock):
    def emit(event):
        if event.stage == 'fusion':
            clock.now = 100.0
    return emit


def test_a_deadline_that_passes_in_the_ladder_stores_a_partial_result_with_unknown_rows(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    clock = FakeClock()
    budget = Budget(deadline=50.0, clock=clock, check_every=1)
    manifest, directory = run(tmp_path, inputs, addr, ir=ir, budget=budget, emit=_expire_at_fusion(clock))
    assert manifest.status == 'partial'
    assert 'timeout' in manifest.limitations and compute.is_degrading('timeout')
    stored = store.read_rows(directory, manifest)
    assert stored and any(r.materiality == 'unknown' for r in stored)
    assert all(r.materiality in ('unknown', 'not-applicable') for r in stored)    # never a negative verdict
    assert not any(r.materiality == 'unchanged' for r in stored)


def test_a_cancel_in_the_ladder_still_aborts_the_run(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    cancelled = threading.Event()

    def emit(event):
        if event.stage == 'fusion':
            cancelled.set()
    with pytest.raises(BudgetExhausted) as stopped:
        run(tmp_path, inputs, addr, ir=ir, budget=Budget(cancel=cancelled, check_every=1), emit=emit)
    assert stopped.value.code == 'PT-UNIFIED-CANCEL'
