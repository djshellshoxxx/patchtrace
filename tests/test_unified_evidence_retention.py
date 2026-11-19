"""SPEC-31 R2 evidence retention: authored atoms and real local publication/read paths.

Support remains a component max-pool inventory. These controls inspect the retained atoms,
not an obsolete requirement that Support itself name the corroborating evidence classes.
No analyzer, target binary, network service or frozen outcome is used here.
"""
from __future__ import annotations

import dataclasses
import json
import os
import random
import subprocess
import sys
from itertools import combinations
from pathlib import Path

import pytest
from unified_read_support import publish, request
from unified_s0_fixtures import make_project

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline, read_model, read_text, store
from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.fusion.components import components_for
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits
from patchtrace.unified.registry import REGISTRY
from patchtrace.unified.sources import SourceGroup

OLD, NEW = 0x1000, 0x1800
COMPONENTS = components_for(REGISTRY)


def atom(*, source='ghidriff', step='ExactMnemonicsFunctionHasher', cls='E-BODY', tier='B',
         old=OLD, new=NEW, ref=None, card='1:1', native=()) -> Atom:
    return Atom(source=source, step=step, tier=tier, cls=cls, older_rva=old, newer_rva=new,
                cardinality=card, ref=ref, native=native)


def crowded(copies=70, *, contest=False) -> list[Atom]:
    atoms = [*(atom(ref=f'body-{i:03}') for i in range(copies)),
             atom(step='StringsRefsHasher', cls='E-DATA', ref='data-witness'),
             atom(source='pt-bytes', step='P08-mnemonic-seq', ref='body-witness')]
    if contest:
        atoms.append(atom(new=0x3000, ref='opposition'))
    return atoms


def selected(atoms, *, cap=DEFAULT_LIMITS.l39_atoms_per_row, pair=(OLD, NEW)):
    return next(row for row in arbiter.decide(atoms, [], limits=UnifiedLimits(l39_atoms_per_row=cap))
                if row.pair == pair)


def component(a):
    return COMPONENTS.of(REGISTRY, a.source, a.step)


def has_witness(row):
    usable = [a for a in row.atoms if (a.older_rva, a.newer_rva) == row.pair
              and a.tier == 'B' and a.cls != 'E-UNKNOWN']
    return any(component(x) != component(y) and x.cls != y.cls for x, y in combinations(usable, 2))


def mirror(a):
    return a.model_copy(update={'older_rva': a.newer_rva, 'newer_rva': a.older_rva,
                                'cardinality': {'1:N': 'N:1', 'N:1': '1:N'}.get(a.cardinality, a.cardinality)})


@pytest.mark.parametrize('copies', [1, 70])
@pytest.mark.parametrize('contest', [False, True])
def test_persisted_acceptance_keeps_its_witness_and_component_inventory(tmp_path, copies, contest):
    atoms = crowded(copies, contest=contest)
    row = selected(atoms)
    assert row.decision == ('contested' if contest else 'matched')
    assert not row.mapped
    if contest:
        assert 'uncontested:matched' in row.hints
        assert row.contest.strength == 'strong'
        assert [row.atoms[i].ref for i in row.contest.against] == ['opposition']
    # This is the current Support contract, even when both selected entries are E-BODY.
    assert [(s.component, s.tier, row.atoms[s.atom_index].ref) for s in row.support] == [
        ('K1', 'B', 'body-000'), ('K2', 'B', 'body-witness')]
    assert len(row.atoms) <= DEFAULT_LIMITS.l39_atoms_per_row
    record = arbiter.to_match(row, {}, 'a' * 64, 'b' * 64)
    loaded = publish(tmp_path / 'result', [record])
    assert store.verify_result_dir(loaded.directory) == loaded.manifest
    [restored] = store.read_rows(loaded.directory, loaded.manifest)
    assert restored == record
    vm = read_model.load_unified(request(loaded))
    detail = read_model.row_detail(vm, vm.rows[0])
    assert has_witness(arbiter.decided_from_match(restored))
    assert 'E-DATA' in detail and 'E-BODY' in detail
    omitted = len(atoms) - len(row.atoms)
    assert (f'atoms-omitted:{omitted}' in row.hints) == bool(omitted)


def test_capped_witness_follows_permutations_mirroring_and_native_text():
    atoms = crowded(contest=True)
    expected = selected(atoms)
    assert has_witness(expected)
    for seed in (7, 19, 101):
        shuffled = list(atoms)
        random.Random(seed).shuffle(shuffled)
        assert selected(shuffled) == expected
        swapped = selected([mirror(a) for a in shuffled], pair=(NEW, OLD))
        assert set(swapped.atoms) == {mirror(a) for a in expected.atoms}
        assert (swapped.decision, swapped.hints, swapped.mapped) == (
            expected.decision, expected.hints, expected.mapped)
        assert {swapped.atoms[i] for i in swapped.contest.against} == {
            mirror(expected.atoms[i]) for i in expected.contest.against}
    for text in ('0.00001', '1.0', 'unknown'):
        changed = selected([a.model_copy(update={'native': (('confidence', text),)}) for a in atoms])
        assert changed.decision == expected.decision and has_witness(changed)
        assert {a.model_copy(update={'native': ()}) for a in changed.atoms} == set(expected.atoms)


@pytest.mark.parametrize('contest,cap', [(False, 2), (True, 3)])
def test_a_cap_too_small_for_the_witness_refuses_both_orientations(contest, cap):
    atoms = crowded(contest=contest)
    for values in (atoms, list(reversed(atoms)), [mirror(a) for a in atoms]):
        with pytest.raises(UnifiedError) as caught:
            arbiter.decide(values, [], limits=UnifiedLimits(l39_atoms_per_row=cap))
        assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-LIMIT', 'atoms-cap')


@pytest.mark.parametrize('cap', [5, 6])
def test_witness_and_opposing_mirror_twins_are_reserved_as_whole_groups(cap):
    atoms = [a.model_copy(update={'newer_rva': OLD}) for a in crowded()
             if a.ref != 'data-witness']
    data = atom(step='StringsRefsHasher', cls='E-DATA', new=OLD, ref='data-witness', card='1:N')
    against = atom(old=OLD, new=0x3000, ref='opposing-twins')
    atoms.extend((data, mirror(data), against, mirror(against)))
    for values in (atoms, [mirror(a) for a in atoms]):
        if cap == 5:
            with pytest.raises(UnifiedError) as caught:
                arbiter.decide(values, [], limits=UnifiedLimits(l39_atoms_per_row=cap))
            assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-LIMIT', 'atoms-cap')
        else:
            row = selected(values, cap=cap, pair=(OLD, OLD))
            assert len(row.atoms) == cap and has_witness(row)
            assert {data, mirror(data), against, mirror(against)} <= set(row.atoms)
            assert {row.atoms[i] for i in row.contest.against} == {against, mirror(against)}


@pytest.mark.parametrize('case,cap,decision', [
    ('same-class', 2, 'tentative'), ('one-component', 1, 'tentative'),
    ('unknown-class', 2, 'tentative'), ('weak-only', 1, 'candidate'),
    ('contested-tentative', 3, 'contested'), ('tier-a', 2, 'matched'), ('tier-m', 3, 'matched'),
])
def test_other_admission_rules_do_not_reserve_a_b_witness(case, cap, decision):
    atoms = crowded()
    if case in ('same-class', 'contested-tentative'):
        atoms = [a for a in atoms if a.cls == 'E-BODY']
    elif case == 'one-component':
        atoms = [a for a in atoms if component(a) == 'K1']
    elif case == 'unknown-class':
        atoms = [atom(), atom(source='pt-bytes', step='P08-mnemonic-seq', cls='E-UNKNOWN')]
    elif case == 'weak-only':
        atoms = [atom(tier='C', step='StructuralGraphHash', cls='E-CFG')]
    elif case == 'tier-a':
        atoms.append(atom(step='SymbolsHash', cls='E-NAME', tier='A', ref='unique-key'))
    elif case == 'tier-m':
        atoms.append(atom(source='manual', step='manual-correction', cls='E-MANUAL', tier='M'))
    if case == 'contested-tentative':
        atoms.append(atom(new=0x3000, ref='opposition'))
    row = selected(atoms, cap=cap)
    assert row.decision == decision and len(row.atoms) <= cap
    assert not has_witness(row)
    if case == 'contested-tentative':
        assert 'uncontested:tentative' in row.hints and row.contest is not None


def test_inferred_group_does_not_claim_an_analyst_or_reserve_a_pair_witness():
    atoms = (atom(ref='first'), atom(step='StringsRefsHasher', cls='E-DATA', new=NEW + 16))
    group = SourceGroup(source='ghidriff', kind='ghidriff-1n', older=(OLD,), newer=(NEW, NEW + 16),
                        decision='ambiguous', reason='authored', atoms=atoms)
    [row] = arbiter.decide([], [group], limits=UnifiedLimits(l39_atoms_per_row=1))
    assert row.decision == 'ambiguous' and row.pair is None and row.support == () and len(row.atoms) == 1
    record = arbiter.to_match(row, {}, 'a' * 64, 'b' * 64)
    assert read_text.reason_text(record) == read_text.DECISION_MEANING['ambiguous']
    # An unsupported hint alone is not analyst evidence.
    assert 'analyst correction' not in read_text.reason_text(
        record.model_copy(update={'hints': ('manual-group:ambiguous',)})).lower()


@pytest.mark.parametrize('kind', ['split', 'merged', 'ambiguous'])
def test_public_manual_group_decision_is_attributed_in_desktop_and_reopened_cli(tmp_path, capsys, kind):
    service = make_project(tmp_path / 'project')
    try:
        first, second = [m for m in service.project.matches if m.older and m.newer][:2]
        older = [first.older[0].id] + ([second.older[0].id] if kind == 'merged' else [])
        newer = [first.newer[0].id] + ([] if kind == 'merged' else [second.newer[0].id])
        service.correct_match(first.id, older, newer, kind, 'Authored analyst group')
        report = pipeline.run_unified(service, pipeline.UnifiedOptions(
            isolate=False, use_ir=False, decompile=False, sources=('manual',)))
        assert report.status == 'ok'
        captured = read_model.request_from_service(service)
        assert captured.loaded.state == 'current'
        store.verify_result_dir(captured.loaded.directory)
        vm = read_model.load_unified(captured)
        [row] = vm.rows
        record = read_model.records_for(vm, [row])[row.row_id].match
        assert record.support == () and f'manual-group:{kind}' in record.hints
        assert record.decision == ('ambiguous' if kind == 'ambiguous' else 'matched')
        detail, root = read_model.row_detail(vm, row), service.root
    finally:
        service.close()
    assert cli.main(['unified', 'explain', str(root), '--row', row.row_id, '--json']) == 0
    document = json.loads(capsys.readouterr().out)
    assert document['result']['state'] == 'current' and document['result']['detail'] == detail
    decision = next(line for line in detail.split('\n') if line.startswith('Decision:'))
    assert 'analyst correction' in decision.lower() and kind in decision
    assert 'Independent tier B evidence' not in decision


def test_arbiter_rekey_preserves_verified_old_history_and_current_source_headless_reads(tmp_path):
    old_registry = dataclasses.replace(REGISTRY, channel_versions=tuple(
        (name, 2 if name == 'arbiter' else version) for name, version in REGISTRY.channel_versions))
    service = make_project(tmp_path / 'project')
    try:
        old_plan = pipeline.make_plan(service, registry=old_registry, use_ir=False)
        new_plan = pipeline.make_plan(service, use_ir=False)
        # Only the arbiter configuration changes the key. Other input/channel/engine policies stay intact.
        assert old_plan.identity.key_inputs.model_copy(update={
            'config_digest': new_plan.config_digest}) == new_plan.identity.key_inputs
        assert old_plan.config_digest != new_plan.config_digest and old_plan.result_id != new_plan.result_id
        # A valid historical record shaped like the old capped omission remains readable, without inventing
        # a replay of the old native producer: two component inventories, only one retained evidence class.
        chosen = selected([atom(), atom(source='pt-bytes', step='P08-mnemonic-seq')])
        old_row = arbiter.to_match(chosen, {}, old_plan.older_sha256, old_plan.newer_sha256).model_copy(
            update={'decision': 'matched', 'hints': ('atoms-omitted:8',)})
        staged = store.new_staging_dir(service.root, old_plan.run_id)
        manifest = store.write_result(
            staged, older_sha256=old_plan.older_sha256, newer_sha256=old_plan.newer_sha256,
            ghidriff_run_id=old_plan.run_id, ghidriff_raw_sha256=old_plan.raw_sha256,
            ir_older=None, ir_newer=None, sources=old_plan.identity.source_refs,
            manual_digest=old_plan.identity.manual_digest, config_digest=old_plan.config_digest,
            status='complete', limitations=(), rows=[old_row], facts=[])
        assert manifest.result_id == old_plan.result_id
        saved = store.publish_result(EnrichmentStore(service.store), staged, guard=old_plan.guard(),
                                     current=old_plan.guard(), revision=service.project.revision)
        assert pipeline.load_current(service, old_plan).state == 'current'
        stale = pipeline.load_current(service, new_plan)
        assert stale.state == 'stale' and list(pipeline.read_rows(stale)) == [old_row]
        before = {p.name: p.read_bytes() for p in saved.directory.iterdir() if p.is_file()}
        root = service.root
    finally:
        service.close()
    source = Path(__file__).resolve().parents[1] / 'src'
    code = ('import sys; from pathlib import Path; import patchtrace; from patchtrace import cli; '
            f'assert Path(patchtrace.__file__).resolve().is_relative_to(Path({str(source)!r})); '
            f'rc = cli.main({["unified", "explain", str(root), "--row", old_row.row_id, "--json"]!r}); '
            'assert not any(k.startswith(("PySide", "PyQt")) for k in sys.modules); raise SystemExit(rc)')
    child = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20,
                           env=dict(os.environ, PYTHONPATH=str(source), QT_QPA_PLATFORM='offscreen'))
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout)['result']['state'] == 'stale'
    service = ProjectService.open(root)
    try:
        report = pipeline.run_unified(service, pipeline.UnifiedOptions(isolate=False, use_ir=False, decompile=False))
        assert report.status == 'ok' and report.result_id == new_plan.result_id
        assert pipeline.load_current(service, pipeline.make_plan(service, use_ir=False)).state == 'current'
        assert store.verify_result_dir(saved.directory) == manifest
        assert list(store.read_rows(saved.directory, manifest)) == [old_row]
        assert {p.name: p.read_bytes() for p in saved.directory.iterdir() if p.is_file()} == before
    finally:
        service.close()
