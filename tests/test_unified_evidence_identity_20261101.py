"""Issue #120: uncertain declarations abstain; changed stored evidence never reuses a result identity."""
from __future__ import annotations

import dataclasses

import pytest
from unified_s0_fixtures import (
    addr_map,
    alternative,
    bd,
    bindiff_set,
    func,
    inputs,
    loaded,
    make_project,
    match,
)

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary.store import publish_engine_set
from patchtrace.unified import pipeline, store
from patchtrace.unified.compute import compute_result, plan_identity
from patchtrace.unified.fusion.arbiter import decide
from patchtrace.unified.limits import Budget
from patchtrace.unified.sources.manual import ManualAdapter
from patchtrace.unified.sources.secondary import SecondaryAdapter


def manual(mid='manual-first', old_name='old-name', new_name='new-name', category='modified'):
    return inputs([match(mid, category, [func(old_name, 0x1000)], [func(new_name, 0x1080)], manual=True)])


def test_one_to_one_ambiguous_declaration_never_maps_a_proof_target(tmp_path):
    data = manual(category='ambiguous')
    output = ManualAdapter().atoms(data, addr_map(), Budget())
    [decided] = decide(output.atoms, output.groups)
    assert decided.decision == 'ambiguous'
    assert not decided.mapped and decided.pair is None and decided.support == ()
    destination = tmp_path / 'ambiguous'
    destination.mkdir()
    manifest = compute_result(data, addr_map(), result_dir=destination, sources=['manual'])
    [row] = list(store.read_rows(destination, manifest))
    assert row.decision == 'ambiguous' and row.support == ()
    assert list(store.read_facts(destination, manifest)) == []


@pytest.mark.parametrize('change', ['reference', 'older-name', 'newer-name', 'code', 'unicode-spelling'])
def test_manual_content_changes_invalidate_the_result_id(change):
    before = manual(old_name='caf\u00e9')
    record = before.matches[0]
    if change == 'reference':
        record = record.model_copy(update={'id': 'manual-second'})
    elif change == 'newer-name':
        record = record.model_copy(update={'newer': (record.newer[0].model_copy(update={'name': 'renamed'}),)})
    else:
        field, value = ('code', 'return 1;') if change == 'code' else (
            'name', 'cafe\u0301' if change == 'unicode-spelling' else 'renamed')
        record = record.model_copy(update={'older': (record.older[0].model_copy(update={field: value}),)})
    after = dataclasses.replace(before, matches=(record,))
    first = plan_identity(before, addr_map(), ['manual'])
    second = plan_identity(after, addr_map(), ['manual'])
    assert first.manual_digest != second.manual_digest
    assert first.result_id != second.result_id


def test_changed_manual_identity_persists_independent_results_and_retains_prior_bytes(tmp_path):
    first_dir, second_dir = tmp_path / 'first', tmp_path / 'second'
    first_dir.mkdir()
    second_dir.mkdir()
    first = compute_result(manual(), addr_map(), result_dir=first_dir, sources=['manual'])
    prior = {path.name: path.read_bytes() for path in first_dir.iterdir()}
    second = compute_result(manual(mid='manual-second', old_name='changed-name'), addr_map(),
                            result_dir=second_dir, sources=['manual'])
    assert first.result_id != second.result_id
    [first_row], [second_row] = list(store.read_rows(first_dir, first)), list(store.read_rows(second_dir, second))
    assert first_row.older[0].name == 'old-name' and second_row.older[0].name == 'changed-name'
    assert first_row.atoms != second_row.atoms
    assert {path.name: path.read_bytes() for path in first_dir.iterdir()} == prior


@pytest.mark.parametrize('change', ['addresses', 'name', 'similarity', 'flags', 'basicblocks', 'algorithm',
                                  'alternatives', 'orientation', 'limitation'])
def test_normalized_secondary_content_invalidates_identity_without_replacing_raw_provenance(change):
    initial = bindiff_set([bd(0x1000, 0x1080)])
    row = initial.matches[0]
    if change == 'alternatives':
        current = initial.model_copy(update={'alternatives': (alternative('older', 0x1000, bd(0x1000, 0x1100)),)})
    elif change == 'orientation':
        current = initial.model_copy(update={'image_base_subtracted': 'yes'})
    elif change == 'limitation':
        current = initial.model_copy(update={'limitations': ('coverage-partial',)})
    else:
        changes = {'addresses': {'newer_address': row.newer_address + 16},
                   'name': {'older_name': 'changed-name'}, 'similarity': {'similarity_text': '0.999'},
                   'flags': {'flags': ('G',)}, 'basicblocks': {'basicblocks': 0},
                   'algorithm': {'algorithm': 'function: hash matching'}}
        current = initial.model_copy(update={'matches': (row.model_copy(update=changes[change]),)})
    before, after = (inputs(secondary=[loaded(value, value.entry_id)]) for value in (initial, current))
    a, b = (plan_identity(value, addr_map(), ['bindiff']) for value in (before, after))
    assert a.result_id != b.result_id
    assert a.source_refs[0].entry_id != b.source_refs[0].entry_id
    assert a.source_refs[0].file_sha256 == b.source_refs[0].file_sha256 == initial.file_sha256
    assert a.source_refs[0].version == b.source_refs[0].version == '8.0'


def test_secondary_identity_changes_with_emitted_atoms_and_persisted_rows(tmp_path):
    old, new = (bindiff_set([bd(0x1000, target)]) for target in (0x1080, 0x1100))
    before, after = (inputs(secondary=[loaded(value, value.entry_id)]) for value in (old, new))
    a, b = (SecondaryAdapter().atoms(value, addr_map(), Budget()) for value in (before, after))
    assert a.atoms != b.atoms
    (tmp_path / 'first').mkdir()
    (tmp_path / 'second').mkdir()
    first = compute_result(before, addr_map(), result_dir=tmp_path / 'first', sources=['bindiff'])
    second = compute_result(after, addr_map(), result_dir=tmp_path / 'second', sources=['bindiff'])
    assert first.result_id != second.result_id
    [first_row] = list(store.read_rows(tmp_path / 'first', first))
    [second_row] = list(store.read_rows(tmp_path / 'second', second))
    assert first_row.newer[0].rva != second_row.newer[0].rva


def test_same_manual_snapshot_reordered_has_the_same_identity():
    first = manual().matches[0]
    second = match('manual-other', 'modified', [func('second-old', 0x1200)], [func('second-new', 0x1280)],
                   manual=True)
    a, b = (plan_identity(inputs(values), addr_map(), ['manual'])
            for values in ([first, second], [second, first]))
    assert a == b


def test_reordered_secondary_rows_with_conflicting_names_have_the_same_content_and_key():
    rows = [bd(0x1000, 0x1080, older_name='one'), bd(0x1000, 0x1080, older_name='two')]
    before, after = (inputs(secondary=[loaded(bindiff_set(values))]) for values in (rows, rows[::-1]))
    a, b = (SecondaryAdapter().atoms(value, addr_map(), Budget()) for value in (before, after))
    assert a == b
    assert plan_identity(before, addr_map(), ['bindiff']) == plan_identity(after, addr_map(), ['bindiff'])


def test_service_correction_worker_snapshot_cache_and_refresh_preserve_manual_abstention(tmp_path):
    project = make_project(tmp_path / 'project')
    try:
        removed = next(row for row in project.project.matches if row.category == 'removed')
        added = next(row for row in project.project.matches if row.category == 'added')
        project.correct_match(removed.id, [removed.older[0].id], [added.newer[0].id], 'ambiguous',
                              'The analyst has not established this relation.')
        options = pipeline.UnifiedOptions(isolate=False)
        first = pipeline.run_unified(project, options)
        current = pipeline.load_current(project, pipeline.make_plan(project))
        rows = list(store.read_rows(current.directory, current.manifest))
        [uncertain] = [row for row in rows if row.older and row.older[0].name == 'debug_dump']
        assert uncertain.decision == 'ambiguous' and uncertain.support == ()
        again = pipeline.run_unified(project, options)
        refreshed = pipeline.run_unified(project, pipeline.UnifiedOptions(isolate=False, refresh=True))
        assert again.status == 'cached' and again.result_id == first.result_id == refreshed.result_id
        assert project.store.load().matches == project.project.matches
    finally:
        project.close()


def test_republished_secondary_content_misses_cache_then_refreshes_without_result_drift(tmp_path):
    project = make_project(tmp_path / 'project')
    try:
        artifacts = {artifact.side: artifact.sha256 for artifact in project.project.artifacts}
        options = pipeline.UnifiedOptions(isolate=False)
        results = []
        for target in (0x1080, 0x1100):
            normalized = bindiff_set([bd(0x1000, target)], older=artifacts['older'], newer=artifacts['newer'])
            run = project.project.runs[-1]
            guard = Guard(project.project.id, run.id, run.raw_sha256, normalized.file_sha256)
            publish_engine_set(EnrichmentStore(project.store), guard, guard, project.project.revision, normalized)
            result = pipeline.run_unified(project, options)
            assert result.status == 'ok'
            results.append(result)
        assert results[0].result_id != results[1].result_id
        assert pipeline.run_unified(project, options).status == 'cached'
        refreshed = pipeline.run_unified(project, pipeline.UnifiedOptions(isolate=False, refresh=True))
        assert refreshed.result_id == results[1].result_id and refreshed.status == 'ok'
        assert results[0].directory.exists() and results[1].directory.exists()
    finally:
        project.close()
