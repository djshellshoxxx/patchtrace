"""SPEC-31 06 s5 wiring: stored `diaphora-matches` rows -> plan (result key) -> worker request file -> compute -> published
result, plus the CLI source list. The project and its Ghidriff document are the synthetic ones of the S0 tests; the
Diaphora sets are hand-built `diaphora/1` models stored through the real enrichment store. Synthetic: not live evidence."""
from __future__ import annotations

import pytest
from test_unified_diaphora_adapter import dm, dset, du
from unified_s0_fixtures import make_project

from patchtrace.diaphora.contracts import KIND
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.unified import compute, exchange, pipeline, store
from patchtrace.unified.cli import SOURCES, _sources
from patchtrace.unified.pipeline import UnifiedOptions

NON_DIAPHORA = tuple(s for s in exchange.ALL_SOURCES if s != 'diaphora')


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def inproc(**kw) -> UnifiedOptions:
    return UnifiedOptions(isolate=False, **kw)


def store_set(service, **kw):
    """Publish a set for the project's pair exactly as `diaphora.service.import_into_project` does."""
    project = service.project
    sides = {a.side: a.sha256 for a in project.artifacts}
    run = next(r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256)
    match_set = dset(**{'older': sides['older'], 'newer': sides['newer'], **kw})
    guard = Guard(project.id, run.id, run.raw_sha256, match_set.result_sha256)
    EnrichmentStore(service.store).publish(KIND, guard, guard, project.revision, 'complete',
                                           match_set.model_dump(mode='json'), match_set.entry_id)
    return match_set


def rows_by_name(service):
    loaded = pipeline.load_current(service, pipeline.make_plan(service))
    return loaded, {(r.older[0].name if r.older else None, r.newer[0].name if r.newer else None): r
                    for r in store.read_rows(loaded.directory, loaded.manifest)}


def test_the_default_source_lists_name_diaphora():
    assert 'diaphora' in exchange.ALL_SOURCES and 'diaphora' in SOURCES and set(SOURCES) == set(exchange.ALL_SOURCES)
    assert _sources('ghidriff,diaphora') == ('ghidriff', 'diaphora')
    from patchtrace.cli import CliError
    with pytest.raises(CliError):
        _sources('ghidriff,diaphora,nope')


def test_cli_help_lists_diaphora(capsys):
    from patchtrace import cli
    assert cli.main(['unified', 'run', '--help']) == 0
    text = ' '.join(capsys.readouterr().out.split())
    assert 'ghidriff, bindiff, rz-diff, diaphora, manual' in text


def test_a_project_without_diaphora_keeps_its_result_id(project):
    """Selecting the new source without any stored set adds no source ref, so every existing id stays what it was."""
    plan = pipeline.make_plan(project)
    assert plan.diaphora == () and all(r.source != 'diaphora' for r in plan.identity.source_refs)
    assert pipeline.make_plan(project, NON_DIAPHORA).result_id == plan.result_id
    assert pipeline.make_plan(project, NON_DIAPHORA).identity.key_inputs == plan.identity.key_inputs


def test_a_new_or_changed_set_changes_the_result_id_and_a_deselected_source_does_not(project):
    before = pipeline.make_plan(project)
    store_set(project, matches=[dm(0, 0x1000, 0x1080)])
    one = pipeline.make_plan(project)
    assert one.result_id != before.result_id and [r.source for r in one.identity.source_refs].count('diaphora') == 1
    assert pipeline.make_plan(project, NON_DIAPHORA).result_id == before.result_id
    store_set(project, matches=[dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280, 'partial')], result='f' * 64)
    two = pipeline.make_plan(project)
    assert two.result_id not in (before.result_id, one.result_id)
    assert [r.source for r in two.identity.source_refs].count('diaphora') == 2
    assert pipeline.make_plan(project).result_id == two.result_id                   # stable: same stored sets, same id


def test_a_set_for_another_pair_is_not_loaded(project):
    store_set(project, matches=[dm(0, 0x1000, 0x1080)], older='1' * 64)
    assert pipeline.make_plan(project).diaphora == ()


def test_worker_request_carries_the_set_files_and_the_worker_rebuilds_the_same_identity(project, tmp_path):
    store_set(project, matches=[dm(0, 0x1000, 0x1080)], unmatched=[du(0, 'older', 0x1400)])
    request = pipeline.prepare(project, inproc())
    private = tmp_path / 'private'
    private.mkdir()
    (tmp_path / 'staged').mkdir()
    (tmp_path / 'staged2').mkdir()
    path = pipeline._write_request(request, private)
    req = exchange.read_request(path)
    assert len(req.diaphora) == 1 and set(req.sources) == set(exchange.ALL_SOURCES)
    report = compute.run_request(path, tmp_path / 'staged')
    assert report.ok and report.result_id == request.plan.result_id and report.status == 'complete'
    # the file is re-hashed by the worker: any change is refused
    from pathlib import Path

    from patchtrace.unified.limits import UnifiedError
    Path(req.diaphora[0].path).write_bytes(Path(req.diaphora[0].path).read_bytes() + b' ')
    with pytest.raises(UnifiedError) as caught:
        compute.run_request(path, tmp_path / 'staged2')
    assert caught.value.code == 'PT-UNIFIED-INPUT'


def test_end_to_end_a_verified_set_adds_evidence_and_never_changes_a_ghidriff_pair(project):
    plain = pipeline.run_unified(project, inproc())
    store_set(project, matches=[dm(0, 0x1000, 0x1080, 'best', 'Pseudo-code fuzzy hash', older_name='read_item',
                                   newer_name='read_item'),
                                dm(1, 0x1200, 0x1280, 'partial', 'Same name'),
                                dm(2, 0x1300, 0x1380, status='external-ea-only'),
                                dm(3, 0x1500, 0x1900, 'unreliable', 'Graph isomorphism')],
              unmatched=[du(0, 'older', 0x1400)])
    report = pipeline.run_unified(project, inproc())
    assert report.status == 'ok' and report.result_id != plain.result_id
    assert 'diaphora-external-ea-skipped:1' in report.limitations and report.result_status == 'complete'
    loaded, rows = rows_by_name(project)
    assert loaded.state == 'current' and loaded.manifest.result_id == report.result_id
    assert 'diaphora' in {s.source for s in loaded.manifest.sources}
    read_item = rows[('read_item', 'read_item')]
    assert {a.source for a in read_item.atoms} == {'ghidriff', 'diaphora'}
    assert {(a.tier, a.cls) for a in read_item.atoms if a.source == 'diaphora'} == {('B', 'E-DECOMP')}
    assert read_item.decision == 'matched'                                  # Ghidriff SymbolsHash is tier A on its own
    assert {s.component for s in read_item.support} == {'K1'}               # one independent component, not two
    assert report.counts.decisions.contested == plain.counts.decisions.contested == 0
    assert any(None in (a.older_rva, a.newer_rva) and a.source == 'diaphora'
               for row in rows.values() for a in row.atoms)                  # the unmatched observation is shown


def test_end_to_end_a_user_attested_set_changes_no_decision(project):
    plain = pipeline.run_unified(project, inproc())
    _loaded, base_rows = rows_by_name(project)
    base = {k: (r.decision, r.support, r.contest) for k, r in base_rows.items()}
    # a misattributed set that pairs every function with the wrong partner
    store_set(project, trust='user-attested', matches=[dm(0, 0x1000, 0x1700), dm(1, 0x1600, 0x1080)])
    report = pipeline.run_unified(project, inproc())
    assert report.result_id != plain.result_id and 'diaphora-unverified-set' in report.limitations
    assert report.result_status == 'complete' and report.counts.decisions.contested == 0
    _loaded, rows = rows_by_name(project)
    assert {k: (r.decision, r.support, r.contest) for k, r in rows.items() if k in base} == base
    assert all(r.contest is None for r in rows.values())
    shown = [a for r in rows.values() for a in r.atoms if a.source == 'diaphora']
    assert shown and all(a.tier == 'W' and None in (a.older_rva, a.newer_rva) for a in shown)


def test_reversed_stored_set_never_reaches_fusion(project):
    sides = {a.side: a.sha256 for a in project.project.artifacts}
    store_set(project, matches=[dm(0, 0x1000, 0x1080)], older=sides['newer'], newer=sides['older'])
    plan = pipeline.make_plan(project)
    assert plan.diaphora == () and all(r.source != 'diaphora' for r in plan.identity.source_refs)
