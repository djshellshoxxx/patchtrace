"""SPEC-50 RPT2-6: headless section adapters over a real (synthetic sample) project; hermetic, no Qt."""
from __future__ import annotations

from pathlib import Path

import pytest
from test_pilot_store import put as put_pilot_result
from test_secondary_store import _set

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.report2.adapters import UnifiedReferencePort, collect_from_service
from patchtrace.secondary import publish_secondary
from patchtrace.service import ProjectService

CSAF = Path(__file__).parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'


@pytest.fixture(autouse=True)
def no_artifact(tmp_path_factory, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path_factory.mktemp('nocal'))


@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as opened:
        yield opened


def publish_engine(service, engine: str, sha: str):
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    run = next(r for r in service.project.runs if r.status == 'completed' and r.raw_sha256)
    guard = Guard(service.project.id, run.id, run.raw_sha256, sha)
    match_set = _set(sides['older'], sides['newer'], sha)
    if engine == 'bindiff':
        row = match_set.matches[0].model_copy(update={'engine': 'bindiff', 'confidence_milli': 900,
                                                      'confidence_text': '0.9'})
        match_set = match_set.model_copy(update={'engine': 'bindiff', 'matches': (row,)})
    return publish_secondary(EnrichmentStore(service.store), guard, guard, service.project.revision, match_set)


def test_empty_project_has_no_optional_sections(service):
    sections = collect_from_service(service)
    assert (sections.engine_evidence, sections.advisories, sections.leads, sections.series) == (None,) * 4
    assert not any('engine_evidence' in u or 'advisories' in u or 'leads' in u for u in sections.unknowns)


def test_collecting_never_writes_to_the_project(tmp_path):
    with ProjectService.sample(tmp_path / 'ro') as opened:
        before = (opened.root / 'project.sqlite3').read_bytes()
        collect_from_service(opened)
        assert (opened.root / 'project.sqlite3').read_bytes() == before


def test_series_stays_none_because_no_project_scoped_record_exists(service):
    assert collect_from_service(service).series is None


def test_engine_evidence_lists_each_engine_and_never_scores_a_missing_one(service):
    publish_engine(service, 'rz-diff', '1' * 64)
    sections = collect_from_service(service)
    evidence = sections.engine_evidence
    assert [e.name for e in evidence.engines] == ['rz-diff'] and len(evidence.rows) == len(service.project.matches)
    assert not evidence.stale
    assert all(c.engine != 'bindiff' for row in evidence.rows for c in row.channels)
    assert 'engine_evidence: bindiff has no stored match set; unknown, not a negative result' in sections.unknowns


def test_engine_evidence_two_engines_stay_separate(service):
    publish_engine(service, 'rz-diff', '1' * 64)
    publish_engine(service, 'bindiff', '2' * 64)
    sections = collect_from_service(service)
    assert sorted(e.name for e in sections.engine_evidence.engines) == ['bindiff', 'rz-diff']
    assert not any('has no stored match set' in u for u in sections.unknowns)


def test_advisories_are_vendor_claims_with_inert_text(service):
    AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id, service.project.revision).add(
        CSAF.read_bytes(), origin='local-import', uri=None, file_name='a.json', retrieved_at='2099-03-01T00:00:00Z')
    advisories = collect_from_service(service).advisories
    assert advisories and {a.kind for a in advisories} >= {'cve'}
    assert all(a.claim_level == 'vendor-claim' and a.snapshot_digest and a.fetched_at for a in advisories)
    assert all(a.id.startswith(('CVE-', 'CWE-')) for a in advisories)
    assert all('\u202e' not in a.text for a in advisories)


def test_failing_producer_gives_none_and_a_recorded_unknown(service, monkeypatch):
    publish_engine(service, 'rz-diff', '1' * 64)

    def boom(self):
        raise RuntimeError('disk on fire')
    monkeypatch.setattr(AdvisoryStore, 'advisories', boom)
    sections = collect_from_service(service)
    assert sections.advisories is None and sections.engine_evidence is not None
    assert any(u.startswith('advisories: producer failed (RuntimeError)') for u in sections.unknowns)
    assert not any('disk on fire' in u for u in sections.unknowns)


def test_build_facts_are_observed_in_file_and_timestamps_are_claims(service):
    facts = collect_from_service(service).build_facts
    assert facts, 'expected at least the claimed COFF timestamp'
    assert {f.side for f in facts} == {'older', 'newer'}
    assert all(f.claim_level == 'observed-in-file' for f in facts)
    stamps = [f for f in facts if f.fact == 'timestamp_claim']
    assert stamps and all(f.value.startswith('claimed ') for f in stamps)


def test_unreadable_artifact_is_unknown_not_fatal(service):
    for artifact in service.project.artifacts:
        path = service.root / artifact.relative_path
        path.chmod(0o600)  # ingested artifacts are deliberately read-only on both supported platforms
        path.write_bytes(b'tampered')
    sections = collect_from_service(service)
    assert sections.build_facts is None
    assert sum('could not be read' in u for u in sections.unknowns) == 2


def test_leads_come_from_a_current_stored_pilot_result(service):
    put_pilot_result(service, EnrichmentStore(service.store))
    sections = collect_from_service(service)
    assert sections.leads
    for lead in sections.leads:
        assert lead.channels and 'not a probability' in lead.statement


def test_stale_pilot_result_is_omitted_with_a_reason(service):
    put_pilot_result(service, EnrichmentStore(service.store), swapped=True)
    sections = collect_from_service(service)
    assert sections.leads is None
    assert any(u.startswith('leads: the stored pilot result is stale') for u in sections.unknowns)


def test_unified_reference_uses_the_read_model_not_the_default_plan(service, monkeypatch):
    seen = []
    from patchtrace.unified import read_model
    monkeypatch.setattr(read_model, 'capture_candidates', lambda s: seen.append('capture') or 'candidates')
    monkeypatch.setattr(read_model, 'resolve_best', lambda c: seen.append(c) or None)
    UnifiedReferencePort(service).load()
    assert seen == ['capture', 'candidates']


@pytest.mark.parametrize('flags', [['--sources', 'manual'], ['--no-extract'], ['--no-residual']],
                         ids=['sources', 'no-extract', 'no-residual'])
def test_unified_result_made_with_non_default_options_is_not_exported_as_stale(tmp_path, capsys, flags):
    from unified_s0_fixtures import make_project

    from patchtrace import cli
    from patchtrace.unified import pipeline
    root = tmp_path / 'unified'
    make_project(root).close()
    assert cli.main(['unified', 'run', str(root), '--in-process', '--json', *flags]) == 0
    capsys.readouterr()
    with ProjectService.open(root) as opened:
        sections = collect_from_service(opened)
        assert sections.unified_result is not None and not sections.unified_result.stale
        default_loaded = pipeline.load_current(opened, pipeline.make_plan(opened))
    if flags != ['--no-extract']:  # the old default-plan lookup is what reported these as stale
        assert default_loaded.state == 'stale'
