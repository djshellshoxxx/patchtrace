"""Regressions for the 2026-10-12 enrichment security review (findings 1-6)."""
from __future__ import annotations

import json
import threading

import pytest

from patchtrace import cli
from patchtrace.enrichment import pipeline, signals
from patchtrace.enrichment.cache import CacheConfig, DerivedCache
from patchtrace.enrichment.contracts import RankingConfig
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    yield svc
    if not svc.store.closed:
        svc.close()


def top(result):
    return result.ranking.entries[0].score


def test_cancelled_run_is_never_cached(service, tmp_path, monkeypatch):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    clean = top(pipeline.run(service.project))
    assert clean > 0
    cancel = threading.Event()
    real = signals.detect

    def cancelling(view, enabled=None, c=None):
        cancel.set()
        return real(view, enabled, cancel)

    monkeypatch.setattr(signals, 'detect', cancelling)
    result = pipeline.run(service.project, pipeline.PipelineOptions(cache=cache), cancel)
    assert result.status.stages[0].status == 'cancelled'
    monkeypatch.setattr(signals, 'detect', real)
    again = pipeline.run(service.project, pipeline.PipelineOptions(cache=cache))
    assert top(again) == clean


def test_non_default_profiles_never_shown_as_default(service, capsys):
    root = service.root
    service.close()
    assert cli.main(['rank', str(root)]) == 0
    assert cli.main(['rank', str(root), '--disable', 'BND', '--disable', 'SCRUB', '--disable', 'OVF',
                     '--disable', 'VAL', '--disable', 'ERR', '--disable', 'SIZE', '--disable', 'INT']) == 0
    cli.main(['flags', str(root), '--feature-id', '7'])
    capsys.readouterr()
    reopened = ProjectService.open(root)
    try:
        ranking, sets, note = pipeline.load_default(EnrichmentStore(reopened.store), reopened.project)
        assert ranking is not None and ranking.entries[0].score > 0, note
        assert ranking.config_digest == __import__('patchtrace.enrichment.ranking', fromlist=['x']).config_digest(
            RankingConfig())
        assert {s.match_id for s in sets} == {e.match_id for e in ranking.entries}
        assert any(s.signals for s in sets)
    finally:
        reopened.close()


def test_only_non_default_profile_yields_no_default(service, capsys):
    root = service.root
    service.close()
    assert cli.main(['rank', str(root), '--disable', 'BND']) == 0
    capsys.readouterr()
    reopened = ProjectService.open(root)
    try:
        ranking, _, _ = pipeline.load_default(EnrichmentStore(reopened.store), reopened.project)
        assert ranking is None
    finally:
        reopened.close()


def test_poisoned_cache_entry_is_ignored(service, tmp_path):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    first = pipeline.run(service.project, pipeline.PipelineOptions(cache=cache))
    key = first.stage_ids['signals']
    payload = json.loads(cache.get('signals', key))
    # Forge: move a signal's excerpt hash so it no longer matches the live code.
    for item in payload:
        for sig in item['signals']:
            sig['locations'][0]['excerpt_sha256'] = 'f' * 64
    poisoned = DerivedCache(CacheConfig(root=tmp_path / 'cache2'))
    assert poisoned.put('signals', key, json.dumps(payload, sort_keys=True, separators=(',', ':')).encode(),
                        {'stage': 'signals'})
    second = pipeline.run(service.project, pipeline.PipelineOptions(cache=poisoned))
    assert second.ranking == first.ranking
    for item in payload:
        item['pairing_id'] = '0' * 64
    forged = DerivedCache(CacheConfig(root=tmp_path / 'cache3'))
    forged.put('signals', key, json.dumps(payload).encode(), {'stage': 'signals'})
    assert pipeline.run(service.project, pipeline.PipelineOptions(cache=forged)).ranking == first.ranking


def test_file_snapshot_feature_claims_ignored_and_stale_warned(service, tmp_path, capsys):
    from pathlib import Path

    from patchtrace.enrichment import cve
    fixtures = Path(__file__).parent / 'fixtures' / 'cve'
    snap = cve.normalize('CVE-2024-38063', {'nvd': (fixtures / 'nvd_CVE-2024-38063.json').read_bytes()},
                         '2020-01-01T00:00:00+00:00').model_copy(update={'feature_ids': (42,)})
    path = tmp_path / 's.json'
    path.write_text(json.dumps([snap.model_dump(mode='json')]))
    root = service.root
    service.close()
    code = cli.main(['correlate', str(root), '--cve', 'CVE-2024-38063', '--snapshot', str(path), '--json',
                     '--dry-run'])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and doc['status'] == 'partial'
    assert any('unverified' in w for w in doc['warnings']) and any('stale' in w for w in doc['warnings'])
    assert all(c['kind'] != 'feature' for e in doc['result']['entries'] for c in e['contributions'])


def test_weights_must_be_object(service, tmp_path, capsys):
    path = tmp_path / 'w.json'
    path.write_text('["BND"]')
    root = service.root
    service.close()
    assert cli.main(['rank', str(root), '--weights', str(path), '--dry-run']) == 2


def test_stale_row_records_computed_revision(service):
    import dataclasses
    result = pipeline.run(service.project)
    older = dataclasses.replace(result, views=dataclasses.replace(result.views, revision=0))
    assert service.project.revision != 0
    written = pipeline.publish(EnrichmentStore(service.store), service.project, older)
    assert all(e.project_revision == 0 for e in written)
