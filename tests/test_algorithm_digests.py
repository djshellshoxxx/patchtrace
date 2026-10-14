"""SPEC-07h Phase D: algorithm digests in derived-cache keys and stored rows (synthetic sample project)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from patchtrace.enrichment import cve, identity, pipeline, ranking, signals
from patchtrace.enrichment.cache import CacheConfig, DerivedCache
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService


@pytest.fixture
def svc(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    yield service
    if not service.store.closed:
        service.close()


@dataclass(frozen=True)
class _Rule:
    name: str
    weight: int
    run: object = field(default=None)


def test_constants_digest_covers_plain_data_only():
    base = {'__name__': 'm', 'A': 1, 'B': 'x', '_C': re.compile(r'a+b'), 'D': frozenset({'b', 'a'}),
            'E': {'k': (1, 2)}, 'F': _Rule('r', 3, run=len), 'G': 0.5, 'f': len, 'json': json, 'T': _Rule}
    digest = identity.constants_digest('t', 1, [base])
    assert digest == identity.constants_digest('t', 1, [dict(base, f=print, json=re, T=int)])  # code ignored
    for name, value in (('A', 2), ('B', 'y'), ('_C', re.compile(r'a+c')), ('D', frozenset({'a'})),
                        ('E', {'k': (1, 3)}), ('F', _Rule('r', 4)), ('G', 0.25)):
        assert identity.constants_digest('t', 1, [dict(base, **{name: value})]) != digest, name
    assert identity.constants_digest('t', 1, [dict(base, A=9)], exclude={'A'}) == \
        identity.constants_digest('t', 1, [base], exclude={'A'})


def test_digests_ignore_cancel_granularity(monkeypatch):
    before = pipeline.algorithm_digests()
    monkeypatch.setattr(signals, 'CANCEL_EVERY', 7)
    assert pipeline.algorithm_digests() == before


@pytest.mark.parametrize('module,name,value,changed', [
    (signals, '_TEMP', re.compile(r'[a-z]Var\d+'), {'signals', 'wil', 'ranking', 'contextual'}),
    (ranking, 'MULTIPLIER', {'strong': 100, 'moderate': 60, 'weak': 35, 'unavailable': 0},
     {'ranking', 'contextual'}),
    (cve, 'STOPWORDS', frozenset({'the'}), {'contextual'}),
], ids=['signals', 'ranking', 'cve'])
def test_constant_change_moves_stage_ids(svc, monkeypatch, module, name, value, changed):
    options = pipeline.PipelineOptions(snapshots=())
    before = pipeline.run(svc.project, options).stage_ids
    monkeypatch.setattr(module, name, value)
    after = pipeline.run(svc.project, options).stage_ids
    assert {stage for stage in before if before[stage] != after[stage]} == changed


def test_derived_cache_misses_after_algorithm_change(svc, tmp_path, monkeypatch):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    options = pipeline.PipelineOptions(cache=cache)
    pipeline.run(svc.project, options)
    calls = []
    real = signals.detect
    monkeypatch.setattr(signals, 'detect', lambda *a, **k: calls.append(1) or real(*a, **k))
    pipeline.run(svc.project, options)
    assert calls == []  # hit
    monkeypatch.setattr(signals, 'WINDOW', signals.WINDOW + 1)
    pipeline.run(svc.project, options)
    assert calls  # the older algorithm's entry is not served


def test_stored_rows_of_older_algorithm_not_served(svc, monkeypatch):
    store = EnrichmentStore(svc.store)
    pipeline.publish(store, svc.project, pipeline.run(svc.project))
    assert pipeline.load_default(store, svc.project)[0] is not None
    monkeypatch.setattr(signals, 'WINDOW', signals.WINDOW + 1)
    result, sets, note = pipeline.load_default(store, svc.project)
    assert result is None and sets == () and 'stale' in note and 'older PatchTrace' in note
    digest = ranking.config_digest(ranking.RankingConfig())
    assert pipeline.load_profile(store, svc.project, digest)[0] is None


def test_rows_without_algorithm_record_not_served(svc):
    store = EnrichmentStore(svc.store)
    pipeline.publish(store, svc.project, pipeline.run(svc.project))
    db = svc.store.connection
    for row_id, body in db.execute("SELECT id, body FROM enrichment_entries WHERE kind='pipeline'").fetchall():
        doc = json.loads(body)
        assert 'algorithms' in doc
        doc.pop('algorithms')
        text = json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        import hashlib
        db.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
                   (text, hashlib.sha256(text.encode()).hexdigest(), row_id))
    db.commit()
    result, _sets, note = pipeline.load_default(store, svc.project)
    assert result is None and 'older PatchTrace' in note


def test_algorithm_digests_are_pinned():
    """Golden values: any change to an algorithm constant must show up here as a reviewed re-baseline
    (record it in docs/qa.md). Identical on every OS: nothing platform-dependent may enter a digest."""
    digests = pipeline.algorithm_digests()
    expected = json.loads((Path(__file__).parent / 'fixtures' / 'algorithm_digests.json').read_text('utf-8'))
    assert digests == expected
