"""Derived-cache hit speed-ups must not move any persisted id, digest or ranking byte (SPEC-07 §12)."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from bench_enrichment import build_project  # noqa: E402

from patchtrace.enrichment import pipeline  # noqa: E402
from patchtrace.enrichment.cache import CacheConfig, DerivedCache  # noqa: E402
from patchtrace.enrichment.contracts import SignalSet  # noqa: E402


def fixed_project(pairs: int = 40):
    """The bench workload with deterministic record ids, so every derived id is reproducible."""
    project = build_project(pairs, pairs * 10)
    for artifact, ident in zip(project.artifacts, ('art-older', 'art-newer'), strict=True):
        object.__setattr__(artifact, 'id', ident)
    object.__setattr__(project.runs[0], 'id', 'run-1')
    for index, match in enumerate(project.matches):
        object.__setattr__(match, 'id', f'match-{index}')
        object.__setattr__(match, 'run_id', 'run-1')
        for side, art in ((match.older, 'art-older'), (match.newer, 'art-newer')):
            for number, record in enumerate(side):
                object.__setattr__(record, 'id', f'fn-{index}-{art}-{number}')
                object.__setattr__(record, 'run_id', 'run-1')
                object.__setattr__(record, 'artifact_id', art)
    return project


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fingerprint(result) -> dict:
    return {'diff': result.views.diff_id, 'pairings': _digest([m.pairing_id for m in result.views.matches]),
            'input': result.guard.input_digest, 'stages': result.stage_ids,
            'signals': _digest([s.model_dump(mode='json') for s in result.signal_sets]),
            'ranking': _digest(result.ranking.model_dump(mode='json'))}


GOLDEN = {  # recorded from the unoptimized implementation
    'diff': 'cd50fcad566d4e5087bf9d20297faefb82f91dbe58c6bc29af0f06c881340234',
    'pairings': '1e30fabe4da2aa363885a7b518422fab74acb2e87b59f13f8fa5ea078b23ec8c',
    'input': 'eb383b9f0a64da2aab6f50f5121516900843f5a77a65b62b323a515c6dcfbaba',
    'stages': {'signals': '0c7a58faae6e916fb21ff38890159186d17f03f16c02d0b20d14cc2f0a04518f',
               'wil': '6f97400c47ec3a9af6adcb127a184453f1e471594ed5013dc75e5a167ebb8a5b',
               'ranking': '94696d1bdf67c80fe778f31bc4242a2b0ebc72680877adceda536d245182ddb8',
               'contextual': '8c34cd253ba30f234cc678e1aec8ea33e9b9f461e3cc7d2e3cd2cdf43e368f0a'},
    'signals': '7b352273f5ec8dccb8b0f4bc2a7896f9f9bcc823e40429757c57bfd2e4d33369',
    'ranking': '70d875efffb48f19409c09dcc920b8d42d484b8845c211fa28d8b5511ca83a02',
}


def test_pipeline_ids_and_ranking_are_pinned():
    assert fingerprint(pipeline.run(fixed_project())) == GOLDEN


def test_cache_hit_equals_miss_and_pins(tmp_path):
    options = pipeline.PipelineOptions(cache=DerivedCache(CacheConfig(root=tmp_path)))
    miss = pipeline.run(fixed_project(), options)
    hit = pipeline.run(fixed_project(), options)
    assert fingerprint(miss) == fingerprint(hit) == GOLDEN
    assert hit.signal_sets == miss.signal_sets


def test_cached_payload_omits_defaults_and_full_payloads_still_load(tmp_path):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'lean'))
    miss = pipeline.run(fixed_project(), pipeline.PipelineOptions(cache=cache))
    key = miss.stage_ids['signals']
    payload = cache.get('signals', key)
    assert b'"contract"' not in payload and b'"typed_evidence"' not in payload
    stored = pipeline._adapter(SignalSet).validate_json(payload)
    full = pipeline._adapter(SignalSet).dump_json(list(stored))
    assert len(payload) < len(full)
    legacy_cache = DerivedCache(CacheConfig(root=tmp_path / 'full'))
    assert legacy_cache.put('signals', key, full, {'stage': 'signals'})
    legacy = pipeline.run(fixed_project(), pipeline.PipelineOptions(cache=legacy_cache))
    assert legacy.signal_sets == miss.signal_sets and legacy.ranking == miss.ranking
