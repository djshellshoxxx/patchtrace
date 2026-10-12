"""Regenerate versioned public schemas; run from repository root."""
import json
from pathlib import Path

from patchtrace import models

NAMES = ['Artifact', 'ComparisonProject', 'AnalysisRun', 'BackendCapabilities',
         'FunctionRecord', 'FunctionMatch', 'DiffHunk', 'EvidenceReference',
         'AnalysisContext', 'InterpretationRun', 'Finding', 'Hypothesis',
         'AnalystAnnotation', 'JobEvent', 'ExportManifest']
root = Path('docs/schemas')
root.mkdir(parents=True, exist_ok=True)
for name in NAMES:
    schema = getattr(models, name).model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/v1/{name}.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    (root / f'{name}.json').write_text(json.dumps(schema, indent=2) + '\n', encoding='utf-8')

# SPEC-07 enrichment/1 records. PatchTrace-authored; not the supplied Phase 2 schema (see spec §0).
from patchtrace.enrichment import contracts  # noqa: E402

ENRICHMENT = ['SourceLocation', 'StageResult', 'ChangeSignal', 'DetectorOutcome', 'SignalSet', 'RankingConfig',
              'GroupSubtotal', 'RankingEntry', 'RankingResult', 'FeatureSite', 'FeatureTransition', 'CveSnapshot',
              'ContextContribution', 'ContextualEntry', 'ContextualRanking', 'CacheManifest', 'PipelineStatus']
enrichment_root = root / 'enrichment'
enrichment_root.mkdir(exist_ok=True)
for name in ENRICHMENT:
    schema = getattr(contracts, name).model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/enrichment/1/{name}.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    (enrichment_root / f'{name}.json').write_text(json.dumps(schema, indent=2) + '\n', encoding='utf-8')
