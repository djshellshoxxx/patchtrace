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
