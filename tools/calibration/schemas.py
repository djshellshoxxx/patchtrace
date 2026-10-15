"""Generate JSON schemas for the calibration contracts into docs/schemas/calibration/ (run from repo root:
`PYTHONPATH=src python -m tools.calibration.schemas`). Kept here so the shared generate_schemas.py is untouched."""
from __future__ import annotations

import json
from pathlib import Path

from patchtrace.calibration.artifact import CalibrationArtifact
from patchtrace.calibration.ledger import ValidationLedger

from .contracts import CalibrationReport, CorpusManifest, LabelRecord

SCHEMAS = ((CalibrationArtifact, 'patchtrace-calibration-model/1'), (CorpusManifest, 'calibration-corpus/1'),
           (LabelRecord, 'calibration-labels/1'), (CalibrationReport, 'calibration-report/1'),
           (ValidationLedger, 'validation-ledger/1'))


def render() -> dict[str, str]:
    out = {}
    for model, ident in SCHEMAS:
        schema = model.model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/{ident}/{model.__name__}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[f'{model.__name__}.json'] = json.dumps(schema, indent=2) + '\n'
    return out


def main() -> int:
    root = Path('docs/schemas/calibration')
    root.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (root / name).write_text(text, encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
