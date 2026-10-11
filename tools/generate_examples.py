"""Generate contract examples using the explicitly synthetic walkthrough."""
import json
import tempfile
from pathlib import Path

from patchtrace.alignment import diff_hunks
from patchtrace.models import BackendCapabilities, ExportManifest, JobEvent
from patchtrace.service import ProjectService

with tempfile.TemporaryDirectory() as directory:
    with ProjectService.sample(Path(directory) / 'sample') as service:
        p = service.project
        match = next(m for m in p.matches if m.category == 'modified')
        interpretation = p.interpretations[0]
        finding = interpretation.findings[0]
        records = {
            'Artifact': p.artifacts[0], 'ComparisonProject': p, 'AnalysisRun': p.runs[0],
            'BackendCapabilities': BackendCapabilities(version='synthetic; no backend invoked'),
            'FunctionRecord': match.older[0], 'FunctionMatch': match,
            'DiffHunk': diff_hunks(match.older[0].code, match.newer[0].code, match.id)[0],
            'EvidenceReference': interpretation.context.evidence[0],
            'AnalysisContext': interpretation.context, 'InterpretationRun': interpretation,
            'Finding': finding, 'Hypothesis': finding.hypothesis,
            'AnalystAnnotation': p.annotations[0],
            'JobEvent': JobEvent(run_id=p.runs[0].id, stage='synthetic', message='Sample only'),
            'ExportManifest': ExportManifest(project_id=p.id, revision=p.revision, format='json',
                                              sha256='a' * 64, finding_ids=[finding.id],
                                              include_code=False, include_notes=True),
        }
        examples = {name: {'valid': record.model_dump(mode='json'),
                            'invalid': record.model_dump(mode='json') | {'schema_version': 2},
                            'invalid_reason': 'Unsupported future schema version; fail without guessing'}
                    for name, record in records.items()}
        Path('docs/schemas/examples.json').write_text(json.dumps(examples, indent=2) + '\n', encoding='utf-8')
