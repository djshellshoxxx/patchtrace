"""Deterministic report.json (canonical, hashed) and report.md. Automated evidence only."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from ..common import canonical_json

PREREG_PATH = Path(__file__).resolve().parents[3] / 'docs' / 'plans' / 'pilot-preregistration-v1.md'
REPORT_CONTRACT = 'pilot-eval/1'


def prereg_sha256(path: Path = PREREG_PATH) -> str:
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def build_report(*, prereg_sha: str, corpus_sha: str, tool_sha: str, arms: Mapping[str, Mapping], gate: Mapping,
                 exclusions: Mapping[str, int]) -> dict:
    body = {'contract': REPORT_CONTRACT, 'prereg_sha256': prereg_sha, 'corpus_sha256': corpus_sha,
            'tool_sha': tool_sha, 'arms': dict(sorted((k, dict(v)) for k, v in arms.items())), 'gate': dict(gate),
            'exclusions': dict(sorted(exclusions.items()))}
    body['report_sha256'] = hashlib.sha256(canonical_json(body)).hexdigest()
    return json.loads(canonical_json(body))


def render_markdown(report: Mapping) -> str:
    gate = report['gate']
    lines = [f"# Patch-intent localization evaluation ({report['contract']})", '',
             f"Preregistration SHA-256: `{report['prereg_sha256']}`",
             f"Corpus SHA-256: `{report['corpus_sha256']}`", f"Tool SHA: `{report['tool_sha']}`", '',
             f"## Gate G-PIL: {gate.get('status', 'not-evaluated')}", '']
    lines += [f'- {name}: {"met" if met else "not met"}' for name, met in sorted(gate.get('conditions', {}).items())]
    lines += ['', '## Exclusions', ''] + [f'- {k}: {v}' for k, v in report['exclusions'].items()]
    lines += ['', '## Arms', ''] + [f'- {name}: {json.dumps(row, sort_keys=True)}' for name, row in report['arms'].items()]
    lines += ['', 'Automated evidence only; owner-only acceptance is outside this protocol.', '']
    return '\n'.join(lines)
