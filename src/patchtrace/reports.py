"""Atomic exports from validated, persisted project snapshots."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
from pathlib import Path

from .models import ComparisonProject, ExportManifest

MAX_REPORT_BYTES = 20 * 1024 * 1024
SAFE_SETTING_KEYS = {'timeout_seconds', 'allow_symbol_downloads', 'older_sha256', 'newer_sha256', 'python_version',
                     'pyghidra_version', 'ghidra_version', 'java_runtime_version'}


class ExportError(ValueError):
    pass


def _redact(text: str) -> str:
    text = re.sub(r'(?i)\b(?:authorization\s*:\s*bearer|bearer)\s+[^\s,;"\']+', '[REDACTED]', text)
    text = re.sub(r'(?i)\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*["\']?[^\s,;"\']+',
                  '[REDACTED]', text)
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{8,}', '[REDACTED]', text)
    text = re.sub(r'(?i)(?:[a-z]:[\\/]|\\\\)[^\s<>"\']+', '[PATH REDACTED]', text)
    text = re.sub(r'(?<![\w:/<])/(?:[^\s/<>"\']+/)*[^\s<>"\']+', '[PATH REDACTED]', text)
    text = re.sub(r'https?://[^\s/@:]+:[^\s/@]+@[^\s]+', '[CREDENTIAL URL REDACTED]', text)
    return text


def _clean(value):
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def _safe_settings(settings: dict) -> dict:
    result = {}
    for key in sorted(SAFE_SETTING_KEYS & settings.keys()):
        value = settings[key]
        if key == 'allow_symbol_downloads':
            if isinstance(value, bool):
                result[key] = value
        elif key == 'timeout_seconds':
            if type(value) is int and 1 <= value <= 86400:
                result[key] = value
        elif key.endswith('_sha256'):
            if isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value):
                result[key] = value
        elif isinstance(value, str) and re.fullmatch(
                r'(?:unknown|unverified|unavailable|not-installed|[0-9][A-Za-z0-9_.+ -]{0,99})', value):
            result[key] = value
    return result


def _snapshot(project: ComparisonProject, include_code: bool, include_notes: bool,
              finding_ids: list[str] | None) -> dict:
    project = ComparisonProject.model_validate(project.model_dump())
    findings = {f.id: (run, f) for run in project.interpretations for f in run.findings}
    selected = sorted(findings if finding_ids is None else set(finding_ids))
    if any(i not in findings for i in selected):
        raise ExportError('PT-EXPORT: requested finding ID is not in the saved project')
    selected_matches = {m for i in selected for m in findings[i][1].match_ids}
    if finding_ids is None:
        selected_matches.update(m.id for m in project.matches)
    function_ids = set()
    matches = []
    for match in sorted(project.matches, key=lambda m: m.id):
        if match.id not in selected_matches:
            continue
        data = match.model_dump(exclude={'older', 'newer'})
        for side in ['older', 'newer']:
            data[side] = []
            for f in sorted(getattr(match, side), key=lambda f: f.id):
                function_ids.add(f.id)
                function = f.model_dump(exclude={'code', 'assembly', 'metadata'})
                if include_code:
                    function['code'] = f.code
                    function['assembly'] = f.assembly
                data[side].append(function)
        matches.append(data)
    interpretations = []
    for run in sorted(project.interpretations, key=lambda r: r.id):
        run_findings = [f for f in run.findings if f.id in selected]
        if finding_ids is not None and not run_findings:
            continue
        citations = {ref for f in run_findings for h in [f.hypothesis] + f.alternatives
                     for ref in h.supporting + h.contradicting}
        context = run.context.model_dump(exclude={'payload', 'evidence'})
        context['evidence'] = []
        for ref in sorted(run.context.evidence, key=lambda e: e.id):
            if finding_ids is not None and ref.id not in citations:
                continue
            context['evidence'].append(ref.model_dump(exclude=set() if include_code else {'text'}))
        # Omission strings describe untrusted input names and may contain source/code fragments.
        context['omitted'] = [f'{len(run.context.omitted)} omitted or unavailable context entries']
        context['stale'] = run.context.stale or run.context.revision != project.revision
        data = run.model_dump(exclude={'context', 'findings', 'raw_response'})
        data['context'] = context
        data['findings'] = []
        for f in sorted(run_findings, key=lambda f: f.id):
            result = f.model_dump()
            result['stale'] = f.stale or context['stale']
            if not include_notes:
                result.pop('analyst_conclusion', None)
            data['findings'].append(result)
        interpretations.append(data)
    relevant = {project.id} | selected_matches | function_ids | set(selected)
    result = {
        'schema_version': 1, 'project_id': project.id, 'name': project.name, 'revision': project.revision,
        'created': project.created, 'sample': project.sample,
        'limitations': ['Static evidence and hypotheses require analyst verification.',
                        'Qualitative confidence is not a vulnerability probability.',
                        'Unavailable context and stale findings remain explicitly identified.',
                        'Raw provider responses and original source paths are excluded.'],
        'selection': {'finding_ids': selected, 'include_code': include_code, 'include_notes': include_notes},
        'artifacts': [{'id': a.id, 'side': a.side, 'name': a.name.replace('\\', '/').split('/')[-1],
                       'sha256': a.sha256, 'size': a.size, 'architecture': a.architecture, 'format': a.format}
                      for a in sorted(project.artifacts, key=lambda a: a.id)],
        'analysis_runs': [r.model_dump(include={'schema_version', 'id', 'created', 'status', 'backend',
                                               'backend_version', 'raw_sha256', 'error'})
                          | {'settings': _safe_settings(r.settings)}
                          for r in sorted(project.runs, key=lambda r: r.id)],
        'matches': matches, 'interpretations': interpretations,
        'annotations': [a.model_dump() for a in sorted(project.annotations, key=lambda a: a.id)
                        if include_notes and (finding_ids is None or a.target_id in relevant)],
    }
    return _clean(result)


def _markdown_escape(value: str) -> str:
    value = html.escape(value, quote=False)
    return re.sub(r'([\\`*_{}\[\]()#+.!|>-])', r'\\\1', value)


def _render(data: dict, format: str) -> str:
    serialized = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    if format == 'json':
        return serialized + '\n'
    if format == 'html':
        title = html.escape(data['name'])
        parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
                 '<meta name="viewport" content="width=device-width, initial-scale=1">',
                 '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
                 f'<title>PatchTrace — {title}</title>',
                 '<style>body{max-width:1000px;margin:2rem auto;padding:0 1rem;font:16px sans-serif;}',
                 'pre{white-space:pre-wrap;overflow-wrap:anywhere;}article{border-top:1px solid #aaa;padding:1rem 0;}</style>',
                 f'</head><body><h1>{title}</h1><p>PatchTrace static comparison report; revision {data["revision"]}.</p>']
        for run in data['interpretations']:
            for finding in run['findings']:
                parts.append('<article><h2>' + html.escape(finding['summary']) + '</h2><p>'
                             + html.escape(finding['fix_purpose']) + '</p><p>Review: '
                             + html.escape(finding['review']) + '; stale: '
                             + str(finding['stale']).lower() + '</p></article>')
        parts += ['<h2>Evidence and provenance</h2><pre>', html.escape(serialized), '</pre></body></html>\n']
        return ''.join(parts)
    parts = ['# PatchTrace report', '', _markdown_escape(data['name']), '',
             f'Project revision: {data["revision"]}', '']
    for run in data['interpretations']:
        for finding in run['findings']:
            parts += ['## ' + _markdown_escape(finding['summary']), '',
                      _markdown_escape(finding['fix_purpose']), '',
                      'Review: ' + _markdown_escape(finding['review']) + '; stale: '
                      + str(finding['stale']).lower(), '']
    parts += ['## Evidence and provenance', '', _markdown_escape(serialized), '']
    return '\n'.join(parts)


def export_project(project: ComparisonProject, format: str, destination: Path, include_code: bool = False,
                   include_notes: bool = True, finding_ids: list[str] | None = None) -> ExportManifest:
    if format not in {'json', 'html', 'md'}:
        raise ExportError('PT-EXPORT: supported formats are json, html, and md')
    data = _snapshot(project, include_code, include_notes, finding_ids)
    content = _render(data, format).encode('utf-8')
    if len(content) > MAX_REPORT_BYTES:
        raise ExportError('PT-EXPORT: report exceeds 20 MiB; select fewer findings or exclude code')
    destination = Path(destination)
    staged = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.patchtrace-export-', delete=False) as stream:
            staged = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, destination)
    except OSError:
        raise ExportError('PT-EXPORT: cannot write report; check destination permissions and free space') from None
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return ExportManifest(project_id=project.id, revision=project.revision, format=format,
                          sha256=hashlib.sha256(content).hexdigest(),
                          finding_ids=data['selection']['finding_ids'],
                          include_code=include_code, include_notes=include_notes)
