"""Build-environment section of the exported report (DIE plan s8): validated, then redacted and escaped.

`build_section` turns two fingerprints and their delta into a strict model of at most 64 KiB; `section_data` is its
redacted JSON form (the same `_clean` the project report uses); the Markdown and HTML renderers escape every value, so a
hostile detection name cannot add markup, a table row or a link. The section states what was read, never how a file was
built, and always ends with the signature disclaimer. Pure: no Qt, no I/O.
"""
from __future__ import annotations

import html
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..reports import _cell, _clean, _markdown_escape
from .contracts import BuildEnvDelta, BuildEnvError, BuildFingerprint
from .copy import DISCLAIMER
from .view_model import PROVENANCE_LIMIT, build_view

CONTRACT = 'build-environment-report/1'
MAX_SECTION = 64 * 1024
Line = Annotated[str, Field(max_length=PROVENANCE_LIMIT)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ReportFinding(_Strict):
    key: str = Field(max_length=32)
    label: str = Field(max_length=64)
    older: str = Field(max_length=200)
    newer: str = Field(max_length=200)
    status: str = Field(max_length=32)
    basis: str = Field(max_length=200)


class ReportNotice(_Strict):
    code: str = Field(max_length=32)
    side: str = Field(max_length=8)
    severity: Literal['notice', 'caution']
    glyph: Literal['[!]', '[i]']
    text: str = Field(max_length=600)


class BuildEnvSection(_Strict):
    contract: Literal['build-environment-report/1'] = CONTRACT
    delta_id: str = Field(pattern=r'^[0-9a-f]{64}$')
    orientation: Literal['older->newer'] = 'older->newer'
    toolchain: Literal['same', 'differs', 'unknown']
    state: str = Field(max_length=4)
    state_text: Line
    findings: tuple[ReportFinding, ...] = Field(max_length=128)
    notices: tuple[ReportNotice, ...] = Field(max_length=16)
    provenance: Line
    technical: tuple[Line, ...] = Field(default=(), max_length=130)
    disclaimer: Literal[DISCLAIMER] = DISCLAIMER


def _dump(section: BuildEnvSection) -> dict:
    return _clean(section.model_dump(mode='json'))


def _size(section: BuildEnvSection) -> int:
    return len(json.dumps(_dump(section), sort_keys=True, ensure_ascii=False).encode())


def build_section(older: BuildFingerprint, newer: BuildFingerprint, delta: BuildEnvDelta, *,
                  technical: bool = False) -> BuildEnvSection:
    """`PT-BUILD-MISMATCH` when the delta belongs to other files or the sides are swapped."""
    if (older.side, newer.side) != ('older', 'newer') or (older.artifact_sha256, newer.artifact_sha256) != (
            delta.older_sha256, delta.newer_sha256):
        raise BuildEnvError('PT-BUILD-MISMATCH', 'the delta does not belong to these fingerprints in this orientation')
    view = build_view(older, newer, delta, technical=technical)
    section = BuildEnvSection(
        delta_id=delta.delta_id, toolchain=delta.toolchain, state=view.state, state_text=view.state_text,
        findings=tuple(ReportFinding(key=r.key, label=r.label, older=r.older, newer=r.newer, status=r.status,
                                     basis=r.basis) for r in view.rows),
        notices=tuple(ReportNotice(code=b.code, side=b.side, severity=b.severity, glyph=b.glyph, text=b.text)
                      for b in view.banners),
        provenance=view.provenance, technical=view.technical)
    if _size(section) > MAX_SECTION and section.technical:
        section = section.model_copy(update={'technical': ()})  # the optional block goes first
    if _size(section) > MAX_SECTION:
        raise BuildEnvError('PT-BUILD-LIMIT', 'the build-environment report section exceeds 64 KiB')
    return section


def section_data(section: BuildEnvSection) -> dict:
    """The redacted JSON form, ready to sit under one key of the project report."""
    return _dump(section)


def render_markdown(data: dict) -> str:
    parts = ['## Build environment', '', _markdown_escape(data['state_text']), '']
    if data['notices']:
        parts += [f'- {_markdown_escape(n["glyph"] + " " + n["text"])}' for n in data['notices']] + ['']
    if data['findings']:
        parts += ['| Fact | OLDER | NEWER | Status | Basis |', '|---|---|---|---|---|']
        parts += ['| ' + ' | '.join(_cell(f[k]) for k in ('label', 'older', 'newer', 'status', 'basis')) + ' |'
                  for f in data['findings']] + ['']
    parts += ['### Provenance', '', _markdown_escape(data['provenance']), '']
    if data['technical']:
        parts += ['### Technical details', '', *[f'- {_markdown_escape(line)}' for line in data['technical']], '']
    parts += [_markdown_escape(data['disclaimer']), '']
    return '\n'.join(parts)


def render_html(data: dict) -> str:
    e = html.escape
    parts = ['<section><h2>Build environment</h2>', f'<p>{e(data["state_text"])}</p>']
    if data['notices']:
        parts.append('<ul>' + ''.join(f'<li>{e(n["glyph"] + " " + n["text"])}</li>' for n in data['notices']) + '</ul>')
    if data['findings']:
        parts.append('<table><tr><th>Fact</th><th>OLDER</th><th>NEWER</th><th>Status</th><th>Basis</th></tr>')
        parts += ['<tr>' + ''.join(f'<td>{e(f[k])}</td>' for k in ('label', 'older', 'newer', 'status', 'basis'))
                  + '</tr>' for f in data['findings']]
        parts.append('</table>')
    parts += ['<h3>Provenance</h3>', f'<pre>{e(data["provenance"])}</pre>']
    if data['technical']:
        parts.append('<h3>Technical details</h3><pre>' + e('\n'.join(data['technical'])) + '</pre>')
    parts.append(f'<p>{e(data["disclaimer"])}</p></section>')
    return ''.join(parts)
