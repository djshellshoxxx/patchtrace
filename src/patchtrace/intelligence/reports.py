"""Exports of the ``intelligence explain`` report (SPEC-28 sections J and L): canonical JSON and escaped Markdown.

Advisory text is untrusted data (AGENTS.md). Nothing here renders it as markup:

* JSON has sorted keys, two-space indentation and pure ASCII, so a bidi or control character can only appear as
  a ``\\uXXXX`` escape, and the text round-trips through ``IntelligenceReport.model_validate_json``.
* Markdown passes every string that is not a fixed template through ``escape_md``: HTML-significant characters
  become entities, Markdown-special characters are backslash-escaped, line breaks and tabs are flattened to one
  space (so a table cell is always one line), C0/C1 controls, bidi and other format characters, private-use,
  unassigned and surrogate code points are shown as ``\\uXXXX``, and long text is cut with a visible marker.
  A URL is therefore text, never a link: ``:`` and ``.`` are escaped, so no renderer finds an autolink. Values
  that are known to be safe identifiers (CVE ids, hashes, JSON pointers, enum words) are shown in a code span,
  and anything else falls back to the escaper. The document has no HTML, no links and no images.
* ``plain_text`` is the same sanitiser without Markdown escaping, for terminals.

``escape_md`` is the shared escaper that later report writers (patch-intent leads) reuse. Files are written as
UTF-8 with LF line endings only, atomically (temporary file in the same directory, then ``os.replace``), so a
failed export leaves any earlier file intact.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from .contracts import IntelError, IntelligenceReport

MAX_CELL = 300    # code points of source text shown in a table cell, a title or a label
MAX_PROSE = 2000  # the same for advisory prose (notes, remediation and threat details)
MAX_ROWS = 100    # rows per table; the rest is counted and left to the JSON export
FORMATS = ('json', 'md')
_SUFFIXES = {'.json': 'json', '.md': 'md'}
_HTML = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'}
_MARKDOWN = frozenset('\\`*_{}[]()#+-.!|~=^$@:')
_BREAKS = frozenset('\t\n\v\f\r\x85' + chr(0x2028) + chr(0x2029))  # layout: flattened to one space
_UNSAFE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn'})  # controls, format (bidi), surrogate, private use, unassigned
_SAFE_CODE = re.compile(r'[A-Za-z0-9_./:@+=,~-]+')  # no space, backtick, pipe or backslash: inert in a code span


# ---------------------------------------------------------------------------------------------- escaping

def _marker(char: str) -> str:
    code = ord(char)
    return f'\\u{code:04x}' if code <= 0xFFFF else f'\\U{code:08x}'


def _convert(value: object, limit: int | None, markup: bool) -> str:
    text = value if isinstance(value, str) else str(value)
    out: list[str] = []
    count = 0
    gap = False
    for index, char in enumerate(text):
        if char == ' ' or char in _BREAKS:
            gap = bool(out)
            continue
        if limit is not None and count >= limit:
            out.append(f' … {len(text) - index} more characters')
            break
        if gap:
            out.append(' ')
            gap = False
        if unicodedata.category(char) in _UNSAFE:
            out.append(_marker(char))
        elif not markup:
            out.append(char)
        elif char in _HTML:
            out.append(_HTML[char])
        elif char in _MARKDOWN:
            out.append('\\' + char)
        else:
            out.append(char)
        count += 1
    return ''.join(out)


def escape_md(value: object, limit: int | None = MAX_CELL) -> str:
    """Inert, single-line Markdown text for untrusted ``value`` (see the module docstring)."""
    return _convert(value, limit, True)


def plain_text(value: object, limit: int | None = MAX_CELL) -> str:
    """Single-line text for a terminal: controls and bidi marks are shown as ``\\uXXXX``; no markup escaping."""
    return _convert(value, limit, False)


# ---------------------------------------------------------------------------------------------- JSON

def to_json(report: IntelligenceReport) -> str:
    return json.dumps(report.model_dump(mode='json'), indent=2, sort_keys=True) + '\n'


# ---------------------------------------------------------------------------------------------- Markdown

def _t(value: object, limit: int | None = MAX_CELL) -> str:
    return escape_md(value, limit)


def _c(value: object) -> str:
    """A code span for a safe identifier, otherwise the escaped text."""
    text = str(value)
    return f'`{text}`' if len(text) <= MAX_CELL and _SAFE_CODE.fullmatch(text) else escape_md(text)


def _join(items: Sequence[object], one=_c) -> str:
    return ', '.join(one(item) for item in items)


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    shown = rows[:MAX_ROWS]
    lines = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |']
    lines += ['| ' + ' | '.join(cell or '-' for cell in row) + ' |' for row in shown]
    lines.append('')
    if len(rows) > len(shown):
        lines += [f'({len(rows) - len(shown)} more row(s) omitted; the JSON export has them all)', '']
    return lines


def _bullets(items: Sequence[str], depth: int = 0, limit: int | None = MAX_PROSE) -> list[str]:
    return [f'{"  " * depth}- {_t(item, limit)}' for item in items]


def _count(items: Sequence[object], noun: str) -> str:
    return f'{len(items)} {noun}'


def _intro(report: IntelligenceReport) -> list[str]:
    return [f'# Advisory report for {_c(report.cve)}', '',
            f'Contract {_c(report.contract)}. This report restates advisory claims and PatchTrace rule hypotheses '
            'with their sources. It does not show that this CVE is present in, or fixed by, any function or binary. '
            'Advisory text is escaped, flattened to one line and shortened here; the JSON export holds the '
            'complete text.', '']


def _sources(report: IntelligenceReport) -> list[str]:
    rows = []
    for item in report.sources:
        s = item.source
        rows.append([_c(s.tracking_id), _c(s.revision), _c(s.document_category), _c(s.tracking_status),
                     'superseded' if item.superseded else 'current', _c(s.origin), _c(s.authenticity_state),
                     _c(s.retrieved_at), _c(s.sha256), _t(s.publisher_name), _t(s.uri) if s.uri else ''])
    return ['## Sources', '', *_table(['Tracking ID', 'Revision', 'Category', 'Doc status', 'State', 'Origin',
                                       'Authenticity', 'Retrieved', 'SHA-256', 'Publisher', 'URI'], rows)]


def _side(report: IntelligenceReport, side, title: str) -> list[str]:
    ident = side.identity
    tracking = {s.source.source_id: s.source.tracking_id for s in report.sources}
    pdb = ident.pdb_identity
    bullets = [f'- SHA-256: {_c(ident.sha256)}',
               f'- Identity facts: {_c(ident.facts_state)}; file version {_c(ident.file_version or "not available")}; '
               f'product version {_c(ident.product_version or "not available")}; PDB '
               + (f'{_c(pdb.name)} {_c(pdb.guid)} age {pdb.age}' if pdb else 'not available'),
               '- Analyst-asserted product IDs: ' + (_join(ident.asserted_product_ids) or 'none'),
               f'- Product mapping: {_c(side.product_mapping_status)}',
               f'- Resolution: {_c(side.resolution)} ({_c(side.assessment)}); remediation recommended: '
               + ('yes' if side.recommended else 'no'),
               '- Why:', *_bullets(side.why, 1)]
    if ident.notes:
        bullets += ['- Identity notes:', *_bullets(ident.notes, 1)]
    lines = [f'### {title}', '', *bullets, '']
    if side.mappings:
        lines += ['Product mappings', '', *_table(
            ['Document', 'Product ID', 'Product', 'Tier', 'Basis', 'Detail'],
            [[_c(tracking.get(m.source_id, m.source_id[:12])), _c(m.product_id), _t(m.product_name), _c(m.status),
              _c(m.basis), _t(m.detail)] for m in side.mappings])]
    if side.statuses:
        lines += ['Status evidence', '', *_table(
            ['Document', 'Revision', 'Product ID', 'Product', 'Status', 'Pointer', 'State'],
            [[_c(e.tracking_id), _c(e.revision), _c(e.product_id), _t(e.product_name), _c(e.status), _c(e.pointer),
              'superseded' if e.superseded else 'current'] for e in side.statuses])]
    return lines


def _applicability(report: IntelligenceReport) -> list[str]:
    ap = report.applicability
    lines = ['## Applicability', '', *_side(report, ap.older, 'Older artifact'),
             *_side(report, ap.newer, 'Newer artifact'), '### Contradictions', '']
    if not ap.contradictions:
        return [*lines, 'None found.', '']
    rows = []
    for c in ap.contradictions:
        claims = '; '.join(_t(f'{e.tracking_id} revision {e.revision}: {e.status} ({e.product_id})', 120)
                           for e in c.claims[:8]) + (f'; (+{len(c.claims) - 8} more)' if len(c.claims) > 8 else '')
        rows.append([_c(c.kind), _t(c.product_name or ''), _t(c.explanation), claims])
    return [*lines, *_table(['Kind', 'Product', 'Explanation', 'Claims'], rows)]


def _fact(fact, state: str, source) -> list[str]:
    lines = [f'### Fact from {_c(source.tracking_id)} revision {_c(source.revision)} ({state})', '',
             f'- Pointer: {_c(fact.pointer)}', f'- Title: {_t(fact.title or "not stated")}']
    if fact.cwe:
        lines.append(f'- CWE stated by the vendor: {_c(fact.cwe.id)} {_t(fact.cwe.name)} at {_c(fact.cwe.pointer)}')
    else:
        lines.append('- CWE stated by the vendor: not stated')
    counts = Counter(claim.status for claim in fact.product_status)
    lines += [f'- Product status claims: {len(fact.product_status)} in total ('
              + (', '.join(f'{_c(status)}: {n}' for status, n in sorted(counts.items())) or 'none')
              + '); those tied to the artifacts are listed under Applicability', '']
    if fact.notes:
        lines += ['Notes', '', *_table(['Category', 'Title', 'Text', 'Pointer'],
                                        [[_c(n.category), _t(n.title or ''), _t(n.text, MAX_PROSE), _c(n.pointer)]
                                         for n in fact.notes])]
    if fact.remediations:
        lines += ['Remediations', '', *_table(
            ['Category', 'Details', 'URL', 'Products', 'Date', 'Pointer'],
            [[_c(r.category), _t(r.details, MAX_PROSE), _t(r.url or ''),
              f'{_count(r.product_ids, "product(s)")}, {_count(r.group_ids, "group(s)")}', _c(r.date or ''),
              _c(r.pointer)] for r in fact.remediations])]
    if fact.threats:
        lines += ['Threats', '', *_table(
            ['Category', 'Details', 'Products', 'Pointer'],
            [[_c(x.category), _t(x.details, MAX_PROSE),
              f'{_count(x.product_ids, "product(s)")}, {_count(x.group_ids, "group(s)")}', _c(x.pointer)]
             for x in fact.threats])]
    if fact.scores:
        lines += ['Scores (severity context only)', '', *_table(
            ['CVSS', 'Base score', 'Severity', 'Vector', 'Products', 'Pointer'],
            [[_c(s.cvss_version), _c(s.base_score), _t(s.base_severity or ''), _c(s.vector or ''),
              _count(s.products, 'product(s)'), _c(s.pointer)] for s in fact.scores])]
    if fact.flags:
        lines += ['Flags', '', *_table(['Label', 'Products', 'Pointer'],
                                       [[_c(f.label), f'{_count(f.product_ids, "product(s)")}, '
                                         f'{_count(f.group_ids, "group(s)")}', _c(f.pointer)] for f in fact.flags])]
    if fact.ids:
        lines += ['Other identifiers', '', *_table(['System', 'Text', 'Pointer'],
                                                    [[_t(i.system_name), _t(i.text), _c(i.pointer)]
                                                     for i in fact.ids])]
    return lines


def _facts(report: IntelligenceReport) -> list[str]:
    by_source = {s.source.source_id: s for s in report.sources}
    lines = ['## Advisory facts', '']
    for fact in report.facts:
        item = by_source[fact.source_id]
        lines += _fact(fact, 'superseded' if item.superseded else 'current', item.source)
    return lines


def _cwe(report: IntelligenceReport) -> list[str]:
    profile = report.cwe_profile
    lines = ['## CWE profile', '', f'- Status: {_c(profile.status)}',
             f'- Lexicon: {_c(profile.lexicon_version)} (digest {_c(profile.lexicon_digest[:12])})', '']
    if profile.classifications:
        lines += ['Classifications', '', *_table(
            ['CWE', 'Family', 'Basis', 'Confidence', 'Assessment', 'Pointers'],
            [[_c(c.cwe_id), _t(c.family), _c(c.basis), _c(c.confidence), _c(c.assessment), _join(c.pointers[:6])]
             for c in profile.classifications])]
    if profile.negated_hits:
        lines += ['Negated phrases (excluded)', '', *_table(
            ['Phrase', 'Cue', 'Pointer', 'Excerpt'],
            [[_t(h.phrase), _t(h.negation_cue or ''), _c(h.pointer), _t(h.excerpt)] for h in profile.negated_hits])]
    if profile.effect_hits:
        lines += ['Effect and primitive phrases (no CWE derived)', '', *_table(
            ['Phrase', 'Scope', 'Strength', 'Pointer', 'Excerpt'],
            [[_t(h.phrase), _c(h.scope), _c(h.strength), _c(h.pointer), _t(h.excerpt)]
             for h in profile.effect_hits])]
    if profile.disagreements:
        lines += ['Disagreements (kept, not resolved)', '', *_bullets(profile.disagreements), '']
    return lines


def _hypotheses(report: IntelligenceReport) -> list[str]:
    hyp = report.hypotheses
    lines = ['## Patch hypotheses', '', f'- Rules: {_c(hyp.rules_version)} (digest {_c(hyp.rules_digest[:12])}); '
             'search guidance only, never evidence that a function is vulnerable or fixed', '']
    if not hyp.hypotheses:
        return [*lines, 'No hypothesis was derived; see the unknowns.', '']
    for h in hyp.hypotheses:
        lines += [f'### {_c(h.cwe_id)} ({_t(h.family)}) via {_c(h.rule_id)} revision {h.rule_revision}', '',
                  f'- Basis: {_c(h.basis)}; assessment {_c(h.assessment)}']
        for label, items in (('Expected operations', h.expected_operations), ('Sources', h.sources),
                             ('Sinks', h.sinks), ('Guards', h.guards), ('API names worth searching', h.api_hints),
                             ('Counterexamples', h.counterexamples),
                             ('Observations that would support it', h.required_observations),
                             ('Observations that would contradict it', h.contradictions)):
            if items:
                lines += [f'- {label}:', *_bullets(items, 1)]
        lines += [f'- Caveat: {_t(h.caveat, MAX_PROSE)}', '']
    return lines


def _anchors(report: IntelligenceReport) -> list[str]:
    lines = ['## Search anchors', '']
    if not report.anchors.anchors:
        return [*lines, 'No anchors were derived.', '']
    return [*lines, *_table(['Kind', 'Value', 'Source', 'Quality', 'Pointer', 'Label'],
                            [[_c(a.kind), _t(a.value), _c(a.source), _c(a.quality), _c(a.pointer or ''), _t(a.label)]
                             for a in report.anchors.anchors])]


def _list(title: str, items: Sequence[str], empty: str) -> list[str]:
    return [f'## {title}', '', *(_bullets(items) if items else [empty]), '']


def to_markdown(report: IntelligenceReport) -> str:
    lines = [*_intro(report), *_sources(report), *_applicability(report), *_facts(report), *_cwe(report),
             *_hypotheses(report), *_anchors(report), *_list('Unknowns', report.unknowns, 'None recorded.'),
             *_list('Limitations', report.limitations, 'None recorded.')]
    return '\n'.join(lines).rstrip('\n') + '\n'


# ---------------------------------------------------------------------------------------------- terminal summary

def summary(report: IntelligenceReport) -> str:
    """Short plain text for the terminal; every advisory-derived string goes through ``plain_text``."""
    current = sum(1 for item in report.sources if not item.superseded)
    lines = [f'{report.cve}: {len(report.sources)} stored source(s), {current} current']
    for item in report.sources:
        lines.append(f'  source {plain_text(item.source.tracking_id, 80)} revision '
                     f'{plain_text(item.source.revision, 20)}: {"superseded" if item.superseded else "current"}, '
                     f'{item.source.sha256[:12]}, {item.source.authenticity_state}')
    for side in (report.applicability.older, report.applicability.newer):
        lines.append(f'{side.side:<6} {side.identity.sha256[:12]}  mapping: {side.product_mapping_status:<9} '
                     f'resolution: {side.resolution}')
    if report.applicability.contradictions:
        lines.append(f'contradictions kept unresolved: {len(report.applicability.contradictions)}')
    profile = report.cwe_profile
    ids = ', '.join(c.cwe_id for c in profile.classifications if c.confidence != 'weak') or 'none'
    lines.append(f'CWE profile: {profile.status} ({ids})')
    lines.append(f'rule hypotheses: {len(report.hypotheses.hypotheses)}; search anchors: '
                 f'{len(report.anchors.anchors)}; unknowns: {len(report.unknowns)}')
    lines.append(plain_text(report.limitations[0], None))
    return '\n'.join(lines)


# ---------------------------------------------------------------------------------------------- files

def format_for(path: Path) -> str:
    fmt = _SUFFIXES.get(Path(path).suffix.lower())
    if fmt is None:
        raise IntelError('PT-INTEL-INPUT', 'the export file name must end in .json or .md')
    return fmt


def render(report: IntelligenceReport, fmt: str) -> bytes:
    """UTF-8 bytes with LF line endings only (the same bytes on every platform)."""
    if fmt == 'json':
        text = to_json(report)
    elif fmt == 'md':
        text = to_markdown(report)
    else:
        raise IntelError('PT-INTEL-INPUT', 'the export format must be json or md')
    return text.encode('utf-8')


def write_export(path: Path, data: bytes) -> None:
    """Write ``data`` next to ``path`` and replace it atomically; an earlier file survives any failure."""
    path = Path(path)
    try:
        fd, name = tempfile.mkstemp(prefix='.partial-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.replace(name, path)
        except BaseException:
            Path(name).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise IntelError('PT-INTEL-STORAGE', f'cannot write {plain_text(path.name, 120)}: '
                                             f'{plain_text(exc.strerror or exc, 120)}') from None
