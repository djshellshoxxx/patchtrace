"""SPEC-31 read model, words and plain text (07 s3-s4): the vocabulary of the Unified view and the plain-text detail,
provenance and context of ONE row, built from its full records. Pure: no Qt, no project database, no process.

Rules (07 s4): every user-visible string passes `secondary.evidence_view.sanitize_text`; text is plain (never
markup); nothing here combines, averages or ranks the native values of different sources; missing is unknown, not a
vote; no probability wording (the banned-word sweep of the tests runs over everything this module can produce).

`SidecarRecords` is the only I/O: a bounded, validated, lazy read of the rows and facts parts of one published result
directory. It re-reads raw part lines through the store's own line reader and only parses the lines it was asked for,
so one detail costs a decompression of the part (about 25 ms at 10,000 rows), not a validated parse of every row.
"""
from __future__ import annotations

from collections.abc import Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..secondary.evidence_view import CLIPBOARD_CAP, CLIPBOARD_ROWS, sanitize_text
from . import keys, store
from .contracts import Atom, ChangeFacts, UnifiedMatch, UnifiedResultManifest
from .limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits
from .registry import REGISTRY, Registry

DETAIL_CAP = 24_000
CONTEXT_CAP = 4_000
CONTEXT_DELTAS = 8
ROW_ID_HEX = 64

DECISION_LABELS: dict[str, str] = {
    'matched': 'Matched', 'tentative': 'Tentative', 'candidate': 'Candidate', 'contested': 'Contested',
    'ambiguous': 'Ambiguous', 'older-only': 'Older only', 'newer-only': 'Newer only', 'unknown': 'Unknown'}
DECISION_GLYPHS: dict[str, str] = {
    'matched': '=', 'tentative': '~', 'candidate': '?', 'contested': '!', 'ambiguous': '#', 'older-only': '-',
    'newer-only': '+', 'unknown': '.'}
MATERIALITY_LABELS: dict[str, str] = {
    'unchanged': 'Unchanged', 'cosmetic': 'Cosmetic', 'material': 'Material', 'review': 'Review',
    'unknown': 'Unknown', 'not-applicable': 'Not applicable'}
TIER_NAMES: dict[str, str] = {
    'M': 'manual correction', 'A': 'unique key', 'B': 'corroborating key', 'C': 'candidate evidence',
    'W': 'weak external evidence'}
CLASS_NAMES: dict[str, str] = {
    'E-NAME': 'names', 'E-BODY': 'code bytes and instructions', 'E-CFG': 'control-flow shape',
    'E-CALL': 'call relations', 'E-DATA': 'strings and constants', 'E-DECOMP': 'decompiler output',
    'E-LAYOUT': 'layout position', 'E-RESID': 'residual voting', 'E-MANUAL': 'analyst correction',
    'E-UNKNOWN': 'unrecognised step'}
DECISION_MEANING: dict[str, str] = {
    'matched': 'A unique tier A key, an analyst correction, or independent evidence from two components and two '
               'evidence classes pairs these functions.',
    'tentative': 'Tier B evidence without an independent second component and class. A proposal, never counted '
                 'as matched.',
    'candidate': 'Only tier C or weak external evidence. Never accepted automatically.',
    'contested': 'At least one source pairs an endpoint differently. Review the pairing manually.',
    'ambiguous': 'Several functions share the same evidence. No single pairing is chosen.',
    'older-only': 'No source pairs this function with one in the newer build. Missing evidence is unknown, not a '
                  'finding.',
    'newer-only': 'No source pairs this function with one in the older build. Missing evidence is unknown, not a '
                  'finding.',
    'unknown': 'No usable evidence for this row.'}
FOOTER = ('Decisions and change classes are rule-based and uncalibrated. Native values are engine-specific and never '
          'combined. Change verdicts cover function code and unwind data, not global data contents.')
PROVENANCE_HEADER = 'PatchTrace unified comparison (derived and ordinal; function pairing and change classes only)'
PROVENANCE_FOOTER = 'Decisions and change classes are rule-based and uncalibrated. Native values are never combined.'
STALE_NOTE = 'This result is stale: {reason}. It is shown for reference only.'
SECTIONS = ('Function', 'Decision', 'Support by component', 'Evidence classes', 'Contest', 'Atoms', 'Change facts',
            'Limitations', 'Provenance')
_ROW_ID_KEY = b'"row_id":"'  # keys are sorted and separators compact (store.dump_line), so this marker is exact


def clean(value: object, limit: int = 200) -> str:
    """One line of untrusted text: controls and bidirectional characters removed, bounded."""
    text = value if type(value) is str else '' if value is None else str(value)
    if text.isprintable() and len(text) <= limit:  # fast path: nothing `sanitize_text` would remove is printable
        return text
    return sanitize_text(text.replace('\n', ' ').replace('\t', ' '), limit)


def hex_rva(rva: int | None) -> str:
    return '-' if rva is None else f'0x{rva:X}'


def side_text(side: Sequence, width: int = 120) -> str:
    """`0x1000 name`, `-` for no function, `(+n)` for a group side."""
    if not side:
        return '-'
    first = side[0]
    text = hex_rva(first.rva) + (f' {clean(first.name, width)}' if first.name else '')
    return text + (f' (+{len(side) - 1})' if len(side) > 1 else '')


def on_pair(atom: Atom, older: Collection[int], newer: Collection[int]) -> bool:
    """True when the atom speaks for this row's pairing; an atom that pairs one endpoint with another function
    (a contest) is not on the pair. An endpoint an atom does not name is a wildcard (one-sided observations)."""
    return ((atom.older_rva is None or atom.older_rva in older)
            and (atom.newer_rva is None or atom.newer_rva in newer))


# --- full records of one row (lazy, validated) -----------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RowRecord:
    match: UnifiedMatch
    facts: ChangeFacts | None


class RecordSource(Protocol):
    """Where the view model gets the full records of a row from; tests and the CLI use `SidecarRecords`."""

    def get(self, row_ids: Collection[str]) -> dict[str, RowRecord]: ...


def _row_id_of(line: bytes) -> bytes:
    at = line.rfind(_ROW_ID_KEY)
    start = at + len(_ROW_ID_KEY)
    return line[start:start + ROW_ID_HEX] if at >= 0 else b''


class SidecarRecords:
    """Lazy access to the rows and facts of one published result directory (any thread, no SQLite). Damage and a
    producer that is newer than this build raise `UnifiedError(STORE|STALE)`, never an untyped exception."""

    def __init__(self, directory: Path, manifest: UnifiedResultManifest, limits: UnifiedLimits = DEFAULT_LIMITS):
        self._directory = Path(directory)
        self._manifest = manifest
        self._limits = limits

    def _lines(self, name: str) -> Iterator[bytes]:
        part = next((p for p in self._manifest.parts if p.name == name), None)
        if part is None:
            raise UnifiedError('PT-UNIFIED-STORE', 'The unified result has no such part', reason='part-missing')
        yield from store.part_lines(self._directory / part.name, self._limits)  # one reader, one set of caps

    def find(self, prefix: str, limit: int | None = 2) -> list[str]:
        """Row ids that start with a lower-case hexadecimal `prefix`, at most `limit` of them (None: all)."""
        if len(prefix) > ROW_ID_HEX or any(c not in '0123456789abcdef' for c in prefix):
            return []
        needle = _ROW_ID_KEY + prefix.encode('ascii')
        found: list[str] = []
        for line in self._lines(store.ROWS):
            if needle in line:
                row = self._row(line)
                if row.row_id.startswith(prefix):
                    found.append(row.row_id)
                    if limit is not None and len(found) >= limit:
                        break
        return found

    def _row(self, line: bytes) -> UnifiedMatch:
        row = store.parse_line(line, UnifiedMatch)
        m = self._manifest
        if row.row_id != keys.row_id(m.older_sha256, m.newer_sha256, [s.rva for s in row.older],
                                     [s.rva for s in row.newer]):
            raise UnifiedError('PT-UNIFIED-STORE', 'A unified row id does not match its pairing', reason='row-id')
        return row

    def get(self, row_ids: Collection[str]) -> dict[str, RowRecord]:
        wanted = {i.encode('ascii', 'ignore') for i in row_ids}
        rows: dict[str, UnifiedMatch] = {}
        for line in self._lines(store.ROWS):
            if _row_id_of(line) in wanted:
                row = self._row(line)
                rows[row.row_id] = row
                if len(rows) == len(wanted):
                    break
        facts: dict[str, ChangeFacts] = {}
        for line in (self._lines(store.FACTS) if rows else ()):
            if _row_id_of(line) in wanted:
                fact = store.parse_line(line, ChangeFacts)
                facts[fact.row_id] = fact
        return {row_id: RowRecord(row, facts.get(row_id)) for row_id, row in rows.items()}


# --- lines of a record -------------------------------------------------------------------------------------------------

def atom_line(index: int, atom: Atom) -> str:
    native = ''.join(f' {clean(k, 32)}={clean(v, 120)}' for k, v in atom.native)
    return (f'[{index}] {clean(atom.source, 32)} {clean(atom.step, 64)} tier {atom.tier} {atom.cls} '
            f'{atom.cardinality} {hex_rva(atom.older_rva)} -> {hex_rva(atom.newer_rva)}{native}')


def facts_lines(facts: ChangeFacts | None) -> list[str]:
    if facts is None:
        return ['none (this row gets no change facts)']
    head = f'verdict {facts.verdict}' + (f', proof {facts.proof}' if facts.proof else '')
    head += f', second channel {facts.second_channel}' if facts.second_channel else ''
    lines = [head, 'channels: ' + ', '.join(f'{c} {s}' for c, s in facts.channels)]
    for delta in facts.deltas:
        change = ('' if delta.old is None and delta.new is None
                  else f' {clean(delta.old, 120) or "-"} -> {clean(delta.new, 120) or "-"}')
        lines.append(f'delta {delta.cls} ({delta.channel}) {hex_rva(delta.older_rva)} -> {hex_rva(delta.newer_rva)}'
                     + change)
    if facts.deltas_omitted:
        lines.append(f'{facts.deltas_omitted} more deltas not listed')
    if facts.limits_hit:
        lines.append('limits: ' + ', '.join(clean(x, 48) for x in facts.limits_hit))
    return lines


def reason_text(match: UnifiedMatch) -> str:
    """Why the row has its decision, from the row alone (fixed templates, no numbers about confidence)."""
    decision = match.decision
    if decision == 'matched':
        if any(s.tier == 'M' for s in match.support):
            return 'Set by an analyst correction' + ('; the contest is listed below.' if match.contest else '.')
        if any(s.tier == 'A' for s in match.support):
            return (f'A unique tier A key pairs these functions; {len(match.support)} independent component(s) '
                    'support it.')
        return 'Independent tier B evidence from different components and evidence classes agrees.'
    if decision == 'contested':
        strength = match.contest.strength if match.contest else 'unknown'
        against = len(match.contest.against) if match.contest else 0
        return f'{strength.capitalize()} contest: {against} piece(s) of evidence pair an endpoint differently.'
    return DECISION_MEANING[decision]


@dataclass(frozen=True, slots=True)
class EvidenceClassLine:
    cls: str
    atoms: int
    sources: tuple[str, ...]
    best_tier: str


def evidence_breakdown(match: UnifiedMatch) -> tuple[EvidenceClassLine, ...]:
    """Evidence on this pairing grouped by evidence class (05 s1.1): two atoms corroborate only when they differ in
    BOTH component and class, so the breakdown shows how many distinct classes carry the pairing."""
    older, newer = [s.rva for s in match.older], [s.rva for s in match.newer]
    grouped: dict[str, list[Atom]] = {}
    for atom in match.atoms:
        if on_pair(atom, older, newer):
            grouped.setdefault(atom.cls, []).append(atom)
    rank = {t: i for i, t in enumerate('MABCW')}
    order = {name: i for i, name in enumerate(CLASS_NAMES)}
    return tuple(EvidenceClassLine(cls, len(atoms), tuple(sorted({a.source for a in atoms})),
                                   min((a.tier for a in atoms), key=rank.__getitem__))
                 for cls, atoms in sorted(grouped.items(), key=lambda item: order.get(item[0], len(order))))


# --- the detail pane / explain text -------------------------------------------------------------------------------------

def _component_order(component: str) -> tuple[int, str]:
    return len(component), component


def _support_lines(match: UnifiedMatch) -> list[str]:
    lines = []
    for s in sorted(match.support, key=lambda s: _component_order(s.component)):
        atom = match.atoms[s.atom_index]
        lines.append(f'{s.component}: {clean(atom.source, 32)} {clean(atom.step, 64)} tier {s.tier} '
                     f'(atom {s.atom_index})')
    return lines or ['none recorded']


def _contest_lines(match: UnifiedMatch) -> list[str]:
    if match.contest is None:
        return ['none']
    lines = [f'{match.contest.strength} (atoms against: {", ".join(map(str, match.contest.against))})']
    lines += [atom_line(i, match.atoms[i]) for i in match.contest.against]
    return lines


def _provenance_lines(manifest: UnifiedResultManifest, registry: Registry) -> list[str]:
    sources = []
    for ref in manifest.sources:
        spec = registry.source(ref.source)
        note = f' ({spec.licence_note})' if spec else ''
        sources.append(f'{clean(ref.source, 32)} {clean(ref.version, 64)}{note}')
    older, newer = manifest.ir_older, manifest.ir_newer
    ir = (f'{older.producer_mode} ({older.functions} / {newer.functions} functions)'
          if older and newer else 'none (stored engine outputs only)')
    return [f'result {manifest.result_id} ({manifest.engine_version}, {manifest.status}, {manifest.created_utc})',
            'inputs: ' + ('; '.join(sources) or 'none'), f'ProgramIR: {ir}',
            f'Ghidriff run: {clean(manifest.ghidriff_run_id, 128)}',
            f'older SHA-256: {manifest.older_sha256}', f'newer SHA-256: {manifest.newer_sha256}',
            'display level: ordinal (no calibrated values are shown)']


def _section(title: str, lines: Iterable[str]) -> list[str]:
    return ['', f'{title}:', *(f'  {line}' for line in lines)]


def _capped(text: str, cap: int) -> str:
    return text if len(text) <= cap else text[:cap - 15] + '\n(truncated)'


def detail_text(manifest: UnifiedResultManifest, record: RowRecord, *, notes: Sequence[str] = (),
                registry: Registry = REGISTRY) -> str:
    """The Unified tab / `explain` text of one row: fixed section headers (`SECTIONS`), plain, deterministic."""
    match, facts = record.match, record.facts
    classes = ', '.join(match.change_classes) or 'none'
    glyph = DECISION_GLYPHS[match.decision]
    lines = [f'Function: older {side_text(match.older)} -> newer {side_text(match.newer)}',
             f'Decision: [{glyph}] {DECISION_LABELS[match.decision]}. {reason_text(match)}',
             f'Change: {MATERIALITY_LABELS[match.materiality]}'
             + (f' (proof {facts.proof})' if facts and facts.proof else '') + f'; classes: {classes}']
    lines += [f'Note: {clean(note, 300)}' for note in notes]
    lines += [f'Hint: {clean(h)}' for h in match.hints]
    lines += _section('Support by component', _support_lines(match))
    lines += _section('Evidence classes (corroboration needs different components and different classes)',
                      [f'{b.cls} ({CLASS_NAMES.get(b.cls, "unknown class")}): {b.atoms} atom(s) from '
                       f'{", ".join(b.sources)}; strongest tier {b.best_tier}' for b in evidence_breakdown(match)]
                      or ['none'])
    lines += _section('Contest', _contest_lines(match))
    lines += _section(f'Atoms ({len(match.atoms)})', [atom_line(i, a) for i, a in enumerate(match.atoms)] or ['none'])
    lines += _section('Change facts', facts_lines(facts))
    limits = [*(clean(x) for x in manifest.limitations)]
    lines += _section('Limitations', [f'- {x}' for x in limits] or ['- none recorded'])
    lines += _section('Provenance', _provenance_lines(manifest, registry))
    lines += ['', FOOTER]
    return _capped('\n'.join(lines), DETAIL_CAP)


# --- clipboard provenance ----------------------------------------------------------------------------------------------

def _row_block(record: RowRecord) -> str:
    m, f = record.match, record.facts
    lines = [f'Row: {m.row_id} | older {side_text(m.older, 80)} -> newer {side_text(m.newer, 80)}',
             f'Decision: {DECISION_LABELS[m.decision]} ({m.decision}) | Change: {MATERIALITY_LABELS[m.materiality]} '
             f'({m.materiality}) | classes: {", ".join(m.change_classes) or "none"}'
             + (f' | proof {f.proof}' if f and f.proof else ''), *('Support: ' + line for line in _support_lines(m))]
    if m.contest:
        lines.append(f'Contest: {m.contest.strength}, atoms against {", ".join(map(str, m.contest.against))}')
    return '\n'.join(lines)


def provenance_block(manifest: UnifiedResultManifest, records: Sequence[RowRecord], *, project_id: str = '',
                     run_id: str | None = None, stale_reason: str | None = None, total: int | None = None) -> str:
    """Deterministic LF-only plain text for the clipboard, at most CLIPBOARD_CAP characters. The result's identity,
    hashes, sources and limitations always come first and the footer last; whole rows (at most CLIPBOARD_ROWS) fill
    the rest and the omitted ones are counted. `total` is how many rows the caller selected."""
    stale = f'yes ({clean(stale_reason, 160)})' if stale_reason else 'no'
    head = [PROVENANCE_HEADER,
            f'Project: {clean(project_id, 128) or "unknown"} | Ghidriff run: '
            f'{clean(run_id or manifest.ghidriff_run_id, 128)} | Result: {manifest.result_id} | STALE: {stale}',
            f'Older SHA-256: {manifest.older_sha256}', f'Newer SHA-256: {manifest.newer_sha256}',
            'Sources: ' + ('; '.join(f'{clean(r.source, 32)} {clean(r.version, 64)}' for r in manifest.sources)
                           or 'none'),
            'Limitations:', *([f'- {clean(x)}' for x in manifest.limitations] or ['- none recorded'])]
    room = CLIPBOARD_CAP - len('\n'.join([*head, PROVENANCE_FOOTER])) - 64   # 64: blank lines and the omitted note
    blocks: list[str] = []
    for record in records[:CLIPBOARD_ROWS]:
        block = _row_block(record)
        room -= len(block) + 2
        if room < 0:
            break
        blocks.append(block)
    omitted = (len(records) if total is None else total) - len(blocks)
    lines = [*head, *(part for block in blocks for part in ('', block)), *([f'({omitted} more rows omitted)']
                                                                         if omitted > 0 else []), PROVENANCE_FOOTER]
    text = '\n'.join(lines)
    return text if len(text) <= CLIPBOARD_CAP else text[:CLIPBOARD_CAP - 12] + '\n(truncated)'


# --- the fragment offered to the existing context preview (D-30) -----------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ContextFragment:
    """A bounded plain-text description of one row for the EXISTING context preview. Nothing is sent from here: the
    preview shows the exact text, and only the analyst's explicit action in that dialog transmits anything."""
    kind: str
    row_id: str
    title: str
    text: str
    omitted: tuple[str, ...]


def context_fragment(record: RowRecord) -> ContextFragment:
    m, f = record.match, record.facts
    lines = [f'Unified row {m.row_id[:16]}: older {side_text(m.older, 80)} -> newer {side_text(m.newer, 80)}',
             f'Decision: {DECISION_LABELS[m.decision]}. Change: {MATERIALITY_LABELS[m.materiality]}; classes: '
             f'{", ".join(m.change_classes) or "none"}'] + ['Support: ' + x for x in _support_lines(m)]
    omitted: list[str] = []
    if f is not None:
        lines += [f'Facts: {line}' for line in facts_lines(f)[:2 + CONTEXT_DELTAS]]
        if len(f.deltas) > CONTEXT_DELTAS:
            omitted.append(f'{len(f.deltas) - CONTEXT_DELTAS} deltas not included')
    else:
        omitted.append('change facts: none for this row')
    lines.append('These values are derived, rule-based and uncalibrated.')
    return ContextFragment('unified-row', m.row_id, clean(f'Unified row {m.row_id[:12]}', 80),
                           _capped('\n'.join(lines), CONTEXT_CAP), tuple(omitted))
