"""Pure bounded PW-01 CSV ingestion. No filesystem, database, network or Qt.

This is an independently written strict CSV lexer. Per-field and per-record
budgets are enforced while scanning, without process-global csv settings.
"""
from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from pydantic import ValidationError

from ..hostile_text import replace_hostile
from .contracts import domain_id
from .inventory_contracts import (
    DEFAULT_LIMITS,
    UINT64_MAX,
    CsvDiagnostic,
    CsvInventory,
    CsvRecordRef,
    InventoryContext,
    InventoryEntry,
    InventoryLimits,
    InventorySection,
    entry_identity,
    inventory_identity,
    normalize_inventory_filename,
)
from .sources.cvrf import SourceError

_HEADERS = frozenset({'file name', 'file version', 'file size', 'date', 'time', 'architecture',
                      'product', 'release', 'build'})
_REQUIRED = frozenset({'file name', 'file version'})
_DELIMITERS = {'comma': ',', 'semicolon': ';', 'tab': '\t'}
_ARCH_ALIASES = {'x64': 'amd64', 'amd64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64',
                 'x86': 'x86', 'i386': 'x86'}
_ARCH_WORD = re.compile(r'(?<![a-z0-9])(?:x64|amd64|arm64|aarch64|x86|i386)(?![a-z0-9])', re.IGNORECASE)
_VERSION = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
_FILE_LIKE = re.compile(r'[^\r\n]*\.[A-Za-z0-9]{1,10}')


@dataclass(frozen=True)
class _Row:
    fields: tuple[str, ...]
    number: int
    start_line: int
    end_line: int
    end_offset: int


def _fail(message: str, *, limit: bool = False) -> SourceError:
    return SourceError('PT-KBC-LIMIT' if limit else 'PT-KBC-SOURCE', message)


def _decode(raw: bytes, limits: InventoryLimits) -> tuple[str, str]:
    if raw.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        raise _fail('UTF-32 CSV sources are not supported.')
    encoding, offset = ('utf-8', 0)
    if raw.startswith(b'\xef\xbb\xbf'):
        encoding, offset = 'utf-8-sig', 3
    elif raw.startswith(b'\xff\xfe'):
        encoding, offset = 'utf-16-le', 2
    elif raw.startswith(b'\xfe\xff'):
        encoding, offset = 'utf-16-be', 2
    try:
        text = raw[offset:].decode('utf-8' if encoding == 'utf-8-sig' else encoding, errors='strict')
    except UnicodeError:
        raise _fail('The CSV encoding is invalid or unsupported; use UTF-8 or BOM-marked UTF-16.') from None
    if '\x00' in text:
        raise _fail('NUL text or unmarked UTF-16 is not a supported CSV encoding.')
    if len(text) > limits.max_text_chars:
        raise _fail('The decoded CSV exceeds its text budget.', limit=True)
    return text, encoding


def _rows(text: str, delimiter: str, limits: InventoryLimits, check: Callable[[], None]) -> Iterator[_Row]:
    """Strict quoted fields and physical spans, enforcing bounds before growing another field."""
    pos, line, number, length, next_check = 0, 1, 0, len(text), 0
    while pos < length:
        start, start_line = pos, line
        fields: list[str] = []
        field: list[str] = []
        field_chars = 0
        state = 'start'
        while True:
            if pos >= next_check:
                check()
                next_check = pos + 4096
            if pos - start > limits.max_record_chars:
                raise _fail('A logical CSV record exceeds its character budget.', limit=True)
            at_end = pos == length
            char = '' if at_end else text[pos]
            if at_end or state != 'quoted' and char in (delimiter, '\r', '\n'):
                if at_end and state == 'quoted':
                    raise _fail('A quoted CSV field is unterminated.')
                fields.append(''.join(field))
                if len(fields) > limits.max_columns:
                    raise _fail('A CSV record exceeds its column budget.', limit=True)
                field, field_chars = [], 0
                if not at_end and char == delimiter:
                    pos += 1
                    state = 'start'
                    continue
                end_line = line
                if not at_end:
                    if char == '\r':
                        if pos + 1 >= length or text[pos + 1] != '\n':
                            raise _fail('CSV line endings must be LF or CRLF.')
                        pos += 2
                    else:
                        pos += 1
                    line += 1
                if pos - start > limits.max_record_chars:
                    raise _fail('A logical CSV record exceeds its character budget.', limit=True)
                number += 1
                yield _Row(tuple(fields), number, start_line, end_line, pos)
                break
            if state == 'closed':
                raise _fail('Unexpected text follows a closing CSV quote.')
            if char == '"':
                if state == 'bare':
                    raise _fail('A quote inside an unquoted CSV field is malformed.')
                if state == 'start':
                    state = 'quoted'
                    pos += 1
                    continue
                if pos + 1 < length and text[pos + 1] == '"':
                    token, advance = '"', 2
                else:
                    state = 'closed'
                    pos += 1
                    continue
            elif char in ('\r', '\n'):
                if char == '\r':
                    if pos + 1 >= length or text[pos + 1] != '\n':
                        raise _fail('CSV line endings must be LF or CRLF.')
                    token, advance = '\r\n', 2
                else:
                    token, advance = '\n', 1
                line += 1
            else:
                token, advance = char, 1
                if state == 'start':
                    state = 'bare'
            field_chars += len(token)
            if field_chars > limits.max_field_chars:
                raise _fail('A CSV field exceeds its character budget.', limit=True)
            field.append(token)
            pos += advance


def _banner(row: _Row, delimiter: str) -> str | None:
    values = [value for value in row.fields if value.strip()]
    if row.start_line != row.end_line or not values or len(values) > 3:
        return None
    joined = delimiter.join(row.fields)
    stripped = joined.strip()
    if len(joined) > 1_000 or replace_hostile(joined) != joined or stripped.startswith(('=', '+', '-', '@')):
        return None
    if _FILE_LIKE.fullmatch(values[0].strip()):
        return None
    if len(values) == 1 or (values[0].lstrip().casefold().startswith('windows ')
                            and any(value.lstrip().casefold().startswith('version ') for value in values[1:])):
        return joined
    return None


def _section_arch(banner: str) -> tuple[str, bool]:
    values = {_ARCH_ALIASES[match.group().casefold()] for match in _ARCH_WORD.finditer(banner)}
    return (next(iter(values)), False) if len(values) == 1 else ('unknown', len(values) > 1)


def _column_arch(value: str) -> str:
    clean = value.strip().casefold()
    if clean.endswith('-based') or clean.endswith(' based'):
        clean = clean[:-6]
    return _ARCH_ALIASES.get(clean, 'unknown')


def _version(value: str) -> tuple[int, int, int, int] | None:
    text = value.strip(' \t')
    if not _VERSION.fullmatch(text):
        return None
    parts = [part.lstrip('0') or '0' for part in text.split('.')]
    if any(len(part) > 20 for part in parts):
        return None
    result = tuple(int(part) for part in parts)
    return result if all(part <= UINT64_MAX for part in result) else None


def _size(value: str | None, locale: str) -> int | None:
    if value is None or not value.strip(' \t'):
        return None
    text = value.strip(' \t')
    if not re.fullmatch(r'[0-9]+', text):
        separator = ',' if locale == 'en-US' else '.' if locale == 'de-DE' else None
        if separator is None or not re.fullmatch(r'[0-9]{1,3}(?:' + re.escape(separator) + r'[0-9]{3})+', text):
            return None
        text = text.replace(separator, '')
    text = text.lstrip('0') or '0'
    if len(text) > 20:
        return None
    result = int(text)
    return result if result <= UINT64_MAX else None


def _scope(entry: InventoryEntry) -> tuple:
    return entry.basename, entry.architecture, entry.product, entry.release, entry.build


def _metadata(entry: InventoryEntry) -> tuple:
    version = entry.version_components if entry.version_components is not None else entry.original_version
    size = entry.size_bytes if entry.size_bytes is not None else entry.original_size
    return version, size, entry.date_text, entry.time_text


def _contradicts(entries: list[InventoryEntry]) -> bool:
    """Unknown values cannot contradict a supplied claim merely by being absent."""
    return any(len({value for entry in entries if (value := getattr(entry, field)) not in (None, '')}) > 1
               for field in ('version_components', 'size_bytes', 'date_text', 'time_text'))


class _Parser:
    def __init__(self, raw_sha: str, context: InventoryContext, limits: InventoryLimits):
        self.sha, self.context, self.limits = raw_sha, context, limits
        self.identity = inventory_identity(raw_sha, context, limits)
        self.entries: list[InventoryEntry] = []
        self.sections: list[InventorySection] = []
        self.diagnostics: list[CsvDiagnostic] = []
        self.omitted = self.rejected = 0
        self.header: dict[str, int] | None = None
        self.had_header = False
        self.section_conflict = False

    def ref(self, row: _Row) -> CsvRecordRef:
        return CsvRecordRef(raw_sha256=self.sha, logical_record=row.number, line_start=row.start_line,
                            line_end=row.end_line, section_index=max(0, len(self.sections) - 1))

    def note(self, code: str, message: str, ref: CsvRecordRef | None, *, error: bool = False):
        if len(self.diagnostics) < self.limits.max_diagnostics:
            self.diagnostics.append(CsvDiagnostic(code=code, message=message, level='error' if error else 'warning',
                                                   reference=ref))
        else:
            self.omitted += 1

    def section(self, row: _Row, banner: str):
        if len(self.sections) >= self.limits.max_sections:
            raise _fail('The CSV exceeds its architecture-section budget.', limit=True)
        arch, self.section_conflict = _section_arch(banner)
        ref = CsvRecordRef(raw_sha256=self.sha, logical_record=row.number, line_start=row.start_line,
                            line_end=row.end_line, section_index=len(self.sections))
        self.sections.append(InventorySection(index=len(self.sections), banner=banner, architecture=arch,
                                               reference=ref))
        self.header = None
        if self.section_conflict:
            self.note('ARCHITECTURE_CONFLICT', 'The section names multiple incompatible architectures.', ref)
        elif banner and arch == 'unknown':
            self.note('UNKNOWN_SECTION', 'The section architecture is unknown; no prior architecture is inherited.', ref)

    def consume(self, row: _Row, delimiter: str):
        if not any(field.strip() for field in row.fields):
            return
        names = tuple(field.strip().casefold() for field in row.fields)
        header_candidate = any(name in _REQUIRED for name in names)
        if header_candidate and self.header is not None and not _REQUIRED.issubset(names):
            filename_index = self.header['file name']
            if filename_index < len(row.fields) and normalize_inventory_filename(row.fields[filename_index]):
                header_candidate = False
        if header_candidate:
            if not _REQUIRED.issubset(names) or any(name not in _HEADERS for name in names):
                raise _fail('CSV headers must use documented English File name and File version columns.')
            if len(set(names)) != len(names):
                raise _fail('Duplicate CSV header names make the column mapping ambiguous.')
            if not self.sections:
                self.section(row, '')
            self.header = {name: index for index, name in enumerate(names)}
            self.had_header = True
            return
        banner = _banner(row, delimiter)
        if banner is not None:
            self.section(row, banner)
            return
        if self.header is None:
            raise _fail('A CSV section has no supported required header; undocumented dialects are refused.')
        ref = self.ref(row)
        if len(row.fields) != len(self.header):
            self.rejected += 1
            self.note('COLUMN_COUNT', 'The data row does not match its section header column count.', ref, error=True)
            return
        values = {name: row.fields[index] for name, index in self.header.items()}
        filename = normalize_inventory_filename(values['file name'])
        if filename is None:
            self.rejected += 1
            self.note('INVALID_FILENAME', 'The filename is unsafe or is not a supported plain basename.', ref, error=True)
            return
        name, is_pe = filename
        codes: list[str] = []

        def note(code: str, message: str):
            if code not in codes:
                codes.append(code)
            self.note(code, message, ref)

        section_arch = self.sections[-1].architecture
        column = values.get('architecture', '')
        column_arch = _column_arch(column)
        known = {arch for arch in (column_arch, section_arch, self.context.architecture) if arch != 'unknown'}
        if self.section_conflict or len(known) > 1:
            architecture, basis = 'unknown', 'conflicted'
            note('ARCHITECTURE_CONFLICT', 'Column, section or asserted context disagree on architecture.')
        elif column.strip() and column_arch == 'unknown':
            architecture, basis = 'unknown', 'unknown'
            note('UNKNOWN_ARCHITECTURE', 'The explicit architecture column is unsupported or unknown.')
        else:
            architecture, basis = next(((arch, origin) for arch, origin in (
                (column_arch, 'column'), (section_arch, 'section'), (self.context.architecture, 'context'))
                                       if arch != 'unknown'), ('unknown', 'unknown'))
            if architecture == 'unknown':
                note('UNKNOWN_ARCHITECTURE', 'No recognized architecture is supplied for this row.')
        version = _version(values['file version'])
        if version is None:
            note('UNKNOWN_VERSION', 'The file version is not an exact supported four-component numeric version.')
        original_size = values.get('file size')
        size = _size(original_size, self.context.locale)
        if original_size is not None and original_size.strip() and size is None:
            note('INVALID_SIZE', 'The size is unknown: grouping or numeric syntax does not match the selected locale.')

        def metadata(field: str) -> str | None:
            asserted = getattr(self.context, field)
            source = values.get(field)
            if source is None or not source.strip():
                return asserted
            if len(source) > 1_000 or replace_hostile(source) != source:
                note('INVALID_METADATA', 'Product, release or build text is outside the plain-text bounds.')
                return None
            source = source.strip()
            if asserted is not None and source.casefold() != asserted.strip().casefold():
                note(field.upper() + '_CONFLICT', 'A source metadata column contradicts the explicitly asserted context.')
            return source

        product, release, build = (metadata(field) for field in ('product', 'release', 'build'))
        conflicts = any(code.endswith('_CONFLICT') for code in codes)
        state = ('conflicted' if conflicts else 'descriptive-only' if not is_pe else
                 'unknown' if architecture == 'unknown' or version is None or 'INVALID_METADATA' in codes
                 or 'INVALID_SIZE' in codes else 'metadata-only')
        self.entries.append(InventoryEntry(
            entry_id=entry_identity(self.identity, row.number), reference=ref, original_fields=row.fields,
            original_filename=values['file name'], basename=name, original_version=values['file version'],
            version_components=version, original_size=original_size, size_bytes=size, date_text=values.get('date'),
            time_text=values.get('time'), architecture=architecture, architecture_basis=basis, product=product,
            release=release, build=build, state=state, diagnostics=tuple(codes)))

    def group_claims(self, check: Callable[[], None]):
        groups: dict[tuple, list[int]] = defaultdict(list)
        duplicates: dict[tuple, str] = {}
        for index, entry in enumerate(self.entries):
            check()
            scope, metadata = _scope(entry), _metadata(entry)
            key = scope, metadata
            first = duplicates.setdefault(key, entry.entry_id)
            if first != entry.entry_id:
                self.entries[index] = entry.model_copy(update={'duplicate_of': first})
            groups[scope].append(index)
        for scope, indexes in groups.items():
            check()
            conflict = _contradicts([self.entries[index] for index in indexes])
            already_conflicted = any(self.entries[index].state == 'conflicted' for index in indexes)
            if not conflict and not already_conflicted:
                continue
            group_id = domain_id('kbc.csv-conflict', 1, {'inventory_id': self.identity, 'scope': scope})
            for index in indexes:
                entry = self.entries[index]
                if not conflict and entry.state != 'conflicted':
                    continue
                codes = entry.diagnostics
                if conflict:
                    codes = tuple(dict.fromkeys((*codes, 'CONFLICTING_METADATA')))
                    self.note('CONFLICTING_METADATA', 'Rows in this filename and scope carry conflicting metadata.',
                              entry.reference)
                self.entries[index] = entry.model_copy(update={'state': 'conflicted', 'conflict_group': group_id,
                                                               'diagnostics': codes})


def parse_inventory(raw: bytes, context: InventoryContext, *, limits: InventoryLimits = DEFAULT_LIMITS,
                    cancel=None) -> CsvInventory:
    """Parse exact bytes and explicit context; fatal failures return no partially published object."""
    if type(raw) is not bytes or not isinstance(context, InventoryContext) or not isinstance(limits, InventoryLimits):
        raise SourceError('PT-KBC-INPUT', 'CSV parsing needs exact bytes, InventoryContext and InventoryLimits.')
    try:
        context = InventoryContext.model_validate(context.model_dump())
        limits = InventoryLimits.model_validate(limits.model_dump())
    except ValidationError:
        raise SourceError('PT-KBC-INPUT', 'CSV parsing context or budgets failed validation.') from None
    if cancel is not None and not callable(getattr(cancel, 'is_set', None)):
        raise SourceError('PT-KBC-INPUT', 'The CSV cancellation token must expose is_set().')
    deadline = time.monotonic() + limits.max_seconds

    def check():
        if cancel is not None and cancel.is_set():
            raise SourceError('PT-KBC-CANCEL', 'CSV parsing was cancelled; no result was published.')
        if time.monotonic() >= deadline:
            raise SourceError('PT-KBC-LIMIT', 'The CSV parsing time budget was exhausted; no result was published.')

    check()
    if len(raw) > limits.max_bytes:
        raise _fail('The CSV exceeds its raw byte budget.', limit=True)
    text, encoding = _decode(raw, limits)
    check()
    parser = _Parser(hashlib.sha256(raw).hexdigest(), context, limits)
    delimiter = _DELIMITERS[context.delimiter]
    scanned, truncated = 0, False
    for row in _rows(text, delimiter, limits, check):
        check()
        scanned = row.number
        parser.consume(row, delimiter)
        if row.end_offset < len(text):
            if len(parser.entries) == limits.max_entries:
                parser.note('RESULT_LIMIT', 'The entry limit was reached; unscanned records may remain.', parser.ref(row))
                truncated = True
                break
            if scanned == limits.max_records:
                parser.note('RECORD_LIMIT', 'The record limit was reached; unscanned records may remain.', parser.ref(row))
                truncated = True
                break
    if not parser.had_header or parser.header is None:
        raise _fail('The CSV does not finish with a supported section header and data layout.')
    parser.group_claims(check)
    check()
    duplicate_count = sum(entry.duplicate_of is not None for entry in parser.entries)
    conflict_count = sum(entry.state == 'conflicted' for entry in parser.entries)
    partial = truncated or parser.rejected or parser.diagnostics or parser.omitted or conflict_count
    result = CsvInventory(inventory_id=parser.identity, raw_sha256=parser.sha, raw_size=len(raw), encoding=encoding,
                          context=context, limits=limits, entries=tuple(parser.entries), sections=tuple(parser.sections),
                          diagnostics=tuple(parser.diagnostics), records_scanned=scanned,
                          accepted_count=len(parser.entries), rejected_count=parser.rejected,
                          duplicate_count=duplicate_count, conflict_count=conflict_count,
                          diagnostics_omitted=parser.omitted, truncated=truncated,
                          status='partial' if partial else 'complete')
    check()
    return result
