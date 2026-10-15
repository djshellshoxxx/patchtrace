"""Export of a strings delta as JSON or CSV (spec WB3 s8, WB3-S6). Pure but for the final file write.

Redacted unless the caller passes the revealed values; the document records the basis digests, the harmonized
settings and the lineage groups, so a file can be traced to the extraction it came from. The write is atomic (a
temporary file in the same folder, then a rename) and never replaces an existing file without `force`.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .contracts import StringChange, StringsDelta, StringsError

EXPORT_CONTRACT = 'strings-export/1'
Format = Literal['json', 'csv']
Scope = Literal['changed', 'all']
CSV_COLUMNS = ('id', 'status', 'review_tier', 'display', 'length', 'cues', 'older_offsets', 'newer_offsets',
               'functions', 'lineage_groups', 'reasons')
_FORMULA_LEADS = ('=', '+', '-', '@', '\t', '\r')


@dataclass(frozen=True, slots=True)
class ExportResult:
    file: str
    format: Format
    scope: Scope
    rows: int
    sha256: str
    redacted: bool


def _fail(message: str) -> StringsError:
    return StringsError('PT-STR-EXPORT', message)


def selected(delta: StringsDelta, scope: Scope) -> list[StringChange]:
    """`changed` leaves out strings that only moved; `all` keeps every row of the delta."""
    return [c for c in delta.changes if scope == 'all' or c.status != 'both']


def _lineage(changes: list[StringChange]) -> list[str]:
    return sorted({link.lineage_group for c in changes for link in c.links})


def _record(change: StringChange, reveal: Mapping[str, str] | None) -> dict:
    record = change.model_dump(mode='json')
    if reveal and change.value_sha256 in reveal:
        record['display'] = reveal[change.value_sha256]
    return record


def document(delta: StringsDelta, *, scope: Scope = 'changed', reveal: Mapping[str, str] | None = None) -> dict:
    changes = selected(delta, scope)
    return {
        'contract': EXPORT_CONTRACT, 'scope': scope, 'redacted': reveal is None,
        'basis': {'older_basis_digest': delta.older_basis_digest, 'newer_basis_digest': delta.newer_basis_digest,
                  'harmonized': delta.harmonized.model_dump(mode='json') if delta.harmonized else None,
                  'notes': list(delta.basis_notes)},
        'counts': dict(delta.counts), 'truncated': delta.truncated,
        'anchors': {'digest': delta.anchors.digest, 'hits': len(delta.anchors.hits)},
        'lineage_groups': _lineage(changes), 'changes': [_record(c, reveal) for c in changes]}


def _cell(value: object) -> str:
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_LEADS) else text


def _csv_row(record: dict) -> list[str]:
    links = record['links']
    values = (record['id'], record['status'], record['review_tier'], record['display'], record['length'],
              ' '.join(record['cues']), ' '.join(f'0x{o:x}' for o in (record['older'] or {}).get('offsets', ())),
              ' '.join(f'0x{o:x}' for o in (record['newer'] or {}).get('offsets', ())),
              ' '.join(dict.fromkeys(f['function']['name'] for f in links if f['function']['name'])),
              ' '.join(dict.fromkeys(f['lineage_group'] for f in links)), ' '.join(record['reasons']))
    return [_cell(v) for v in values]


def render(doc: dict, fmt: Format) -> bytes:
    if fmt == 'json':
        return (json.dumps(doc, sort_keys=True, indent=2) + '\n').encode('utf-8')
    out = io.StringIO(newline='')
    writer = csv.writer(out, lineterminator='\n')
    writer.writerow(CSV_COLUMNS)
    writer.writerows(_csv_row(r) for r in doc['changes'])
    return out.getvalue().encode('utf-8')


def write_atomic(path: Path, data: bytes, *, force: bool) -> None:
    if path.exists() and not force:
        raise _fail(f'{path.name} already exists; pass --force to replace it')
    if path.is_dir():
        raise _fail(f'{path.name} is a folder')
    temp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    try:
        with open(temp, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise _fail(f'could not write {path.name}: {exc.strerror or type(exc).__name__}') from None


def export_delta(delta: StringsDelta, path: Path, *, fmt: Format, scope: Scope = 'changed',
                 reveal: Mapping[str, str] | None = None, force: bool = False) -> ExportResult:
    if not delta.comparable:
        raise StringsError('PT-STR-BASIS', 'the two string tables are not comparable; nothing to export')
    doc = document(delta, scope=scope, reveal=reveal)
    data = render(doc, fmt)
    write_atomic(path, data, force=force)
    return ExportResult(path.name, fmt, scope, len(doc['changes']), hashlib.sha256(data).hexdigest(),
                        reveal is None)
