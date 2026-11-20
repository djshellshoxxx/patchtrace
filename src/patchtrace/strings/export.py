"""Export of a strings delta as JSON or CSV (spec WB3 s8, WB3-S6). Pure but for the final file write.

Redacted unless the caller passes the revealed values; the document records the basis digests, the harmonized
settings and the lineage groups, so a file can be traced to the extraction it came from. Publication binds
the held source and parent. Linux requires a new destination; Windows also supports held-source replacement.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..owned_publication import (
    OwnedPublicationError,
    directory_anchor,
    publish_bytes,
    publish_windows,
)
from .contracts import StringChange, StringsDelta, StringsError

EXPORT_CONTRACT = 'strings-export/1'
CSV_CONTRACT = 'strings-export-csv/2'
Format = Literal['json', 'csv']
Scope = Literal['changed', 'all']
CSV_COLUMNS = ('id', 'status', 'review_tier', 'display', 'length', 'cues', 'older_offsets', 'newer_offsets',
               'functions', 'lineage_groups', 'reasons')
_FORMULA_LEADS = ('=', '+', '-', '@')
_CSV_IGNORABLE_PREFIX = ' \t\r\n\f\v\ufeff'


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
    # Some CSV viewers can ignore whitespace/BOM before interpreting a cell.
    # Prefix the original bytes, never strip them, when a formula may follow.
    guarded = text.startswith(('\t', '\r', '\n')) or text.lstrip(_CSV_IGNORABLE_PREFIX).startswith(_FORMULA_LEADS)
    return "'" + text if guarded else text


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
    metadata = {key: value for key, value in doc.items() if key != 'changes'}
    writer.writerow((CSV_CONTRACT, json.dumps(metadata, sort_keys=True, separators=(',', ':'))))
    writer.writerow(CSV_COLUMNS)
    writer.writerows(_csv_row(r) for r in doc['changes'])
    return out.getvalue().encode('utf-8')


def _write_new(path: Path, data: bytes) -> None:
    """No stage pathname can substitute bytes or become an unsafe cleanup target."""
    try:
        target = Path(os.path.abspath(path))
        anchor = directory_anchor(target.parent)  # the selected parent must already exist
        publish_bytes(target, data, anchor=anchor)  # no reuse: identical content still refuses
    except FileExistsError:
        if sys.platform.startswith('linux'):
            raise _fail(f'{path.name} already exists; replacement is unavailable on Linux; '
                        'choose a new destination') from None
        raise _fail(f'{path.name} already exists; pass --force to replace it') from None
    except NotImplementedError:
        raise _fail(f'{path.name}: safe publication capability is unavailable') from None
    except (OSError, OwnedPublicationError) as exc:
        reason = (exc.strerror or type(exc).__name__) if isinstance(exc, OSError) else str(exc)
        raise _fail(f'could not write {path.name}: {reason}') from None


def write_atomic(path: Path, data: bytes, *, force: bool) -> None:
    # Linux cannot atomically select a held source inode while replacing a name.
    # Both flag values use exclusive publication; an existing name is preserved.
    if not force or sys.platform.startswith('linux'):
        return _write_new(path, data)
    if path.is_dir():
        raise _fail(f'{path.name} is a folder')
    try:
        target = Path(os.path.abspath(path))
        if os.name == 'nt':
            publish_windows(target, data, anchor=directory_anchor(target.parent), replace=True)
        else:
            raise OwnedPublicationError('forced export is unsupported on this platform')
    except FileExistsError:
        raise _fail(f'{path.name} already exists; pass --force to replace it') from None
    except NotImplementedError:
        raise _fail(f'{path.name}: safe publication capability is unavailable') from None
    except (OSError, OwnedPublicationError) as exc:
        reason = (exc.strerror or type(exc).__name__) if isinstance(exc, OSError) else str(exc)
        raise _fail(f'could not write {path.name}: {reason}') from None


def export_delta(delta: StringsDelta, path: Path, *, fmt: Format, scope: Scope = 'changed',
                 reveal: Mapping[str, str] | None = None, force: bool = False) -> ExportResult:
    if not delta.comparable:
        raise StringsError('PT-STR-BASIS', 'the two string tables are not comparable; nothing to export')
    doc = document(delta, scope=scope, reveal=reveal)
    data = render(doc, fmt)
    write_atomic(path, data, force=force)
    return ExportResult(path.name, fmt, scope, len(doc['changes']), hashlib.sha256(data).hexdigest(),
                        reveal is None)
