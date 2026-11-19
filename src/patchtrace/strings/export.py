"""Export of a strings delta as JSON or CSV (spec WB3 s8, WB3-S6). Pure but for the final file write.

Redacted unless the caller passes the revealed values; the document records the basis digests, the harmonized
settings and the lineage groups, so a file can be traced to the extraction it came from. No-force publication
binds the held source and parent. Linux forced replacement retains an explicit final pathname race.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import stat
import sys
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..owned_publication import (
    OwnedPublicationError,
    check_linux_parent,
    directory_anchor,
    file_identity,
    linux_directory,
    publish_bytes,
    publish_windows,
    verify_stage,
    write_stage,
)
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


def _write_new(path: Path, data: bytes) -> None:
    """No stage pathname can substitute bytes or become an unsafe cleanup target."""
    try:
        target = Path(os.path.abspath(path))
        anchor = directory_anchor(target.parent)  # the selected parent must already exist
        publish_bytes(target, data, anchor=anchor)  # no reuse: identical content still refuses
    except FileExistsError:
        raise _fail(f'{path.name} already exists; pass --force to replace it') from None
    except (OSError, OwnedPublicationError) as exc:
        reason = (exc.strerror or type(exc).__name__) if isinstance(exc, OSError) else str(exc)
        raise _fail(f'could not write {path.name}: {reason}') from None


def _close_owned(descriptor: int, primary: BaseException | None) -> None:
    """Close exactly this descriptor without replacing a primary failure."""
    try:
        os.close(descriptor)
    except BaseException as exc:
        if primary is None:
            raise
        primary.add_note(f'Export descriptor cleanup also failed: {type(exc).__name__}'[:160])


def _replace_linux(target: Path, data: bytes) -> None:
    anchor = directory_anchor(target.parent)
    with ExitStack() as stack:
        parent = linux_directory(target.parent, create=False, anchor=anchor)
        stack.push(lambda _type, error, _trace: _close_owned(parent, error))
        if not hasattr(os, 'O_TMPFILE'):
            raise OwnedPublicationError('forced export requires Linux anonymous staging support')
        descriptor = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=parent)
        stack.push(lambda _type, error, _trace: _close_owned(descriptor, error))
        identity = write_stage(descriptor, data)
        check_linux_parent(target.parent, parent, anchor=anchor)
        stage = f'.{target.name}.{secrets.token_hex(16)}.tmp'
        os.link(f'/proc/self/fd/{descriptor}', stage, dst_dir_fd=parent, follow_symlinks=True)
        # A failed linked-stage admission or rename retains the named entry. No
        # pathname unlink can prove that it still denotes our source atomically.
        held = verify_stage(descriptor, data, identity)
        named = os.stat(stage, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or file_identity(named) != identity or
                (named.st_size, named.st_mtime_ns, named.st_ctime_ns) !=
                (held.st_size, held.st_mtime_ns, held.st_ctime_ns)):
            raise OwnedPublicationError('forced export staging identity changed')
        check_linux_parent(target.parent, parent, anchor=anchor)
        # Linux has no rename-by-fd here. A source substitution after the final
        # check remains possible; the check below refuses a false success receipt
        # but does not undo foreign bytes that the rename may have published.
        os.replace(stage, target.name, src_dir_fd=parent, dst_dir_fd=parent)
        verify_stage(descriptor, data, identity)
        if file_identity(os.stat(target.name, dir_fd=parent, follow_symlinks=False)) != identity:
            raise OwnedPublicationError('forced export destination identity changed')
        check_linux_parent(target.parent, parent, anchor=anchor)


def write_atomic(path: Path, data: bytes, *, force: bool) -> None:
    if not force:
        return _write_new(path, data)
    if path.is_dir():
        raise _fail(f'{path.name} is a folder')
    try:
        target = Path(os.path.abspath(path))
        if sys.platform.startswith('linux'):
            _replace_linux(target, data)
        elif os.name == 'nt':
            publish_windows(target, data, anchor=directory_anchor(target.parent), replace=True)
        else:
            raise OwnedPublicationError('forced export is unsupported on this platform')
    except FileExistsError:
        raise _fail(f'{path.name} already exists; pass --force to replace it') from None
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
