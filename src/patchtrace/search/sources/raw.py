"""Group `raw`: Ghidra strings and symbols added or deleted, from the hash-verified raw Ghidriff JSON (WB1 section 7).

The shape of `strings` and `symbols` is [unverified] until a real Ghidriff JSON is a golden (live gate), so the
reader accepts only `{added: [...], deleted: [...]}` lists of text (or of objects with a text field) and anything
else makes the group fail with a fixed message instead of guessing. Names of unchanged functions (`name_matches`)
are not indexed; the coverage entry says so. Added strings are `newer`, deleted ones `older`; that is a side of a
diff list, never proof that the other side lacks the text.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.ingestion import safe_path
from patchtrace.intelligence.tools.common import redacted_display, secret_kind
from patchtrace.models import AnalysisRun, ComparisonProject
from patchtrace.persistence import strict_json
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.segment import Flag, SegmentDoc
from patchtrace.search.sources.base import SourceSpec, name_fields, selected_run, skipped

KINDS = ('string', 'function')
TABLE_SETS = ('name', 'text')
MAX_RAW_BYTES = 100 * 1024 * 1024
MAX_ITEMS = 1_000_000
SIDES = {'added': 'newer', 'deleted': 'older'}
TEXT_FIELDS = ('string', 'value', 'text', 'name')
UNCHANGED_NOT_INDEXED = 'unchanged functions: not indexed'
NO_RAW = 'The run has no saved raw output.'
RAW_VERSION = 1


def _source_error(message: str) -> SearchError:
    return SearchError('PT-SEARCH-SOURCE', message, recoverable=True)


def _load(path: Path, sha256: str) -> dict:
    try:
        with VerifiedArtifactReader.open_path(path, sha256) as reader:
            if reader.size > MAX_RAW_BYTES:
                raise _source_error('the raw analysis output is too large to index')
            document = strict_json(reader.read(0, reader.size).decode('utf-8'))
    except (ArtifactBytesError, OSError, UnicodeError, ValueError):
        raise _source_error('the raw analysis output could not be read or does not match its recorded hash') from None
    return document


def _item_text(item: object) -> str | None:
    if isinstance(item, dict):
        item = next((item[k] for k in TEXT_FIELDS if isinstance(item.get(k), str)), None)
    return item if isinstance(item, str) and item else None


def _texts(document: dict, key: str) -> set[tuple[str, str]]:
    """(side, text) of one root list. An absent list is empty; a list of another shape is an error."""
    section = document.get(key)
    if section is None:
        return set()
    if not isinstance(section, dict) or not set(section) <= set(SIDES) or any(
            not isinstance(section.get(name, []), list) for name in SIDES):
        raise _source_error(f'the raw analysis output has an unrecognised {key} section')
    found: set[tuple[str, str]] = set()
    for name, side in SIDES.items():
        items = section.get(name, [])
        if len(items) > MAX_ITEMS:
            raise _source_error(f'the raw analysis output has too many {key} to index')
        found.update((side, text) for item in items if (text := _item_text(item)) is not None)
    return found


def _documents(path: Path, sha256: str) -> Iterable[SegmentDoc]:
    document = _load(path, sha256)
    if not isinstance(document, dict) or not ({'strings', 'symbols'} & set(document)):
        raise _source_error('the raw analysis output has no strings or symbols section')
    rows = sorted([(side, 0, text) for side, text in _texts(document, 'strings')]
                  + [(side, 1, text) for side, text in _texts(document, 'symbols')])
    limit = DEFAULT_LIMITS.string_field_bytes
    for ref, (side, symbol, text) in enumerate(rows):
        if symbol:
            fields = name_fields(text)
            fields['flags'] |= int(Flag.SYMBOL)
            yield SegmentDoc('function', side, text[:64], text, ref, **fields)
            continue
        kind = secret_kind(text)
        shown = redacted_display(text, kind)[:limit]
        yield SegmentDoc('string', side, '', shown, ref, flags=int(Flag.SECRET) if kind else 0,
                         value_sha=hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest(),
                         text_title=shown)


def raw_spec(project: ComparisonProject, root: Path, run_id: str | None) -> SourceSpec:
    run: AnalysisRun | None = selected_run(project, run_id)
    if run is None:
        return skipped('raw', KINDS, None, 'not-applicable', 'No completed analysis run with raw output yet.')
    if not run.raw_path:
        return skipped('raw', KINDS, None, 'unavailable', NO_RAW)
    try:
        path = safe_path(Path(root), run.raw_path)
    except ValueError:
        return skipped('raw', KINDS, None, 'unavailable', NO_RAW)
    sha256 = run.raw_sha256 or ''
    return SourceSpec('raw', KINDS, TABLE_SETS, None, {'raw_sha256': sha256, 'reader': RAW_VERSION},
                      lambda: _documents(path, sha256), reason=UNCHANGED_NOT_INDEXED)
