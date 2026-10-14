"""Group `fn`: names and decompiled code of every function in the latest completed run (WB1 section 7).

Read through `enrichment.views.build_views`, so ownership of every function is validated and the text caps
(2 MB, 20,000 lines) are the views' own. A function yields a `function` document (name tables) and, when
decompiled text exists, a `code` document whose identifier words also carry the signature and the caller and
callee names. Instruction text is not indexed: Ghidriff keeps only a hash of it (coverage entry `ir`).
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from patchtrace.enrichment import identity
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.views import FunctionView, build_views
from patchtrace.models import ComparisonProject, FunctionRecord
from patchtrace.search.segment import Flag, SegmentDoc
from patchtrace.search.sources.base import SourceSpec, name_fields, skipped
from patchtrace.search.sources.pe import PeLoader
from patchtrace.search.tokenize import code_idents

KINDS = ('function', 'code')
TABLE_SETS = ('code', 'name')
NO_RUN = 'No completed analysis run with raw output yet.'


@dataclass(frozen=True, slots=True)
class _Entry:
    view: FunctionView
    record: FunctionRecord
    category: str


def _text(value: object) -> str:
    return value if isinstance(value, str) else ''


def _entries(project: ComparisonProject, run_id: str | None) -> tuple[str, str, tuple[_Entry, ...]]:
    """(run id, diff id, entries sorted by (function id, side)); a function seen twice counts once."""
    run = build_views(project, run_id)
    records = {(f.id, side): f for m in project.matches if m.run_id == run.run_id
               for side, funcs in (('older', m.older), ('newer', m.newer)) for f in funcs}
    unique = {(f.id, f.side): _Entry(f, records[(f.id, f.side)], m.category)
              for m in run.matches for f in (*m.older, *m.newer)}
    return run.run_id, run.diff_id, tuple(unique[key] for key in sorted(unique))


def _functions_digest(entries: Iterable[_Entry]) -> str:
    """sha256 over `(function id, side, name, address, code, assembly, category)` in sorted order. The code text
    itself is hashed (the card's `len(code)` would miss an edit of equal length)."""
    digest = hashlib.sha256()
    for e in entries:
        v = e.view
        row = (v.id, v.side, v.name, v.address, e.category, '\n'.join(v.code) if v.code else None,
               len(v.assembly) if v.assembly else None)
        digest.update(identity.canonical_json(row) + b'\n')
    return digest.hexdigest()


def _rva(entry: _Entry, image_base: int | None) -> int | None:
    address = entry.view.address
    if address is None:
        return None
    space = entry.record.address_space
    if space == 'relative':
        return address
    return address - image_base if space == 'virtual' and image_base is not None and address >= image_base else None


def _code_words(entry: _Entry, signature: str) -> str:
    related = ' '.join((*entry.record.callers, *entry.record.callees))
    return code_idents('\n'.join((signature, entry.view.name, related, '\n'.join(entry.view.code or ()))))


def _documents(entries: tuple[_Entry, ...], loader: PeLoader) -> Iterable[SegmentDoc]:
    bases = {'older': loader.image_base('older'), 'newer': loader.image_base('newer')}
    for ref, entry in enumerate(entries):
        view, meta = entry.view, entry.record.metadata
        signature = _text(meta.get('sig') or meta.get('signature'))
        upstream = _text(meta.get('upstream_name'))
        fields = name_fields(view.name, *(n for n in (upstream, _text(meta.get('parent'))) if n and n != view.name))
        if entry.category == 'unchanged':
            fields['flags'] |= int(Flag.UNCHANGED)
        rva = _rva(entry, bases[view.side])
        yield SegmentDoc('function', view.side, view.id[:64], view.name, ref, extra=signature, rva=rva, **fields)
        if view.code:
            yield SegmentDoc('code', view.side, view.id[:64], view.name, ref, rva=rva,
                             code_body='\n'.join(view.code), code_idents=_code_words(entry, signature))


def function_spec(project: ComparisonProject, run_id: str | None, loader: PeLoader) -> SourceSpec:
    try:
        run, diff, entries = _entries(project, run_id)
    except EnrichmentError:
        return skipped('fn', KINDS, None, 'not-applicable', NO_RUN)
    inputs = {'diff_id': diff, 'run_id': run, 'functions': _functions_digest(entries)}
    return SourceSpec('fn', KINDS, TABLE_SETS, None, inputs, lambda: _documents(entries, loader))
