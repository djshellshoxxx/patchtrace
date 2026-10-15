"""The project row ``kev-context`` and its drift (KEV-integration-plan sections 4, 7 and 8).

A row records what one catalog said about a set of CVEs when a person looked, so an export can show it as of that day
and a later catalog that disagrees can be reported. It is written like every other project row: on the thread that owns
the project store, through ``EnrichmentStore.publish``. The kind is registered in ``enrichment.storage.KINDS`` and is
not a derived kind, so retention never deletes it, and a reader from before KEV never queries it. A row holds CVE-level
facts only: this module imports no ranking code and reads no clock (``created_at`` is passed in).
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.identity import domain_id
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from . import limits
from .contracts import KevChange, KevContext, KevEntry, KevEntrySlim, KevError, KevTracked, clean_text
from .ports import KevLookupPort
from .view_model import _change_text  # one wording for a changed field, in the dock and in a project

KIND = 'kev-context'
DRIFT_PREFIX = 'KEV data changed since recorded: '


@dataclass(frozen=True, slots=True)
class Recorded:
    """A stored row and the context it holds. ``entry.stale`` is set when the row was written while another catalog
    than the one its answers came from was loaded."""
    entry: Entry
    context: KevContext


def _digest(snapshot_id: str | None, cves: list[str]) -> str:
    """Identity of a set of CVEs under one snapshot: the ``context_id`` of the row, and the guard of a publication."""
    return domain_id('kev-context', 1, {'snapshot_id': snapshot_id, 'cves': cves, 'join_version': limits.JOIN_VERSION})


def _reason(error: Exception) -> str:
    """The user-safe message of an enrichment failure; of a database failure only its class (its text can hold paths)."""
    return error.message if isinstance(error, EnrichmentError) else error.__class__.__name__


def build_context(kev: KevLookupPort, cves: Iterable[str], *, created_at: str, kb: str | None = None,
                  release_date: str | None = None, orientation_verified: bool = False) -> KevContext:
    """What the loaded catalog says about ``cves``, as a row: listed or not listed, with slim entries, sorted by CVE ID.
    An ID the catalog cannot judge (not a CVE ID) says nothing and is left out. ``kb`` and ``release_date`` name the
    update the CVEs were looked up for and ``orientation_verified`` says whether its release date is the fix's; none of
    them is identity. Raises ``KevError``: PT-KEV-NOTFOUND without a catalog, PT-KEV-INPUT for nothing to record or a
    field of the wrong shape (the field is named, its value never), PT-KEV-LIMIT past 256 CVEs or 256 KiB."""
    meta = kev.meta
    if meta is None:
        raise KevError('PT-KEV-NOTFOUND', 'no KEV catalog is loaded')
    wanted = list(dict.fromkeys(cves))
    if len(wanted) > limits.MAX_LOOKUP_CVES:
        raise KevError('PT-KEV-LIMIT', f'more than {limits.MAX_LOOKUP_CVES} CVE IDs at once')
    answers = sorted((row for row in map(kev.lookup, wanted) if row.status in ('listed', 'not-listed')),
                     key=lambda row: row.cve_id)
    if not answers:
        raise KevError('PT-KEV-INPUT', 'none of the CVE IDs could be answered by the loaded catalog')
    if len(answers) > limits.MAX_CONTEXT_CVES:
        raise KevError('PT-KEV-LIMIT', f'more than {limits.MAX_CONTEXT_CVES} CVEs in one project row')
    lookups = tuple(row.model_copy(update={'entry': row.entry.slim() if row.entry else None}) for row in answers)
    try:
        context = KevContext(
            context_id=_digest(meta.snapshot_id, [row.cve_id for row in lookups]), created_at=created_at,
            snapshot_id=meta.snapshot_id, catalog_version=meta.catalog_version, date_released=meta.date_released,
            content_digest=meta.content_digest, source=meta.source, lookups=lookups, kb=kb, release_date=release_date,
            orientation_verified=orientation_verified)
    except ValidationError as exc:
        fields = sorted({str(error['loc'][0]) for error in exc.errors() if error['loc']}) or ['context']
        raise KevError('PT-KEV-INPUT', 'the KEV context is not valid: ' + ', '.join(fields)) from None
    if len(context.model_dump_json().encode('utf-8')) > limits.MAX_CONTEXT_ROW_BYTES:
        raise KevError('PT-KEV-LIMIT',
                       f'the KEV context row would exceed {limits.MAX_CONTEXT_ROW_BYTES // limits.KIB} KiB')
    return context


def publish_context(store: EnrichmentStore, project_id: str, revision: int, context: KevContext, *,
                    loaded_snapshot_id: str | None) -> Entry:
    """Write the row; the same CVEs under the same catalog replace it. The row is stored stale, never current, when the
    catalog loaded now (``loaded_snapshot_id``, None without one) is not the catalog its answers came from. Owner thread
    only, like ``EnrichmentStore``. Raises ``KevError`` PT-KEV-STORAGE when the project cannot take the row."""
    guard = Guard(project_id, '', '', context.context_id)
    current = Guard(project_id, '', '', _digest(loaded_snapshot_id, [row.cve_id for row in context.lookups]))
    try:
        return store.publish(KIND, guard, current, revision, 'complete', json.loads(context.model_dump_json()),
                             f'{KIND}:{context.context_id}')
    except (EnrichmentError, sqlite3.Error) as exc:
        raise KevError('PT-KEV-STORAGE', 'cannot record the KEV context: ' + _reason(exc)) from None


def load_contexts(store: EnrichmentStore) -> tuple[tuple[Recorded, ...], tuple[str, ...]]:
    """Every readable ``kev-context`` row, newest first, and one warning for each row that is not readable (a failed
    integrity hash, a body that is not a ``kev/1`` row). A bad row never hides the others. Raises ``KevError``
    PT-KEV-STORAGE when the project cannot be read at all."""
    warnings: list[str] = []

    def damaged(row_id: str) -> None:
        warnings.append(f'KEV row {clean_text(row_id, 40)} failed its integrity hash; skipped')

    try:
        entries = store.entries(KIND, on_corrupt=damaged)
    except (EnrichmentError, sqlite3.Error) as exc:
        raise KevError('PT-KEV-STORAGE', 'cannot read the KEV contexts: ' + _reason(exc)) from None
    found = []
    for entry in entries:
        try:
            found.append(Recorded(entry, KevContext.model_validate_json(json.dumps(entry.body))))
        except ValueError:
            warnings.append(f'KEV row {clean_text(entry.id, 40)} is not a valid kev/1 row; skipped')
    return tuple(found), tuple(warnings)


def _tracked(entry: KevEntry | KevEntrySlim) -> KevTracked:
    return KevTracked(**{name: getattr(entry, name) for name in KevTracked.model_fields})


def drift_lines(context: KevContext, kev: KevLookupPort) -> tuple[str, ...]:
    """One sentence for each recorded CVE whose answer differs in the catalog loaded now, newly listed CVEs first (the
    headline), then CVEs whose tracked CISA facts changed, then CVEs no longer listed, each group in CVE order. A
    reworded description is not a change. Nothing when no catalog is loaded or the recorded facts still hold."""
    recorded_on = context.date_released[:10]
    newly, changed, removed = [], [], []
    for before in context.lookups:
        now = kev.lookup(before.cve_id)
        if before.status == 'not-listed' and now.status == 'listed':
            newly.append(f'{DRIFT_PREFIX}{before.cve_id} was not listed on {recorded_on} and is listed now '
                         f'(added {now.entry.date_added}).')
        elif before.status == 'listed' and now.status == 'not-listed':
            removed.append(f'{DRIFT_PREFIX}{before.cve_id} was listed on {recorded_on} and is not listed now.')
        elif before.status == 'listed' and now.status == 'listed' and _tracked(before.entry) != _tracked(now.entry):
            change = KevChange(cve_id=before.cve_id, before=_tracked(before.entry), after=_tracked(now.entry))
            changed.append(f'{DRIFT_PREFIX}{_change_text(change)}.')
    return (*newly, *changed, *removed)
