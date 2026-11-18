"""Saved advisory search boundary (KB plan saved-scope amendment). Pure; no storage or recovery.

Coverage states what was inspected, while the full index still decides which source
revisions may contribute current claims. Month selectors cannot reconstruct exact
historical snapshots that the saved record never named.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from .contracts import Coverage, Lead, SearchScope
from .sources.scope import build_coverage, corpus_digest

if TYPE_CHECKING:
    from .index import ReverseIndex


class SavedScopeError(ValueError):
    def __init__(self, reason: str):
        super().__init__(f'The saved search coverage {reason}; restore its sources or repeat the search.')


def resolve(lead: Lead, coverage: Sequence[Coverage | None], *, index: ReverseIndex | None = None,
            keys: Sequence[str] | None = None, scope: SearchScope | None = None) -> SearchScope | None:
    """Validate one advisory search and return its finite selector, never a subset index.

    ``keys`` binds workspace row references to their bodies. The context builder has
    only the bodies, so it still checks their recomputed identities. An index enables
    readability and detectable coverage-drift checks; caller-only selector reads use
    the same record validation without inventing source availability.
    """
    if lead.kind not in {'kb', 'cve'}:
        return scope
    if len(coverage) != 1 or not isinstance(coverage[0], Coverage) or (keys is not None and len(keys) != 1):
        raise SavedScopeError('needs exactly one available record')
    # model_copy/model_construct are not validation boundaries for direct callers.
    try:
        saved = Coverage.model_validate_json(coverage[0].model_dump_json())
    except ValueError:
        raise SavedScopeError('is malformed') from None
    selected = saved.scope
    if keys is not None and keys[0] != saved.coverage_id:
        raise SavedScopeError('does not match its referenced row')
    if scope is not None and scope != selected:
        raise SavedScopeError('does not match the requested selector')
    if ((selected.kind == 'selected_months' and selected.doc_ids)
            or (selected.kind in {'provided_files', 'cached_corpus'} and selected.months)
            or (selected.kind == 'mixed' and (not selected.months or not selected.doc_ids))):
        raise SavedScopeError('has contradictory selector fields')
    if selected.kind == 'cached_corpus' and selected.corpus_digest != corpus_digest(selected.doc_ids):
        raise SavedScopeError('does not match its cached document identities')
    rebuilt = build_coverage(
        source_kind=saved.source_kind, scope=selected, requested=saved.requested_ids,
        inspected=saved.inspected_ids, failed=((item.id, item.reason) for item in saved.failed),
        unfetchable=saved.unfetchable_ids, watermark=saved.watermark_current_release_date,
        retrieved_at=saved.retrieved_at, scope_known=saved.state != 'unknown_scope',
        stale=saved.state == 'stale_cache')
    if rebuilt != saved:
        raise SavedScopeError('does not match its recorded identity or state')
    if selected.kind != 'cached_corpus' and set(saved.requested_ids) != set(selected.months) | set(selected.doc_ids):
        raise SavedScopeError('does not describe its selected months and documents')
    if index is not None:
        if selected.kind == 'cached_corpus' and any(index.get(doc_id) is None for doc_id in selected.doc_ids):
            raise SavedScopeError('names a cached source that is no longer readable')
        current = index.coverage(selected, now=saved.retrieved_at)
        # Age/cache-growth warnings do not rewrite the recorded receipt. Its actual
        # coverage and watermark must still describe the inputs being used now.
        fields = ('source_kind', 'requested_ids', 'inspected_ids', 'failed', 'unfetchable_ids',
                  'watermark_current_release_date')
        if any(getattr(saved, name) != getattr(current, name) for name in fields):
            raise SavedScopeError('no longer describes the readable selected sources')
    return selected
