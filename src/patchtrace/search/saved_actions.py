"""Owner-thread saved-query actions and canonical input preparation; no Qt, index or extra project opens."""
from __future__ import annotations

import dataclasses
import re
from typing import get_args

from .contracts import Mode, SearchKind
from .errors import SearchError
from .query import parse_query
from .saved import RECENT_MAX, EnrichmentSavedStore, dump_recent, remember

RECENT_BYTES = 8192


def effective_plan(text: str, *, mode: Mode = 'auto', side: str | None = None, scope: str | None = None,
                   kinds: tuple[str, ...] = ()):
    """Explicit controls replace matching unquoted filters; absent controls preserve textual filters.

    Parse before token rewriting so an invalid phrase cannot turn into an accepted query. Parse the completed
    text again to enforce the ordinary grammar and final length; this text and validated mode replay exactly.
    """
    if (mode not in get_args(Mode) or side not in (None, 'both', 'older', 'newer')
            or scope not in (None, 'indexed', 'changed') or any(kind not in get_args(SearchKind) for kind in kinds)):
        raise SearchError('PT-SEARCH-QUERY', 'unsupported search mode, side, scope or kind', recoverable=True)
    plan = parse_query(' '.join([text, *(f'kind:{kind}' for kind in dict.fromkeys(kinds))]), mode=mode)
    tokens = re.findall(r'"[^"]*"|\S+', plan.text)
    overridden = {key for key, value in (('side', side), ('scope', scope)) if value is not None}
    tokens = [token for token in tokens if token.startswith('"') or ':' not in token
              or token.partition(':')[0].lower() not in overridden]
    if side in ('older', 'newer'):
        tokens.append(f'side:{side}')
    if scope == 'changed':
        tokens.append('scope:changed')
    return parse_query(' '.join(tokens), mode=mode)


def project_store(service) -> EnrichmentSavedStore:
    """Use the service already owned by this thread; a detached/test-only project cannot persist analyst data."""
    from patchtrace.enrichment.storage import EnrichmentStore

    project, store = getattr(service, 'project', None), getattr(service, 'store', None)
    if project is None or store is None:
        raise SearchError('PT-SEARCH-STORE', 'saved searches need the current open project store', recoverable=True)
    return EnrichmentSavedStore(EnrichmentStore(store), project.id, revision=lambda: service.project.revision)


def find_saved(store, saved_id: str):
    item = next((item for item in store.list().items if item.saved_id == saved_id), None)
    if item is None:
        raise SearchError('PT-SEARCH-INPUT', 'that saved query is no longer present in this project', recoverable=True)
    return item


def storage_result(service, operation: str, *, value: str | None = None, plan=None) -> dict:
    """Data-only CLI operation. No SearchService is constructed for listing, saving or deleting."""
    store = project_store(service)
    if operation == 'list':
        result = store.list()
        return {'operation': 'list', 'items': [dataclasses.asdict(item) for item in result.items],
                'skipped': result.skipped}
    if operation == 'save':
        return {'operation': 'save', 'item': dataclasses.asdict(store.save(value, plan))}
    if operation == 'delete':
        return {'operation': 'delete', 'saved_id': value, 'deleted': store.delete(value)}
    raise SearchError('PT-SEARCH-INPUT', 'unsupported saved query operation', recoverable=True)


def bounded_recent(values) -> tuple[str, ...]:
    """Sanitize at most twenty settings entries, then remove oldest complete queries until JSON fits."""
    if not isinstance(values, (tuple, list)):
        return ()
    result: tuple[str, ...] = ()
    for value in reversed(values[:RECENT_MAX]):
        result = remember(result, value)
    while result and len(dump_recent(result).encode('utf-8')) > RECENT_BYTES:
        result = result[:-1]
    return result
