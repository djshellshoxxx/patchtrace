"""``patchtrace search PROJECT --anchors-from CVE-ID``: the S10 bridge on the command line.

Builds the search anchors for one CVE from the project's STORED advisories (offline; nothing is fetched), runs each
anchor changed-code first and then over everything indexed (`search.anchors`), and returns per-anchor coverage.
Anchors are hints: a hit says nothing about causation and a miss is `none` only when every group was indexed.
"""
from __future__ import annotations

from collections.abc import Callable

from patchtrace.search.errors import SearchError

AnchorSource = Callable[[object, str], tuple[object | None, list[str]]]  # (service, cve) -> (AnchorSet|None, warnings)
CVE_HINT = 'the CVE must look like CVE-YYYY-NNNN'


def stored_anchors(service, cve: str) -> tuple[object | None, list[str]]:
    """The anchors of the current stored advisories that list ``cve``; ``None`` when no advisory lists it."""
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.intelligence.anchors import anchors_for
    from patchtrace.intelligence.storage import AdvisoryStore
    store = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id, service.project.revision)
    advisories, warnings = store.for_cve(cve)
    if not advisories:
        return None, list(warnings)
    current = [a for a in advisories if not a.superseded] or advisories
    return anchors_for(cve, [a.facts for a in current]), list(warnings)


def run(args, out, service, source: AnchorSource | None, emit, clean) -> int:
    """Exit code: 0 coverage given, 3 absence unproven for every anchor, 4 nothing to search."""
    from patchtrace.intelligence.explain import CVE_ID
    from patchtrace.search.anchors import coverage_for, plans_for
    cve = args.anchors_from
    if not isinstance(cve, str) or len(cve) > 32 or CVE_ID.fullmatch(cve) is None:
        raise SearchError('PT-SEARCH-QUERY', CVE_HINT)
    if args.query or args.kind or args.status:
        raise SearchError('PT-SEARCH-QUERY', '--anchors-from takes no --query, --kind or --status')
    anchor_set, warnings = (source or stored_anchors)(service, cve)
    anchors = tuple(anchor_set.anchors) if anchor_set is not None else ()
    if not anchors:
        why = ('no stored advisory lists this CVE; run `intelligence import` or `intelligence fetch` first'
               if anchor_set is None else 'the stored advisories give no search anchors')
        emit(out, args, 'complete', {'cve': cve, 'anchors': [], 'limitations': [why]}, warnings, f'{cve}: {why}')
        return 4
    if args.rebuild and not args.no_index_build:
        service.build(rebuild=True)
    build = not args.no_index_build
    rows = coverage_for(plans_for(anchor_set), lambda request: service.search(request, build=build))
    value = {a.anchor_id: a.value for a in anchors}
    items = [{'anchor_id': r.anchor_id, 'kind': r.kind, 'label': r.label, 'value': value[r.anchor_id],
              'status': r.status, 'hits': r.hits, 'unindexed': list(r.unindexed), 'reason': r.reason} for r in rows]
    lines = [f'{cve}: {len(rows)} anchor(s)']
    lines += [f'{r.status:<13} {r.kind:<9} {clean(value[r.anchor_id])}  hits={r.hits}' for r in rows]
    result = {'cve': cve, 'anchors': items, 'limitations': list(anchor_set.limitations)}
    unproven = all(r.status in ('unknown', 'not-searchable') for r in rows)
    emit(out, args, 'partial' if unproven else 'complete', result, warnings, '\n'.join(lines))
    return 3 if unproven else 0
