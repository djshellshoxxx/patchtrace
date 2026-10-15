"""A3 call delta of one modified pair: rename-invariant classes of every callee change (sets, not counts)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ..models import ComparisonProject
from .apis import api_hits
from .contracts import GraphNode, Pairing, Side
from .contracts_delta import MAX_CHANGES, ApiHintPort, CallDelta, CalleeChange, ChangeClass, Downgrade
from .limits import CANCEL_CLAIM_INTERVAL, CancelCheck, GraphError
from .noise import DEFAULT_HUBS, HubRegistry, hub_flags
from .project_input import Entry
from .snapshot import CallSnapshot
from .text import sanitize

_ORDER: dict[str, int] = {c: i for i, c in enumerate(
    ('call-to-new-function', 'added-call', 'removed-call', 'callee-deleted', 'cannot-determine', 'same-link'))}
_NEW_CLASSES = frozenset({'added-call', 'call-to-new-function'})
_NOTE = 'only distinct callees are compared: call counts, order and call sites are not known'


@dataclass(frozen=True)
class DeltaContext:
    hints: ApiHintPort | None = None
    registry: HubRegistry = DEFAULT_HUBS
    diff_types: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # match id -> Ghidriff diff types


def diff_types_by_match(project: ComparisonProject) -> dict[str, tuple[str, ...]]:
    """Ghidriff's `diff_type` flags per match (hint text and the renumber-only test only)."""
    found: dict[str, tuple[str, ...]] = {}
    for match in project.matches:
        for record in (*match.older, *match.newer):
            types = record.metadata.get('diff_types')
            if isinstance(types, list):
                found[match.id] = tuple(sanitize(t, 40) for t in types if isinstance(t, str))
                break
    return found


def lookup(snap: CallSnapshot, side: Side, label: str) -> tuple[int, GraphNode] | None:
    """The unique node of a raw label (same encoding rule as the resolver); ambiguous labels have none."""
    graph = snap.side(side)
    positions = graph.by_label.get(sanitize(label.encode('utf-8', 'backslashreplace').decode('utf-8')), ())
    return (positions[0], graph.nodes[positions[0]]) if len(positions) == 1 else None


def _flags(snap: CallSnapshot, ctx: DeltaContext, side: Side, label: str, found: tuple[int, GraphNode] | None,
           pairing: Pairing, cls: ChangeClass) -> tuple[str, ...]:
    flags: list[str] = ['inferred'] if pairing.inferred else []
    if found is None:
        return tuple(flags)
    position, node = found
    if node.kind == 'external':
        flags.append('import')
        if cls in _NEW_CLASSES:
            flags.append('newly-imported')
    if 'thunk-suspect' in node.flags:
        flags.append('thunk-suspect')
    flags.extend(hub_flags(ctx.registry, label, snap.side(side).graph.in_degree(position)))
    return tuple(flags)


def _change(snap: CallSnapshot, ctx: DeltaContext, cls: ChangeClass, older: str | None, newer: str | None,
            pairing: Pairing, reason: str = '') -> CalleeChange:
    old_found = lookup(snap, 'older', older) if older is not None else None
    new_found = lookup(snap, 'newer', newer) if newer is not None else None
    side: Side = 'newer' if newer is not None else 'older'
    label, found = (newer, new_found) if newer is not None else (older, old_found)
    assert label is not None
    flags = _flags(snap, ctx, side, label, found, pairing, cls)
    hits = api_hits(ctx.hints, label) if found is not None and found[1].kind == 'external' and cls != 'same-link' else ()
    return CalleeChange(
        cls=cls, older_label=sanitize(older) if older is not None else None,
        newer_label=sanitize(newer) if newer is not None else None,
        older_node=old_found[1].id if old_found else None, newer_node=new_found[1].id if new_found else None,
        pairing=pairing, flags=(*flags, 'api-hint') if hits else flags, api=hits, reason=sanitize(reason, 200))


def _why(pairing: Pairing) -> str:
    return {'many': 'the callee pairs with several functions',
            'contested': 'engines disagree on the pairing'}.get(pairing.kind, 'no pairing was found for this callee')


def _old_changes(snap: CallSnapshot, ctx: DeltaContext, old: list[str], new: set[str],
                 covered: set[str]) -> list[CalleeChange]:
    out = []
    for label in old:
        pairing = snap.pairs.partner('older', label)
        if pairing.kind in {'one', 'many'}:
            covered.update(pairing.partners)
        if pairing.kind == 'one':
            partner = pairing.partners[0]
            out.append(_change(snap, ctx, 'same-link', label, partner, pairing) if partner in new
                       else _change(snap, ctx, 'removed-call', label, None, pairing))
        elif pairing.kind == 'removed':
            out.append(_change(snap, ctx, 'callee-deleted', label, None, pairing))
        else:
            out.append(_change(snap, ctx, 'cannot-determine', label, None, pairing, _why(pairing)))
    return out


def _new_changes(snap: CallSnapshot, ctx: DeltaContext, new: list[str], covered: set[str]) -> list[CalleeChange]:
    out = []
    for label in new:
        if label in covered:
            continue
        pairing = snap.pairs.partner('newer', label)
        if pairing.kind == 'one':
            out.append(_change(snap, ctx, 'added-call', pairing.partners[0], label, pairing))
        elif pairing.kind == 'added':
            found = lookup(snap, 'newer', label)
            external = found is not None and found[1].kind == 'external'
            out.append(_change(snap, ctx, 'added-call' if external else 'call-to-new-function', None, label,
                               pairing))
        else:
            out.append(_change(snap, ctx, 'cannot-determine', None, label, pairing, _why(pairing)))
    return out


def _downgrade(changes: list[CalleeChange], diff_types: tuple[str, ...]) -> Downgrade:
    different = [c for c in changes if c.cls != 'same-link']
    if changes and not different and 'called' in diff_types:
        return 'renumber-only'
    if different and all('hub' in c.flags for c in different):
        return 'hub-only'
    return 'none'


def _delta(snap: CallSnapshot, ctx: DeltaContext, match_id: str, older: list[Entry],
           newer: list[Entry]) -> CallDelta:
    types = ctx.diff_types.get(match_id, ())
    first_old, first_new = (older[0] if older else None), (newer[0] if newer else None)
    base = {'match_id': match_id, 'ghidriff_diff_types': types,
            'older_function_id': first_old.function_id if first_old else None,
            'newer_function_id': first_new.function_id if first_new else None,
            'older_label': sanitize(first_old.label) if first_old else None,
            'newer_label': sanitize(first_new.label) if first_new else None}
    if len(older) != 1 or len(newer) != 1:
        one_sided = not (older and newer)
        note = 'the function exists in only one build' if one_sided else 'several functions share the name'
        return CallDelta(state='one-sided' if one_sided else 'not-comparable', limitations=(note,), **base)
    old, new = older[0], newer[0]
    if not (old.callees or new.callees or old.callers or new.callers):
        return CallDelta(state='unavailable', limitations=('no call lists are stored for this pair',), **base)
    covered: set[str] = set()
    new_set = set(new.callees)
    changes = _old_changes(snap, ctx, sorted(set(old.callees)), new_set, covered)
    changes += _new_changes(snap, ctx, sorted(new_set), covered)
    ordered = sorted(changes, key=lambda c: (_ORDER[c.cls], c.newer_label or '', c.older_label or ''))
    return CallDelta(
        state='compared', downgrade=_downgrade(changes, types), changes=tuple(ordered[:MAX_CHANGES]),
        omitted=max(0, len(ordered) - MAX_CHANGES), limitations=(_NOTE,),
        callers_listed_older=len(set(old.callers)), callers_listed_newer=len(set(new.callers)), **base)


def _by_match(snap: CallSnapshot) -> dict[str, tuple[list[Entry], list[Entry]]]:
    grouped: dict[str, tuple[list[Entry], list[Entry]]] = {}
    for entry in snap.data.entries:
        older, newer = grouped.setdefault(entry.match_id, ([], []))
        (older if entry.side == 'older' else newer).append(entry)
    return grouped


def compute_delta(snap: CallSnapshot, match_id: str, ctx: DeltaContext | None = None) -> CallDelta:
    grouped = _by_match(snap).get(match_id)
    if grouped is None:
        raise GraphError('PT-GRAPH-INPUT', 'unknown match id')
    return _delta(snap, ctx or DeltaContext(), match_id, *grouped)


def compute_deltas(snap: CallSnapshot, ctx: DeltaContext | None = None,
                   cancel: CancelCheck = None) -> tuple[CallDelta, ...]:
    """Deltas of every emitted pair with a function on both sides, in emission order."""
    ctx = ctx or DeltaContext()
    grouped = _by_match(snap)
    out = []
    for count, pair in enumerate(snap.data.pairs):
        if cancel is not None and count % CANCEL_CLAIM_INTERVAL == 0 and cancel():
            raise GraphError('PT-GRAPH-CANCEL', 'cancelled')
        if pair.older and pair.newer and pair.match_id in grouped:
            out.append(_delta(snap, ctx, pair.match_id, *grouped[pair.match_id]))
    return tuple(out)
