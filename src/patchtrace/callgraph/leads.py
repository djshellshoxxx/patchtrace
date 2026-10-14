"""Graph leads: ordinal signals per changed function (7.4), kept as their own channel, never scored."""
from __future__ import annotations

from collections.abc import Iterable

from .blast import blast, entry_distance
from .contracts_delta import (
    CallDelta,
    CalleeChange,
    ClaimRef,
    EntryPort,
    GraphLead,
    GraphSignal,
    Origin,
    SignalId,
)
from .delta import lookup
from .limits import CancelCheck
from .snapshot import CallSnapshot
from .text import sanitize

MAX_SIGNALS = 50
_NAMES_SHOWN = 3
# id -> (rank, next step). Rank is a sort key and is never displayed.
_COPY: dict[SignalId, tuple[int, str]] = {
    'new-function-called': (1, 'Open the new function and read what it checks or does.'),
    'api-hint-called': (2, 'Read the call site. A hint is a search aid, not a finding.'),
    'import-called': (3, 'Read the call site and the arguments.'),
    'call-dropped': (4, 'Check whether the logic moved or was inlined.'),
    'known-function-called': (5, 'Compare how {name} is used by its other callers.'),
    'fan-in-context': (6, 'Check which callers are also in the change set.'),
    'hub-only': (7, 'Usually build plumbing; open it only if nothing else stands out.'),
}


def _names(labels: Iterable[str | None]) -> str:
    unique = sorted({sanitize(label, 120) for label in labels if label})
    shown = ', '.join(unique[:_NAMES_SHOWN])
    return shown if len(unique) <= _NAMES_SHOWN else f'{shown} and {len(unique) - _NAMES_SHOWN} more'


def _signal(signal_id: SignalId, meaning: str, record_id: str | None, field: str = 'callees',
            name: str = '') -> GraphSignal:
    rank, step = _COPY[signal_id]
    return GraphSignal(id=signal_id, rank=rank, meaning=sanitize(meaning, 400),
                       next_step=step.format(name=sanitize(name, 120)),
                       evidence=ClaimRef(record_id=record_id or '', field=field))  # type: ignore[arg-type]


def _signal_id(change: CalleeChange) -> SignalId | None:
    if change.cls == 'call-to-new-function':
        return 'new-function-called'
    if change.cls in {'removed-call', 'callee-deleted'}:
        return 'call-dropped'
    if change.cls != 'added-call':
        return None
    if change.api:
        return 'api-hint-called'
    return 'import-called' if 'import' in change.flags else 'known-function-called'


def signals_for(delta: CallDelta) -> tuple[GraphSignal, ...]:
    if delta.state != 'compared':
        return ()
    changed = [c for c in delta.changes if c.cls != 'same-link']
    out: list[GraphSignal] = []
    if delta.downgrade == 'hub-only':
        out.append(_signal('hub-only', f'Only hub calls changed: {_names(c.newer_label or c.older_label for c in changed)}',
                           delta.newer_function_id))
    else:
        out.extend(_change_signals(delta, changed))
    if delta.callers_listed_newer != delta.callers_listed_older:
        out.append(_signal('fan-in-context', f'Listed as called from {delta.callers_listed_newer} functions',
                           delta.newer_function_id, 'callers'))
    return tuple(sorted(out, key=lambda s: (s.rank, s.meaning))[:MAX_SIGNALS])


def _change_signals(delta: CallDelta, changed: list[CalleeChange]) -> list[GraphSignal]:
    out: list[GraphSignal] = []
    grouped: dict[SignalId, list[CalleeChange]] = {}
    for change in changed:
        signal_id = _signal_id(change)
        if signal_id is not None:
            grouped.setdefault(signal_id, []).append(change)
    for change in grouped.pop('api-hint-called', []):
        rules = ', '.join(sorted({h.rule_id for h in change.api}))
        families = ', '.join(sorted({h.family for h in change.api}))
        out.append(_signal('api-hint-called', f'Newly calls {sanitize(change.api[0].api, 120)}, listed by patch rule '
                           f'{rules} for {families}', delta.newer_function_id))
    for signal_id, items in grouped.items():
        newer = [c.newer_label for c in items]
        older = [c.older_label for c in items]
        if signal_id == 'new-function-called':
            text, record = f'Calls a function that exists only in the newer build: {_names(newer)}', delta.newer_function_id
        elif signal_id == 'import-called':
            note = ' (also new to the import table)' if any('newly-imported' in c.flags for c in items) else ''
            text, record = f'Newly calls the import {_names(newer)}{note}', delta.newer_function_id
        elif signal_id == 'call-dropped':
            text, record = f'No longer calls {_names(older)}, or it was deleted', delta.older_function_id
        else:
            text, record = f'Newly calls {_names(newer)}, present in both builds', delta.newer_function_id
        out.append(_signal(signal_id, text, record, name=_names(newer)))
    return out


def build_leads(snap: CallSnapshot, deltas: Iterable[CallDelta], entries: EntryPort | None = None,
                cancel: CancelCheck = None) -> tuple[GraphLead, ...]:
    """Leads for every delta with a signal, lowest signal rank first, ties by newer address then match id."""
    origin = Origin(engine=snap.source.source_id, run_id=snap.data.run_id, raw_sha256=snap.data.raw_sha256)
    addresses = {e.match_id: e.address for e in snap.data.side_entries('newer')}
    leads = []
    for delta in deltas:
        signals = signals_for(delta)
        if not signals:
            continue
        found = lookup(snap, 'newer', delta.newer_label) if delta.newer_label is not None else None
        node_id = found[1].id if found else None
        leads.append(GraphLead(
            match_id=delta.match_id, signals=signals, origin=origin,
            blast=blast(snap, 'newer', node_id, cancel) if node_id else None,
            entry=entry_distance(snap, 'newer', node_id, entries, cancel) if node_id else None))
    return tuple(sorted(leads, key=lambda lead: (
        lead.signals[0].rank, addresses.get(lead.match_id) is None, addresses.get(lead.match_id) or 0, lead.match_id)))
