"""A4 call groups: one callee shared by several changed pairs (a view; member rows stay listed)."""
from __future__ import annotations

from collections.abc import Iterable

from .contracts_delta import CallDelta, CallGroup, ChangeClass

MAX_GROUPS = 200  # GL-07
MIN_MEMBERS = 2
_GROUPED: frozenset[str] = frozenset({'call-to-new-function', 'added-call', 'removed-call'})


def build_groups(deltas: Iterable[CallDelta]) -> tuple[CallGroup, ...]:
    found: dict[tuple[str, ChangeClass], tuple[str, set[str], bool]] = {}
    for delta in deltas:
        if delta.state != 'compared':
            continue
        for change in delta.changes:
            if change.cls not in _GROUPED:
                continue
            removed = change.cls == 'removed-call'
            node = change.older_node if removed else change.newer_node
            label = change.older_label if removed else change.newer_label
            if node is None or label is None:
                continue
            _, members, _ = found.setdefault((node, change.cls), (label, set(), 'hub' in change.flags))
            members.add(delta.match_id)
    groups = [CallGroup(callee=node, label=label, cls=cls, members=tuple(sorted(members)), hub=hub)
              for (node, cls), (label, members, hub) in found.items() if len(members) >= MIN_MEMBERS]
    groups.sort(key=lambda g: (g.hub, -len(g.members), g.label, g.callee))
    return tuple(groups[:MAX_GROUPS])
