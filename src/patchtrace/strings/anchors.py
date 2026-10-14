"""Advisory anchors joined to a strings delta (spec WB3 s4, WB3-S6). Pure: no Qt, no I/O.

An anchor is a search hint taken from an advisory (`AnchorSet`). A hit says only that a string equals or contains
the hint; its strength is fixed at `anchor`, it never changes the review tier, and it makes no vulnerability claim.
Matching reads the escaped display text, so a redacted secret can never match.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..enrichment.identity import domain_id
from ..intelligence.contracts import Anchor, AnchorSet
from .contracts import AnchorJoin, MatchKind, StringAnchorHit, StringChange, StringsDelta
from .cues import ADVISORY_MIN_LENGTH
from .limits import MAX_ANCHORS

_KINDS = frozenset({'string', 'api', 'module', 'pdb', 'feature'})


@dataclass(frozen=True, slots=True)
class AnchorTerms:
    """What the cue layer needs from the anchors (`CueContext.api_hints` and `.advisory_phrases`)."""
    api_hints: frozenset[str] = frozenset()
    advisory_phrases: tuple[str, ...] = ()


def usable(anchors: AnchorSet | None) -> tuple[Anchor, ...]:
    """The anchors that can match a string, at most `MAX_ANCHORS`, in a stable order."""
    if anchors is None:
        return ()
    return tuple(sorted((a for a in anchors.anchors if a.kind in _KINDS), key=lambda a: a.anchor_id)[:MAX_ANCHORS])


def terms(anchors: AnchorSet | None) -> AnchorTerms:
    found = usable(anchors)
    return AnchorTerms(
        api_hints=frozenset(a.value for a in found if a.kind == 'api'),
        advisory_phrases=tuple(dict.fromkeys(a.value.casefold() for a in found if a.kind == 'string')))


def _match(anchor: Anchor, text: str, folded: str, cues: Sequence[str]) -> MatchKind | None:
    value, value_folded = anchor.value, anchor.value.casefold()
    if anchor.kind == 'pdb':
        return 'substring' if 'pdb-path' in cues and value_folded in folded else None
    if text == value:
        return 'import-equal' if anchor.kind == 'api' and 'api-name' in cues else 'exact'
    if folded == value_folded:
        return 'casefold'
    if anchor.kind == 'module':
        return 'casefold' if folded.endswith(('\\' + value_folded, '/' + value_folded)) else None
    if anchor.kind == 'string' and len(value) >= ADVISORY_MIN_LENGTH and value_folded in folded:
        return 'substring'
    return None


def _hit(anchor: Anchor, match: MatchKind, change: StringChange) -> StringAnchorHit:
    return StringAnchorHit(
        anchor_id=anchor.anchor_id, kind=anchor.kind, match=match, string_id=change.value_sha256,
        presence_older=change.older is not None, presence_newer=change.newer is not None, links=change.links,
        lineage_group=change.links[0].lineage_group if change.links else f'bytes:{change.value_sha256}')


def join_anchors(delta: StringsDelta, anchors: AnchorSet | None) -> AnchorJoin:
    """Every anchor/string pair that matches. A secret-like string is skipped: its display is not the value."""
    found = usable(anchors)
    if not found:
        return AnchorJoin()
    haystack = [(c, c.display, c.display.casefold()) for c in delta.changes if 'secret-like' not in c.cues]
    hits = []
    for anchor in found:
        for change, text, folded in haystack:
            match = _match(anchor, text, folded, change.cues)
            if match:
                hits.append(_hit(anchor, match, change))
    hits.sort(key=lambda h: (h.anchor_id, h.string_id))
    digest = domain_id('strings-anchors', 1, [a.anchor_id for a in found])
    return AnchorJoin(digest=digest, hits=tuple(hits[:MAX_ANCHORS * 8]))


def attach_anchors(delta: StringsDelta, anchors: AnchorSet | None) -> StringsDelta:
    """`delta` with its `anchors` filled in; a delta that is not comparable has nothing to join."""
    if not delta.comparable or anchors is None:
        return delta
    return delta.model_copy(update={'anchors': join_anchors(delta, anchors)})
