"""Capability hints for the hypothesis engine (CAP-7, contract `capability-hints/1`). Pure: no Qt, no I/O.

Joins gained or lost capabilities in a matched function pair to the patch hypotheses of an advisory and returns
`MechanismContext` records. Context only: a context can add a line to a detail pane, never a confidence, a rank or a
contradiction. capa describes behaviours, so most weakness families (memory safety, lifetime, integer, input, race)
have no honest tag and the absence of a capability change says nothing about any hypothesis.

Two joins, strongest first: (1) a matched `api` feature equal (after `api_key`) to a hypothesis `api_hint`;
(2) the capability's namespace under a hint whose tag the hypothesis family lists in `FAMILY_TAGS`.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import Field

from ..contracts import HypothesisSet, PatchHypothesis
from .capa_pairs import PairChange
from .common import _Strict

CONTRACT = 'capability-hints/1'
TAGS = ('file-access', 'process-launch', 'dynamic-linking', 'privilege-identity', 'crypto-primitive')
Tag = Literal['file-access', 'process-launch', 'dynamic-linking', 'privilege-identity', 'crypto-primitive']
LIMITATIONS = ('Context only: capa rules describe behaviours, not weaknesses, and a gained or lost behaviour is '
               'not evidence that the weakness is present or fixed.',
               'The capability-to-weakness hint table is unvalidated.',
               'A missing capability change says nothing about the hypothesis.')
DEFAULT_LINEAGE = ('D_capa_rules',)
_JOINABLE = ('gained', 'lost')


class Hint(_Strict):
    id: str = Field(pattern=r'^H-[A-Z0-9-]{1,40}$')
    namespace_prefix: str = Field(min_length=1, max_length=128)
    tag: Tag
    note: str = Field(min_length=1, max_length=200)


# Every prefix must resolve in the committed rules inventory (`test_every_hint_resolves_in_pinned_inventory`). The
# proposed process-launch, privilege-identity and crypto-primitive prefixes and `load-code/*` did not resolve in the
# only inventory available (derived from capa results, not the full rule pack) and are left out until a complete
# inventory can confirm them; an invented namespace would be a false claim.
HINTS: tuple[Hint, ...] = (
    Hint(id='H-FILE-SYSTEM', namespace_prefix='host-interaction/file-system', tag='file-access',
         note='the function now or no longer performs file system operations'),
    Hint(id='H-RUNTIME-LINKING', namespace_prefix='linking/runtime-linking', tag='dynamic-linking',
         note='the function now or no longer resolves code at runtime'),
)
FAMILY_TAGS: dict[str, tuple[Tag, ...]] = {
    'path': ('file-access',),
    'search-path': ('dynamic-linking', 'file-access'),
}


class ContextObservation(_Strict):
    observation_key: str = Field(max_length=64)   # the `capobs/1` key of the pair change
    rule_id: str = Field(max_length=256)
    namespace: str | None = Field(default=None, max_length=256)
    scope: str = Field(max_length=16)
    change: Literal['gained', 'lost']


class MechanismContext(_Strict):
    contract: Literal['capability-hints/1'] = CONTRACT
    hypothesis_id: str = Field(min_length=64, max_length=64)
    rule_id: str = Field(pattern=r'^R-[A-Z0-9-]{1,40}$')   # the hypothesis rule, not a capa rule
    group_id: str = Field(max_length=160)
    observations: tuple[ContextObservation, ...] = Field(min_length=1, max_length=64)
    api_hint_hits: tuple[str, ...] = Field(default=(), max_length=64)
    hint_ids: tuple[str, ...] = Field(default=(), max_length=16)
    support: Literal['context'] = 'context'
    lineage: tuple[str, ...] = Field(default=DEFAULT_LINEAGE, max_length=8)
    limitations: tuple[str, ...] = LIMITATIONS


def api_key(name: str) -> str:
    """Join key for an API name: lower case, no module prefix, trailing A/W folded when >= 4 characters remain."""
    key = name.strip().lower().rsplit('.', 1)[-1].rsplit('!', 1)[-1]
    return key[:-1] if len(key) >= 5 and key[-1] in 'aw' else key


def _under(namespace: str | None, prefix: str) -> bool:
    return namespace is not None and (namespace == prefix or namespace.startswith(prefix + '/'))


def _side_apis(row: PairChange) -> set[str]:
    """API keys on the side where the behaviour exists: the newer side when gained, the older when lost."""
    cell = row.newer if row.change == 'gained' else row.older
    return {api_key(feature.value) for feature in cell.features if feature.kind == 'api'}


def _eligible(row: PairChange) -> bool:
    return (row.kind == 'capability' and row.change in _JOINABLE and row.noise == 'none'
            and row.relocation == 'none' and row.category != 'unchanged')


def _joins(hypothesis: PatchHypothesis, row: PairChange) -> tuple[list[str], list[str]]:
    """(api hints hit, ids of the tag hints matched) for one row."""
    apis = _side_apis(row)
    hits = [hint for hint in hypothesis.api_hints if api_key(hint) in apis]
    tags = FAMILY_TAGS.get(hypothesis.family, ())
    ids = [hint.id for hint in HINTS if hint.tag in tags and _under(row.namespace, hint.namespace_prefix)]
    return hits, ids


def capability_context(hypotheses: HypothesisSet, observations: Iterable[PairChange], *,
                       lineage: tuple[str, ...] = DEFAULT_LINEAGE) -> tuple[MechanismContext, ...]:
    """One context per hypothesis and matched pair that has at least one joined gained or lost capability."""
    rows = [row for row in observations if _eligible(row)]
    contexts: list[MechanismContext] = []
    for hypothesis in hypotheses.hypotheses:
        grouped: dict[str, list[tuple[PairChange, list[str], list[str]]]] = {}
        for row in rows:
            hits, ids = _joins(hypothesis, row)
            if hits or ids:
                grouped.setdefault(row.group_id, []).append((row, hits, ids))
        for group_id, found in grouped.items():
            found.sort(key=lambda item: (item[0].namespace or '', item[0].rule_id, item[0].scope, item[0].change))
            contexts.append(MechanismContext(
                hypothesis_id=hypothesis.hypothesis_id, rule_id=hypothesis.rule_id, group_id=group_id,
                observations=tuple(ContextObservation(
                    observation_key=row.observation_key, rule_id=row.rule_id, namespace=row.namespace,
                    scope=row.scope, change=row.change) for row, _, _ in found),
                api_hint_hits=tuple(sorted({hit for _, hits, _ in found for hit in hits})),
                hint_ids=tuple(sorted({hint for _, _, ids in found for hint in ids})), lineage=lineage))
    contexts.sort(key=lambda c: (c.rule_id, c.group_id, c.hypothesis_id))
    return tuple(contexts)
