"""API-hint lookups: a callee import matched against patch-rule hints (a search aid, never a finding)."""
from __future__ import annotations

from collections.abc import Iterable
from typing import NamedTuple

from .contracts_delta import ApiHintPort, ApiHit
from .labels import api_variants, parse_external


class HintRule(NamedTuple):
    rule_id: str
    revision: str
    family: str
    apis: tuple[str, ...]


class RuleHints:
    """`ApiHintPort` over patch-rule `api_hints` lists."""

    def __init__(self, rules: Iterable[HintRule]) -> None:
        self._by_api: dict[str, list[ApiHit]] = {}
        for rule in rules:
            for api in rule.apis:
                self._by_api.setdefault(api, []).append(
                    ApiHit(api=api, rule_id=rule.rule_id, rule_revision=rule.revision, family=rule.family,
                           via='rule-hint'))

    def hints(self, name: str) -> tuple[ApiHit, ...]:
        return tuple(self._by_api.get(name, ()))


def api_hits(port: ApiHintPort | None, label: str) -> tuple[ApiHit, ...]:
    """Hits for an import label, trying the A/W-stripped and ordinal spellings; deduplicated, order kept."""
    parsed = parse_external(label)
    if port is None or parsed is None:
        return ()
    hits: dict[tuple[str, str, str], ApiHit] = {}
    for variant in api_variants(parsed.name, parsed.library):
        for hit in port.hints(variant):
            hits.setdefault((hit.api, hit.rule_id, hit.rule_revision), hit)
    return tuple(hits.values())
