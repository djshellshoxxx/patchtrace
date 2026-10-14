"""Rule candidates from strings, imports and capabilities (R3; bytes windows join in R4). Pure: no Qt, no I/O.

One candidate per direction the pair has a function for. A rule for `older` may use only what the older build alone has (plus the imports that
a lost capability's APIs resolve to, as positive gates); `newer` mirrors it. Nothing is generated from a pair that is
neither reviewed material nor confirmed by the analyst. The rule text comes from a `RuleWriter` (the closed-grammar
synthesizer); a toggle is a new revision with the same lineage, never free text. A source that returns nothing
yields fewer features, never a negative vote.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol

from ..enrichment.identity import domain_id
from .contracts import (
    BytesFeature,
    CapabilityFeature,
    EngineStamp,
    Feature,
    ImportFeature,
    PairSource,
    RuleCandidate,
    Side,
    StringFeature,
    text_sha256,
)
from .errors import RulesError
from .features import canonical, feature_id, owned_by, with_included
from .gates import evaluate, regate
from .limits import LIMITS, RuleLimits
from .ports import CapabilitySource, ImportSource, StringSource

DIRECTIONS: tuple[Side, ...] = ('older', 'newer')


class RuleWriter(Protocol):
    def __call__(self, pair: PairSource, *, direction: Side, rule_name: str, features: Sequence[Feature]) -> str:
        """Rule text for the included features (canonical order). Raises `RulesError` when it cannot serialize."""
        ...


def _gate_names(capabilities: Iterable[CapabilityFeature]) -> frozenset[str]:
    return frozenset(name.lower() for c in capabilities for name in c.api_gates)


def _names_api(name: str, gate_names: frozenset[str]) -> bool:
    """capa names `CreateFile` for the import `CreateFileW`."""
    lowered = name.lower()
    return lowered in gate_names or (lowered[-1:] in ('a', 'w') and lowered[:-1] in gate_names)


def _eligible(direction: Side, feature: Feature, gate_names: frozenset[str]) -> bool:
    if isinstance(feature, ImportFeature) and feature.origin == 'capa-api':
        # the API is called in this build: a positive gate, whether or not the other build imports it too
        return _names_api(feature.name or '', gate_names) and (owned_by(direction, feature) or
                                                                feature.separation == 'both')
    return owned_by(direction, feature)


def _defaults(features: Sequence[Feature], limits: RuleLimits) -> frozenset[str]:
    """Byte windows and capa API gates are on; text is on when nothing else anchors the rule, or when xref-linked."""
    has_bytes = any(isinstance(f, BytesFeature) for f in features)
    on: set[str] = set()
    texts = 0
    for feature in features:
        if isinstance(feature, StringFeature):
            if (feature.linked_by == 'xref' or not has_bytes) and texts < limits.text_patterns_v1:
                texts += 1
                on.add(feature_id(feature))
        elif isinstance(feature, BytesFeature) or (isinstance(feature, ImportFeature) and feature.origin == 'capa-api'):
            on.add(feature_id(feature))
    return frozenset(on)


def _bound(features: Sequence[Feature], included: frozenset[str], limits: RuleLimits) -> tuple[Feature, ...]:
    """At most `2 * patterns_per_rule` features are offered; the included ones are never the ones dropped."""
    room = limits.patterns_per_rule * 2
    kept = [f for f in features if feature_id(f) in included]
    kept += [f for f in features if feature_id(f) not in included][:max(0, room - len(kept))]
    return canonical(kept)


def _check_selection(features: Sequence[Feature], included: frozenset[str], limits: RuleLimits) -> None:
    known = {feature_id(f) for f in features}
    if not included <= known:
        raise RulesError('PT-RULE-INPUT', 'a selected feature is not part of this candidate')
    chosen = [f for f in features if feature_id(f) in included]
    if sum(isinstance(f, StringFeature) for f in chosen) > limits.text_patterns_v1:
        raise RulesError('PT-RULE-LIMIT', f'at most {limits.text_patterns_v1} text patterns per rule')
    if sum(isinstance(f, BytesFeature) for f in chosen) > limits.hex_patterns_v1:
        raise RulesError('PT-RULE-LIMIT', f'at most {limits.hex_patterns_v1} byte pattern per rule')
    if len(chosen) > limits.patterns_per_rule:
        raise RulesError('PT-RULE-LIMIT', f'at most {limits.patterns_per_rule} features per rule')


def lineage_id(pair: PairSource, direction: Side) -> str:
    return domain_id('rule-lineage', 1, {'project': pair.project_id, 'older': pair.older_sha256,
                                         'newer': pair.newer_sha256, 'match': pair.match_id,
                                         'direction': direction})


def _candidate_id(lineage: str, pair: PairSource, features: Sequence[Feature], engine: EngineStamp,
                  limits: RuleLimits) -> str:
    return domain_id('rule-candidate', 1, {
        'lineage': lineage, 'run': pair.run_id, 'features': [[feature_id(f), f.included] for f in features],
        'grammar': engine.grammar, 'decoder': [engine.decoder, engine.decoder_version],
        'engine': engine.version, 'limits': limits.digest()})


def _build(pair: PairSource, direction: Side, features: Sequence[Feature], gates, engine: EngineStamp,
           writer: RuleWriter, limits: RuleLimits) -> RuleCandidate:
    lineage = lineage_id(pair, direction)
    name = f'PT_{lineage[:12]}_{direction}'
    text = writer(pair, direction=direction, rule_name=name, features=[f for f in features if f.included])
    return RuleCandidate(
        candidate_id=_candidate_id(lineage, pair, features, engine, limits), lineage_id=lineage,
        direction=direction, source=pair, features=tuple(features), rule_name=name, rule_text=text,
        rule_sha256=text_sha256(text), gates=gates, engine=engine, unvetted=pair.materiality != 'material')


def propose(pair: PairSource, *, writer: RuleWriter, engine: EngineStamp, strings: StringSource | None = None,
            capabilities: CapabilitySource | None = None, imports: ImportSource | None = None,
            flag_codes: Iterable[str] = (), secrets_excluded: int = 0,
            limits: RuleLimits = LIMITS) -> tuple[RuleCandidate, ...]:
    if pair.materiality != 'material' and not pair.analyst_confirmed_material:
        raise RulesError('PT-RULE-INPUT', 'the pair is neither reviewed as material nor confirmed by the analyst')
    flag_codes = tuple(flag_codes)
    found: list[Feature] = [
        *(strings.string_features(pair) if strings else ()),
        *(capabilities.capability_features(pair) if capabilities else ()),
        *(imports.import_features(pair) if imports else ())]
    candidates = []
    for direction in DIRECTIONS:
        if getattr(pair, direction) is None:
            continue   # an added function has no older body to describe, a removed one no newer body
        names = _gate_names(c for c in found if isinstance(c, CapabilityFeature) and owned_by(direction, c))
        own = canonical(f for f in found if _eligible(direction, f, names))
        included = _defaults(own, limits)
        if not included:
            continue   # nothing anchors a rule in this build: offer no empty candidate
        features = with_included(_bound(own, included, limits), included)
        gates = evaluate(pair, features, secrets_excluded=secrets_excluded, flag_codes=flag_codes)
        candidates.append(_build(pair, direction, features, gates, engine, writer, limits))
    return tuple(candidates)


def recompose(candidate: RuleCandidate, included: Iterable[str], *, writer: RuleWriter,
              limits: RuleLimits = LIMITS) -> RuleCandidate:
    """A revision with another feature selection: same lineage, gates re-run, scan and compile results reset."""
    chosen = frozenset(included)
    _check_selection(candidate.features, chosen, limits)
    features = with_included(candidate.features, chosen)
    return _build(candidate.source, candidate.direction, features, regate(candidate.gates, features),
                  candidate.engine, writer, limits)
