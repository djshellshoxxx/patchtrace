"""Pure helpers over rule features: separation, escaping, canonical order, stable toggle ids (plan s7).

A feature separates the builds only when it is present in exactly one of them; a side that could not be read
(missing, truncated) makes the answer `unknown`, never `neither`.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence

from .contracts import BytesFeature, Feature, ImportFeature, Separation, Side, StringFeature

SIDE_ONLY: dict[Side, Separation] = {'older': 'older-only', 'newer': 'newer-only'}
_KIND_ORDER = {'bytes': 0, 'string': 1, 'import': 2, 'capability': 3}
_NAMED_ESCAPES = {ord('\\'): '\\\\', ord('"'): '\\"', ord('\t'): '\\t', ord('\n'): '\\n', ord('\r'): '\\r'}


def separation_of(in_older: bool | None, in_newer: bool | None) -> Separation:
    """None means the side could not say."""
    if in_older is None or in_newer is None:
        return 'unknown'
    if in_older and in_newer:
        return 'both'
    if in_older or in_newer:
        return SIDE_ONLY['older' if in_older else 'newer']
    return 'neither'


def escape_text(raw: bytes) -> str | None:
    """YARA text-string escaped form of ASCII bytes; None for any byte outside ASCII (no lossy conversion)."""
    out: list[str] = []
    for byte in raw:
        if byte >= 0x80:
            return None
        if byte in _NAMED_ESCAPES:
            out.append(_NAMED_ESCAPES[byte])
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f'\\x{byte:02x}')
    return ''.join(out)


def feature_id(feature: Feature) -> str:
    """Stable id of a feature for toggling; the same fact keeps its id across revisions."""
    if isinstance(feature, BytesFeature):
        return f'bytes:{feature.side}:{feature.window_rva:x}:{feature.length}'
    if isinstance(feature, StringFeature):
        return f'string:{feature.side}:{feature.value_sha256}:{feature.encoding}'
    if isinstance(feature, ImportFeature):
        symbol = feature.name if feature.name is not None else f'#{feature.ordinal}'
        return f'import:{feature.dll.lower()}!{symbol}'
    return f'capability:{feature.rule_id}:{feature.separation}'


def _rank(feature: Feature) -> tuple:
    if isinstance(feature, BytesFeature):
        return (-feature.literal, feature.window_rva)
    if isinstance(feature, StringFeature):
        return (-feature.length, feature.text, feature.encoding)
    if isinstance(feature, ImportFeature):
        return (feature.dll.lower(), feature.name or '', feature.ordinal or 0)
    return (feature.namespace, feature.rule_id)


def canonical(features: Iterable[Feature]) -> tuple[Feature, ...]:
    """Kind order, then a total order inside the kind: the result never depends on the input order."""
    unique = {feature_id(f): f for f in features}
    return tuple(sorted(unique.values(), key=lambda f: (_KIND_ORDER[f.kind], _rank(f), feature_id(f))))


def owned_by(direction: Side, feature: Feature) -> bool:
    """A rule for `direction` may use features present in that build only."""
    return feature.separation == SIDE_ONLY[direction]


def with_included(features: Sequence[Feature], included: frozenset[str]) -> tuple[Feature, ...]:
    return tuple(f.model_copy(update={'included': feature_id(f) in included}) for f in features)


def included_ids(features: Iterable[Feature]) -> frozenset[str]:
    return frozenset(feature_id(f) for f in features if f.included)
