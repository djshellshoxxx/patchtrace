"""Ghidriff's raw `matches` object as label and address maps (unchanged pairs the normalized run omits)."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, NamedTuple

from ..enrichment.identity import parse_address
from .contracts import RawMatchesReader
from .limits import GraphError
from .text import sanitize

Target = tuple[str, str]  # (partner label, first match type)
AddressTarget = tuple[int, str]
_EXTERNAL = 'EXTERNAL:'


class RawMatches(NamedTuple):
    names: Mapping[str, tuple[Target, ...]]  # older label -> newer labels
    addresses: Mapping[int, tuple[AddressTarget, ...]]  # older address -> newer addresses
    reverse_names: Mapping[str, tuple[Target, ...]]
    reverse_addresses: Mapping[int, tuple[AddressTarget, ...]]


class RawMatchesResult(NamedTuple):
    matches: RawMatches | None
    status: Literal['ok', 'absent', 'degraded']
    notes: tuple[str, ...]


def _targets(value: object, what: str) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        raise GraphError('PT-GRAPH-SOURCE', f'raw matches.{what} entry must be a list of [target, [types]]')
    out = []
    for item in value:
        if (not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str)
                or not isinstance(item[1], list) or not all(isinstance(t, str) for t in item[1])):
            raise GraphError('PT-GRAPH-SOURCE', f'raw matches.{what} target must be [target, [match types]]')
        out.append((item[0], item[1][0] if item[1] else ''))
    return out


def _table(raw: object, what: str) -> dict[str, list[tuple[str, str]]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise GraphError('PT-GRAPH-SOURCE', f'raw matches.{what} must be an object')
    return {key: _targets(value, what) for key, value in raw.items()}


def _reverse(forward: Mapping) -> dict:
    reverse: dict = {}
    for source, targets in forward.items():
        for target, kind in targets:
            reverse.setdefault(target, []).append((source, kind))
    return {key: tuple(value) for key, value in reverse.items()}


def _addresses(raw: object) -> dict[int, tuple[AddressTarget, ...]]:
    table: dict[int, tuple[AddressTarget, ...]] = {}
    for key, targets in _table(raw, 'address_matches').items():
        # EXTERNAL:<hex> import locations are not functions of either image; a partial 1:N relation would
        # look 1:1, so an entry touching one is dropped whole (same rule as the N-way chain reader).
        if key.startswith(_EXTERNAL) or any(target.startswith(_EXTERNAL) for target, _ in targets):
            continue
        source = parse_address(key)
        parsed = [(parse_address(target), kind) for target, kind in targets]
        if source is None or any(address is None for address, _ in parsed):
            raise GraphError('PT-GRAPH-SOURCE', 'raw matches.address_matches has an unparsable address')
        table[source] = tuple((address, kind) for address, kind in parsed if address is not None)
    return table


def parse_raw_matches(raw: Mapping) -> RawMatches:
    names = {key: tuple(value) for key, value in _table(raw.get('name_matches'), 'name_matches').items()}
    addresses = _addresses(raw.get('address_matches'))
    return RawMatches(names, addresses, _reverse(names), _reverse(addresses))


def load_raw_matches(reader: RawMatchesReader | None, root: object, project: object) -> RawMatchesResult:
    """Read through the injected reader; a missing, tampered or malformed raw file degrades, never fails."""
    if reader is None:
        return RawMatchesResult(None, 'absent', ('no raw matches reader: pairing uses the emitted pairs only',))
    try:
        raw, notes = reader(root, project)
        parsed = None if raw is None else parse_raw_matches(raw)
    except Exception as exc:  # noqa: BLE001 - the injected reader raises its own error types (e.g. NwayError)
        note = f'raw matches unavailable ({sanitize(exc, 200)}): pairing uses the emitted pairs only'
        return RawMatchesResult(None, 'degraded', (note,))
    clean = tuple(sanitize(n, 300) for n in notes)
    return RawMatchesResult(parsed, 'absent' if parsed is None else 'ok', clean)
