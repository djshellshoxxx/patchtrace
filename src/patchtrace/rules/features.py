"""Features of a rule candidate (YRX-integration-plan section 7, candidate generation steps 3 and 4): the observations that
cross the ports become contract features here, and the canonical order that makes a candidate reproducible lives here.

Pure: no I/O, no engine, no Qt. Everything an adapter returns is untrusted: one bad observation is counted in `notes` and
dropped, it never fails the proposal and never reaches rule text. Strings are carried only as the escaped form the
contract validates, built from the exact bytes the adapter re-read from the verified artifact (the SPEC-29 display form
is escaped and bounded for people and can never seed a pattern). A string that looks like a secret is dropped before it
is converted, whatever the adapter said.

Notes are counters like `string-secret:1`: a feature that was left out is reported, never silently lost, so "nothing
offered" can be told apart from "something was held back".
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass

from pydantic import ValidationError

from .contracts import (
    ApiRef,
    BytesFeature,
    CapabilityFeature,
    Feature,
    ImportFeature,
    StringFeature,
)
from .limits import DEFAULT_LIMITS, RuleLimits
from .ports import CapabilityObservation, ImportEntry, ImportTable, StringObservation

# Imports that differ between the builds but are not tied to the pair by a capability or a call pin are offered unticked;
# a real build can differ in hundreds of imports, which is inventory, not delta.
OFFERED_IMPORTS = 16
ATTACK_IDS = 16     # the contract's ceilings, applied before validation so a long list is cut, not refused
API_GATES = 8
_KIND_RANK = {BytesFeature: 0, StringFeature: 1, ImportFeature: 2, CapabilityFeature: 3}
_OPPOSITE = {'older': 'newer', 'newer': 'older'}
_ESCAPES = tuple({0x22: '\\"', 0x5C: '\\\\', 0x0A: '\\n', 0x0D: '\\r', 0x09: '\\t'}.get(
    byte, chr(byte) if 0x20 <= byte <= 0x7E else f'\\x{byte:02x}') for byte in range(256))
_UNESCAPE = re.compile(r'\\(["\\nrt]|x[0-9A-Fa-f]{2})|(.)', re.DOTALL)
_SIMPLE = {'"': 0x22, '\\': 0x5C, 'n': 0x0A, 'r': 0x0D, 't': 0x09}


@dataclass(frozen=True)
class Built:
    """Features converted from one channel, in canonical order, and what was held back (`reason:count`, sorted)."""
    features: tuple[Feature, ...] = ()
    notes: tuple[str, ...] = ()


def _notes(counter: Counter) -> tuple[str, ...]:
    return tuple(f'{reason}:{count}' for reason, count in sorted(counter.items()))


# --- escaping --------------------------------------------------------------------------------------------------------

def escape_text(data: bytes) -> str:
    """Exact bytes -> the escaped form `StringFeature.text` holds: printable ASCII as is; the quote, the backslash and
    every byte outside printable ASCII escaped, so the text can never close the string or add a line to a rule."""
    return ''.join(_ESCAPES[byte] for byte in data)


def unescape_text(text: str) -> bytes:
    """Inverse of `escape_text` (the bytes a stored `StringFeature.text` stands for)."""
    out = bytearray()
    for match in _UNESCAPE.finditer(text):
        token, plain = match.groups()
        if plain is not None:
            out.append(ord(plain))
        else:
            out.append(_SIMPLE[token] if token in _SIMPLE else int(token[1:], 16))
    return bytes(out)


# --- strings ---------------------------------------------------------------------------------------------------------

def _pattern_bytes(observation: StringObservation) -> bytes | None:
    """The bytes of the text pattern. `wide` data is UTF-16LE: only code points up to U+00FF can be written as an escaped
    one-byte-per-character pattern with the `wide` modifier, so anything else is not offered."""
    data = observation.data
    if observation.encoding != 'wide':
        return data
    if len(data) % 2 or any(data[1::2]):
        return None
    return data[0::2]


def string_features(observations: Iterable[StringObservation], *, limits: RuleLimits = DEFAULT_LIMITS,
                    detect_secret: Callable[[str], str | None] | None = None) -> Built:
    """One feature per distinct (side, string, encoding), lowest offset first. `detect_secret(text) -> kind | None` is the
    second line of defence after the adapter's own `secret_kind`."""
    notes: Counter = Counter()
    found: dict[tuple, StringFeature] = {}
    for item in sorted(observations, key=lambda o: (o.side, o.offset, o.value_sha256, o.encoding)):
        key = (item.side, item.value_sha256, item.encoding)
        if key in found:
            continue
        if item.secret_kind:
            notes['string-secret'] += 1
            continue
        pattern = _pattern_bytes(item)
        if pattern is None:
            notes['string-not-expressible'] += 1
            continue
        if not pattern:  # the adapter could not re-read and verify the bytes: the tool's claim alone seeds nothing
            notes['string-unverified'] += 1
            continue
        if len(pattern) > limits.text_pattern_bytes:
            notes['string-size'] += 1
            continue
        if detect_secret is not None and detect_secret(pattern.decode('latin-1')):
            notes['string-secret'] += 1
            continue
        if item.separation == f'{_OPPOSITE[item.side]}-only':
            notes['string-contradiction'] += 1
            continue
        try:
            found[key] = StringFeature(
                included=False, side=item.side, value_sha256=item.value_sha256, length=len(pattern),
                text=escape_text(pattern), encoding=item.encoding, offset=item.offset,
                evidence_run_id=item.evidence_run_id, linked_by=item.linked_by, separation=item.separation)
        except ValidationError:
            notes['string-invalid'] += 1
    return Built(canonical_order(found.values()), _notes(notes))


# --- imports ---------------------------------------------------------------------------------------------------------

def import_key(item: ImportEntry | ImportFeature) -> tuple[str, str]:
    """Identity of an import for comparison: the loader compares DLL names case-insensitively; an ordinal reads `#N`."""
    return item.dll.lower(), item.name if item.name is not None else f'#{item.ordinal}'


def _table(table: ImportTable | None) -> dict[tuple[str, str], ImportEntry]:
    return {} if table is None else {import_key(entry): entry for entry in table.entries}


def import_features(older: ImportTable | None, newer: ImportTable | None,
                    referenced: Collection[tuple[str, str]] = ()) -> Built:
    """The import delta, plus the imports a capability points at even when both builds have them (shown, never
    included). A build whose table is unavailable (`None`) cannot say "absent": what the other build has is `unknown`,
    never `only` it. `referenced` holds `import_key`s and is always kept; the rest is capped at `OFFERED_IMPORTS` per
    side."""
    old, new = _table(older), _table(newer)
    chosen: list[ImportFeature] = []
    notes: Counter = Counter()
    offered: Counter = Counter()
    for key in sorted(set(old) | set(new)):
        if key in old and key in new:
            if key not in referenced:
                continue
            entry, separation, side = old[key], 'both-sides', 'both'
        elif key in old:
            entry, separation, side = old[key], 'older-only' if newer is not None else 'unknown', 'older'
        else:
            entry, separation, side = new[key], 'newer-only' if older is not None else 'unknown', 'newer'
        if key not in referenced:
            offered[side] += 1
            if offered[side] > OFFERED_IMPORTS:
                notes['imports-not-offered'] += 1
                continue
        try:
            chosen.append(ImportFeature(included=False, dll=entry.dll, name=entry.name, ordinal=entry.ordinal,
                                        delay=entry.delay, origin='pe-imports', separation=separation))
        except ValidationError:
            notes['import-invalid'] += 1
    return Built(canonical_order(chosen), _notes(notes))


# --- capabilities ----------------------------------------------------------------------------------------------------

def capability_features(observations: Iterable[CapabilityObservation]) -> Built:
    """Capabilities that appeared or disappeared with the changed function. They become metadata and import gates, never
    a condition on their own (plan s4)."""
    notes: Counter = Counter()
    found: dict[tuple[str, str], CapabilityFeature] = {}
    for item in sorted(observations, key=lambda o: (o.rule_id, o.classification)):
        key = (item.rule_id, item.classification)
        if key in found:
            continue
        gates = sorted({(g.dll, g.name) for g in item.api_gates})[:API_GATES]
        try:
            found[key] = CapabilityFeature(
                included=False, rule_id=item.rule_id, namespace=item.namespace,
                attack=tuple(sorted(set(item.attack)))[:ATTACK_IDS], classification=item.classification,
                api_gates=tuple(ApiRef(dll=dll, name=name) for dll, name in gates),
                separation='newer-only' if item.classification == 'newly-introduced' else 'older-only')
        except ValidationError:
            notes['capability-invalid'] += 1
    return Built(canonical_order(found.values()), _notes(notes))


def referenced_imports(capabilities: Iterable[Feature]) -> frozenset[tuple[str, str]]:
    """`import_key`s of the APIs the capabilities gate on."""
    return frozenset((gate.dll.lower(), gate.name) for feature in capabilities
                     if isinstance(feature, CapabilityFeature) for gate in feature.api_gates)


# --- order and identity ----------------------------------------------------------------------------------------------

def _sort_key(feature: Feature) -> tuple:
    if isinstance(feature, BytesFeature):
        return _KIND_RANK[BytesFeature], feature.side, feature.window_rva, feature.length
    if isinstance(feature, StringFeature):
        return _KIND_RANK[StringFeature], feature.side, feature.offset, feature.value_sha256, feature.encoding
    if isinstance(feature, ImportFeature):
        return (_KIND_RANK[ImportFeature], feature.dll.lower(), feature.name or '', feature.ordinal or 0,
                feature.delay)
    return _KIND_RANK[CapabilityFeature], feature.rule_id, feature.classification


def canonical_order(features: Iterable[Feature]) -> tuple[Feature, ...]:
    """Kind (bytes, strings, imports, capabilities), then a stable key: the same facts give the same candidate however
    the ports ordered them."""
    return tuple(sorted(features, key=_sort_key))


def feature_identity(feature: Feature) -> dict:
    """What makes a feature *that* feature, without its `included` flag or provenance (it enters candidate ids)."""
    if isinstance(feature, BytesFeature):
        return {'kind': 'bytes', 'side': feature.side, 'rva': feature.window_rva, 'pattern': feature.pattern,
                'pins': [[p.disp_offset, p.end_offset, p.dll.lower(), p.name] for p in feature.pins]}
    if isinstance(feature, StringFeature):
        return {'kind': 'string', 'side': feature.side, 'sha256': feature.value_sha256, 'encoding': feature.encoding}
    if isinstance(feature, ImportFeature):
        return {'kind': 'import', 'dll': feature.dll.lower(), 'name': feature.name, 'ordinal': feature.ordinal,
                'delay': feature.delay}
    return {'kind': 'capability', 'rule': feature.rule_id, 'classification': feature.classification}


def with_included(feature: Feature, value: bool) -> Feature:
    return feature if feature.included is value else feature.model_copy(update={'included': value})
