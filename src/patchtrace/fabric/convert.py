"""Converters from the K and PIL records to fabric anchors (FAB-integration-plan.md s4, s9 FAB-2). Pure.

K (`intelligence.contracts.Anchor`) hints are published by the KB track as producer `kb`. PIL (`pilot.contracts.
PilotAnchor`) offers wanted names, strings, CWEs and CVEs, and candidate functions, as producer `pil`. Both records are
read structurally: importing those packages here would break this package's import rule. A record converts only when the
fabric can state it honestly: a candidate needs the pair record its key names, a PDB name needs the artifact identity it
was verified in, a JSON pointer needs the advisory document it points into. Anything else is refused with a typed error.

Origins come from the registry. Advisory text, the hypothesis rules (chosen by the advisory's classified CWE) and PIL's
wanted names, CWEs and CVEs share `advisory-text`; a verified PDB name is a PE self-report; a PIL candidate is the UE
pairing. The witness label is the phrase, name or PDB name the key is computed from. K's descriptive label is not kept,
and K's quality is the facet `basis`.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol

from pydantic import ValidationError

from . import ids, origins
from .contracts import Anchor, PairRef, Ref
from .limits import FabricError
from .ports import OriginRegistry

K_PRODUCER = 'kb'
PIL_PRODUCER = 'pil'
_ADVISORY = 'advisory-text'
_DEFAULT_REGISTRY = origins.DefaultOriginRegistry()


class KAnchorRecord(Protocol):
    """The fields of a K `intelligence` anchor that the conversion reads."""

    kind: str
    value: str
    source: str
    pointer: str | None
    quality: str


class PdbNameRecord(Protocol):
    name: str


class ArtifactIdentityRecord(Protocol):
    """The side, the input hash and the verified PDB name of one artifact (K `ArtifactIdentity`)."""

    side: str
    sha256: str
    pdb_identity: PdbNameRecord | None


class PilotAnchorRecord(Protocol):
    """A PIL offer (`pilot.contracts.PilotAnchor`)."""

    anchor_id: str
    kind: str
    label: str
    facets: tuple[tuple[str, str], ...]


# K kind -> fabric kind and role. A module, feature or component is an advisory phrase (facet `phrase_kind`).
_K_KINDS: Mapping[str, tuple[str, str]] = MappingProxyType({
    'module': ('advisory_phrase', 'stated'), 'feature': ('advisory_phrase', 'hint'),
    'component': ('advisory_phrase', 'hint'), 'string': ('string', 'hint'), 'api': ('import', 'hint'),
    'pdb': ('build_fact', 'observed')})
_PHRASE_KINDS = frozenset({'module', 'feature', 'component'})
# K source -> fabric source. The artifact identity is the PE's own self-report; everything else is advisory text.
_K_SOURCES: Mapping[str, str] = MappingProxyType({
    'csaf-title': _ADVISORY, 'csaf-note': _ADVISORY, 'csaf-product': _ADVISORY, 'csaf-remediation': _ADVISORY,
    'cvrf-title': _ADVISORY, 'cvrf-note': _ADVISORY, 'cvrf-tag': _ADVISORY, 'hypothesis-rule': _ADVISORY,
    'artifact-identity': 'pe-self-report'})
# PIL kind -> anchor-id prefix, fabric kind, role, side and source. A rule is not converted: PIL's `patch-rule:`
# fit is a judgment with no fabric key yet, and the rule kind waits for its own row (plan s4).
_PIL_KINDS: Mapping[str, tuple[str, str, str, str, str]] = MappingProxyType({
    'function': ('fn', 'function', 'observed', 'both', 'pairing'),
    'api': ('api', 'import', 'hint', 'none', _ADVISORY),
    'string': ('str', 'string', 'hint', 'none', _ADVISORY),
    'cwe': ('cwe', 'cwe', 'stated', 'none', _ADVISORY),
    'cve': ('cve', 'cve', 'stated', 'none', _ADVISORY)})


def _refuse(message: str, reason: str) -> FabricError:
    return FabricError('PT-FAB-INPUT', message, reason=reason)


def _mismatch(message: str, reason: str) -> FabricError:
    return FabricError('PT-FAB-INTEGRITY', message, reason=reason)


def _lookup[T](table: Mapping[str, T], key: str, reason: str) -> T:
    try:
        return table[key]
    except KeyError:
        raise _refuse('The record has no fabric conversion', reason) from None


def _tags(source: str, registry: OriginRegistry | None) -> tuple[str, ...]:
    return (_DEFAULT_REGISTRY if registry is None else registry).tags_for(source)


def _pointer_ref(pointer: str | None, document: Ref | None) -> Ref | None:
    """The witness reference of a JSON pointer: the advisory document (kind, id, digest) and the pointer into it."""
    if pointer is None:
        return None
    if document is None:
        raise _refuse('A JSON pointer needs the advisory document it points into', 'document-required')
    try:
        return Ref(kind=document.kind, id=document.id, pointer=pointer, sha256=document.sha256)
    except ValidationError:
        raise _refuse('The JSON pointer is malformed', 'pointer-shape') from None


def _pdb_target(name: str, identity: ArtifactIdentityRecord | None) -> tuple[str, str, str]:
    """Key, side and input hash of a verified PDB name: the artifact it was read from fixes the side and the hash."""
    if identity is None:
        raise _refuse('A PDB name needs the artifact identity it was verified in', 'identity-required')
    if identity.pdb_identity is None or identity.pdb_identity.name != name:
        raise _mismatch('The PDB name is not the one the artifact identity holds', 'pdb-name-mismatch')
    return f'pdb={name}', identity.side, identity.sha256


def from_k_anchor(anchor: KAnchorRecord, *, batch: str, document: Ref | None = None,
                  identity: ArtifactIdentityRecord | None = None, registry: OriginRegistry | None = None) -> Anchor:
    """One K hint as a fabric anchor with one witness (producer `kb`).

    `document` is the advisory a JSON pointer points into and is required when the anchor has a pointer. `identity` is
    the artifact a `pdb` anchor was verified in; its side and input hash become the observation's.
    """
    fabric_kind, role = _lookup(_K_KINDS, anchor.kind, 'k-kind')
    source = _lookup(_K_SOURCES, anchor.source, 'k-source')
    if (fabric_kind == 'build_fact') != (source == 'pe-self-report'):
        raise _refuse('A PDB name comes from the artifact identity and from no other record', 'k-kind-source')
    if fabric_kind == 'build_fact':
        key, side, input_sha = _pdb_target(anchor.value, identity)
    else:
        key = ids.api_key(anchor.value) if fabric_kind == 'import' else ids.string_key(anchor.value)
        side, input_sha = 'none', None
    facets = {'basis': anchor.quality}
    if anchor.kind in _PHRASE_KINDS:
        facets['phrase_kind'] = anchor.kind
    witness = ids.make_witness(producer=K_PRODUCER, batch=batch, source=source, origins=_tags(source, registry),
                               label=anchor.value, facets=facets, input_sha256=input_sha,
                               ref=_pointer_ref(anchor.pointer, document))
    return ids.make_anchor(kind=fabric_kind, key=key, side=side, role=role, witnesses=(witness,))


def _pil_key(fabric_kind: str, value: str, label: str, pair: PairRef | None) -> tuple[str, PairRef | None]:
    """The fabric key of a PIL offer and, for a candidate, the pair record that reproduces it."""
    if fabric_kind == 'function':
        if pair is None:
            raise _refuse('A candidate needs the pair record its key names', 'pair-required')
        key = ids.pair_key_of(pair)
        if key != f'pair:{value}':
            raise _mismatch('The pair record does not reproduce the candidate key', 'pair-key-mismatch')
        return key, pair
    if fabric_kind == 'string':
        if ids.string_key(label) != value:
            raise _mismatch('The string key is not the hash of the label', 'string-key-mismatch')
        return value, None
    keyed = {'import': ids.api_key, 'cwe': ids.cwe_key, 'cve': ids.cve_key}
    return keyed[fabric_kind](value), None


def from_pilot_anchor(anchor: PilotAnchorRecord, *, batch: str, pair: PairRef | None = None,
                      registry: OriginRegistry | None = None) -> Anchor:
    """One PIL offer as a fabric anchor with one witness (producer `pil`).

    A candidate (`fn:`) needs `pair`, the pair record whose key is the candidate key. A string anchor's id carries the
    SHA-256 of its label, which the conversion checks.
    """
    prefix, fabric_kind, role, side, source = _lookup(_PIL_KINDS, anchor.kind, 'pil-kind')
    anchor_prefix, separator, value = anchor.anchor_id.partition(':')
    if not separator or anchor_prefix != prefix:
        raise _refuse('The anchor id prefix does not match its kind', 'anchor-id-kind')
    key, pair_record = _pil_key(fabric_kind, value, anchor.label, pair)
    witness = ids.make_witness(producer=PIL_PRODUCER, batch=batch, source=source, origins=_tags(source, registry),
                               label=anchor.label, facets=anchor.facets)
    return ids.make_anchor(kind=fabric_kind, key=key, side=side, role=role, pair=pair_record, witnesses=(witness,))
