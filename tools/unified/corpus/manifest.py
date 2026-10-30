"""`unified-corpus-manifest/1`: which built pairs feed which gate (08-evaluation s1, s2), facts only.

The manifest is read from the SPEC-32 label documents (`known-answer-labels/1`) and says, per pair, its role, the gates it
feeds, the image digests, the label digest, the function counts and, for a mutant, the class, the planted function and
the verdicts the gate accepts. It holds no threshold: the gate report applies those. Deterministic (sorted, no
timestamps), strict on load, and nothing is dropped silently: strata that belong to SPEC-32 alone are listed in
`ignored`, work that cannot be built yet is listed in `pending` with the reason.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_serializer

from tools.calibration.common import digest, strict_json
from tools.calibration.tier_r import contracts as C
from tools.unified.mutations import classes

from . import aa

CONTRACT = 'unified-corpus-manifest/1'
GATES = {'release': ('G-U3', 'G-U5', 'G-U7'), 'cve-fix': ('G-U3', 'G-U7'), 'control': ('G-U3',),
         'P0': ('G-U1',), 'P1': ('G-U1',), 'P2': ('G-U1',), 'mutation': ('G-U2', 'G-U6')}
NOT_GATED = frozenset({'P2'})      # 08 s2: stress pairs are expected to be `induced`, reported, never gated
STRATUM_ROLE = {'release': 'release', 'cve': 'cve-fix', 'control': 'control'}
Role = Literal['release', 'cve-fix', 'control', 'P0', 'P1', 'P2', 'mutation']


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Image(_Strict):
    sha256: C.Sha256
    size: int
    file_name: str


class MutationFacts(_Strict):
    unified_class: str
    target: str
    verdicts: tuple[str, ...]


class ManifestPair(_Strict):
    pair_id: C.Ident
    role: Role
    gates: tuple[str, ...]
    gated: bool
    project: C.Ident
    lineage: C.Ident
    x_vs_x: bool
    older: Image
    newer: Image
    labels_sha256: C.Sha256
    functions: int
    by_label: dict[str, int]
    mutation: MutationFacts | None = None
    variant: str = ''                 # P1 only: `link-order` or the nuisance (icf, timestamp, guid, path)
    older_rvas: tuple[C.Rva, ...] | None = None   # None: legacy manifest, cannot attest endpoint coverage
    newer_rvas: tuple[C.Rva, ...] | None = None

    @model_serializer(mode='wrap')
    def _omit_legacy_coverage(self, handler):
        data = handler(self)
        for key in ('older_rvas', 'newer_rvas'):
            if data.get(key) is None:
                data.pop(key, None)
        return data


class Pending(_Strict):
    item: str
    reason: str


class CorpusManifest(_Strict):
    contract: Literal['unified-corpus-manifest/1']
    toolchain: dict[str, str]
    pairs: tuple[ManifestPair, ...]
    ignored: tuple[str, ...]
    pending: tuple[Pending, ...]
    manifest_sha256: C.Sha256


def role_of(doc: C.KnownAnswerLabels) -> tuple[str | None, str]:
    """(role, reason it has none). Mutants need a known class in their case provenance."""
    if doc.stratum in ('aa', 'noise'):
        return aa.classify(doc), f'method {doc.method} is not an A/A method'
    if doc.stratum in STRATUM_ROLE:
        return STRATUM_ROLE[doc.stratum], ''
    if doc.stratum == 'mutation':
        known = doc.case.get('unified_class') in classes.BY_ID
        return ('mutation' if known else None), 'the case has no known unified_class'
    return None, f'stratum {doc.stratum} belongs to the SPEC-32 evaluation'


def _pair(doc: C.KnownAnswerLabels, role: str) -> ManifestPair:
    def image(side) -> Image:
        return Image(sha256=side.sha256, size=side.size, file_name=side.file_name)
    case = doc.case
    mutation = MutationFacts(unified_class=case['unified_class'], target=case['target'],
                             verdicts=tuple(case['verdicts'])) if role == 'mutation' else None
    return ManifestPair(
        pair_id=doc.pair_id, role=role, gates=GATES[role], gated=role not in NOT_GATED, project=doc.project,
        lineage=doc.lineage, x_vs_x=doc.older.sha256 == doc.newer.sha256, older=image(doc.older),
        newer=image(doc.newer), labels_sha256=doc.digest_sha256, functions=doc.summary.functions,
        by_label=dict(doc.summary.by_label), mutation=mutation,
        variant=aa.variant_of(doc) if role == 'P1' else '',
        older_rvas=tuple(sorted({f.old_rva for f in doc.functions if f.old_rva is not None})),
        newer_rvas=tuple(sorted({f.new_rva for f in doc.functions if f.new_rva is not None})))


def pending() -> tuple[Pending, ...]:
    return tuple(Pending(item=f'mutation:{p.id}', reason=f'needs {p.needs}: {p.reason}') for p in classes.PENDING)


def build(docs: Iterable[C.KnownAnswerLabels], toolchain: Mapping[str, str]) -> CorpusManifest:
    pairs, ignored = [], []
    for doc in docs:
        role, reason = role_of(doc)
        if role is None:
            ignored.append(f'{doc.pair_id}: {reason}')
        else:
            pairs.append(_pair(doc, role))
    ids = [p.pair_id for p in pairs]
    if len(ids) != len(set(ids)):
        raise C.ContractError(f'a pair id occurs twice: {sorted(i for i in ids if ids.count(i) > 1)[:3]}')
    body = {'contract': CONTRACT, 'toolchain': dict(sorted(toolchain.items())),
            'pairs': [p.model_dump(mode='json') for p in sorted(pairs, key=lambda p: p.pair_id)],
            'ignored': sorted(ignored), 'pending': [p.model_dump(mode='json') for p in pending()]}
    return CorpusManifest.model_validate_json(json.dumps({**body, 'manifest_sha256': digest(body, 'manifest_sha256')}))


def dump(manifest: CorpusManifest) -> bytes:
    return C.dump_json(manifest.model_dump(mode='json'))


def load(data: bytes) -> CorpusManifest:
    try:
        raw = strict_json(data)
        manifest = CorpusManifest.model_validate_json(data)
    except (ValueError, ValidationError) as exc:
        raise C.ContractError(f'manifest invalid: {exc}') from None
    if digest(raw, 'manifest_sha256') != manifest.manifest_sha256:
        raise C.ContractError('manifest digest mismatch (edited after generation)')
    return manifest
