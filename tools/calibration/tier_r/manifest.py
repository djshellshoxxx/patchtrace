"""SPEC-32 s11: a `calibration-corpus/1` manifest from `known-answer-labels/1` documents (Tier R binaries, pairs, lineages).

Deterministic (no clock, sorted ids). The result loads with `corpus.load_manifest` and feeds `lineage.assign_roles`. Tier R
images live under `<store>/images/<sha256>/`, not under `corpus verify`'s `binaries/` layout, so `verify` reports them as
missing until they are linked or copied there; the manifest records identity, not location. A suite source (no git
commit) is expressed as `git = "suite:<suite>"` with `commit` = the first 40 hex digits of SHA-256("suite|<suite>|<version>").
"""
from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence

from ..common import canonical_json
from ..contracts import CorpusManifest, load_manifest
from . import contracts as C
from .build import env_digest

DEFAULT_CREATED = '1970-01-01T00:00:00Z'      # deterministic placeholder: manifests carry no wall-clock
CLUSTER_RULE = 'known-answer lineage = project; mutants, A/A and noise pairs inherit their base source (SPEC-32 s11)'
SPLIT = {'salt': 'c9-v1', 'method': 'sha256(lineage_id|salt) -> u; <.60 dev, <.85 locked-test, else shift-test',
         'shift_test_lineages': []}
KIND = {'release': 'cross-version', 'noise': 'cross-version', 'aa': 'cross-version'}


class ManifestError(ValueError):
    pass


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def binary_id(project: str, sha256: str) -> str:
    return f'r-{project[:40]}-{sha256[:12]}'


def _source(side: C.ImageSide) -> dict:
    src = side.source
    if src.git is not None:
        return {'git': src.git, 'commit': src.commit, 'license': src.license_spdx}
    return {'git': f'suite:{src.suite}', 'commit': _sha(f'suite|{src.suite}|{src.version}')[:40],
            'license': src.license_spdx}


def _binary(side: C.ImageSide, project: str) -> dict:
    b = side.build
    toolchain_digest = _sha(f'{b.profile}|{b.compiler}|{b.compiler_version}')
    return {'id': binary_id(project, side.sha256), 'tier': 'R', 'file_name': side.file_name, 'arch': 'x64',
            'sha256': side.sha256, 'size': side.size, 'winbindex': None,
            'pdb': {'guid_age': None, 'name': None, 'used_for': 'labels-only'} if side.pdb_sha256 else None,
            'toolchain': f'{b.profile}/{b.compiler} {b.compiler_version}'[:200], 'source': _source(side),
            'recipe': {'toolchain_digest': toolchain_digest,
                       'argv': [f'profile={b.profile}', f'opt={b.opt}', f'link-order={b.link_order}',
                                f'recipe-digest={b.recipe_digest}'],
                       'opt': b.opt, 'strip': True, 'env_digest': env_digest()},
            'redistribution': 'not-committed'}


def build_manifest(docs: Sequence[C.KnownAnswerLabels], *, corpus_id: str = 'known-answer-tier-r',
                   tool_git: str = 'unknown', created: str = DEFAULT_CREATED) -> dict:
    """Raises ManifestError when one image would belong to two lineages (a lineage is never split or merged here)."""
    binaries: dict[str, dict] = {}
    owner: dict[str, str] = {}
    image_owner: dict[str, str] = {}     # by content: the binary id carries the project, the image hash does not
    families: dict[str, Counter] = {}
    pairs = []
    for doc in sorted(docs, key=lambda d: d.pair_id):
        ids = []
        for side in (doc.older, doc.newer):
            bid = binary_id(doc.project, side.sha256)
            if owner.setdefault(bid, doc.lineage) != doc.lineage:
                raise ManifestError(f'image {side.sha256[:12]} is claimed by lineages {owner[bid]} and {doc.lineage}')
            if image_owner.setdefault(side.sha256, doc.lineage) != doc.lineage:
                raise ManifestError(f'image {side.sha256[:12]} is claimed by lineages {image_owner[side.sha256]} '
                                    f'and {doc.lineage} (same content under two projects)')
            binaries.setdefault(bid, _binary(side, doc.project))
            ids.append(bid)
        families.setdefault(doc.lineage, Counter())[doc.family] += 1
        pairs.append({'id': doc.pair_id, 'older': ids[0], 'newer': ids[1], 'kind': KIND.get(doc.stratum, 'adjacent-patch'),
                      'lineage': doc.lineage, 'family_tags': [doc.family, f'stratum:{doc.stratum}'], 'role': None})
    members: dict[str, list[str]] = {}
    for bid, lineage in owner.items():
        members.setdefault(lineage, []).append(bid)
    lineages = []
    for lineage in sorted(members):
        ids = sorted(members[lineage])
        counts = families[lineage]
        lineages.append({'id': lineage, 'members': ids, 'cluster_rule': CLUSTER_RULE,
                         'cluster_evidence_sha256': hashlib.sha256(canonical_json({'lineage': lineage, 'members': ids})
                                                                   ).hexdigest(),
                         'family': sorted(counts, key=lambda f: (-counts[f], f))[0]})
    document = {'contract': 'calibration-corpus/1', 'corpus_id': corpus_id, 'created': created, 'tool_git': tool_git,
                'binaries': [binaries[k] for k in sorted(binaries)], 'pairs': pairs, 'lineages': lineages,
                'split': {**SPLIT, 'shift_test_lineages': list(SPLIT['shift_test_lineages'])}}
    load_manifest(canonical_json(document))     # raises ContractError when the result is not a valid manifest
    return document


def check_manifest(document: dict) -> CorpusManifest:
    return load_manifest(canonical_json(document))
