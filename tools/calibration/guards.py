"""Input and split-integrity guards for the label-training pipeline (audit 20261014-C; spec §18 amendment 17).

Pure functions, stdlib only. Every guard fails closed with a message naming the offending ids, never with a
bare ZeroDivision/Cholesky error deep inside the fit.

* `validate_rows` - unique row ids, finite positive weights, binary labels, finite features, both classes present.
* `validate_preds` - one finite probability per row.
* `audit_manifest` - split integrity on a `calibration-corpus/1` document: no lineage, source project, PDB name or
  image hash on both sides of a role split; A/A, noise and planted-mutation pairs inherit a lineage that also owns
  both of their images; time-inverted pairs; empty roles. Returns `{'violations': [...], 'warnings': [...]}`.
* `evidence_pairs` - the pairs that may count as accuracy evidence (A/A, toolchain-noise and planted-mutation
  pairs are controls, never evidence; spec SPEC-32 s7/s11).
* `canonical_manifest_sha256` - order-independent hash of a manifest document.
"""
from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping, Sequence

from .common import canonical_json

CONTROL_STRATA = frozenset({'aa', 'noise', 'mutation'})
STRATUM_TAG = 'stratum:'


class RowError(ValueError):
    """Unusable training/evaluation rows (message lists ids)."""


def _ids(ids: Iterable[str], limit: int = 5) -> str:
    ids = sorted(set(ids))
    return ', '.join(ids[:limit]) + (f' (+{len(ids) - limit} more)' if len(ids) > limit else '')


def validate_rows(rows: Sequence, *, require_both_classes: bool = True) -> None:
    if not rows:
        raise RowError('no rows')
    seen: set[str] = set()
    dup = {r.id for r in rows if r.id in seen or seen.add(r.id)}
    if dup:
        raise RowError(f'duplicate row ids: {_ids(dup)}')
    bad_w = [r.id for r in rows if not (isinstance(r.w, int | float) and math.isfinite(r.w) and r.w > 0)]
    if bad_w:
        raise RowError(f'weights must be finite and > 0: {_ids(bad_w)}')
    bad_y = [r.id for r in rows if r.y not in (0, 1)]
    if bad_y:
        raise RowError(f'labels must be 0 or 1: {_ids(bad_y)}')
    bad_x = [r.id for r in rows if not all(math.isfinite(v) for v in r.x)]
    if bad_x:
        raise RowError(f'non-finite features: {_ids(bad_x)}')
    if not all(r.group for r in rows):
        raise RowError('every row needs a non-empty lineage group')
    if require_both_classes and len({r.y for r in rows}) < 2:
        raise RowError('only one class present: nothing to calibrate or test')


def validate_preds(rows: Sequence, preds: Mapping[str, float]) -> None:
    missing = [r.id for r in rows if r.id not in preds]
    if missing:
        raise RowError(f'no prediction for rows: {_ids(missing)}')
    bad = [r.id for r in rows if not (math.isfinite(preds[r.id]) and 0.0 <= preds[r.id] <= 1.0)]
    if bad:
        raise RowError(f'predictions must be finite probabilities: {_ids(bad)}')


# ---- manifest / split audit ---------------------------------------------------------------------------------

def stratum_of_pair(pair: Mapping) -> str | None:
    for tag in pair.get('family_tags', ()):
        if tag.startswith(STRATUM_TAG):
            return tag[len(STRATUM_TAG):]
    return None


def evidence_pairs(manifest: Mapping) -> list[dict]:
    """Pairs allowed to count as accuracy evidence. Untagged pairs are kept (legacy Tier W manifests)."""
    return [p for p in manifest['pairs'] if stratum_of_pair(p) not in CONTROL_STRATA]


def _project_key(binary: Mapping) -> str | None:
    src = binary.get('source') or {}
    return src.get('git') if src.get('git') else None


def audit_manifest(manifest: Mapping, roles: Mapping[str, str] | None = None) -> dict:
    """`roles` maps lineage id -> role (default: the roles recorded on pairs, else `lineage.assign_roles`)."""
    from .lineage import assign_roles
    violations: list[str] = []
    warnings: list[str] = []
    binaries = {b['id']: b for b in manifest['binaries']}
    owner = {m: lin['id'] for lin in manifest['lineages'] for m in lin['members']}
    split = manifest.get('split', {})
    if roles is None:
        roles = assign_roles([lin['id'] for lin in manifest['lineages']], split.get('salt', ''),
                             split.get('shift_test_lineages', ()))
        for p in manifest['pairs']:
            if p.get('role') and roles.get(p['lineage']) != p['role']:
                violations.append(f'pair {p["id"]}: recorded role {p["role"]} differs from lineage role '
                                  f'{roles.get(p["lineage"])}')
    pair_roles: dict[str, set[str]] = {}
    for p in manifest['pairs']:
        pair_roles.setdefault(p['lineage'], set()).add(roles.get(p['lineage'], '?'))
        stratum = stratum_of_pair(p)
        sides_owner = {owner.get(p['older']), owner.get(p['newer'])}
        if len({roles.get(o) for o in sides_owner}) > 1:
            violations.append(f'pair {p["id"]} joins images of different roles (it crosses the split)')
        if stratum in CONTROL_STRATA:
            for side in ('older', 'newer'):
                if owner.get(p[side]) != p['lineage']:
                    violations.append(f'pair {p["id"]}: {stratum} control must inherit the lineage of its base '
                                      f'source ({side} image is in {owner.get(p[side])})')
        elif p['kind'] != 'unrelated-control' and sides_owner != {p['lineage']}:
            violations.append(f'pair {p["id"]}: images are not both in lineage {p["lineage"]}')
    for lid, rs in sorted(pair_roles.items()):
        if len(rs) > 1:
            violations.append(f'lineage {lid} appears in several roles: {sorted(rs)}')
    sides: dict[str, dict[str, set[str]]] = {'project': {}, 'pdb': {}, 'sha256': {}}
    for bid, b in sorted(binaries.items()):
        role = roles.get(owner.get(bid, ''), None)
        if role is None:
            violations.append(f'binary {bid} has no lineage role')
            continue
        keys = {'project': _project_key(b), 'sha256': b['sha256'],
                'pdb': ((b.get('pdb') or {}).get('name') or '').lower() or None}
        for kind, key in keys.items():
            if key:
                sides[kind].setdefault(key, set()).add(role)
    for kind, table in sides.items():
        for key, rs in sorted(table.items()):
            if len(rs) > 1:
                violations.append(f'{kind} {key} is on both sides of the split: {sorted(rs)}')
    for p in manifest['pairs']:
        t0 = ((binaries.get(p['older']) or {}).get('winbindex') or {}).get('timestamp')
        t1 = ((binaries.get(p['newer']) or {}).get('winbindex') or {}).get('timestamp')
        if p['kind'] == 'adjacent-patch' and t0 is not None and t1 is not None and t0 > t1:
            violations.append(f'pair {p["id"]}: older image is newer than the newer image (time-inverted)')
    by_role: dict[str, int] = {}
    for lin in manifest['lineages']:
        by_role[roles.get(lin['id'], '?')] = by_role.get(roles.get(lin['id'], '?'), 0) + 1
    for role in ('dev', 'locked-test', 'shift-test'):
        if not by_role.get(role):
            warnings.append(f'role {role} has no lineage (tiny corpus: no claim can rest on it)')
    return {'violations': violations, 'warnings': warnings, 'roles': by_role}


def canonical_manifest_sha256(manifest: Mapping) -> str:
    """Hash of a `calibration-corpus/1` document that ignores list order and key order (lists of records are
    sorted by id, member and tag lists sorted); `created` and `tool_git` are provenance and are excluded so a
    rebuild of the same content on another day hashes equal."""
    doc = {k: v for k, v in manifest.items() if k not in ('created', 'tool_git')}
    for key in ('binaries', 'pairs', 'lineages'):
        doc[key] = sorted(doc.get(key, ()), key=lambda r: r['id'])
    doc['pairs'] = [dict(p, family_tags=sorted(p.get('family_tags', ()))) for p in doc['pairs']]
    doc['lineages'] = [dict(lin, members=sorted(lin['members'])) for lin in doc['lineages']]
    split = dict(doc.get('split', {}))
    split['shift_test_lineages'] = sorted(split.get('shift_test_lineages', ()))
    doc['split'] = split
    return hashlib.sha256(canonical_json(doc)).hexdigest()
