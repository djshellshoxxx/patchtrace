"""AV-1: accuracy case manifest, validator and freeze check.

A manifest lists the cases an engine will be scored on. It must be frozen (hash recorded) BEFORE any engine
runs, so cases cannot be chosen after seeing results. Facts not yet confirmed by a fetch stay `unverified`.
Counts are by distinct project: cases from one project are not independent evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .sample_size import lower_bound

SCHEMA = 'rq-case-manifest/1'
LAYERS = ('L1', 'L2', 'L3')
FACTS = ('verified', 'unverified')
_HEX = re.compile(r'^[0-9a-f]{64}$')
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_CASE_KEYS = {'id', 'layer', 'stratum', 'project', 'source_url', 'licence', 'older', 'newer', 'expected',
              'facts', 'holdout', 'notes'}
_SIDE_KEYS = {'ref', 'sha256'}


def _text(v: Any, name: str, limit: int = 300) -> str:
    if not isinstance(v, str) or not v.strip() or len(v) > limit:
        raise ValueError(f'{name} must be a non-empty string of at most {limit} characters')
    return v


def _side(v: Any, name: str, facts: str) -> None:
    if not isinstance(v, dict) or set(v) - _SIDE_KEYS or 'ref' not in v:
        raise ValueError(f'{name} must be an object with ref and optional sha256')
    _text(v['ref'], f'{name}.ref')
    sha = v.get('sha256')
    if sha is not None and not (isinstance(sha, str) and _HEX.match(sha)):
        raise ValueError(f'{name}.sha256 must be 64 lowercase hex characters or absent')
    if facts == 'verified' and sha is None:
        raise ValueError(f'{name}: a verified case needs a sha256')


def validate_case(c: Any) -> None:
    if not isinstance(c, dict) or set(c) - _CASE_KEYS:
        raise ValueError(f'case has unknown or missing keys: {sorted(set(c) - _CASE_KEYS) if isinstance(c, dict) else c!r}')
    missing = {'id', 'layer', 'stratum', 'project', 'source_url', 'licence', 'older', 'newer', 'expected',
               'facts', 'holdout'} - set(c)
    if missing:
        raise ValueError(f'case {c.get("id")!r} is missing {sorted(missing)}')
    if not isinstance(c['id'], str) or not _ID.match(c['id']):
        raise ValueError(f'bad case id {c["id"]!r}')
    if c['layer'] not in LAYERS or c['facts'] not in FACTS or not isinstance(c['holdout'], bool):
        raise ValueError(f'case {c["id"]}: layer, facts or holdout invalid')
    for k in ('stratum', 'project', 'licence'):
        _text(c[k], f'{c["id"]}.{k}', 80)
    if not re.match(r'^https://', _text(c['source_url'], f'{c["id"]}.source_url', 500)):
        raise ValueError(f'case {c["id"]}: source_url must be https')
    _side(c['older'], f'{c["id"]}.older', c['facts'])
    _side(c['newer'], f'{c["id"]}.newer', c['facts'])
    e = c['expected']
    if not isinstance(e, dict) or set(e) - {'function', 'cve', 'no_change', 'accept'}:
        raise ValueError(f'case {c["id"]}: expected has unknown keys')
    if e.get('no_change') is True:
        if e.get('function'):
            raise ValueError(f'case {c["id"]}: a no_change case cannot name a function')
    else:
        _text(e.get('function'), f'{c["id"]}.expected.function', 200)
        acc = e.get('accept', [])
        if not isinstance(acc, list) or len(acc) > 8:
            raise ValueError(f'case {c["id"]}: expected.accept must be a list of at most 8 names')
        for i, name in enumerate(acc):
            _text(name, f'{c["id"]}.expected.accept[{i}]', 200)
    if e.get('no_change') is True and e.get('accept'):
        raise ValueError(f'case {c["id"]}: a no_change case cannot list accepted functions')


def canonical_hash(manifest: dict[str, Any]) -> str:
    body = {'schema': manifest['schema'], 'cases': sorted(manifest['cases'], key=lambda c: c['id'])}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_manifest(m: Any) -> dict[str, Any]:
    if not isinstance(m, dict) or m.get('schema') != SCHEMA or not isinstance(m.get('cases'), list):
        raise ValueError(f'manifest must be an object with schema {SCHEMA} and a cases list')
    seen: set[str] = set()
    for c in m['cases']:
        validate_case(c)
        if c['id'] in seen:
            raise ValueError(f'duplicate case id {c["id"]}')
        seen.add(c['id'])
    return summary(m)


def summary(m: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {'manifest_sha256': canonical_hash(m), 'cases': len(m['cases']), 'layers': {}}
    for layer in LAYERS:
        cs = [c for c in m['cases'] if c['layer'] == layer]
        projects = {c['project'] for c in cs}
        strata: dict[str, int] = {}
        for c in cs:
            strata[c['stratum']] = strata.get(c['stratum'], 0) + 1
        n = len(projects)
        out['layers'][layer] = {
            'cases': len(cs), 'independent_projects': n, 'holdout': sum(c['holdout'] for c in cs),
            'unverified': sum(c['facts'] == 'unverified' for c in cs), 'strata': strata,
            'best_case_lower_bound_if_no_errors': round(lower_bound(n, n), 3) if n else None,
        }
    return out


def check_frozen(m: dict[str, Any], frozen_sha: str) -> None:
    """Fail unless the manifest still hashes to the recorded freeze value."""
    if not _HEX.match(frozen_sha or ''):
        raise ValueError('frozen sha must be 64 lowercase hex characters')
    if canonical_hash(m) != frozen_sha:
        raise ValueError('manifest changed after it was frozen; start a new manifest id instead of editing cases')
