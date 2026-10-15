"""Defensive adapter for the researched ghidriff PDiff structure."""
from __future__ import annotations

import math

from .models import ComparisonProject, FunctionMatch, FunctionRecord

ROOT_KEYS = {'program_options', 'matches', 'symbols', 'strings', 'functions', 'stats',
             'old_meta', 'new_meta', 'md_credits', 'html_credits', 'old_pe_url', 'new_pe_url'}
HASH_KEYS = ('Executable SHA256', 'SHA256', 'sha256', 'sha256_hash', 'Executable SHA-256')


def _strings(value, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f'PT-SCHEMA: {label} must be a list of strings')
    return value


def verify_diff_identity(raw: dict, project: ComparisonProject) -> None:
    """An imported result must identify the exact ordered immutable input pair."""
    for side, key in [('older', 'old_meta'), ('newer', 'new_meta')]:
        meta = raw.get(key)
        if not isinstance(meta, dict):
            raise ValueError(f'PT-SCHEMA: {key} with input SHA-256 is required')
        hashes = [meta[k] for k in HASH_KEYS if k in meta]
        if not hashes or any(not isinstance(value, str) for value in hashes):
            raise ValueError(f'PT-SCHEMA: {key} has no valid input SHA-256')
        expected = next(a.sha256 for a in project.artifacts if a.side == side)
        if any(value.lower() != expected for value in hashes):
            raise ValueError(f'PT-SCHEMA: {side} diff input hash does not match this project')


def normalize_ghidriff(raw: dict, project: ComparisonProject, run_id: str) -> list[FunctionMatch]:
    if not isinstance(raw, dict) or 'functions' not in raw or set(raw) - ROOT_KEYS:
        raise ValueError('PT-SCHEMA: unsupported ghidriff root; expected PDiff functions')
    functions = raw['functions']
    if not isinstance(functions, dict) or set(functions) != {'added', 'deleted', 'modified'}:
        raise ValueError('PT-SCHEMA: expected functions added/deleted/modified collections')
    if any(not isinstance(functions[key], list) for key in functions):
        raise ValueError('PT-SCHEMA: function collections must be lists')
    if run_id not in {run.id for run in project.runs}:
        raise ValueError('PT-SCHEMA: normalization requires a project-owned analysis run')
    artifacts = {artifact.side: artifact for artifact in project.artifacts}
    seen: set[tuple[str, str, str | None]] = set()

    def function(record, side: str) -> FunctionRecord:
        if not isinstance(record, dict) or not isinstance(record.get('name'), str) or not record['name']:
            raise ValueError('PT-SCHEMA: enhanced function requires a nonempty name')
        for key in ['fullname', 'address', 'code']:
            if record.get(key) is not None and not isinstance(record[key], str):
                raise ValueError(f'PT-SCHEMA: function {key} must be text or null')
        instructions = record.get('instructions')
        assembly = None
        metadata = {key: value for key, value in record.items()
                    if key not in {'name', 'fullname', 'address', 'code', 'calling', 'called', 'instructions'}}
        if instructions is not None:
            if isinstance(instructions, list):
                assembly = '\n'.join(_strings(instructions, 'instructions')) or None
            elif isinstance(instructions, int) and not isinstance(instructions, bool):
                metadata['instructions_hash'] = instructions
                metadata['assembly_unavailable'] = 'Upstream persisted an instruction hash, not assembly'
            else:
                raise ValueError('PT-SCHEMA: instructions must be a string list, integer hash or null')
        metadata['upstream_name'] = record['name']
        identity = (side, record.get('fullname') or record['name'], record.get('address'))
        if identity in seen:
            raise ValueError('PT-SCHEMA: upstream function is repeated; shared evidence counts once')
        seen.add(identity)
        return FunctionRecord(artifact_id=artifacts[side].id, run_id=run_id,
                              name=record.get('fullname') or record['name'], address=record.get('address'),
                              address_space='virtual' if record.get('address') else 'unknown',
                              code=record.get('code'), assembly=assembly,
                              callers=_strings(record.get('calling', []), 'calling'),
                              callees=_strings(record.get('called', []), 'called'), metadata=metadata)

    result = []
    for category, key, side in [('added', 'added', 'newer'), ('removed', 'deleted', 'older')]:
        for item in functions[key]:
            result.append(FunctionMatch(run_id=run_id, category=category,
                                        **{side: [function(item, side)]}))
    for item in functions['modified']:
        if not isinstance(item, dict) or 'old' not in item or 'new' not in item:
            raise ValueError('PT-SCHEMA: modified function requires enhanced old and new records')
        match_types = _strings(item.get('match_types', []), 'match_types')
        diff_types = _strings(item.get('diff_type', []), 'diff_type')
        ratio = item.get('ratio')
        if ratio is not None and (isinstance(ratio, bool) or not isinstance(ratio, (int, float))
                                  or not math.isfinite(ratio) or not 0 <= ratio <= 1):
            raise ValueError('PT-SCHEMA: upstream ratio must be a finite number from zero to one')
        old, new = function(item['old'], 'older'), function(item['new'], 'newer')
        old.metadata['diff_types'] = diff_types
        new.metadata['diff_types'] = diff_types
        if ratio is not None:
            old.metadata['upstream_similarity'] = ratio
            new.metadata['upstream_similarity'] = ratio
        result.append(FunctionMatch(run_id=run_id, older=[old], newer=[new], category='modified',
                                    match_types=match_types,
                                    quality=f'upstream similarity {ratio:.2f} (uncalibrated)' if ratio is not None
                                    else 'unknown'))
    return result
