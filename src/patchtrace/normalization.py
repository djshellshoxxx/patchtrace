"""Defensive adapter for the researched ghidriff PDiff structure."""
from __future__ import annotations

import hashlib
import json
import math

from .enrichment.identity import parse_address
from .models import ComparisonProject, FunctionMatch, FunctionRecord

ROOT_KEYS = {'program_options', 'matches', 'symbols', 'strings', 'functions', 'stats',
             'old_meta', 'new_meta', 'md_credits', 'html_credits', 'old_pe_url', 'new_pe_url'}
HASH_KEYS = ('Executable SHA256', 'SHA256', 'sha256', 'sha256_hash', 'Executable SHA-256')
CORE_KEYS = frozenset({'name', 'fullname', 'address', 'code', 'calling', 'called', 'instructions'})
ONE_TO_MANY = 'upstream_one_to_many'
# Metadata keys PatchTrace derives; an upstream record that already carries one is rejected, never stripped (A-28).
RESERVED_METADATA = frozenset({'upstream_similarity', 'diff_types', 'upstream_name', 'instructions_hash',
                               'assembly_unavailable', ONE_TO_MANY})
Identity = tuple[str, str, int | None]  # side, name, parsed address (None: address-less)


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


def is_abstention(match) -> bool:
    """A non-manual one-sided `ambiguous` row: the normalizer abstained on a Ghidriff one-to-many group (A-28).
    Duck-typed, so the unified snapshot rows use the same rule."""
    return not match.manual and match.category == 'ambiguous' and len(match.older) + len(match.newer) == 1


def _canonical(value) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    except (TypeError, ValueError):
        raise ValueError('PT-SCHEMA: enhanced function must be JSON data') from None


def _identity_key(identity: Identity) -> tuple:
    side, name, address = identity
    return side != 'older', name, address is None, -1 if address is None else address


def normalize_ghidriff(raw: dict, project: ComparisonProject, run_id: str) -> list[FunctionMatch]:
    """Two passes (A-28): validate and index the whole document, then emit. A record repeated with identical content
    across distinct `modified` pairs joins their connected pairs into a conflict group; no pairing in a group becomes a
    match, and each distinct function of the group is one record in its own one-sided `ambiguous` row."""
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
    seen: dict[Identity, tuple[dict, bool]] = {}  # identity -> (first upstream record, one-sided)
    first: dict[Identity, FunctionRecord] = {}

    def function(record, side: str, one_sided: bool) -> tuple[Identity, FunctionRecord]:
        if not isinstance(record, dict) or not isinstance(record.get('name'), str) or not record['name']:
            raise ValueError('PT-SCHEMA: enhanced function requires a nonempty name')
        for key in ['fullname', 'address', 'code']:
            if record.get(key) is not None and not isinstance(record[key], str):
                raise ValueError(f'PT-SCHEMA: function {key} must be text or null')
        planted = sorted(RESERVED_METADATA.intersection(record))
        if planted:
            raise ValueError(f'PT-SCHEMA: upstream function carries the PatchTrace-reserved metadata key {planted[0]}')
        instructions = record.get('instructions')
        assembly = None
        metadata = {key: value for key, value in record.items() if key not in CORE_KEYS}
        if instructions is not None:
            if isinstance(instructions, list):
                assembly = '\n'.join(_strings(instructions, 'instructions')) or None
            elif isinstance(instructions, int) and not isinstance(instructions, bool):
                metadata['instructions_hash'] = instructions
                metadata['assembly_unavailable'] = 'Upstream persisted an instruction hash, not assembly'
            else:
                raise ValueError('PT-SCHEMA: instructions must be a string list, integer hash or null')
        metadata['upstream_name'] = record['name']
        # Consumers read addresses through parse_address ('0x180001000' == '180001000'; '' and unparsable text are
        # address-less), so identity does too: one function never sits in two active matches under two spellings.
        identity = (side, record.get('fullname') or record['name'], parse_address(record.get('address')))
        if identity in seen:
            earlier, earlier_one_sided = seen[identity]
            if one_sided or earlier_one_sided:  # "no counterpart" and "matched", or a repeated one-sided entry
                raise ValueError('PT-SCHEMA: upstream function is repeated; shared evidence counts once')
            if _canonical(record) != _canonical(earlier):  # canonical JSON: 0 is not false, 1 is not 1.0
                raise ValueError('PT-SCHEMA: upstream function is repeated with conflicting content; '
                                 'one address has one body')
        seen[identity] = (record, one_sided)
        built = FunctionRecord(artifact_id=artifacts[side].id, run_id=run_id,
                               name=record.get('fullname') or record['name'], address=record.get('address'),
                               address_space='virtual' if record.get('address') else 'unknown',
                               code=record.get('code'), assembly=assembly,
                               callers=_strings(record.get('calling', []), 'calling'),
                               callees=_strings(record.get('called', []), 'called'), metadata=metadata)
        first.setdefault(identity, built)
        return identity, built

    # pass 1: validate everything and index every record; nothing is returned before the whole document passed
    result = []
    for category, key, side in [('added', 'added', 'newer'), ('removed', 'deleted', 'older')]:
        for item in functions[key]:
            result.append(FunctionMatch(run_id=run_id, category=category,
                                        **{side: [function(item, side, True)[1]]}))
    entries = []
    pairs: set[tuple[Identity, Identity]] = set()
    for item in functions['modified']:
        if not isinstance(item, dict) or 'old' not in item or 'new' not in item:
            raise ValueError('PT-SCHEMA: modified function requires enhanced old and new records')
        match_types = _strings(item.get('match_types', []), 'match_types')
        diff_types = _strings(item.get('diff_type', []), 'diff_type')
        ratio = item.get('ratio')
        if ratio is not None and (isinstance(ratio, bool) or not isinstance(ratio, (int, float))
                                  or not 0 <= ratio <= 1 or not math.isfinite(ratio)):
            raise ValueError('PT-SCHEMA: upstream ratio must be a finite number from zero to one')
        old_id, old = function(item['old'], 'older', False)
        new_id, new = function(item['new'], 'newer', False)
        if (old_id, new_id) in pairs:  # CORE-2: a copied entry claims one pair twice
            raise ValueError('PT-SCHEMA: upstream pair is repeated; shared evidence counts once')
        pairs.add((old_id, new_id))
        entries.append((item, old_id, old, new_id, new, match_types, diff_types, ratio))

    # pass 2: conflict groups are the connected components of the pair graph with more than one pair
    parent: dict[Identity, Identity] = {}

    def find(node: Identity) -> Identity:
        while parent.setdefault(node, node) != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node
    for entry in entries:
        parent[find(entry[1])] = find(entry[3])
    components: dict[Identity, list[int]] = {}
    for index, entry in enumerate(entries):
        components.setdefault(find(entry[1]), []).append(index)
    grouped = {index for members in components.values() if len(members) > 1 for index in members}
    for index, (_item, _old_id, old, _new_id, new, match_types, diff_types, ratio) in enumerate(entries):
        if index in grouped:
            continue
        old.metadata['diff_types'] = diff_types
        new.metadata['diff_types'] = diff_types
        if ratio is not None:
            old.metadata['upstream_similarity'] = ratio
            new.metadata['upstream_similarity'] = ratio
        result.append(FunctionMatch(run_id=run_id, older=[old], newer=[new], category='modified',
                                    match_types=match_types,
                                    quality=f'upstream similarity {ratio:.2f} (uncalibrated)' if ratio is not None
                                    else 'unknown'))
    for members in sorted((m for m in components.values() if len(m) > 1), key=lambda m: m[0]):
        result.extend(_abstain(run_id, [(index, entries[index]) for index in members], first))
    return result


def _abstain(run_id: str, members: list, first: dict[Identity, FunctionRecord]) -> list[FunctionMatch]:
    """One one-sided `ambiguous` row per distinct function of a conflict group. Every per-pair claim stays in the
    side-relative metadata of both its endpoints; an aggregator deduplicates claims on (run id, entry)."""
    claims: dict[Identity, list[dict]] = {}
    for index, (item, old_id, _old, new_id, _new, match_types, diff_types, ratio) in members:
        for mine, other in ((old_id, item['new']), (new_id, item['old'])):
            claims.setdefault(mine, []).append({
                'entry': index, 'pointer': f'/functions/modified/{index}',
                'counterpart': {'name': other['name'], 'fullname': other.get('fullname'),
                                'address': other.get('address')},
                'match_types': list(match_types), 'diff_types': list(diff_types), 'ratio': ratio})
    identities = sorted(claims, key=_identity_key)
    group = 'g1n-' + hashlib.sha256(_canonical([list(i) for i in identities]).encode('utf-8')).hexdigest()[:16]
    rows = []
    for identity in identities:
        record, pairings = first[identity], claims[identity]
        record.metadata[ONE_TO_MANY] = {'group': group, 'pairings': pairings}
        plural = '' if len(pairings) == 1 else 's'
        reason = (f'Ghidriff matched this function to {len(pairings)} counterpart function{plural} (one-to-many, '
                  f'group {group}, {len(identities)} functions); PatchTrace does not choose. '
                  'Record a relation with Correct match.')
        rows.append(FunctionMatch(run_id=run_id, category='ambiguous', review='needs-review', reason=reason,
                                  **{identity[0]: [record]}))
    return rows
