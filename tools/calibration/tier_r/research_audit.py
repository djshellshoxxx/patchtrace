"""Pure R1 audits over existing labels; no builds, label promotion, or engine decisions.

Callers select accepted truth before scoring: ``check=ok`` alone is not acceptance.
Partition findings cover supplied identities, not undetected near duplicates. Optional
template keys are case.mutation_template/template_id/mutation_group and nested
case.mutation.operator/template_id; source.mutation also links authored derivatives.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

from ..common import canonical_json
from .contracts import KnownAnswerLabels

ROLES = frozenset({'dev', 'validation', 'locked-test', 'shift-test'})
Observation = tuple[int | None, int | None, bool | None]


def _keys(doc: KnownAnswerLabels) -> set[tuple[str, str]]:
    keys = {('project', doc.project), ('lineage', doc.lineage)}
    for side in (doc.older, doc.newer):
        for digest in (side.sha256, side.debug_sha256, side.pdb_sha256):
            if digest is not None:
                keys.add(('artifact', digest))
        source = side.source
        origin = ('git', source.git, source.commit) if source.git else ('suite', source.suite, source.version)
        keys.add(('source', canonical_json(origin).decode()))
        if source.mutation:
            keys.add(('mutation-template', source.mutation))
    for name in ('mutation_template', 'template_id', 'mutation_group'):
        if name in doc.case:
            value = doc.case[name]
            if not isinstance(value, str) or not value:
                raise ValueError(f'{doc.pair_id}: {name} must be a nonempty string')
            keys.add(('mutation-template', value))
    mutation = doc.case.get('mutation')
    if isinstance(mutation, dict):
        for name in ('operator', 'template_id'):
            if name in mutation:
                value = mutation[name]
                if not isinstance(value, str) or not value:
                    raise ValueError(f'{doc.pair_id}: mutation.{name} must be a nonempty string')
                keys.add(('mutation-template', value))
    return keys


def audit_partitions(docs: Sequence[KnownAnswerLabels], roles: Mapping[str, str]) -> dict:
    """Return deterministic cross-role findings; invalid pair/role inventories raise ValueError.

    ``roles`` is a mapping (one value per pair); duplicate pair IDs in docs are refused.
    Artifact checks share a namespace, catching engine/debug/PDB cross-kind overlap.
    A pass establishes separation only for the identifiers provided by the caller.
    """
    ids = [d.pair_id for d in docs]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate pair IDs')
    if set(ids) != set(roles):
        raise ValueError('roles must cover exactly the supplied pair IDs')
    if any(not isinstance(role, str) or role not in ROLES for role in roles.values()):
        raise ValueError('invalid partition role')
    owners: dict[tuple[str, str], set[str]] = defaultdict(set)
    for doc in docs:
        for key in _keys(doc):
            owners[key].add(doc.pair_id)
    findings = []
    for (kind, key), pairs in sorted(owners.items()):
        shared_roles = sorted({roles[p] for p in pairs})
        if len(shared_roles) > 1:
            findings.append({'kind': kind, 'key': key, 'roles': shared_roles, 'pair_ids': sorted(pairs)})
    return {'passed': not findings, 'pairs': len(ids), 'findings': findings,
            'scope': 'supplied identifiers only; near duplicates and unrecorded fragments are not certified'}


def _observations(predictions: Iterable[Observation]) -> tuple[dict, int, int]:
    grouped: dict[tuple[int | None, int | None], set[bool | None]] = defaultdict(set)
    count = 0
    for row in predictions:
        if not isinstance(row, tuple | list) or len(row) != 3:
            raise ValueError('an observation must contain old RVA, new RVA and change verdict')
        old, new, changed = row
        if old is None and new is None:
            raise ValueError('an observation needs at least one endpoint')
        if any(r is not None and (type(r) is not int or not 0 <= r < 2**32) for r in (old, new)):
            raise ValueError('RVA must be a uint32 integer or None')
        if changed is not None and type(changed) is not bool:
            raise ValueError('change verdict must be bool or None')
        grouped[(old, new)].add(changed)
        count += 1
    conflicts = sum(len(flags) > 1 for key, flags in grouped.items() if None not in key)
    # Any disagreement, including known vs unknown, stays unknown. No order-dependent choice.
    reduced = {key: next(iter(flags)) if len(flags) == 1 else None for key, flags in grouped.items()}
    return reduced, count - len(grouped), conflicts


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def supplemental_metrics(labels: KnownAnswerLabels, predictions: Iterable[Observation], *,
                         implicit_unchanged: bool = False) -> dict:
    """Score explicit endpoint tuples; ``None`` verdict preserves paired identity.

    One-sided tuples are explicit unpaired observations. This interface cannot encode
    candidate/contested identity decisions; those must not be converted to paired tuples.
    ``implicit_unchanged`` is recorded but grants no inferred credit. Ambiguous truth
    and observations touching only unlabelled code are counted aside. FPR is undefined
    because these inputs do not define a verified negative candidate-edge universe.
    """
    if type(implicit_unchanged) is not bool:
        raise ValueError('implicit_unchanged must be bool')
    observations, duplicates, conflicts = _observations(predictions)
    scored = [f for f in labels.functions if f.identity != 'ambiguous' and f.label != 'ambiguous']
    ambiguous = [f for f in labels.functions if f.identity == 'ambiguous' or f.label == 'ambiguous']
    truth = {(f.old_rva, f.new_rva): f for f in scored if f.identity == 'same'}

    def endpoints(records):
        return {(side, rva) for f in records for side, rva in (('old', f.old_rva), ('new', f.new_rva))
                if rva is not None}

    eligible, uncertain = endpoints(scored), endpoints(ambiguous)
    counts = dict.fromkeys(('identity_tp', 'identity_fp', 'identity_fn', 'material_detected', 'material_unknown',
                           'material_not_flagged', 'negative_flagged', 'unknown_change_pairs',
                           'unlabelled_predictions', 'ambiguous_predictions'), 0)
    paired_endpoints, unpaired_endpoints = set(), set()
    scored_predictions = 0
    for (old, new), flag in observations.items():
        touched = ({('old', old)} if old is not None else set()) | \
                  ({('new', new)} if new is not None else set())
        if not touched & eligible:
            counts['ambiguous_predictions' if touched & uncertain else 'unlabelled_predictions'] += 1
            continue
        if old is None or new is None:
            unpaired_endpoints |= touched & eligible
            continue
        paired_endpoints |= touched & eligible
        scored_predictions += 1
        counts['unknown_change_pairs'] += flag is None
        record = truth.get((old, new))
        if record is None:
            counts['identity_fp'] += 1
            continue
        counts['identity_tp'] += 1
        if record.label == 'changed':
            field = 'material_unknown' if flag is None else 'material_detected' if flag else 'material_not_flagged'
            counts[field] += 1
        elif flag is True:
            counts['negative_flagged'] += 1
    tp, fp = counts['identity_tp'], counts['identity_fp']
    counts['identity_fn'] = len(truth) - tp
    material = sum(f.label == 'changed' for f in truth.values())
    negatives = sum(f.label in {'unchanged', 'cosmetic'} for f in truth.values())
    counts.update(duplicate_observations=duplicates, conflicting_pairs=conflicts,
                  ambiguous_truth_records=len(ambiguous), unmatched_endpoints=len(eligible - paired_endpoints),
                  explicit_unpaired_endpoints=len(unpaired_endpoints), unmatched_truth_pairs=len(truth) - tp,
                  material_missed=material - counts['material_detected'],
                  material_unmatched=material - counts['material_detected'] - counts['material_unknown']
                  - counts['material_not_flagged'])
    denominators = {'truth_pairs': len(truth), 'material_truth_pairs': material, 'negative_truth_pairs': negatives,
                    'truth_records': len(labels.functions), 'eligible_endpoints': len(eligible),
                    'scored_predictions': scored_predictions, 'f1': 2 * tp + fp + counts['identity_fn'],
                    'negative_candidate_edges': None}
    rates = {'identity_precision': _ratio(tp, scored_predictions), 'identity_recall': _ratio(tp, len(truth)),
             'identity_f1': _ratio(2 * tp, denominators['f1']),
             'identity_false_negative_rate': _ratio(counts['identity_fn'], len(truth)),
             'false_discovery_rate': _ratio(fp, scored_predictions), 'correspondence_false_positive_rate': None,
             'material_detection_recall': _ratio(counts['material_detected'], material),
             'negative_flag_rate': _ratio(counts['negative_flagged'], negatives),
             'truth_ambiguity_rate': _ratio(len(ambiguous), len(labels.functions)),
             'unmatched_endpoint_rate': _ratio(counts['unmatched_endpoints'], len(eligible)),
             'unmatched_truth_pair_rate': _ratio(counts['identity_fn'], len(truth)),
             'unknown_change_rate': _ratio(counts['unknown_change_pairs'], scored_predictions)}
    return {'counts': counts, 'denominators': denominators, 'rates': rates,
            'implicit_unchanged_requested': implicit_unchanged,
            'scope': 'explicit observations only; supplied labels require independent acceptance audit'}
