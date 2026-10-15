"""`mutation-case/1` record contract (SPEC-32 s8).

The strict pydantic models (`MutationCase`, `MutationSite`, `Rejection`), their JSON schema and the loader already live
in `tier_r/contracts.py` / `tier_r/schemas.py` (shared with the labels document, so they stay there unedited). This
module is the mutation package's single import point for them and adds what only the planter needs: the patch digest
that makes a case reproducible byte for byte, the case id, and the deterministic on-disk form.
"""
from __future__ import annotations

from collections.abc import Mapping

from ..common import canonical_json, sha256_bytes
from ..tier_r.contracts import (  # noqa: F401  (re-exported)
    COSMETIC_OPERATORS,
    SEMANTIC_OPERATORS,
    ContractError,
    MutationCase,
    MutationSite,
    Rejection,
    SourceRef,
    dump_json,
    load_mutation_case,
)

CONTRACT = 'mutation-case/1'
OPERATORS = SEMANTIC_OPERATORS + COSMETIC_OPERATORS

__all__ = ['CONTRACT', 'COSMETIC_OPERATORS', 'OPERATORS', 'SEMANTIC_OPERATORS', 'ContractError', 'MutationCase',
           'MutationSite', 'Rejection', 'SourceRef', 'case_id', 'dump_case', 'kind_of', 'load_case', 'patch_digest']


def kind_of(operator: str) -> str:
    if operator in SEMANTIC_OPERATORS:
        return 'semantic'
    if operator in COSMETIC_OPERATORS:
        return 'cosmetic'
    raise ValueError(f'unknown mutation operator {operator!r}')


def patch_digest(old: Mapping[str, str], new: Mapping[str, str]) -> str:
    """sha256 over the canonical JSON of {path: {old, new}} content hashes of every file that differs."""
    changed = {}
    for rel in sorted(set(old) | set(new)):
        a, b = old.get(rel), new.get(rel)
        if a != b:
            changed[rel] = {'old': None if a is None else sha256_bytes(a.encode('utf-8')),
                            'new': None if b is None else sha256_bytes(b.encode('utf-8'))}
    return sha256_bytes(canonical_json(changed))


def case_id(operator: str, seed: int, patch_sha256: str) -> str:
    return f'{operator}-{seed}-{patch_sha256[:10]}'


def dump_case(case: MutationCase) -> bytes:
    return dump_json(case.model_dump(mode='json'))


def load_case(data: bytes) -> MutationCase:
    return load_mutation_case(data)
