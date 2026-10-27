"""Phase 2 handoff contracts: the supplied JSON Schema and its nine valid / nine invalid synthetic examples.

Scope: JSON Schema (draft 2020-12) conformance only. The schema's own $comment states that exact score
arithmetic, identity hashes, run/side ownership, evidence linkage and atomic store invariants need runtime
semantic validators; those are NOT covered here and are not claimed by these tests.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / 'docs' / 'schemas' / 'phase2'
SPEC_DIR = ROOT / 'docs' / 'specs' / 'phase2'
SCHEMA_PATH = SCHEMA_DIR / 'PatchTrace-Phase2-Contracts-v1.schema.json'
EXAMPLES_PATH = SCHEMA_DIR / 'PatchTrace-Phase2-Synthetic-Examples-v1.json'

SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
EXAMPLES = json.loads(EXAMPLES_PATH.read_text(encoding='utf-8'))
CONTRACTS = sorted(ref.rsplit('/', 1)[1] for ref in (o['$ref'] for o in SCHEMA['oneOf']))


def _contract_validator(name: str) -> Draft202012Validator:
    # Validate one named $defs entry on its own so a failure names the real rule, not the generic oneOf message.
    return Draft202012Validator({'$defs': SCHEMA['$defs'], '$ref': f'#/$defs/{name}'})


def test_schema_is_a_valid_draft_2020_12_document():
    Draft202012Validator.check_schema(SCHEMA)


def test_schema_covers_the_nine_top_level_contracts():
    assert len(CONTRACTS) == 9
    assert set(EXAMPLES['valid']) == set(CONTRACTS) == set(EXAMPLES['invalid'])


@pytest.mark.parametrize('name', CONTRACTS)
def test_valid_example_passes_its_contract(name):
    errors = list(_contract_validator(name).iter_errors(EXAMPLES['valid'][name]))
    assert not errors, [e.message for e in errors]


@pytest.mark.parametrize('name', CONTRACTS)
def test_invalid_example_fails_its_contract(name):
    assert list(_contract_validator(name).iter_errors(EXAMPLES['invalid'][name])), name


@pytest.mark.parametrize('kind,expect_ok', [('valid', True), ('invalid', False)])
def test_top_level_one_of_agrees_with_the_labels(kind, expect_ok):
    top = Draft202012Validator(SCHEMA)
    for name, obj in EXAMPLES[kind].items():
        assert top.is_valid(obj) is expect_ok, name


def test_provenance_hashes_match_the_imported_files():
    recorded = {}
    for line in (SPEC_DIR / 'PROVENANCE.md').read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64 and all(c in '0123456789abcdef' for c in parts[0]):
            recorded[parts[1]] = parts[0]
    assert set(recorded) == {
        'PatchTrace-Extension-Specification-2026-10-11.md',
        'PatchTrace-Phase2-Contracts-v1.schema.json',
        'PatchTrace-Phase2-Synthetic-Examples-v1.json',
    }
    for name, digest in recorded.items():
        path = SPEC_DIR / name if name.endswith('.md') else SCHEMA_DIR / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
