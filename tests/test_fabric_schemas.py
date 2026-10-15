"""FAB-1 persisted contracts: JSON Schemas and examples of `fabric/1` (docs/specs/program-e/FAB-integration-plan.md s7).

Gates: regenerate-and-compare, valid and invalid examples behave as labelled (each invalid one for its own reason),
every valid example certifies its own ids, the stored batch contract is strict, frozen and float-free, and the schema
directory holds exactly what the generator writes, with LF only. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from patchtrace.fabric import contracts, ids, pins, store

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / 'docs' / 'schemas' / 'fabric'
CONTRACTS = {'FabricBatch': store.CONTRACT, 'PinEvent': pins.CONTRACT}


def generator():
    path = ROOT / 'tools' / 'generate_fabric_schemas.py'
    spec = importlib.util.spec_from_file_location('generate_fabric_schemas', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = generator()
MODELS = GEN.models()
RECORDS = GEN.valid_records()
EXAMPLES = json.loads((SCHEMAS / 'examples.json').read_text(encoding='utf-8'))
VALID = [(name, i) for name in GEN.CONTRACTS for i in range(len(EXAMPLES[name]['valid']))]
INVALID = [(name, i) for name in GEN.CONTRACTS for i in range(len(EXAMPLES[name]['invalid']))]


def rejection(name: str, document) -> str | None:
    """None when the document validates, else the validation error text (JSON mode, as stored rows are read)."""
    try:
        MODELS[name].model_validate_json(json.dumps(document))
    except ValidationError as exc:
        return str(exc)
    return None


# --- generated artefacts ------------------------------------------------------------------------------------------

def test_committed_files_equal_a_fresh_regeneration():
    rendered = GEN.render()
    assert len(rendered) == len(GEN.CONTRACTS) + 1
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'


def test_check_mode_reports_drift_and_write_mode_repairs_it(tmp_path, monkeypatch):
    monkeypatch.setattr(GEN, 'ROOT', tmp_path)
    monkeypatch.setattr(GEN, 'OUT', tmp_path / 'fabric')
    assert GEN.main(['--check']) == 1  # nothing written yet
    assert GEN.main([]) == 0 and GEN.main(['--check']) == 0
    (tmp_path / 'fabric' / 'Anchor.json').write_text('{}\n', encoding='utf-8')
    assert GEN.main(['--check']) == 1 and GEN.main([]) == 0 and GEN.main(['--check']) == 0


def test_no_stray_schema_files_and_lf_only():
    assert {p.name for p in SCHEMAS.iterdir()} == {p.name for p in GEN.render()}
    assert all(b'\r' not in p.read_bytes() for p in SCHEMAS.iterdir())


def test_gitattributes_pins_the_schema_directory_to_lf():
    lines = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
    assert 'docs/schemas/**/*.json text eol=lf' in lines


def test_every_persisted_record_class_of_the_package_is_covered_by_the_generator():
    classes = set()
    for module in (contracts, store, pins):
        classes |= {name for name, value in vars(module).items()
                    if isinstance(value, type) and issubclass(value, BaseModel) and value.__module__ == module.__name__
                    and not name.startswith('_')}
    # BatchHead is the part of a batch a reader checks first; StrictModel is the base of the stored rows
    assert classes - {'BatchHead', 'StrictModel'} == set(GEN.CONTRACTS)
    assert tuple(MODELS) == GEN.CONTRACTS


def test_examples_cover_every_contract_with_valid_and_invalid_cases():
    assert set(EXAMPLES) == set(GEN.CONTRACTS)
    for name, entry in EXAMPLES.items():
        assert entry['valid'] and len(entry['invalid']) >= 2, name


@pytest.mark.parametrize('name, index', VALID, ids=[f'{n}-{i}' for n, i in VALID])
def test_valid_examples_validate_and_round_trip(name, index):
    document = EXAMPLES[name]['valid'][index]
    record = MODELS[name].model_validate_json(json.dumps(document))
    assert json.loads(record.model_dump_json()) == document
    again = MODELS[name].model_validate_json(record.model_dump_json())
    assert again == record and again.model_dump_json() == record.model_dump_json()


@pytest.mark.parametrize('name, index', INVALID, ids=[f'{n}-{i}' for n, i in INVALID])
def test_invalid_examples_are_rejected_for_their_reason(name, index):
    case = EXAMPLES[name]['invalid'][index]
    error = rejection(name, case['example'])
    assert error is not None, case['reason']
    assert case['match'] in error, (case['reason'], error)


def test_valid_examples_certify_their_own_identities():
    for name in ('Anchor', 'FabricBatch'):
        for record in RECORDS[name]:
            for anchor in (record.anchors if name == 'FabricBatch' else (record,)):
                ids.verify_anchor(anchor)
    assert [w.witness_id for w in RECORDS['Witness']] == [ids.witness_id(w) for w in RECORDS['Witness']]
    assert {a.kind for a in RECORDS['Anchor']} == {'function', 'import', 'cwe'}
    assert {a.role for a in RECORDS['Anchor']} == {'observed', 'hint', 'stated'}


def test_a_stored_batch_is_internally_consistent():
    for batch in RECORDS['FabricBatch']:
        assert batch.contract == store.CONTRACT
        assert all((w.producer, w.batch) == (batch.producer, batch.batch) for a in batch.anchors for w in a.witnesses)
        assert [a.anchor_id for a in batch.anchors] == sorted(a.anchor_id for a in batch.anchors)


def test_schema_ids_and_contract_constants():
    for path in SCHEMAS.glob('*.json'):
        if path.name == 'examples.json':
            continue
        schema = json.loads(path.read_text(encoding='utf-8'))
        assert schema['$id'] == f'https://patchtrace.local/schemas/fabric/1/{path.stem}.json'
        assert schema['$schema'] == 'https://json-schema.org/draft/2020-12/schema'
        if path.stem in GEN.STANDALONE:
            assert schema['properties']['contract']['const'] == GEN.STANDALONE[path.stem] == CONTRACTS[path.stem]
        else:
            assert 'contract' not in schema['properties']


@pytest.mark.parametrize('name', GEN.CONTRACTS, ids=GEN.CONTRACTS)
def test_records_are_strict_frozen_and_forbid_extra_fields(name):
    record = RECORDS[name][0]
    assert record.model_config['extra'] == 'forbid' and record.model_config['strict'] is True
    assert record.model_config['frozen'] is True
    with pytest.raises(ValidationError):
        setattr(record, next(iter(type(record).model_fields)), None)


def test_no_contract_has_a_float_field():
    def walk(node):
        if isinstance(node, dict):
            assert node.get('type') != 'number', 'a contract carries no float'
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    for path in SCHEMAS.glob('*.json'):
        if path.name != 'examples.json':
            walk(json.loads(path.read_text(encoding='utf-8')))

