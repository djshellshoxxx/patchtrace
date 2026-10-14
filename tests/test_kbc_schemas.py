"""kbcorrelation/1 generated artefacts are current (regenerate-and-compare) and examples behave as labelled."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.kbcorrelation import contracts, errors

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kbcorrelation'


def generator():
    spec = importlib.util.spec_from_file_location('generate_kbc_schemas', ROOT / 'tools' / 'generate_kbc_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_files_equal_a_fresh_regeneration():
    rendered = generator().render()
    assert len(rendered) == len(generator().CONTRACTS) + 1
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'


def test_no_stray_schema_files():
    assert {p.name for p in OUT.iterdir()} == {p.name for p in generator().render()}


def test_examples_validate_as_labelled():
    examples = json.loads((OUT / 'examples.json').read_text(encoding='utf-8'))
    assert set(examples) == set(generator().CONTRACTS)
    for name, entry in examples.items():
        model = getattr(contracts, name, None) or getattr(errors, name)
        model.model_validate_json(json.dumps(entry['valid']))
        assert entry['invalid'], name
        for bad in entry['invalid']:
            with pytest.raises(ValidationError):
                model.model_validate_json(json.dumps(bad['example']))


def test_schema_ids_and_contract_const():
    for path in OUT.glob('*.json'):
        if path.name == 'examples.json':
            continue
        schema = json.loads(path.read_text(encoding='utf-8'))
        assert schema['$id'] == f'https://patchtrace.local/schemas/kbcorrelation/1/{path.stem}.json'
        if path.stem not in {'SourceRef', 'SearchScope'}:
            assert schema['properties']['contract']['const'] == 'kbcorrelation/1'
