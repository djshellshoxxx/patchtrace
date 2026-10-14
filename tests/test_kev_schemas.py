"""kev/1 generated artefacts are current (regenerate-and-compare) and the examples behave as labelled."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.kev import contracts

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kev'


def generator():
    spec = importlib.util.spec_from_file_location('generate_kev_schemas', ROOT / 'tools' / 'generate_kev_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_schemas_regenerate_identically():
    rendered = generator().render()
    assert len(rendered) == len(generator().CONTRACTS) + 1
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'
        assert '\r' not in text


def test_no_stray_schema_files():
    assert {p.name for p in OUT.iterdir() if p.is_file()} == {p.name for p in generator().render()}
    assert {p.name for p in (OUT / 'upstream').iterdir()} == {'README.md', 'known_exploited_vulnerabilities_schema.json'}


def test_examples_validate_as_labelled():
    examples = json.loads((OUT / 'examples.json').read_text(encoding='utf-8'))
    assert set(examples) == set(generator().CONTRACTS)
    for name, entry in examples.items():
        model = getattr(contracts, name)
        model.model_validate_json(json.dumps(entry['valid']))
        assert entry['invalid'], name
        for bad in entry['invalid']:
            with pytest.raises(ValidationError):
                model.model_validate_json(json.dumps(bad['example']))


def test_schema_ids_and_contract_const():
    for name in generator().CONTRACTS:
        schema = json.loads((OUT / f'{name}.json').read_text(encoding='utf-8'))
        assert schema['$id'] == f'https://patchtrace.local/schemas/kev/1/{name}.json'
        assert schema['properties']['contract']['const'] == 'kev/1'
        assert schema['additionalProperties'] is False


def test_examples_are_synthetic_only():
    text = (OUT / 'examples.json').read_text(encoding='utf-8')
    assert 'CVE-2099-' in text and 'CVE-2021-' not in text and 'CVE-2026-' not in text
