"""kev/1 generated artefacts are current (regenerate-and-compare) and the examples behave as labelled."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from kev_helpers import socket_guard
from pydantic import ValidationError

from patchtrace.kev import contracts

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kev'
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)


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


def test_no_stray_files_and_the_upstream_directory_is_left_to_k0():
    assert {p.name for p in OUT.iterdir() if p.is_file()} == {p.name for p in generator().render()}
    upstream = {p.name for p in (OUT / 'upstream').iterdir()}
    assert upstream == {'README.md', 'known_exploited_vulnerabilities_schema.json'}
    assert all(path.parent == OUT for path in generator().render())


def test_the_check_mode_reports_no_drift_on_a_clean_tree(capsys):
    assert generator().main(['--check']) == 0
    assert capsys.readouterr().err == ''


@pytest.mark.parametrize('name', generator().CONTRACTS)
def test_examples_validate_as_labelled(name):
    examples = json.loads((OUT / 'examples.json').read_text(encoding='utf-8'))
    assert set(examples) == set(generator().CONTRACTS)
    model = getattr(contracts, name)
    model.model_validate_json(json.dumps(examples[name]['valid']))
    assert len(examples[name]['invalid']) == 3
    for bad in examples[name]['invalid']:
        with pytest.raises(ValidationError):
            model.model_validate_json(json.dumps(bad['example']))


@pytest.mark.parametrize('name', generator().CONTRACTS)
def test_schema_ids_and_contract_const(name):
    schema = json.loads((OUT / f'{name}.json').read_text(encoding='utf-8'))
    assert schema['$id'] == f'https://patchtrace.local/schemas/kev/1/{name}.json'
    assert schema['$schema'] == 'https://json-schema.org/draft/2020-12/schema'
    assert schema['properties']['contract']['const'] == 'kev/1'
    assert schema['additionalProperties'] is False


def test_examples_are_synthetic_only():
    text = (OUT / 'examples.json').read_text(encoding='utf-8')
    assert 'SYNTHETIC' in text and 'example.invalid' in text
    assert 'microsoft.com' not in text and 'cisa.gov' not in json.dumps(json.loads(text)['KevEntry'])
