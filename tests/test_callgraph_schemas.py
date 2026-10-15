"""callgraph generated schemas are current (regenerate-and-compare) and every example behaves as labelled."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]


def generator():
    spec = importlib.util.spec_from_file_location('generate_callgraph_schemas',
                                                  ROOT / 'tools' / 'generate_callgraph_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_files_equal_a_fresh_regeneration():
    gen = generator()
    rendered = gen.render()
    assert len(rendered) == len(gen.CONTRACTS) + 1  # one schema per contract + examples.json
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'
    assert {p.name for p in gen.OUT.iterdir()} == {p.name for p in rendered}


def test_committed_files_use_lf():
    gen = generator()
    assert all(b'\r' not in p.read_bytes() for p in gen.OUT.iterdir())


def test_examples_validate_as_labelled():
    gen = generator()
    examples = json.loads((gen.OUT / 'examples.json').read_text(encoding='utf-8'))
    models = gen._models()
    assert set(examples) == set(gen.CONTRACTS)
    invalid = 0
    for name, entry in examples.items():
        for value in entry['valid']:
            models[name].model_validate_json(json.dumps(value))
        for bad in entry['invalid']:
            invalid += 1
            with pytest.raises(ValidationError):
                models[name].model_validate_json(json.dumps(bad['value']))
    assert invalid >= 8


def test_every_schema_names_its_contract_literal():
    gen = generator()
    for name in ('GraphView', 'CallDelta', 'GraphLead', 'NeighbourhoodEvolution', 'GraphExport'):
        schema = json.loads((gen.OUT / f'{name}.json').read_text(encoding='utf-8'))
        assert schema['properties']['contract']['const'].startswith('workbench-graph')
