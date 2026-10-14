"""tool-evidence/1 generated schemas are current (regenerate-and-compare) and every example behaves as labelled."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]


def generator():
    spec = importlib.util.spec_from_file_location('generate_intel_tools_schemas',
                                                  ROOT / 'tools' / 'generate_intel_tools_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_files_equal_a_fresh_regeneration():
    rendered = generator().render()
    assert len(rendered) == 9  # 8 contract schemas + examples.json
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'


def test_examples_validate_as_labelled():
    gen = generator()
    examples = json.loads((gen.OUT / 'examples.json').read_text(encoding='utf-8'))
    models = gen._models()
    assert set(examples) == set(gen.CONTRACTS)
    for name, entry in examples.items():
        for value in entry['valid']:
            models[name].model_validate_json(json.dumps(value))
        for bad in entry['invalid']:
            with pytest.raises(ValidationError):
                models[name].model_validate_json(json.dumps(bad['value']))
