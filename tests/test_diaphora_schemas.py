"""diaphora/1 generated artefacts are current and the examples behave as labelled."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.diaphora import contracts

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'diaphora'


def generator():
    spec = importlib.util.spec_from_file_location('generate_diaphora_schemas',
                                                  ROOT / 'tools' / 'generate_diaphora_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_schemas_regenerate_identically_and_no_strays():
    rendered = generator().render()
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'
        assert '\r' not in text
    assert {p.name for p in OUT.iterdir()} == {p.name for p in rendered}


@pytest.mark.parametrize('name', generator().CONTRACTS)
def test_examples_validate_or_fail_as_labelled(name):
    model = getattr(contracts, name)
    entry = json.loads((OUT / 'examples.json').read_text(encoding='utf-8'))[name]
    model.model_validate_json(json.dumps(entry['valid']))
    assert entry['invalid']
    for case in entry['invalid']:
        with pytest.raises(ValidationError):
            model.model_validate_json(json.dumps(case['example']))


def test_ratio_and_transform_must_agree():
    valid = json.loads((OUT / 'examples.json').read_text(encoding='utf-8'))['DiaphoraMatch']['valid']
    with pytest.raises(ValidationError):
        contracts.DiaphoraMatch.model_validate_json(json.dumps(valid | {'ratio_milli': None}))
    with pytest.raises(ValidationError):
        contracts.DiaphoraMatch.model_validate_json(json.dumps(valid | {'older_rva': None}))
