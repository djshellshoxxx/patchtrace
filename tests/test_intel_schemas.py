"""intelligence/1 generated artefacts are current (regenerate-and-compare), the vendored OASIS schemas keep their
pinned hashes, and every generated example behaves as labelled (SPEC-28 sections B and E)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.intelligence import contracts

ROOT = Path(__file__).resolve().parents[1]


def generator():
    spec = importlib.util.spec_from_file_location('generate_intelligence_schemas',
                                                  ROOT / 'tools' / 'generate_intelligence_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_files_equal_a_fresh_regeneration():
    rendered = generator().render()
    assert len(rendered) == 13  # schema_data.py + 11 contract schemas + examples.json
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'


def test_vendored_oasis_schemas_keep_their_pinned_hashes():
    gen = generator()
    for name, digest in gen.PINNED.items():
        assert hashlib.sha256((gen.OASIS / name).read_bytes()).hexdigest() == digest
    from patchtrace.intelligence.csaf import schema_data
    assert schema_data.CSAF_SCHEMA_SHA256 == gen.PINNED['csaf_json_schema.json']


def test_unsupported_schema_keywords_fail_generation():
    with pytest.raises(SystemExit, match='unsupported JSON Schema keyword'):
        generator().strip({'type': 'object', 'if': {}})


def test_examples_validate_as_labelled():
    examples = json.loads((ROOT / 'docs' / 'schemas' / 'intelligence' / 'examples.json').read_text(encoding='utf-8'))
    assert set(examples) == set(generator().CONTRACTS)
    for name, entry in examples.items():
        model = getattr(contracts, name)
        record = model.model_validate_json(json.dumps(entry['valid']))
        assert json.loads(record.model_dump_json()) == entry['valid']  # schema round trip
        for case in entry['invalid']:
            with pytest.raises(ValidationError):
                model.model_validate_json(json.dumps(case['example']))
