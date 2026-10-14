"""yara-rules/1 contracts: strict, frozen, additive; generated schemas and examples do not drift."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.yarax import contracts as c
from patchtrace.yarax import errors, ports
from patchtrace.yarax.limits import LIMITS, RuleLimits

ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location('generate_yarax_schemas', ROOT / 'tools' / 'generate_yarax_schemas.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GEN = _generator()


def test_schemas_and_examples_are_current():
    stale = [p.name for p, text in GEN.render().items() if not p.is_file() or p.read_text(encoding='utf-8') != text]
    assert stale == []


@pytest.mark.parametrize('name', GEN.CONTRACTS)
def test_valid_examples_roundtrip(name):
    model = getattr(c, name)
    record = GEN.valid_records()[name]
    assert model.model_validate_json(record.model_dump_json()) == record


def _invalid_cases():
    valid = GEN.valid_records()
    for name, cases in GEN._invalid(valid).items():
        for number, case in enumerate(cases):
            yield pytest.param(name, case['value'], id=f'{name[:8]}-{number}')


@pytest.mark.parametrize('name,value', list(_invalid_cases()))
def test_invalid_examples_are_rejected(name, value):
    with pytest.raises(ValidationError):
        getattr(c, name).model_validate_json(json.dumps(value))


def test_models_are_frozen_and_forbid_extra():
    stamp = GEN.valid_records()['EngineStamp']
    with pytest.raises(ValidationError):
        stamp.version = '2'
    with pytest.raises(ValidationError):
        c.EngineStamp.model_validate({**stamp.model_dump(), 'x': 1})


def test_strict_mode_coerces_nothing():
    cell = GEN.valid_records()['CellResult'].model_dump()
    with pytest.raises(ValidationError):
        c.CellResult.model_validate({**cell, 'hits': '1'})


def test_bytes_pattern_must_agree_with_its_counts():
    feature = GEN.valid_records()['RuleCandidate'].features[0].model_dump()
    with pytest.raises(ValidationError):
        c.BytesFeature.model_validate({**feature, 'literal': 9})
    with pytest.raises(ValidationError):
        c.BytesFeature.model_validate({**feature, 'pattern': 'zz ' + feature['pattern'][3:]})


def test_unscanned_cell_is_never_a_negative():
    base = dict(rule_name='r', target_id='t', state='not-scanned')
    assert c.CellResult(**base).verdict == 'unscored'
    with pytest.raises(ValidationError):
        c.CellResult(**base, verdict='unexpected-miss')


def test_import_needs_exactly_one_of_name_and_ordinal():
    base = dict(dll='a.dll', origin='pe-imports', separation='both')
    c.ImportFeature(name='X', **base)
    c.ImportFeature(ordinal=7, **base)
    for extra in ({}, {'name': 'X', 'ordinal': 7}):
        with pytest.raises(ValidationError):
            c.ImportFeature(**base, **extra)


def test_error_codes_match_the_plan():
    assert len(errors.ERROR_CODES) == 14
    assert all(code.startswith('PT-RULE-') for code in errors.ERROR_CODES)
    err = errors.RulesError('PT-RULE-MASK', 'no verified extent')
    assert (err.code, str(err)) == ('PT-RULE-MASK', 'PT-RULE-MASK: no verified extent')


def test_limits_digest_is_stable_and_sensitive():
    assert LIMITS.digest() == RuleLimits().digest()
    assert LIMITS.digest() != RuleLimits(cells=1).digest()
    assert (LIMITS.rule_text_bytes, LIMITS.cells, LIMITS.target_timeout_s) == (65536, 105000, 30)


def test_ports_are_protocols_with_no_behaviour():
    class Fake:
        def accepted_pairs(self, project_id):
            return ()

    assert isinstance(Fake(), ports.PairSourcePort)
    assert not isinstance(object(), ports.PairSourcePort)


def test_contract_modules_do_not_import_the_engine_or_qt():
    code = ('import sys; import patchtrace.yarax.contracts, patchtrace.yarax.ports, patchtrace.yarax.errors;'
            ' bad = {"yara_x", "iced_x86", "PySide6", "PyQt5", "PyQt6"} & set(sys.modules); assert not bad, bad')
    import subprocess
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                          env={'PYTHONPATH': str(ROOT / 'src')})
    assert done.returncode == 0, done.stderr
