"""Dependency pin and bounded upstream security controls, not app reachability claims."""
from __future__ import annotations

import importlib.metadata
import json
import tomllib
from fractions import Fraction
from pathlib import Path
from typing import Annotated

import pytest
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, with_config
from pydantic.dataclasses import dataclass
from typing_extensions import TypedDict


class ExtraKeys(BaseModel):
    model_config = ConfigDict(extra='allow')
    __pydantic_extra__: dict[Annotated[str, Field(pattern=r'^x_')], int] = Field(init=False)


@with_config(ConfigDict(extra='allow'))
class AliasedTypedDict(TypedDict):
    value: Annotated[int, Field(alias='wire_value')]


@dataclass(config=ConfigDict(extra='allow'))
class AliasedDataclass:
    value: int = Field(alias='wire_value')


def test_runtime_pin_contains_reviewed_pydantic_security_fixes():
    root = Path(__file__).resolve().parents[1]
    dependencies = tomllib.loads((root / 'pyproject.toml').read_text())['project']['dependencies']
    assert [item for item in dependencies if item.startswith('pydantic==')] == ['pydantic==2.14.2']
    assert importlib.metadata.version('pydantic') == '2.14.2'
    assert importlib.metadata.version('pydantic-core') == '2.50.2'


@pytest.mark.parametrize('mode', ['python', 'json'])
def test_extra_key_constraints_apply_in_both_validation_modes(mode):
    """GHSA-qpmf-fgh3-ff25: JSON extras must validate keys as well as values."""
    def validate(data):
        return (ExtraKeys.model_validate(data) if mode == 'python'
                else ExtraKeys.model_validate_json(json.dumps(data)))

    assert validate({'x_allowed': 1}).model_extra == {'x_allowed': 1}
    with pytest.raises(ValidationError):
        validate({'outside_prefix': 1})


@pytest.mark.parametrize('model', [AliasedTypedDict, AliasedDataclass])
@pytest.mark.parametrize('mode', ['python', 'json'])
def test_extra_field_name_cannot_overwrite_validated_alias(model, mode):
    """GHSA-3r8g-cqwr-jr29: both aliases must retain the validated integer."""
    adapter = TypeAdapter(model)
    data = {'wire_value': 1, 'value': 'not-an-integer', 'unrelated_extra': 'retained'}
    result = (adapter.validate_python(data) if mode == 'python'
              else adapter.validate_json(json.dumps(data)))
    result = result if isinstance(result, dict) else vars(result)
    assert result == {'value': 1, 'unrelated_extra': 'retained'}


@pytest.mark.parametrize('sign', ['', '-'])
def test_fraction_exponent_is_bounded_before_large_integer_construction(sign):
    """GHSA-gj4f-r7mf-jjxh: exercise only the adjacent, bounded 4300/4301 cases."""
    adapter = TypeAdapter(Fraction)
    assert isinstance(adapter.validate_python(f'1e{sign}4300'), Fraction)
    with pytest.raises(ValidationError):
        adapter.validate_python(f'1e{sign}4301')
