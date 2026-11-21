"""Unexpected optional-package initialization errors must not prevent PatchTrace startup."""
import builtins
import importlib.util
import sys
from pathlib import Path

import pytest

from patchtrace import optional_deps


@pytest.mark.parametrize('module_name,capability', [
    ('rapidfuzz', 'rapidfuzz'),
    ('iced_x86', 'iced-x86'),
    ('yara_x', 'yara-x'),
])
def test_unexpected_optional_package_init_failure_is_reported_as_unavailable(
        monkeypatch, module_name, capability):
    name = 'patchtrace._optional_test_' + module_name
    spec = importlib.util.spec_from_file_location(name, Path(optional_deps.__file__))
    candidate = importlib.util.module_from_spec(spec)
    original_import = builtins.__import__

    def broken_import(name, *args, **kwargs):
        if name == module_name:
            raise RuntimeError('synthetic optional extension initialization failure')
        return original_import(name, *args, **kwargs)

    sys.modules[name] = candidate
    try:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, '__import__', broken_import)
            spec.loader.exec_module(candidate)
        cap = candidate.probe((capability,))[capability]
        assert not cap.available
        assert 'RuntimeError' in cap.detail
        assert 'patchtrace[' in cap.detail
    finally:
        sys.modules.pop(name, None)
