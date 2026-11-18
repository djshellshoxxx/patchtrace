"""Platform prerequisites are explicit; these controls confer no native acceptance."""
from __future__ import annotations

import importlib
import subprocess
from pathlib import Path

import pytest

from patchtrace.acquisition.contracts import AcquisitionError


@pytest.mark.parametrize('system,machine,bits', [('linux', 'x86_64', 64), ('darwin', 'arm64', 64),
                                              ('win32', 'ARM64', 64), ('win32', 'x86', 32),
                                              ('win32', 'AMD64', 32), ('win32', 'AMD64', True)])
def test_unsupported_platform_refuses_before_files_or_children(monkeypatch, system, machine, bits):
    module = importlib.import_module('patchtrace.acquisition.package_platform')

    def forbidden(*args, **kwargs):
        pytest.fail('platform refusal reached I/O or process creation')

    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    with pytest.raises(AcquisitionError) as error:
        module.require_supported_platform(system=system, machine=machine, pointer_bits=bits)
    assert error.value.code == 'PT-ACQ-UNSUPPORTED'


@pytest.mark.parametrize('machine', ['AMD64', 'x86_64'])
def test_windows_amd64_prerequisite_is_not_a_decoder_or_qualification_receipt(machine):
    module = importlib.import_module('patchtrace.acquisition.package_platform')
    assert module.require_supported_platform(system='win32', machine=machine, pointer_bits=64) == 'windows-amd64'
