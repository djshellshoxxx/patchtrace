"""Portable checker-boundary controls; no compiler, SDK probe, DLL or package executes."""
from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest

from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.acquisition.package_fdi_abi import EXPECTED_LAYOUT


@pytest.mark.parametrize('overflow', ['probe', 'compiler'])
def test_completed_process_total_cannot_bypass_native_checker_output_cap(monkeypatch, tmp_path, overflow):
    checker = importlib.import_module('tools.check_package_fdi_abi')
    monkeypatch.setattr(checker, 'require_supported_platform', lambda: 'windows-amd64')
    raw = json.dumps(EXPECTED_LAYOUT, sort_keys=True).encode()
    tail = b' ' * (4096 - len(raw)) + raw
    calls = []

    def reported(_argv, **options):
        calls.append(options)
        if len(calls) == 1:
            return SimpleNamespace(returncode=0, reason=None, stderr_total=0,
                                   stdout_total=1024 * 1024 + 1 if overflow == 'compiler' else 0,
                                   log_bytes=b'')
        return SimpleNamespace(returncode=0, reason=None, stderr_total=0,
                               stdout_total=8192 if overflow == 'probe' else len(tail), log_bytes=tail)

    monkeypatch.setattr(checker, 'run_process', reported)
    with pytest.raises(AcquisitionError):
        checker.check(str(tmp_path / 'authored-compiler.exe'))


@pytest.mark.parametrize('phase', ['compiler', 'probe'])
@pytest.mark.parametrize('fault', ['exit', 'reason'])
def test_native_checker_refuses_failed_phase_before_success_receipt(monkeypatch, tmp_path, phase, fault):
    checker = importlib.import_module('tools.check_package_fdi_abi')
    monkeypatch.setattr(checker, 'require_supported_platform', lambda: 'windows-amd64')
    raw = json.dumps(EXPECTED_LAYOUT, sort_keys=True).encode()
    calls = []

    def reported(_argv, **options):
        calls.append(options)
        current = 'compiler' if len(calls) == 1 else 'probe'
        failed = current == phase
        return SimpleNamespace(returncode=1 if failed and fault == 'exit' else 0,
                               reason='timeout' if failed and fault == 'reason' else None,
                               stdout_total=0 if current == 'compiler' else len(raw), stderr_total=0,
                               log_bytes=b'' if current == 'compiler' else raw)

    monkeypatch.setattr(checker, 'run_process', reported)
    with pytest.raises(AcquisitionError):
        checker.check(str(tmp_path / 'authored-compiler.exe'))
    assert len(calls) == (1 if phase == 'compiler' else 2)
