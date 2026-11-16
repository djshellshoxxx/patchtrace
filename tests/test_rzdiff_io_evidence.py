"""Authored output/fake process controls, never evidence of a live native run."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from tools.rzdiff import native_evidence as evidence


def rows(errors=(0, 0, 0, 0), reads=(2, 2), overlaps=(0, 1)):
    keys = [(a, b, overlap) for overlap in overlaps for a, b in ((1, 2), (2, 1))]
    return ''.join(f'distinct-io {a}:{b} overlap={overlap} errors={error} reads={reads[0]},{reads[1]}\n'
                   for (a, b, overlap), error in zip(keys, errors, strict=True))


CASES = [
    ('stock', 'io', 1, rows((3, 0, 3, 0))),
    ('corrected', 'io', 0, rows()),
    ('corrected', 'io-wrong-bytes', 1, rows((2, 2, 2, 2))),
    ('corrected', 'io-wrong-io', 1, rows((3, 2), reads=(4, 0), overlaps=(1,))),
]
IDS = ['stock', 'corrected', 'wrong-bytes', 'wrong-io']


@pytest.mark.parametrize('variant,mode,code,stdout', CASES, ids=IDS)
def test_exact_mode_observations_pass_and_row_order_is_irrelevant(variant, mode, code, stdout):
    evidence.validate(variant, code, stdout, mode=mode)
    evidence.validate(variant, code, '\n'.join(reversed(stdout.splitlines())), mode=mode)


@pytest.mark.parametrize('variant,mode,code,stdout', CASES, ids=IDS)
@pytest.mark.parametrize('mutation', [
    lambda s: '',
    lambda s: '\n'.join(s.splitlines()[:-1]),
    lambda s: s + s.splitlines()[0] + '\n',
    lambda s: s.replace('distinct-io 1:2', 'distinct-io 1:1', 1),
    lambda s: s.replace('errors=', 'errors=-', 1),
    lambda s: s.replace('errors=', 'errors=9', 1),
    lambda s: s.replace('reads=2', 'reads=0', 1).replace('reads=4', 'reads=0', 1),
    lambda s: s.replace(',2', ',0', 1).replace(',0', ',9', 1),
    lambda s: s + 'unrelated diagnostic\n',
], ids=['empty', 'truncated', 'duplicate', 'wrong-inventory', 'negative-errors', 'wrong-errors',
        'missing-left-reads', 'wrong-right-reads', 'extra-output'])
def test_incomplete_or_changed_io_evidence_fails(variant, mode, code, stdout, mutation):
    with pytest.raises(ValueError):
        evidence.validate(variant, code, mutation(stdout), mode=mode)


@pytest.mark.parametrize('variant,mode,code,stdout', CASES, ids=IDS)
@pytest.mark.parametrize('wrong_exit', [-11, 2, 127])
def test_complete_rows_cannot_hide_process_failure(variant, mode, code, stdout, wrong_exit):
    with pytest.raises(ValueError):
        evidence.validate(variant, wrong_exit, stdout, mode=mode)
    with pytest.raises(ValueError):
        evidence.validate(variant, 1 - code, stdout, mode=mode)


@pytest.mark.parametrize('mode', ['io-wrong-bytes', 'io-wrong-io'])
def test_negative_control_requires_real_observed_failure(mode):
    with pytest.raises(ValueError):
        evidence.validate('corrected', 1, rows(), mode=mode)


@pytest.mark.parametrize('variant,mode', [('unknown', 'io'), ('corrected', 'unknown'),
                                        ('stock', 'io-wrong-bytes'), ('stock', 'io-wrong-io')])
def test_invalid_selection_refused_before_filesystem_or_process(variant, mode, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('must not execute'))
    out = tmp_path / 'not-created'
    with pytest.raises(ValueError):
        evidence.run(variant, tmp_path / 'absent', out, mode=mode)
    assert not out.exists()


@pytest.mark.parametrize('variant,mode,code,stdout', CASES, ids=IDS)
def test_runner_dispatches_exact_mode_and_preserves_receipts(variant, mode, code, stdout, tmp_path, monkeypatch):
    executable = tmp_path / 'fake-control'
    executable.write_bytes(b'not executable; fake process output only')
    calls = []

    def fake(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, code, stdout.encode(), b'')

    monkeypatch.setattr(subprocess, 'run', fake)
    out = tmp_path / 'evidence'
    assert evidence.run(variant, executable, out, mode=mode)
    assert calls == [[str(executable.resolve()), *evidence.MODE_ARGS[mode]]]
    receipt = json.loads((out / 'native-result.json').read_text())
    assert receipt['accepted'] is True and receipt['mode'] == mode
    assert receipt['arguments'] == list(evidence.MODE_ARGS[mode])
    assert receipt['stdout_sha256'] == hashlib.sha256(stdout.encode()).hexdigest()
    original = {p.name: p.read_bytes() for p in out.iterdir()}
    with pytest.raises(FileExistsError):
        evidence.run(variant, executable, out, mode=mode)
    assert len(calls) == 1
    assert original == {p.name: p.read_bytes() for p in out.iterdir()}


@pytest.mark.parametrize('failure', ['truncated', 'invalid-utf8', 'stderr', 'timeout'])
def test_failure_retains_exact_raw_output(tmp_path, monkeypatch, failure):
    executable = tmp_path / 'fake'
    executable.write_bytes(b'fake')
    stdout = b'partial' if failure in ('truncated', 'timeout') else rows().encode()
    if failure == 'invalid-utf8':
        stdout = b'\xff'
    stderr = b'first diagnostic' if failure in ('stderr', 'timeout') else b''

    def fake(argv, **kwargs):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(argv, 1, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, 0, stdout, stderr)

    monkeypatch.setattr(subprocess, 'run', fake)
    out = tmp_path / 'evidence'
    assert not evidence.run('corrected', executable, out, mode='io')
    assert (out / 'native-matrix.log').read_bytes() == stdout
    assert (out / 'native-stderr.log').read_bytes() == stderr
    receipt = json.loads((out / 'native-result.json').read_text())
    assert receipt['accepted'] is False and receipt['error']
    assert receipt['stdout_sha256'] == hashlib.sha256(stdout).hexdigest()
    assert receipt['stderr_sha256'] == hashlib.sha256(stderr).hexdigest()


@pytest.mark.parametrize('mode', tuple(evidence.MODE_ARGS))
def test_cli_selects_mode_without_executing_native_code(mode, tmp_path, monkeypatch):
    calls = []

    def fake(variant, executable, output, **kwargs):
        calls.append((variant, executable, output, kwargs))
        return False

    monkeypatch.setattr(evidence, 'run', fake)
    monkeypatch.setattr(sys, 'argv', ['native_evidence.py', '--variant', 'corrected',
                                    '--executable', str(tmp_path / 'fake'), '--output', str(tmp_path / 'out'),
                                    '--mode', mode])
    with pytest.raises(SystemExit) as stopped:
        evidence.main()
    assert stopped.value.code == 1
    assert calls == [('corrected', tmp_path / 'fake', tmp_path / 'out', {'mode': mode})]


def test_cli_rejects_stock_negative_mode_before_run(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, 'run', lambda *a, **k: pytest.fail('must not execute'))
    monkeypatch.setattr(sys, 'argv', ['native_evidence.py', '--variant', 'stock', '--mode', 'io-wrong-io',
                                    '--executable', str(tmp_path / 'fake'), '--output', str(tmp_path / 'out')])
    with pytest.raises(SystemExit) as stopped:
        evidence.main()
    assert stopped.value.code == 2
    assert not (tmp_path / 'out').exists()
