"""Portable setup/child-exit controls; never native Ghidriff qualification."""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'tools/live_symbol_store_setup.py'


def workflow():
    return yaml.safe_load((ROOT / '.github/workflows/live-backend.yml').read_text(encoding='utf-8'))


def setup_step():
    return next(step for step in workflow()['jobs']['native']['steps']
                if step.get('name', '').startswith('Persist a symbol store'))


def test_seed_setup_does_not_clear_failed_child_status():
    assert '$global:LASTEXITCODE = 0' not in setup_step()['run']


def test_matrix_and_intentional_negative_reproduction_remain_distinct():
    native = workflow()['jobs']['native']
    assert native['strategy']['matrix']['variant'] == [
        'repro-plain-ghidriff', 'patchtrace-clean', 'patchtrace-seeded-store',
        'patchtrace-seeded-store-no-adjacent-pdb', 'raw-cache-hit']
    step = setup_step()
    assert step['if'] == "matrix.variant != 'patchtrace-clean' && matrix.variant != 'raw-cache-hit'"
    assert not step.get('continue-on-error') and not native.get('continue-on-error')
    assert 'python tools/live_symbol_store_setup.py "$fx" C:\\gsym C:\\gout' in step['run']
    repro = next(step for step in native['steps'] if step.get('name', '').startswith('Reproduce cached-PDB'))
    assert repro['if'] == "matrix.variant == 'repro-plain-ghidriff'"
    assert '--no-symbols' in repro['run'] and '$code = $LASTEXITCODE' in repro['run']
    assert "if ($code -eq 0 -or -not (Select-String -Path repro.log -SimpleMatch 'symbol is already downloaded' -Quiet))" in repro['run']
    assert 'throw ' in repro['run'] and '$global:LASTEXITCODE = 0' in repro['run']
    triggers = workflow().get('on', workflow().get(True))
    for event in ('push', 'pull_request'):
        assert 'tools/live_symbol_store_setup.py' in triggers[event]['paths']


def authored_setup(tmp_path, *, missing_pdb=False, engine_exit=0):
    fixtures = tmp_path / 'fixture inputs'
    analysed = tmp_path / 'analysed copies'
    output = tmp_path / 'engine output'
    fake = tmp_path / 'authored modules'
    for folder in (fixtures, analysed, output, fake / 'ghidriff'):
        folder.mkdir(parents=True)
    identity = uuid.UUID('01234567-89ab-cdef-0123-456789abcdef')
    key = identity.hex.upper() + '1'
    for side in ('old', 'new'):
        contents = b'authored inert fixture RSDS' + identity.bytes_le + struct.pack('<I', 1)
        contents += (side + '.pdb').encode() + b'\0'
        (fixtures / (side + '.dll')).write_bytes(contents)
        (analysed / (side + '.dll')).write_bytes(contents)
        if not (missing_pdb and side == 'old'):
            (fixtures / (side + '.pdb')).write_bytes(('authored ' + side + ' symbols').encode())
    receipt = tmp_path / 'authored-child.json'
    (fake / 'ghidriff/__init__.py').write_text('', encoding='utf-8')
    (fake / 'ghidriff/__main__.py').write_text(
        'import json, os, sys\nfrom pathlib import Path\n'
        'Path(os.environ["AUTHORED_SETUP_RECEIPT"]).write_text(json.dumps({'
        '"argv": sys.argv[1:], "sentinel": os.environ.get("AUTHORED_SETUP_SENTINEL")}))\n'
        'print("authored engine stdout")\n'
        'print("authored engine stderr", file=sys.stderr)\n'
        'raise SystemExit(int(os.environ["AUTHORED_ENGINE_EXIT"]))\n', encoding='utf-8')
    environment = {**os.environ, 'PYTHONPATH': str(fake), 'AUTHORED_SETUP_RECEIPT': str(receipt),
                   'AUTHORED_SETUP_SENTINEL': 'preserve inherited setup environment',
                   'AUTHORED_ENGINE_EXIT': str(engine_exit)}
    result = subprocess.run([sys.executable, str(RUNNER), str(fixtures), str(analysed), str(output)],
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    return result, receipt, fixtures, analysed, output, key


def test_success_seeds_exact_bytes_and_preserves_symbol_enabled_arguments(tmp_path):
    result, receipt, fixtures, analysed, output, key = authored_setup(tmp_path)
    assert result.returncode == 0, result.stderr
    record = json.loads(receipt.read_text())
    assert record == {'argv': [str(analysed / 'old.dll'), str(analysed / 'new.dll'),
                               '--output-path', str(output)],
                      'sentinel': 'preserve inherited setup environment'}
    for side in ('old', 'new'):
        name = side + '.pdb'
        assert (output / 'symbols' / name / key / name).read_bytes() == (fixtures / name).read_bytes()
    assert 'authored engine stdout' in result.stdout
    assert 'authored engine stderr' in result.stderr


def test_failed_seed_stops_before_engine_launch(tmp_path):
    result, receipt, *_ = authored_setup(tmp_path, missing_pdb=True)
    assert result.returncode != 0
    assert not receipt.exists()
    assert 'FileNotFoundError' in result.stderr


@pytest.mark.parametrize('engine_exit', [1, 23])
def test_nonzero_engine_exit_fails_setup(tmp_path, engine_exit):
    result, receipt, *_ = authored_setup(tmp_path, engine_exit=engine_exit)
    assert receipt.is_file()  # the seed succeeded and the authored child actually ran
    assert result.returncode == engine_exit
    assert 'authored engine stdout' in result.stdout and 'authored engine stderr' in result.stderr


def test_invalid_setup_arguments_do_not_succeed(tmp_path):
    result = subprocess.run([sys.executable, str(RUNNER)], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
    assert 'required' in result.stderr
