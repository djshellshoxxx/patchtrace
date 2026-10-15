"""U8 prep: `tools/unified/bindiff_pin.py` checks the BinDiff pin file offline. It never invents a digest and refuses
placeholders; the committed pin is trust-on-first-use today, so the verified gate stays closed (G-U3 blocked)."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tools.unified import bindiff_pin as bp

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / 'tools' / 'bindiff_pin.json'
REAL = hashlib.sha256(b'a digest made by the test, not a BinDiff asset').hexdigest()
REAL2 = hashlib.sha256(b'another one').hexdigest()


def good() -> dict:
    """A well-formed, fully verified pin made of test digests (never a real BinDiff value)."""
    pin = json.loads(PIN.read_text(encoding='utf-8'))
    pin['verified'] = True
    pin['signature'].update(verified=True, signature_verified_by='gpg 2.4 key 4EB27DB2A3B88B8B', sha256=REAL2)
    pin['assets']['linux'].update(sha256=REAL, executable_sha256=REAL2)
    return pin


def write(tmp_path, pin) -> Path:
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps(pin), encoding='utf-8', newline='\n')
    return path


def test_committed_pin_is_schema_valid_and_not_verified():
    report = bp.check(PIN)
    assert report.errors == () and report.placeholders == ()
    pin = json.loads(PIN.read_text(encoding='utf-8'))
    if pin['verified'] is True:
        assert report.verified and not report.reasons
    else:
        assert not report.verified and any('verified' in r for r in report.reasons)


def test_a_fully_verified_pin_passes(tmp_path):
    report = bp.check(write(tmp_path, good()))
    assert report.verified and report.errors == () and report.reasons == ()


@pytest.mark.parametrize('digest', ['0' * 64, 'f' * 64, 'ab' * 32, '0123456789abcdef' * 4, hashlib.sha256(b'').hexdigest(),
                                    'TODO', 'unpinned', '', REAL[:63], REAL.upper(), 'g' * 64],
                         ids=['zeros', 'fs', 'two-chars', 'sequence', 'empty-input', 'todo', 'unpinned', 'blank',
                              'short', 'uppercase', 'not-hex'])
def test_placeholder_digests_are_refused_in_every_digest_field(tmp_path, digest):
    for edit in (lambda p: p['assets']['linux'].update(sha256=digest),
                 lambda p: p['assets']['linux'].update(executable_sha256=digest),
                 lambda p: p['signature'].update(sha256=digest)):
        pin = good()
        edit(pin)
        report = bp.check(write(tmp_path, pin))
        assert not report.verified and (report.placeholders or report.errors)


@pytest.mark.parametrize('edit, text', [
    (lambda p: p.update(contract='bindiff-pin/2'), 'contract'),
    (lambda p: p['assets']['linux'].update(url='https://evil.example/bindiff.deb'), 'url'),
    (lambda p: p['assets']['linux'].update(size=0), 'size'),
    (lambda p: p['assets']['linux'].update(size=True), 'size'),
    (lambda p: p['assets']['linux'].update(sha256=None), 'sha256'),
    (lambda p: p['assets'].pop('linux'), 'linux'),
    (lambda p: p['signature'].update(verified=False), 'signature'),
    (lambda p: p['signature'].update(signature_verified_by=None), 'signature'),
    (lambda p: p.update(verified='yes'), 'verified'),
    (lambda p: p.update(verified=False), 'verified')],
    ids=['contract', 'url', 'size-zero', 'size-bool', 'sha-null', 'no-linux', 'sig-unverified', 'sig-nobody',
         'verified-text', 'verified-false'])
def test_an_unverifiable_pin_names_the_reason(tmp_path, edit, text):
    pin = copy.deepcopy(good())
    edit(pin)
    report = bp.check(write(tmp_path, pin))
    assert not report.verified and any(text in line for line in (*report.errors, *report.reasons, *report.placeholders))


def test_the_advisory_windows_asset_may_stay_unverified_but_never_a_placeholder(tmp_path):
    pin = good()
    pin['assets']['windows'].update(sha256='0' * 64)
    report = bp.check(write(tmp_path, pin))
    assert not report.verified and report.placeholders


@pytest.mark.parametrize('text', ['', '{', '[]', '{"contract": 1}'], ids=['empty', 'truncated', 'list', 'bad-contract'])
def test_damaged_files_are_errors_not_crashes(tmp_path, text):
    path = tmp_path / 'pin.json'
    path.write_text(text, encoding='utf-8')
    assert bp.check(path).errors and not bp.check(path).verified
    assert bp.check(tmp_path / 'missing.json').errors


def test_cli_exit_codes_and_output(tmp_path, capsys):
    assert bp.main(['verify', '--pin', str(write(tmp_path, good()))]) == 0
    assert bp.main(['verify', '--pin', str(PIN), '--require-verified']) in (0, 3)
    capsys.readouterr()
    unverified = good()
    unverified['verified'] = False
    path = write(tmp_path, unverified)
    assert bp.main(['verify', '--pin', str(path)]) == 0           # schema is fine; the gate is separate
    assert bp.main(['verify', '--pin', str(path), '--require-verified']) == 3
    capsys.readouterr()
    assert bp.main(['verify', '--pin', str(tmp_path / 'missing.json')]) == 2
    assert bp.main(['print', '--pin', str(path)]) == 0
    doc = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert doc['verified'] is False and doc['contract'] == 'bindiff-pin-report/1' and doc['reasons']


def test_github_output_lines(tmp_path, capsys):
    out = tmp_path / 'gh.txt'
    assert bp.main(['verify', '--pin', str(write(tmp_path, good())), '--github-output', str(out)]) == 0
    assert out.read_text(encoding='utf-8').splitlines() == ['bindiff_pin_verified=true', 'bindiff_pin_version=8']
    capsys.readouterr()
