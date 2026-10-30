"""tools/milestone_notes.py: evidence/gate rendering never overstates (windows-acceptance spec section 4)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'milestone_notes.py'
spec = importlib.util.spec_from_file_location('milestone_notes', TOOL)
notes = importlib.util.module_from_spec(spec)
sys.modules['milestone_notes'] = notes
spec.loader.exec_module(notes)

BASE = ['--tag', 'v0.1.0-beta.9', '--sha', 'a' * 40, '--run-url', 'https://example.test/run/1', '--run-number', '9']


def junit(path, tests, failures=0, skipped=0):
    path.write_text(f'<testsuites><testsuite tests="{tests}" failures="{failures}" errors="0" skipped="{skipped}"/>'
                    '</testsuites>', encoding='utf-8')
    return path


def gen(tmp_path, *extra):
    out = tmp_path / 'notes.md'
    assert notes.main([*BASE, *extra, '--output', str(out)]) == 0
    return out.read_text(encoding='utf-8')


def test_nothing_supplied_claims_nothing(tmp_path):
    text = gen(tmp_path)
    assert 'production ready' not in text.lower()
    assert '0 pass, 0 fail, 18 not-run' in text
    assert 'FAIL' not in text and '| pass' not in text
    assert 'not run (no result file supplied)' in text
    assert '- Clean Windows GUI acceptance M01-M18' in text
    assert '- rz-diff and BinDiff live runs' in text
    assert 'not present in this build' in text


def test_counts_results_and_assets(tmp_path):
    assets = tmp_path / 'assets'
    assets.mkdir()
    (assets / 'PatchTrace-0.1.0-windows-x64.zip').write_bytes(b'zip-bytes')
    lin, win = junit(tmp_path / 'l.xml', 10, skipped=2), junit(tmp_path / 'w.xml', 12, failures=1)
    text = gen(tmp_path, '--assets', str(assets), '--junit', f'linux={lin}', '--junit', f'windows={win}',
               '--result', 'qa-ubuntu=success', '--result', 'qa-windows=failure', '--result', 'live-rizin=success')
    assert '9 bytes - SHA-256 ' in text
    assert 'linux-x86_64.tar.gz - not present' in text
    assert '8 passed, 2 skipped, 0 failed' in text
    assert 'FAIL: 11 passed, 0 skipped, 1 failed' in text
    assert '| Live rz-diff (rizin 0.9.1, CI fixture pair) | pass' in text
    assert '- BinDiff live run' in text and '- rz-diff and BinDiff' not in text
    assert 'Not implemented or not run: A6 native' in text


def test_the_setup_installer_is_listed_with_its_digest(tmp_path):
    # beta.543 attached PatchTrace-Windows-x64-Setup.exe but its notes listed only the ZIP and the tar.gz.
    assets = tmp_path / 'assets'
    assets.mkdir()
    (assets / 'PatchTrace-Windows-x64-Setup.exe').write_bytes(b'MZ-setup')
    text = gen(tmp_path, '--assets', str(assets))
    assert '- PatchTrace-Windows-x64-Setup.exe - 8 bytes - SHA-256 ' in text


def test_manual_pass_needs_evidence_and_all_18_close_the_gate(tmp_path):
    manual = tmp_path / 'm.json'
    manual.write_text(json.dumps({'M01': {'result': 'pass'}, 'M02': {'result': 'fail', 'evidence': 'x'}}))
    text = gen(tmp_path, '--manual', str(manual))
    assert '0 pass, 1 fail, 17 not-run' in text and 'M01: pass without evidence' in text
    manual.write_text(json.dumps({k: {'result': 'pass', 'evidence': 'docs/qa.md'} for k in notes.MANUAL_IDS}))
    text = gen(tmp_path, '--manual', str(manual))
    assert '18 pass, 0 fail, 0 not-run' in text and '- Clean Windows GUI acceptance' not in text
    manual.write_text(json.dumps({'M99': {'result': 'pass', 'evidence': 'x'}}))
    assert notes.main([*BASE, '--manual', str(manual)]) == 2


def test_invalid_inputs_and_preamble(tmp_path):
    with pytest.raises(SystemExit):
        notes.main([*BASE, '--result', 'qa-windows=passed'])
    with pytest.raises(SystemExit):
        notes.main([*BASE, '--result', 'unknown=success'])
    pre = tmp_path / 'pre.md'
    pre.write_text('Static intro.\n')
    assert gen(tmp_path, '--preamble', str(pre)).startswith('Static intro.\n\n## PatchTrace v0.1.0-beta.9')
    assert notes.main([*BASE, '--junit', f'linux={tmp_path / "missing.xml"}']) == 2
