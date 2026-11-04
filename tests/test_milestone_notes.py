"""tools/milestone_notes.py: evidence/gate rendering never overstates (windows-acceptance spec section 4)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest
from pe_builder import PeSpec, build_pe

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


ZIP, PORTABLE, SETUP, TARBALL = ('PatchTrace-0.1.0-windows-x64.zip', 'PatchTrace-Windows-x64-Portable.zip',
                                  'PatchTrace-Windows-x64-Setup.exe', 'PatchTrace-0.1.0-linux-x86_64.tar.gz')
UNSIGNED = 'Signed: no (PatchTrace.exe has no Authenticode signature)'
PRESENT = 'Signed: certificate table present; signer and trust not evaluated by this generator'
SMARTSCREEN = ('SmartScreen: unsigned or low-reputation builds can show "Windows protected your PC". Choose '
               '"More info" then "Run anyway" only after checking the SHA-256 above.')


def asset(directory, name, data, sidecar=True):
    (directory / name).write_bytes(data)
    if sidecar:
        line = f'{hashlib.sha256(data).hexdigest()}  {name}\n'
        (directory / f'{name}.sha256').write_text(line, encoding='utf-8', newline='\n')


def windows_zip(path, member='PatchTrace/PatchTrace.exe', data=None):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('PatchTrace/dependency-versions.json', '{}')
        if member:
            archive.writestr(member, build_pe() if data is None else data)
    return path.read_bytes()


def line_of(text, prefix):
    found = [line for line in text.splitlines() if line.startswith(prefix)]
    assert len(found) == 1, (prefix, text)
    return found[0]


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


def test_every_published_package_listed_with_verified_sidecar(tmp_path):
    assets = tmp_path / 'assets'
    assets.mkdir()
    zip_bytes = windows_zip(tmp_path / 'w.zip')
    for name, data in ((ZIP, zip_bytes), (PORTABLE, zip_bytes), (SETUP, b'MZ-setup'), (TARBALL, b'tar')):
        asset(assets, name, data)
    text = gen(tmp_path, '--assets', str(assets))
    digest = hashlib.sha256(zip_bytes).hexdigest()
    assert line_of(text, f'- {ZIP} ') == f'- {ZIP} - {len(zip_bytes)} bytes - SHA-256 {digest} - sidecar verified'
    assert line_of(text, f'- {PORTABLE} ').endswith(f'SHA-256 {digest} - sidecar verified - same bytes as {ZIP}')
    setup_digest = hashlib.sha256(b'MZ-setup').hexdigest()
    assert line_of(text, f'- {SETUP} ').endswith(f'SHA-256 {setup_digest} - sidecar verified')
    assert line_of(text, f'- {TARBALL} ').startswith(f'- {TARBALL} - 3 bytes - SHA-256 ')
    assert 'MISMATCH' not in text and 'Asset integrity' not in text and 'not present' not in text
    assert 'SHA-256 shows the download is intact. It does not show who built it.' in text


def test_tampered_sidecar_and_portable_difference_open_gates(tmp_path):
    assets = tmp_path / 'assets'
    assets.mkdir()
    zip_bytes = windows_zip(tmp_path / 'w.zip')
    asset(assets, ZIP, zip_bytes)
    asset(assets, PORTABLE, zip_bytes + b'x')
    asset(assets, SETUP, b'setup')
    (assets / f'{SETUP}.sha256').write_text(f'{"0" * 64}  {SETUP}\n', encoding='utf-8', newline='\n')
    asset(assets, TARBALL, b'tar', sidecar=False)
    wrong_name = f'{hashlib.sha256(zip_bytes).hexdigest()}  other.zip\n'
    (assets / f'{ZIP}.sha256').write_text(wrong_name, encoding='utf-8', newline='\n')
    (assets / 'notes`[x](y).txt').write_bytes(b'extra')
    text = gen(tmp_path, '--assets', str(assets))
    assert line_of(text, f'- {SETUP} ').endswith(' - SIDECAR MISMATCH')
    assert line_of(text, f'- {ZIP} ').endswith(' - SIDECAR MISMATCH')
    assert line_of(text, f'- {PORTABLE} ').endswith(f'sidecar verified - BYTES DIFFER from {ZIP}')
    assert line_of(text, f'- {TARBALL} ').endswith(' - no sidecar')
    gates = text.split('### Open gates')[1]
    assert f'- Asset integrity: {SETUP} does not match its .sha256 sidecar' in gates
    assert f'- Asset integrity: {ZIP} does not match its .sha256 sidecar' in gates
    assert f'- Asset integrity: {PORTABLE} bytes differ from {ZIP}' in gates
    assert f'{TARBALL} does not match' not in text
    extra = line_of(text, '- notes')
    assert extra == f'- notes??x?(y).txt - 5 bytes - SHA-256 {hashlib.sha256(b"extra").hexdigest()} - not a listed package'


def test_portable_without_zip_is_not_compared(tmp_path):
    assets = tmp_path / 'assets'
    assets.mkdir()
    asset(assets, PORTABLE, b'portable')
    (assets / f'{SETUP}.sha256').write_text(f'{"0" * 64}  {SETUP}\n', encoding='utf-8', newline='\n')
    text = gen(tmp_path, '--assets', str(assets))
    assert line_of(text, f'- {PORTABLE} ').endswith(f'sidecar verified - not compared ({ZIP} not present)')
    assert f'- {ZIP} - not present in this build' in text and 'Asset integrity' not in text
    assert f'- {SETUP} - not present in this build' in text
    assert line_of(text, f'- {SETUP}.sha256 - ').endswith(' - not a listed package')


def journey(path, runs=5, passed=5, **extra):
    summary = {'runs': runs, 'passed': passed, 'failed': runs - passed, 'durations': [1.0] * runs,
               'exit_codes': [0] * passed + [1] * (runs - passed), 'test': 'tests/test_journey_analyst.py',
               'evidence_class': 'automated-offscreen-fake-backend (not native Windows acceptance, not live evidence)'}
    summary.update(extra)
    path.write_text(json.dumps(summary), encoding='utf-8')
    return path


def journey_row(text, leg):
    return line_of(text, f'| Analyst journey gate (RB-05), {leg} leg: automated offscreen, fake backend, '
                         'not native acceptance | ')


def test_journey_pass_fail_and_missing(tmp_path):
    lin, win = journey(tmp_path / 'l.json'), journey(tmp_path / 'w.json', passed=4)
    text = gen(tmp_path, '--journey', f'linux={lin}', '--journey', f'windows={win}')
    row = journey_row(text, 'Linux')
    assert '| 5/5 runs passed; evidence class: automated-offscreen-fake-backend (not native Windows acceptance' in row
    assert '| FAIL: 4/5 runs passed; evidence class: automated-' in journey_row(text, 'Windows')
    text = gen(tmp_path, '--journey', f'linux={tmp_path / "absent.json"}')
    assert '| not run (summary file not found) |' in journey_row(text, 'Linux')
    assert '| not run (no summary supplied) |' in journey_row(text, 'Windows')
    with pytest.raises(SystemExit):
        notes.main([*BASE, '--journey', f'macos={lin}'])


@pytest.mark.parametrize('content', [
    'not json', '[]', json.dumps({'runs': 5, 'passed': 5, 'failed': 1}),
    json.dumps({'runs': 0, 'passed': 0, 'failed': 0, 'evidence_class': 'automated-x'}),
    json.dumps({'runs': 5, 'passed': True, 'failed': 4, 'evidence_class': 'automated-x'}),
    json.dumps({'runs': 2, 'passed': 2, 'failed': 0, 'exit_codes': [0, 1], 'evidence_class': 'automated-x'}),
    json.dumps({'runs': 1, 'passed': 1, 'failed': 0, 'evidence_class': 'native Windows acceptance'}),
    json.dumps({'runs': 1, 'passed': 1, 'failed': 0}),
    '{"runs": 1, "passed": 1, "failed": 0, "evidence_class": "automated-x", "pad": "' + 'x' * 70000 + '"}',
], ids=['text', 'list', 'sum', 'zero', 'bool', 'codes', 'class', 'noclass', 'big'])
def test_journey_malformed_counts_as_not_run(tmp_path, content):
    bad = tmp_path / 'j.json'
    bad.write_text(content, encoding='utf-8')
    text = gen(tmp_path, '--journey', f'windows={bad}')
    assert '| unreadable summary, counted as not run |' in journey_row(text, 'Windows')
    assert 'runs passed' not in text


def test_journey_evidence_class_is_bounded_and_escaped(tmp_path):
    hostile = journey(tmp_path / 'j.json', evidence_class='automated-' + '|`<script>\n' * 100)
    row = journey_row(gen(tmp_path, '--journey', f'linux={hostile}'), 'Linux')
    cell = row.split(' | ')[1]
    assert '|' not in cell and '`' not in cell and '<' not in cell and len(cell) <= 220


def test_rows_for_windows_package_steps_and_panel_manifest(tmp_path):
    text = gen(tmp_path, '--result', 'qa-ubuntu=success', '--result', 'qa-windows=failure')
    assert '| Panel manifest check (G6) | Linux pass, Windows FAIL (a step of each qa job) |' in text
    for label in ('Windows exe identity read-back (version resource and icon; tools/check_windows_exe.py inside '
                  'tools/build_windows.py)',
                  'Windows portable ZIP extracted and run outside the checkout (tools/test_windows_portable.ps1)',
                  'Windows Setup.exe per-user install, self-test launch and uninstall '
                  '(tools/test_windows_installer.ps1)'):
        assert f'| {label} | FAIL (step of the Windows qa job) |' in text
    assert 'A13 unified-engine package contents' in text and 'help for every CLI command' in text
    assert 'not run (step of the Windows qa job)' in gen(tmp_path)


@pytest.mark.parametrize('plus', [True, False], ids=['pe32p', 'pe32'])
def test_signed_line_reads_the_certificate_directory(tmp_path, plus):
    assets = tmp_path / 'assets'
    assets.mkdir()
    asset(assets, ZIP, windows_zip(tmp_path / 'u.zip', data=build_pe(PeSpec(pe32plus=plus))))
    text = gen(tmp_path, '--assets', str(assets))
    assert line_of(text, 'Signed: ') == UNSIGNED and SMARTSCREEN in text
    assert 'Limitations: unsigned beta;' in text
    signed = build_pe(PeSpec(pe32plus=plus, cert_payloads=[b'x' * 16]))
    asset(assets, ZIP, windows_zip(tmp_path / 's.zip', data=signed))
    text = gen(tmp_path, '--assets', str(assets))
    assert line_of(text, 'Signed: ') == PRESENT and 'SmartScreen:' not in text
    assert 'Signed: yes' not in text and 'unsigned beta' not in text
    assert '- Code signing and SmartScreen reputation' in text


@pytest.mark.parametrize('case', ['nozip', 'badzip', 'member', 'notpe'])
def test_signed_not_checked_without_a_readable_pe(tmp_path, case):
    assets = tmp_path / 'assets'
    assets.mkdir()
    if case == 'badzip':
        asset(assets, ZIP, b'zip-bytes')
    elif case == 'member':
        asset(assets, ZIP, windows_zip(tmp_path / 'w.zip', member=None))
    elif case == 'notpe':
        asset(assets, ZIP, windows_zip(tmp_path / 'w.zip', data=b'MZ' + b'\0' * 100))
    text = gen(tmp_path, '--assets', str(assets))
    assert line_of(text, 'Signed: ').startswith('Signed: not checked (')
    assert SMARTSCREEN in text and 'Limitations: beta, signature not checked;' in text


def test_provenance_and_supersedes_default_claim_nothing(tmp_path):
    text = gen(tmp_path)
    assert line_of(text, 'Provenance: ') == 'Provenance: attestation not generated: no attestation step in this workflow'
    assert line_of(text, 'Supersedes: ') == 'Supersedes: not recorded'
    assert 'production ready' not in text.lower()
    url = 'https://github.com/o/r/attestations/123'
    text = gen(tmp_path, '--supersedes', 'v0.1.0-beta.8', '--attestation-url', url)
    assert line_of(text, 'Supersedes: ') == 'Supersedes: v0.1.0-beta.8'
    assert line_of(text, 'Provenance: ') == f'Provenance: attestation {url}'


@pytest.mark.parametrize('option, value', [
    ('--supersedes', 'v0.1.0-beta.8\n- Signed: yes'), ('--supersedes', 'v0.1.0 | pass'), ('--supersedes', '0.1.0'),
    ('--supersedes', 'v0.1.0-' + 'a' * 80), ('--attestation-url', 'http://example.test/a'),
    ('--attestation-url', 'https://example.test/a)<b>'), ('--attestation-url', 'https://e.test/' + 'a' * 400),
], ids=['newline', 'pipe', 'nov', 'long', 'http', 'markup', 'urllong'])
def test_hostile_supersedes_and_attestation_rejected(option, value):
    with pytest.raises(SystemExit) as excinfo:
        notes.main([*BASE, option, value])
    assert excinfo.value.code == 2
