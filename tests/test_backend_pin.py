"""BUNDLE slice B1: tools/backend_pin.json and tools/check_backend_pin.py (hermetic: no network)."""
from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / 'tools' / 'backend_pin.json'
TOOL = ROOT / 'tools' / 'check_backend_pin.py'

_spec = importlib.util.spec_from_file_location('check_backend_pin', TOOL)
checker = importlib.util.module_from_spec(_spec)
sys.modules['check_backend_pin'] = checker
_spec.loader.exec_module(checker)


@pytest.fixture()
def pin() -> dict:
    return json.loads(PIN_PATH.read_text(encoding='utf-8'))


def resolved(data: dict) -> dict:
    """A copy of the pin with every placeholder replaced by a well-formed digest (as B10 will do)."""
    data = copy.deepcopy(data)
    for entry, source in ((data['components']['python-windows'], 'sigstore-verified'),
                          (data['ghidriff']['source_tarball'], 'git-rebuilt')):
        entry.update(status='pinned', sha256='ab' * 32, size=1234, digest_source=source)
    return data


def test_committed_pin_is_valid(pin):
    assert checker.validate_pin(pin) == []


def test_committed_pin_is_lf_json_with_trailing_newline():
    raw = PIN_PATH.read_bytes()
    assert b'\r' not in raw and raw.endswith(b'\n')


def test_gitattributes_pins_lf_for_the_pin():
    lines = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
    assert 'tools/backend_pin.json text eol=lf' in lines


def test_known_resolved_values(pin):
    components = pin['components']
    assert components['ghidra']['sha256'] == 'c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120'
    assert components['ghidra']['size'] == 509952513
    assert components['jdk-windows']['version'] == '21.0.12.1+1'
    assert components['python-linux']['sha256'].startswith('8c59b9ac')
    assert pin['ghidriff']['sha'] == '4f5d895fcbb1eacd65efd81145922c15bb7e741d'


def test_digest_sources_are_traceable(pin):
    for name, entry in pin['components'].items():
        if entry['status'] == 'pinned':
            assert entry['digest_source'] in ('vendor-file', 'vendor-listing'), name
        if entry['digest_source'] == 'vendor-file':
            assert entry['digest_file'].startswith('https://'), name


def test_no_url_is_plain_http():
    assert not re.findall(rb'"http://', PIN_PATH.read_bytes())


def test_every_dependency_closure_member_pinned_per_lane(pin):
    for lane in ('windows', 'linux'):
        names = {w['distribution'] for w in pin['wheels'][lane] + pin['wheels']['any']}
        assert names == set(checker.REQUIRED_DISTRIBUTIONS)


def test_ghidriff_requirements_match_the_pins(pin):
    versions = {w['distribution']: w['version'] for part in pin['wheels'].values() for w in part}
    assert versions['mdutils'] == '1.6.0' and versions['jpype1'] == '1.5.2'
    assert versions['pyghidra'] == '3.0.2'
    assert pin['ghidra_pypkg_crosscheck']['jpype1']['same_sha256_as_pinned'] is True


def test_placeholders_are_declared_and_listed(pin):
    unresolved = checker.release_problems(pin)
    assert len(unresolved) == 2
    assert any(line.startswith('components.python-windows') for line in unresolved)
    assert any(line.startswith('ghidriff.source_tarball') for line in unresolved)


def _break(data: dict, path: str, value) -> None:
    node = data
    parts = re.findall(r'[^.\[\]]+', path)
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = parts[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


BROKEN = [
    pytest.param('schema', 'other/1', id='schema'),
    pytest.param('components.ghidra.sha256', 'ABC', id='sha-short'),
    pytest.param('components.ghidra.sha256', 'C' * 64, id='sha-upper'),
    pytest.param('components.ghidra.sha256', 'PLACEHOLDER-UNRESOLVED', id='sha-ph-pinned'),
    pytest.param('components.ghidra.url', 'http://example.invalid/ghidra.zip', id='http'),
    pytest.param('components.ghidra.size', 0, id='size-zero'),
    pytest.param('components.ghidra.size', True, id='size-bool'),
    pytest.param('components.ghidra.spdx', '', id='spdx-empty'),
    pytest.param('components.ghidra.digest_source', 'none', id='source-none'),
    pytest.param('components.ghidra.digest_source', 'rumour', id='source-bad'),
    pytest.param('components.jdk-linux.version', '25.0.1+8', id='jdk-25'),
    pytest.param('components.python-linux.version', '3.13.0', id='py-skew'),
    pytest.param('wheels.any[0].sha256', 'f' * 63, id='wheel-sha'),
    pytest.param('wheels.any[0].spdx', None, id='wheel-spdx'),
    pytest.param('wheels.any[0].url', 'http://files.invalid/pyghidra-3.0.2-py3-none-any.whl', id='wheel-http'),
    pytest.param('wheels.windows[0].name', 'jpype1-1.5.2-cp312-cp312-manylinux_2_17_x86_64.whl', id='wheel-lane'),
    pytest.param('wheels.any[0].status', 'placeholder', id='wheel-ph'),
    pytest.param('ghidriff.sha', '4f5d895', id='ghidriff-sha'),
    pytest.param('jdk_source_offer.sha256', 'zz', id='offer-sha'),
]


@pytest.mark.parametrize(('path', 'value'), BROKEN)
def test_validate_rejects(pin, path, value):
    _break(pin, path, value)
    assert checker.validate_pin(pin), path


@pytest.mark.parametrize('dist', sorted(checker.REQUIRED_DISTRIBUTIONS))
def test_unpinned_dependency_rejected(pin, dist):
    for part in pin['wheels'].values():
        part[:] = [w for w in part if w['distribution'] != dist]
    assert any(dist in line for line in checker.validate_pin(pin))


def test_placeholder_needs_exact_marker_and_null_size(pin):
    pin['components']['python-windows']['size'] = 5
    pin['ghidriff']['source_tarball']['sha256'] = 'deadbeef'
    problems = checker.validate_pin(pin)
    assert len(problems) >= 2


def test_validate_rejects_non_object():
    assert checker.validate_pin([]) == ['pin is not a JSON object']


def test_resolved_pin_is_valid_and_release_clean(pin):
    data = resolved(pin)
    assert checker.validate_pin(data) == []
    assert checker.release_problems(data) == []


def test_placeholder_digest_cannot_hide_under_pinned_status(pin):
    data = resolved(pin)
    data['components']['ghidra']['sha256'] = checker.PLACEHOLDER
    assert checker.validate_pin(data)
    assert checker.release_problems(data)


def run_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, '-I', str(TOOL), *args], capture_output=True, text=True, timeout=60, check=False)


def test_cli_default_mode_accepts_placeholders():
    result = run_tool()
    assert result.returncode == 0, result.stderr
    assert 'backend pin ok' in result.stdout and '2 unresolved' in result.stdout


def test_cli_release_mode_refuses_the_committed_placeholders():
    """The release gate: while any placeholder remains, a release build (--release) must fail."""
    result = run_tool('--release')
    assert result.returncode == 3
    assert 'unresolved placeholder' in result.stderr


def test_cli_release_mode_passes_once_resolved(pin, tmp_path):
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps(approved(resolved(pin))), encoding='utf-8')
    assert run_tool('--pin', str(path), '--release').returncode == 0


def test_cli_reports_malformed_pin(tmp_path):
    path = tmp_path / 'pin.json'
    path.write_text('{"schema": "x"}', encoding='utf-8')
    assert run_tool('--pin', str(path)).returncode == 1
    path.write_text('not json', encoding='utf-8')
    assert run_tool('--pin', str(path)).returncode == 1
    assert run_tool('--pin', str(tmp_path / 'missing.json')).returncode == 1


# ---- license_policy (CODEX-15): an explicit, enforced gate for GPL-family components ----------------------

def approved(data: dict) -> dict:
    """Copy of the pin in which every shipped policy component carries owner approval."""
    data = copy.deepcopy(data)
    for entry in data['license_policy']['allowed'].values():
        if entry['shipped']:
            entry['owner_approved'] = True
    return data


def test_committed_policy_lists_exactly_the_known_gpl_family_components(pin):
    allowed = pin['license_policy']['allowed']
    assert set(allowed) == {'ghidriff', 'temurin-jdk', 'ghidra-GPL-dir'}
    assert allowed['ghidriff']['owner_approved'] is True and allowed['ghidriff']['shipped'] is True
    assert allowed['ghidra-GPL-dir']['shipped'] is False
    assert allowed['temurin-jdk']['spdx'] == 'GPL-2.0-only WITH Classpath-exception-2.0'


def test_ghidra_gpl_directory_is_stripped_not_kept(pin):
    assert 'GPL/**' in pin['strip']['ghidra'] and 'GPL/**' not in pin['strip']['keep']


@pytest.mark.parametrize(('spdx', 'expected'),
                         [('GPL-3.0-only', True), ('LGPL-3.0-only OR GPL-2.0-only', True), ('AGPL-3.0-or-later', True),
                          ('GPL-2.0-only WITH Classpath-exception-2.0', True), ('Apache-2.0', False),
                          ('MIT', False), ('LicenseRef-GPLish-none', False)],
                         ids=['gpl', 'lgpl-or', 'agpl', 'classpath', 'apache', 'mit', 'ref-substring'])
def test_is_copyleft(spdx, expected):
    assert checker.is_copyleft(spdx) is expected


def test_unlisted_gpl_wheel_is_refused(pin):
    pin['wheels']['any'][0]['spdx'] = 'AGPL-3.0-only'
    problems = checker.validate_pin(pin)
    assert any(p.startswith('PT-BUNDLE-LICENSE') for p in problems), problems


def test_listed_component_with_changed_spdx_is_refused_again(pin):
    pin['components']['jdk-linux']['spdx'] = 'GPL-3.0-only'
    assert any(p.startswith('PT-BUNDLE-LICENSE') for p in checker.validate_pin(pin))


@pytest.mark.parametrize('mutate', [lambda d: d['strip']['keep'].append('GPL/**'),
                                    lambda d: d['strip']['ghidra'].remove('GPL/**'),
                                    lambda d: d['license_policy']['allowed'].pop('ghidra-GPL-dir'),
                                    lambda d: d['license_policy']['allowed']['temurin-jdk'].pop('rationale'),
                                    lambda d: d['license_policy']['allowed']['temurin-jdk'].update(owner_approved='yes')],
                         ids=['keep-gpl', 'unstrip-gpl', 'drop-gpl-entry', 'no-rationale', 'non-bool'])
def test_policy_structure_is_enforced(pin, mutate):
    mutate(pin)
    assert checker.validate_pin(pin)


def test_pending_approval_is_reported_and_blocks_release_only(pin, tmp_path):
    assert checker.unapproved_licenses(pin) == ['temurin-jdk']  # stripped GPL dir is not shipped, so not pending
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps(resolved(pin)), encoding='utf-8')
    plain = run_tool('--pin', str(path))
    assert plain.returncode == 0 and 'WARNING' in plain.stderr and 'temurin-jdk' in plain.stderr
    refused = run_tool('--pin', str(path), '--release')
    assert refused.returncode == 4 and 'PT-BUNDLE-LICENSE' in refused.stderr
    acceptance = run_tool('--pin', str(path), '--release', '--allow-unapproved-licenses')
    assert acceptance.returncode == 0 and 'WARNING' in acceptance.stderr


@pytest.mark.parametrize('component', ['ghidriff', 'temurin-jdk'])
def test_flipping_an_approval_to_false_fails_the_release_gate(pin, tmp_path, component):
    data = approved(resolved(pin))
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    assert run_tool('--pin', str(path), '--release').returncode == 0
    data['license_policy']['allowed'][component]['owner_approved'] = False
    path.write_text(json.dumps(data), encoding='utf-8')
    assert run_tool('--pin', str(path), '--release').returncode == 4


def test_shipped_ghidra_gpl_files_are_refused_while_stripped_by_policy(pin):
    files = ['ghidra/LICENSE', 'ghidra/GPL/DemanglerGnu/readme.txt']
    assert checker.shipped_gpl_dir_problems(files, pin)
    assert checker.shipped_gpl_dir_problems(['ghidra/LICENSE'], pin) == []
