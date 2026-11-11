"""TB-12: `safe_path` refuses Windows device names and trailing dot/space components on every platform.

The rule is on the string, not the running OS: a project edited on Linux is opened on Windows later, where
`runs/x/CON` is the console device and `raw.json.` names a different file than the one written.
"""
from __future__ import annotations

import pytest

from patchtrace import offline_bundle
from patchtrace.ingestion import safe_path

SHA = 'a' * 64
RUN = '6f1f2a0e-7d0b-4c58-9f0a-3d8c1f6f2b11'
REFUSAL = 'PT-STORAGE: project path has an invalid or over-long component'

REFUSED = {
    'con': 'CON',
    'nul-ext': 'nul.txt',
    'com1': 'COM1',
    'lpt9-ext': 'LPT9.bin',
    'trailing-dot-dir': 'a./b',
    'trailing-space-dir': 'a /b',
    'aux-lower': 'aux',
    'aux-mixed': 'aUx',
    'aux-upper': 'AUX',
    'device-in-run': f'runs/{RUN}/CON',
    'device-leaf-two-ext': f'runs/{RUN}/raw/json/nul.ghidriff.json',
    'device-then-space': 'artifacts/NUL .bin',
    'superscript-com': 'artifacts/COM¹',
    'conin': 'CONIN$',
    'trailing-dot-leaf': f'runs/{RUN}/raw.json.',
    'trailing-space-leaf': 'artifacts/older.bin ',
    'three-dots': 'artifacts/.../x',
}

ACCEPTED = {
    'artifact': f'artifacts/{SHA}.bin',
    'raw-json': f'runs/{RUN}/raw/json/result.ghidriff.json',
    'lock': '.patchtrace.lock',
    'backup-part': 'backups/project-pre-unified-20261111T000000Z.sqlite3.part',
    'device-prefix-only': 'artifacts/console.bin',
    'device-not-first-segment': 'artifacts/x.con',
    'com-without-digit': 'artifacts/com',
    'com-two-digits': 'artifacts/COM10',
}


@pytest.mark.parametrize('relative', list(REFUSED.values()), ids=list(REFUSED))
def test_safe_path_refuses_windows_device_names_and_trailing_dot_or_space(tmp_path, relative):
    with pytest.raises(ValueError, match=REFUSAL):
        safe_path(tmp_path, relative)


@pytest.mark.parametrize('relative', list(ACCEPTED.values()), ids=list(ACCEPTED))
def test_safe_path_still_accepts_project_owned_paths(tmp_path, relative):
    assert safe_path(tmp_path, relative) == tmp_path.resolve() / relative


def test_safe_path_keeps_its_older_refusal_messages(tmp_path):
    # The new rule must not shadow the containment message that callers and tests already match.
    with pytest.raises(ValueError, match='PT-STORAGE: project path must be relative and contained'):
        safe_path(tmp_path, '../CON')
    with pytest.raises(ValueError, match='PT-STORAGE: project path must be relative and contained'):
        safe_path(tmp_path, 'C:/NUL')


def test_safe_path_and_the_offline_bundle_share_one_reserved_name_rule():
    # No second copy of the list: both guards consult the same predicate object.
    from patchtrace import ingestion

    assert ingestion.windows_unsafe_component is offline_bundle.windows_unsafe_component
    for name in ('CON', 'nul.txt', 'COM1', 'LPT9.bin', 'a.', 'a ', 'aux'):
        assert offline_bundle.windows_unsafe_component(name)
    for name in ('console.bin', 'x.con', 'COM10', f'{SHA}.bin'):
        assert not offline_bundle.windows_unsafe_component(name)


@pytest.mark.parametrize('name', ['payload/CON', 'payload/nul.txt', 'payload/a./b', 'payload/a /b', 'payload/COM¹.txt'],
                         ids=['con', 'nul-ext', 'dot-dir', 'space-dir', 'superscript'])
def test_offline_bundle_archive_rule_is_unchanged_by_the_shared_predicate(name):
    with pytest.raises(offline_bundle.OfflineBundleError, match='PT-OFFLINE: unsafe archive path'):
        offline_bundle._safe_relative(name)
    assert offline_bundle._safe_relative('payload/python/python.exe') == 'payload/python/python.exe'
