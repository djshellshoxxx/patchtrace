"""Version/help responses only: Windows executable names do not bypass probe admission."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from patchtrace.intelligence.tools import capa, floss, pins
from patchtrace.jobs import ProcessResult

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools'
ADAPTERS = {'capa': (capa, capa.CapaConfig, '9.4.0', '--help', 'help.stdout.txt'),
            'floss': (floss, floss.FlossConfig, '3.1.1', '-H', 'help-advanced.stdout.txt')}


def probe_banner(tmp_path, monkeypatch, engine, banner, *, stream='stdout', returncode=0,
                 pinned=True, accept_untested=False):
    module, config, _version, help_flag, help_file = ADAPTERS[engine]
    exe = tmp_path / f'{engine}.exe'
    exe.write_bytes(b'authored version-probe fixture; never executed')
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    if pinned:
        monkeypatch.setitem(pins.PINNED_EXECUTABLES[engine], digest, 'authored probe fixture')
    help_text = (FIXTURES / engine / help_file).read_text(encoding='utf-8')
    calls = []

    def runner(argv, **_kwargs):
        calls.append(argv)
        assert argv[0] == str(exe)
        if argv[1:] == ['--version']:
            return ProcessResult(returncode, banner if stream == 'stdout' else '', None,
                                 banner if stream == 'stderr' else '')
        assert argv[1:] == [help_flag]
        return ProcessResult(0, help_text, None, '')

    result = module.probe(config(exe, accept_untested=accept_untested), runner=runner, use_cache=False)
    assert calls == [[str(exe), '--version'], [str(exe), help_flag]]
    assert result.executable_sha256 == digest
    return result


@pytest.mark.parametrize('engine, banner', [
    ('capa', 'capa 9.4.0\n'),
    ('capa', 'capa.exe 9.4.0\r\n'),
    ('floss', 'floss 3.1.1\n'),
    ('floss', 'floss.exe 3.1.1\r\n'),
    ('floss', 'floss v3.1.1-0-g3cd3ee6\n'),
    ('floss', 'floss.exe v3.1.1-0-g3cd3ee6\r\n'),
])
@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_probe_accepts_exact_unix_and_windows_program_names(tmp_path, monkeypatch, engine, banner, stream):
    result = probe_banner(tmp_path, monkeypatch, engine, banner, stream=stream)
    assert result.supported, result.reason
    assert result.version == ADAPTERS[engine][2]
    assert result.version_text == banner.strip()
    assert result.pin_status == 'pinned'
    assert not result.untested_version


@pytest.mark.parametrize('engine', ['capa', 'floss'])
@pytest.mark.parametrize('name', ['x{engine}.exe', '{engine}Xexe', '{engine}.exe.bak',
                                 '{engine}.cmd', '{engine}.exe-extra'])
def test_probe_rejects_lookalike_program_names(tmp_path, monkeypatch, engine, name):
    banner = f'{name.format(engine=engine)} {ADAPTERS[engine][2]}\n'
    result = probe_banner(tmp_path, monkeypatch, engine, banner)
    assert not result.supported
    assert 'did not report a version' in result.reason
    assert result.version is None


@pytest.mark.parametrize('engine, version', [('capa', '10.0.0'), ('floss', '4.0.0')])
@pytest.mark.parametrize('suffix', ['', '.exe'])
def test_program_name_variant_preserves_supported_major(tmp_path, monkeypatch, engine, version, suffix):
    result = probe_banner(tmp_path, monkeypatch, engine, f'{engine}{suffix} {version}\n')
    assert not result.supported
    assert result.version == version
    assert 'parser contract' in result.reason


@pytest.mark.parametrize('engine', ['capa', 'floss'])
@pytest.mark.parametrize('suffix', ['', '.exe'])
def test_program_name_variant_preserves_pin_and_explicit_opt_in(tmp_path, monkeypatch, engine, suffix):
    banner = f'{engine}{suffix} {ADAPTERS[engine][2]}\n'
    refused = probe_banner(tmp_path, monkeypatch, engine, banner, pinned=False)
    assert not refused.supported
    assert 'not the pinned release' in refused.reason
    assert refused.pin_status == 'unpinned'
    opted = probe_banner(tmp_path, monkeypatch, engine, banner, pinned=False, accept_untested=True)
    assert opted.supported, opted.reason
    assert opted.pin_status == 'unpinned' and opted.untested_version


@pytest.mark.parametrize('engine', ['capa', 'floss'])
@pytest.mark.parametrize('suffix', ['', '.exe'])
def test_program_name_variant_cannot_accept_nonzero_exit(tmp_path, monkeypatch, engine, suffix):
    result = probe_banner(tmp_path, monkeypatch, engine,
                          f'{engine}{suffix} {ADAPTERS[engine][2]}\n', returncode=1)
    assert not result.supported
    assert 'did not report a version (exit 1)' in result.reason
    assert result.version is None
