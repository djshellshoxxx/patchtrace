"""SPEC-29 §2: BinDiff capability probe against fake executables (mocked evidence, not live)."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from fake_bindiff import FULL_HELP, launcher_names, make_fake_bindiff, spy_calls

from patchtrace.jobs import ProcessResult
from patchtrace.secondary import bindiff_probe
from patchtrace.secondary.bindiff_probe import parse_version, probe, probe_report, sanitize


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    bindiff_probe.clear_probe_cache()
    monkeypatch.setattr(bindiff_probe, 'EXECUTABLE_NAMES', bindiff_probe.EXECUTABLE_NAMES | launcher_names())
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'sentinel-secret')
    monkeypatch.setenv('JAVA_TOOL_OPTIONS', '-javaagent:evil.jar')
    monkeypatch.setenv('LD_PRELOAD', '/evil.so')
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy')
    yield
    bindiff_probe.clear_probe_cache()


@pytest.mark.parametrize('text, expected', [
    ('BinDiff 8', (8, '')),
    ('BinDiff 8 (@568181968, Sep 25 2023), (c)2004 zynamics', (8, ' (@568181968, Sep 25 2023), (c)2004 zynamics')),
    ('noise\nBinDiff 9 (@abc)\n', (9, ' (@abc)')),
    ('BinDiff 7.0\x1b', (7, '.0')),
    ('garbage', None),
    ('Bindiff 8', None),
    ('', None),
])
def test_version_parsing_table(text, expected):
    assert parse_version(text) == expected


def test_supported_v8_probe_uses_private_cwd_and_allowlisted_env(tmp_path):
    exe = make_fake_bindiff(tmp_path / 'bd')
    report = probe_report(exe)
    cap = report.capability
    assert cap.supported and cap.engine == 'bindiff' and cap.version.startswith('8 (@568181968')
    assert report.major == 8 and not report.untested_version and not cap.supports_json
    calls = spy_calls(tmp_path / 'bd')
    assert [c['argv'] for c in calls] == [['--version'], ['--nologo', '--help']]
    for call in calls:
        assert not {'AWS_SECRET_ACCESS_KEY', 'JAVA_TOOL_OPTIONS', 'LD_PRELOAD', 'HTTPS_PROXY'} & set(call['env'])
        assert Path(call['cwd']).name == 'cwd' and 'patchtrace-bindiff-probe-' in call['cwd']
    assert not Path(calls[0]['cwd']).exists()  # private probe dir removed


def test_probe_result_is_cached_per_path_mtime_size(tmp_path):
    exe = make_fake_bindiff(tmp_path / 'bd')
    assert probe(exe).supported and probe(exe).supported
    assert len(spy_calls(tmp_path / 'bd')) == 2  # second probe served from the in-process cache


@pytest.mark.parametrize('mode, kind', [
    ('no-version', 'probe-failed'),
    ('version-exit-1', 'probe-failed'),
    ('missing-option', 'missing-option'),
])
def test_unsupported_modes(tmp_path, mode, kind):
    report = probe_report(make_fake_bindiff(tmp_path / 'bd', mode))
    assert not report.capability.supported and report.kind == kind
    if kind == 'missing-option':
        assert '--logo' in report.capability.reason


def test_help_exit_1_is_accepted(tmp_path):
    assert probe_report(make_fake_bindiff(tmp_path / 'bd', 'help-exit-1')).capability.supported


def test_old_major_is_unsupported_without_help_call(tmp_path):
    report = probe_report(make_fake_bindiff(tmp_path / 'bd', version='BinDiff 7 (@123)'))
    assert report.kind == 'unsupported-version' and report.capability.version == '7 (@123)'
    assert 'older than the supported version 8' in report.capability.reason
    assert [c['argv'] for c in spy_calls(tmp_path / 'bd')] == [['--version']]


def test_newer_major_with_options_is_supported_but_untested(tmp_path):
    report = probe_report(make_fake_bindiff(tmp_path / 'bd', version='BinDiff 9 (@abc)'))
    assert report.capability.supported and report.untested_version and report.major == 9


def test_newer_major_without_options_is_unsupported(tmp_path):
    report = probe_report(make_fake_bindiff(tmp_path / 'bd', version='BinDiff 9', help_text=FULL_HELP.replace(
        '--primary', '--first')))
    assert report.kind == 'missing-option'


def test_not_configured_and_missing_paths(tmp_path):
    assert probe_report(None).kind == 'not-configured'
    assert probe_report('').kind == 'not-configured'
    assert probe_report(tmp_path / 'nope' / 'bindiff').kind == 'not-found'
    assert probe_report('bindiff').kind == 'not-found'  # relative: never a PATH lookup
    assert probe_report(tmp_path).kind == 'not-found'   # a directory


@pytest.mark.parametrize('name', ['bindiff_ui', 'bindiff_ui.exe', 'BinDiff_UI.cmd', 'bindiff_cli', 'bindiff_cli.exe',
                                  'rz-diff', 'bindiff.sh'])
def test_ui_launcher_cli_and_foreign_names_rejected_without_execution(tmp_path, name):
    path = tmp_path / name
    path.write_text('must never run')
    called = []
    report = probe_report(path, runner=lambda *a, **k: called.append(a))
    assert not report.capability.supported and report.kind == 'not-found' and not called
    if 'cli' in name:
        assert 'bindiff_cli' in report.capability.reason


def test_spawn_error_and_cancel_are_unsupported_not_raised(tmp_path):
    exe = make_fake_bindiff(tmp_path / 'bd')

    def boom(*args, **kwargs):
        raise OSError('cannot spawn')

    assert probe_report(exe, runner=boom, use_cache=False).kind == 'probe-failed'
    cancelled = probe_report(exe, runner=lambda *a, **k: ProcessResult(-1, '', 'cancelled'), use_cache=False,
                             cancel=threading.Event())
    assert cancelled.kind == 'probe-cancelled'


def test_sanitize_strips_ansi_controls_and_paths():
    text = '\x1b[31mError: could not load /secret/home/user/older.BinExport: C:\\Users\\bob\\x.BinExport\x07 bad'
    clean = sanitize(text)
    assert '\x1b' not in clean and '\x07' not in clean
    assert '/secret' not in clean and 'Users' not in clean
    assert 'older.BinExport' in clean and 'x.BinExport' in clean
    assert len(sanitize('x' * 1000)) == 200
