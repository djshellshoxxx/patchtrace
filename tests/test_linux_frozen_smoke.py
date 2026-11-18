"""Drive Linux builder publication ordering with inert files; never freeze/run a binary."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def builder(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('linux_smoke_boundary', ROOT / 'tools/build_linux.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / 'fixture tree \u00fc'
    package = root / 'dist/PatchTrace'
    package.mkdir(parents=True)
    for path, data in [('LICENSE', b'fixture license'), ('README.md', b'fixture readme'),
                       ('tools/build_linux.py', b'not executed'), ('tools/frozen_smoke.py', b'not executed'),
                       ('dist/PatchTrace/PatchTrace', b'inert executable fixture'),
                       ('dist/PatchTrace/_internal/google/_upb/_message.authored', b'inert extension')]:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    executable = package / 'PatchTrace'
    executable.chmod(0o755)
    for script in (module.EXTRACTOR_SCRIPT, module.LAUNCHER_SCRIPT):
        for base in (root / 'src', package / '_internal'):
            target = base / script
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'authored source data, never executed\n')
    (root / 'docs').mkdir()
    (root / 'third_party/notices').mkdir(parents=True)
    monkeypatch.setattr(module, '__file__', str(root / 'tools/build_linux.py'))
    monkeypatch.setattr(module, 'sys', SimpleNamespace(platform='linux', executable=sys.executable,
                                                     version=sys.version))
    monkeypatch.setattr(module, 'platform', SimpleNamespace(machine=lambda: 'x86_64'))
    monkeypatch.setattr(module, 'require_upb_protobuf', lambda: None)
    monkeypatch.setattr(module, 'check_desktop_mark', lambda *_: None)
    monkeypatch.setattr(module, 'DISTRIBUTIONS', [])
    monkeypatch.setattr(module, 'OPTIONAL_DISTRIBUTIONS', [])
    monkeypatch.setattr(module, 'REQUIRED_NOTICES', [])
    monkeypatch.setattr(module, 'python_license', lambda: root / 'LICENSE')
    calls = []
    state = {'smoke_exit': 0, 'smoke_timeout': False}

    def run(argv, **kwargs):
        args = [str(value) for value in argv]
        if 'PyInstaller' in args:
            calls.append(('freeze', args, kwargs))
        elif len(args) > 1 and args[1] == str(root / 'tools/frozen_smoke.py'):
            calls.append(('full-smoke', args, kwargs))
            if state['smoke_timeout']:
                raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 0))
            if state['smoke_exit'] and kwargs.get('check'):
                raise subprocess.CalledProcessError(state['smoke_exit'], args)
            return subprocess.CompletedProcess(args, state['smoke_exit'], 'authored smoke result', '')
        else:
            assert args[0] == str(executable)
            assert args[1:] in (['--self-test'], ['rank', '--help'])
            calls.append(('historical-narrow-smoke', args, kwargs))
        return subprocess.CompletedProcess(args, 0, 'usage: authored fixture', '')

    def archive(source, target):
        calls.append(('archive', source, target))
        target.write_bytes(b'authored archive; never a frozen package')

    monkeypatch.setattr(module.subprocess, 'run', run)
    monkeypatch.setattr(module, 'write_tar_gz', archive)
    return module, root, executable, calls, state


@pytest.mark.parametrize('qt_platform', [None, 'offscreen', 'xcb'])
def test_linux_builder_requires_complete_smoke_before_archiving(builder, monkeypatch, qt_platform):
    module, root, executable, calls, _ = builder
    if qt_platform is None:
        monkeypatch.delenv('QT_QPA_PLATFORM', raising=False)
    else:
        monkeypatch.setenv('QT_QPA_PLATFORM', qt_platform)
    module.main([])
    assert [call[0] for call in calls] == ['freeze', 'full-smoke', 'archive']
    _, args, options = calls[1]
    assert args == [sys.executable, str(root / 'tools/frozen_smoke.py'), str(executable)]
    assert options['check'] is True and 0 < options['timeout'] <= 900
    assert options['cwd'] == root
    assert options['env']['QT_QPA_PLATFORM'] == (qt_platform or 'offscreen')
    assert (root / 'dist/PatchTrace-0.1.0-linux-x86_64.tar.gz.sha256').is_file()


@pytest.mark.parametrize('failure', ['exit', 'timeout'])
def test_full_smoke_failure_or_timeout_stops_archive_publication(builder, failure):
    module, root, _, calls, state = builder
    state['smoke_exit'] = 1 if failure == 'exit' else 0
    state['smoke_timeout'] = failure == 'timeout'
    error = subprocess.CalledProcessError if failure == 'exit' else subprocess.TimeoutExpired
    with pytest.raises(error):
        module.main([])
    assert [call[0] for call in calls] == ['freeze', 'full-smoke']
    assert not list((root / 'dist').glob('*.tar.gz*'))
