"""Controlled onedir builds exercise real record/inventory/archive boundaries.

The freezer and native smoke/resource checks are authored doubles, never native
platform qualification. Records, frozen-consumer parsing and ZIP/tar output are real.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace import buildinfo, jobs

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'
sys.path.insert(0, str(TOOLS))
import package_buildinfo  # noqa: E402

COMMIT = 'a' * 40
RECORD = '_internal/patchtrace/build-info.json'


def _load_builder(platform):
    spec = importlib.util.spec_from_file_location(f'_record_build_{platform}', TOOLS / f'build_{platform}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=['linux', 'windows'])
def builder(request, tmp_path, monkeypatch):
    platform = request.param
    module = _load_builder(platform)
    root = tmp_path / 'source'
    package = root / 'dist' / 'PatchTrace'
    source = root / 'src' / 'patchtrace'
    source.mkdir(parents=True)
    for name in ('buildinfo.py', '__init__.py', 'unified/extract/ghidra_script.py',
                 'ghidriff_launch/ptlaunch.py', 'resources/patchtrace-mark.svg'):
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'src' / 'patchtrace' / name, target)
    for name in ('LICENSE', 'README.md'):
        shutil.copy2(ROOT / name, root / name)
    (root / 'docs').mkdir()
    (root / 'docs' / 'fixture.md').write_text('Authored builder fixture.\n', encoding='utf-8')
    shutil.copytree(ROOT / 'third_party' / 'notices', root / 'third_party' / 'notices')
    python = tmp_path / 'python'
    python.mkdir()
    (python / 'LICENSE.txt').write_text('Authored Python notice fixture.\n', encoding='utf-8')
    payload = tmp_path / 'backend-payload'
    payload.mkdir()
    events = []
    state = SimpleNamespace(raw=None, failure=None, commit=COMMIT, archives=[])

    monkeypatch.setattr(module, '__file__', str(root / 'tools' / f'build_{platform}.py'))
    monkeypatch.setattr(module, 'sys', SimpleNamespace(
        platform='win32' if platform == 'windows' else 'linux', executable=sys.executable,
        version=sys.version, base_prefix=str(python)))
    monkeypatch.setattr(module, 'require_upb_protobuf', lambda: None)
    monkeypatch.setattr(module, '_installed', lambda name: False)
    dist = SimpleNamespace(version='fixture', files=[Path('LICENSE.txt')],
                           locate_file=lambda file: python / 'LICENSE.txt')
    monkeypatch.setattr(module, 'importlib', SimpleNamespace(metadata=SimpleNamespace(distribution=lambda name: dist)))
    monkeypatch.setattr(buildinfo, '__file__', str(source / 'buildinfo.py'))
    monkeypatch.setattr(buildinfo, 'git_info', lambda root: {
        'commit': state.commit, 'describe': 'fixture' if state.commit != 'unknown' else 'unknown', 'dirty': None})
    monkeypatch.setenv('GITHUB_SHA', COMMIT)
    monkeypatch.setenv('GITHUB_REF', 'refs/tags/v0.1.0')
    monkeypatch.setenv('GITHUB_RUN_NUMBER', '1')

    def gate(name):
        events.append(name)
        if state.failure == name:
            raise package_buildinfo.PackageBuildInfoError(f'{name} refused')

    original_prepare = package_buildinfo.prepare_record
    original_install = package_buildinfo.install_record
    original_check = package_buildinfo.check_frozen_record

    def prepare(selected_root):
        gate('prepare')
        assert selected_root == root and not package.exists()
        state.raw = original_prepare(selected_root)
        return state.raw

    def install(selected_root, selected_package, raw):
        gate('install')
        assert (selected_root, selected_package, raw) == (root, package, state.raw)
        assert not (package / 'file-inventory.json').exists()
        return original_install(selected_root, selected_package, raw)

    def check(executable, raw, *, cwd):
        gate('version')
        assert raw == state.raw and cwd == root
        assert RECORD in json.loads((package / 'file-inventory.json').read_text(encoding='utf-8'))
        return original_check(executable, raw, cwd=cwd)

    monkeypatch.setattr(package_buildinfo, 'prepare_record', prepare)
    monkeypatch.setattr(package_buildinfo, 'install_record', install)
    monkeypatch.setattr(package_buildinfo, 'check_frozen_record', check)

    executable = package / ('PatchTrace.exe' if platform == 'windows' else 'PatchTrace')

    def run(argv, **kwargs):
        if argv[1:3] == ['-m', 'PyInstaller']:
            events.append('freeze')
            internal = package / '_internal'
            (internal / 'google' / '_upb').mkdir(parents=True)
            (internal / 'google' / '_upb' / '_message.fixture').write_bytes(b'authored extension placeholder')
            for name in ('unified/extract/ghidra_script.py', 'ghidriff_launch/ptlaunch.py',
                         'resources/patchtrace-mark.svg'):
                target = internal / 'patchtrace' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / name, target)
            library = 'Qt6Svg.dll' if platform == 'windows' else 'libQt6Svg.so.6'
            (internal / library).write_bytes(b'authored Qt placeholder')
            executable.write_bytes(b'authored application placeholder; never executed')
            executable.chmod(0o700)
        elif argv == [str(executable), '--self-test']:
            events.append('self-test')
            if state.failure == 'self-test':
                raise subprocess.CalledProcessError(1, argv)
        elif argv == [str(executable), 'rank', '--help']:
            events.append('rank-help')
            if state.failure == 'rank-help':
                return subprocess.CompletedProcess(argv, 1, '', 'authored smoke failure')
        else:
            pytest.fail(f'unexpected builder child: {argv}')
        return subprocess.CompletedProcess(argv, 0, 'usage: authored smoke', '')

    monkeypatch.setattr(module, 'subprocess', SimpleNamespace(run=run))

    def frozen_consumer(argv, **kwargs):
        assert argv == [str(executable), 'version', '--json'] and executable.is_absolute()
        with monkeypatch.context() as frozen:
            frozen.setattr(buildinfo, 'sys', SimpleNamespace(
                frozen=True, _MEIPASS=str(package / '_internal'), version_info=sys.version_info))
            result, warnings = buildinfo.read_info()
        raw = json.dumps({'contract': 'enrichment-cli/1', 'command': 'version', 'status': 'complete',
                          'warnings': warnings, 'result': result}).encode()
        return jobs.ProcessResult(0, raw.decode(), log_bytes=raw, stdout_total=len(raw))

    monkeypatch.setattr(jobs, 'run_process', frozen_consumer)

    def attach(selected_package, selected_payload, **kwargs):
        events.append('backend')
        assert selected_package == package and selected_payload == payload
        assert kwargs['platform_key'] == platform and kwargs['release'] is False
        (package / 'backend').mkdir()
        (package / 'backend' / 'fixture.txt').write_bytes(b'authored backend placeholder')

    monkeypatch.setattr(module, 'attach_backend', attach)

    if platform == 'windows':
        monkeypatch.setattr(module, 'windows_icon', SimpleNamespace(render_frames=lambda: [], pack_ico=lambda frames: b'icon'))
        monkeypatch.setattr(module, 'check_windows_exe', SimpleNamespace(
            read_resources=lambda path: events.append('resources'), problems=lambda *args: []))

        def archive(*args, **kwargs):
            events.append('archive')
            path = Path(shutil.make_archive(*args, **kwargs))
            state.archives.append(path)
            return str(path)

        monkeypatch.setattr(module, 'shutil', SimpleNamespace(
            copy2=shutil.copy2, copytree=shutil.copytree, make_archive=archive))
    else:
        monkeypatch.setattr(module, 'platform', SimpleNamespace(machine=lambda: 'x86_64'))
        monkeypatch.setattr(module, 'python_license', lambda: python / 'LICENSE.txt')
        write_tar = module.write_tar_gz

        def archive(selected_package, path):
            events.append('archive')
            write_tar(selected_package, path)
            state.archives.append(path)

        monkeypatch.setattr(module, 'write_tar_gz', archive)

    return SimpleNamespace(module=module, root=root, package=package, events=events, state=state,
                           argv=['--version', '0.1.0', '--full', '--backend-payload', str(payload)])


@pytest.mark.parametrize('commit', [COMMIT, 'unknown'])
def test_record_reaches_inventory_and_both_archives_only_after_smokes(builder, commit):
    builder.state.commit = commit
    builder.module.main(builder.argv)
    assert builder.events[:3] == ['prepare', 'freeze', 'install']
    assert builder.events.index('self-test') < builder.events.index('rank-help') < builder.events.index('version')
    assert builder.events[-4:] == ['version', 'archive', 'backend', 'archive']
    assert len(builder.state.archives) == 2
    for archive in builder.state.archives:
        if archive.suffix == '.zip':
            with zipfile.ZipFile(archive) as packed:
                raw = packed.read('PatchTrace/' + RECORD)
                inventory = packed.read('PatchTrace/file-inventory.json')
        else:
            with tarfile.open(archive, 'r:gz') as packed:
                raw = packed.extractfile('PatchTrace/' + RECORD).read()
                inventory = packed.extractfile('PatchTrace/file-inventory.json').read()
        assert raw == builder.state.raw and json.loads(raw)['git_commit'] == commit
        assert RECORD in json.loads(inventory)


@pytest.mark.parametrize('failure', ['prepare', 'install', 'version'])
def test_provenance_failure_prevents_every_archive_and_backend_attachment(builder, failure):
    builder.state.failure = failure
    with pytest.raises(package_buildinfo.PackageBuildInfoError, match=f'{failure} refused'):
        builder.module.main(builder.argv)
    assert builder.events[-1] == failure
    assert 'archive' not in builder.events and 'backend' not in builder.events
    assert builder.state.archives == []
    assert not list(builder.root.rglob('*.zip')) and not list(builder.root.rglob('*.tar.gz'))
    if failure == 'prepare':
        assert 'freeze' not in builder.events and not builder.package.exists()


@pytest.mark.parametrize('failure', ['self-test', 'rank-help'])
def test_existing_smoke_failure_still_prevents_provenance_check_and_archiving(builder, failure):
    builder.state.failure = failure
    with pytest.raises((subprocess.CalledProcessError, RuntimeError)):
        builder.module.main(builder.argv)
    assert builder.events[-1] == failure
    assert 'version' not in builder.events and builder.state.archives == []


@pytest.mark.parametrize('builder', ['windows'], indirect=True)
def test_windows_resource_commit_mismatch_refuses_before_freezing(builder):
    builder.state.commit = 'b' * 40
    with pytest.raises(SystemExit, match='resource conflicts with the observed source commit'):
        builder.module.main(builder.argv)
    assert builder.events == ['prepare']
    assert not builder.package.exists() and builder.state.archives == []
