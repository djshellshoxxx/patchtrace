"""Offline runtime bundle verifier / installer contract tests.

Tiny text payloads test only ZIP isolation and transaction semantics, not an
operational Python, Java, Ghidra or Ghidriff runtime.
"""
from __future__ import annotations

import hashlib
import json
import threading
import zipfile

import pytest

from patchtrace.offline_bundle import (
    OfflineBundleError,
    inspect_offline_bundle,
    install_offline_bundle,
)

RUNTIME_ID = 'ghidra-12.0.4-ghidriff-4f5d895-windows-amd64'
FILES = {
    'python/python.exe': b'fake-python-executable',
    'ghidra/Ghidra/application.properties': b'application.version=12.0.4',
    'jdk/bin/java.exe': b'fake-java-executable',
    'LICENSES/NOTICE.txt': b'Test stub licenses - not redistributable runtime',
}


def make_bundle(tmp_path, files=None, *, extra_members=(), manifest_override=None):
    data = dict(FILES if files is None else files)
    manifest = {
        'format': 'patchtrace-offline-runtime',
        'schema_version': 1,
        'runtime_id': RUNTIME_ID,
        'platform': 'windows',
        'architecture': 'amd64',
        'python': 'python/python.exe',
        'ghidra': 'ghidra',
        'java': 'jdk',
        'versions': {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '25',
                     'ghidriff_revision': '4f5d895fcbb1eacd65efd81145922c15bb7e741d'},
        'files': [
            {'path': name, 'size': len(data[name]), 'sha256': hashlib.sha256(data[name]).hexdigest()}
            for name in sorted(data)
        ],
    }
    if manifest_override:
        manifest = manifest_override(manifest)
    archive = tmp_path / 'runtime.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr('manifest.json', json.dumps(manifest))
        for path, blob in data.items():
            out.writestr('payload/' + path, blob)
        for name, blob in extra_members:
            out.writestr(name, blob)
    return archive


def test_inspect_valid_bundle_without_executing_stub_tools(tmp_path, monkeypatch):
    bundle = make_bundle(tmp_path)
    monkeypatch.setattr('subprocess.run', lambda *args, **kwargs: pytest.fail('Must never execute'))
    plan = inspect_offline_bundle(bundle)
    assert plan.runtime_id == RUNTIME_ID
    assert plan.file_count == 4
    assert plan.total_bytes == sum(map(len, FILES.values()))
    assert len(plan.sha256) == 64


def test_atomic_install_retains_files_and_is_usable_from_paths(tmp_path):
    bundle = make_bundle(tmp_path)
    plan = inspect_offline_bundle(bundle)
    root = tmp_path / 'Program Files with spaces' / 'runtimes'
    installed = install_offline_bundle(plan, root)
    assert installed.root == root / RUNTIME_ID
    assert installed.python_executable.read_bytes() == FILES['python/python.exe']
    assert (installed.ghidra_dir / 'Ghidra' / 'application.properties').read_bytes().startswith(b'application')
    assert installed.java_home.joinpath('bin', 'java.exe').is_file()
    assert (installed.root / 'manifest.json').is_file()
    assert list(root.glob('.install-*')) == []
    assert not list(root.glob('.runtime-*.lock'))


@pytest.mark.parametrize('member', [
    'payload/../escape', 'payload/./ignored', 'payload/C:/Windows/file',
    'payload/python\\danger', 'payload/CON.txt', 'payload/file:stream',
    'payload/trailing. ', 'other-dir/evil',
])
def test_rejects_malicious_archive_entries(tmp_path, member):
    bundle = make_bundle(tmp_path, extra_members=[(member, b'malicious')])
    with pytest.raises(OfflineBundleError, match='PT-OFFLINE'):
        inspect_offline_bundle(bundle)


def test_rejects_duplicate_zip_entries(tmp_path):
    bundle = make_bundle(tmp_path, extra_members=[('payload/python/python.exe', b'overwritten')])
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(bundle)


def test_rejects_hash_mismatch_and_missing_components(tmp_path):
    bundle = make_bundle(tmp_path, files={**FILES, 'LICENSES/NOTICE.txt': b'changed'},
                         manifest_override=lambda m: {
                             **m, 'files': [{**f, 'sha256': '0' * 64}
                                            if f['path'] == 'LICENSES/NOTICE.txt' else f
                                            for f in m['files']]})
    with pytest.raises(OfflineBundleError, match='hash'):
        inspect_offline_bundle(bundle)
    bundle = make_bundle(tmp_path, files={k: v for k, v in FILES.items() if not k.startswith('jdk/')})
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(bundle)


def test_external_sha_is_checked(tmp_path):
    bundle = make_bundle(tmp_path)
    with pytest.raises(OfflineBundleError, match='SHA-256'):
        inspect_offline_bundle(bundle, expected_sha256='f' * 64)
    correct = hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert inspect_offline_bundle(bundle, expected_sha256=correct).sha256 == correct


def test_cancel_before_install_leaves_previous_runtimes_alone(tmp_path):
    plan = inspect_offline_bundle(make_bundle(tmp_path))
    root = tmp_path / 'runtimes'
    root.mkdir()
    existing = root / 'existing'
    existing.mkdir()
    (existing / 'marker').write_text('retain')
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(OfflineBundleError, match='cancel'):
        install_offline_bundle(plan, root, cancel=cancel)
    assert (existing / 'marker').read_text() == 'retain'
    assert not (root / RUNTIME_ID).exists()
    assert not list(root.glob('.install-*'))


def test_idempotence_no_overwrite_and_lock_not_stolen(tmp_path):
    plan = inspect_offline_bundle(make_bundle(tmp_path))
    root = tmp_path / 'runtimes'
    install_offline_bundle(plan, root)
    marker = root / RUNTIME_ID / 'marker.txt'
    marker.write_text('analyst data')
    with pytest.raises(OfflineBundleError, match='already installed'):
        install_offline_bundle(plan, root)
    assert marker.read_text() == 'analyst data'

    second = tmp_path / 'second' / 'runtimes'
    second.mkdir(parents=True)
    lock = second / f'.runtime-{RUNTIME_ID}.lock'
    lock.write_text('other process')
    with pytest.raises(OfflineBundleError, match='lock'):
        install_offline_bundle(plan, second)
    assert lock.read_text() == 'other process'


def test_detects_archive_replacement_after_inspection(tmp_path):
    archive = make_bundle(tmp_path)
    plan = inspect_offline_bundle(archive)
    archive.write_bytes(archive.read_bytes() + b'changed after inspection')
    root = tmp_path / 'runtimes'
    with pytest.raises(OfflineBundleError, match='changed'):
        install_offline_bundle(plan, root)
    assert not (root / RUNTIME_ID).exists()


def test_rejects_symlinked_install_root(tmp_path):
    plan = inspect_offline_bundle(make_bundle(tmp_path))
    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'linked'
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation not permitted')
    with pytest.raises(OfflineBundleError, match='symbolic'):
        install_offline_bundle(plan, link)
    assert not list(real.iterdir())


def test_rejects_corrupt_json_and_non_windows_manifest(tmp_path):
    archive = make_bundle(tmp_path, manifest_override=lambda m: {**m, 'platform': 'linux'})
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(archive)
    archive = tmp_path / 'bad.zip'
    archive.write_bytes(b'not zip data')
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(archive)


def test_producer_does_not_modify_source_and_creates_installable_bundle(tmp_path):
    from patchtrace.offline_bundle import build_offline_bundle

    source = tmp_path / 'payload'
    for relative, value in FILES.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    archive = tmp_path / 'output.zip'
    versions = {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '25',
                'ghidriff_revision': '4f5d895fcbb1eacd65efd81145922c15bb7e741d'}
    build_offline_bundle(source, RUNTIME_ID, versions, archive)
    plan = inspect_offline_bundle(archive)
    assert plan.runtime_id == RUNTIME_ID
    assert install_offline_bundle(plan, tmp_path / 'installed').python_executable.read_bytes() == FILES['python/python.exe']


def test_cancellation_during_extraction_removes_stage_and_lock(tmp_path):
    plan = inspect_offline_bundle(make_bundle(tmp_path))
    cancel = threading.Event()
    root = tmp_path / 'runtimes'
    events = []
    def stop_after_first_file(message):
        events.append(message)
        cancel.set()

    with pytest.raises(OfflineBundleError, match='cancel'):
        install_offline_bundle(plan, root, cancel=cancel, event=stop_after_first_file)
    assert events
    assert not (root / RUNTIME_ID).exists()
    assert not list(root.iterdir())


def test_rejects_case_insensitive_member_collision(tmp_path):
    archive = make_bundle(tmp_path, extra_members=[('payload/PYTHON/python.exe', b'collision')])
    with pytest.raises(OfflineBundleError, match='colliding'):
        inspect_offline_bundle(archive)


def test_rejects_windows_device_name_runtime_id(tmp_path):
    archive = make_bundle(tmp_path, manifest_override=lambda m: {**m, 'runtime_id': 'CON'})
    with pytest.raises(OfflineBundleError, match='runtime ID'):
        inspect_offline_bundle(archive)


def test_rejects_symlink_member(tmp_path):
    archive = make_bundle(tmp_path)
    # Rebuild ZIP using identical manifest but a Unix symbolic-link mode for a payload file.
    with zipfile.ZipFile(archive) as original:
        contents = [(info.filename, original.read(info.filename)) for info in original.infolist()]
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as dest:
        for name, data in contents:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name == 'payload/python/python.exe':
                info.create_system = 3
                info.external_attr = 0o120777 << 16
            dest.writestr(info, data)
    with pytest.raises(OfflineBundleError, match='symlink'):
        inspect_offline_bundle(archive)


def test_insufficient_disk_space_is_reported_before_install(tmp_path, monkeypatch):
    from collections import namedtuple
    from patchtrace import offline_bundle

    plan = inspect_offline_bundle(make_bundle(tmp_path))
    usage = namedtuple('usage', ['total', 'used', 'free'])
    monkeypatch.setattr(offline_bundle.shutil, 'disk_usage', lambda _: usage(100, 100, 0))
    root = tmp_path / 'runtimes'
    with pytest.raises(OfflineBundleError, match='disk space'):
        install_offline_bundle(plan, root)
    assert not root.exists()


def test_producer_is_byte_deterministic_across_distinct_destinations(tmp_path):
    from patchtrace.offline_bundle import build_offline_bundle

    source = tmp_path / 'payload'
    for name, content in FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    versions = {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '25',
                'ghidriff_revision': '4f5d895fcbb1eacd65efd81145922c15bb7e741d'}
    a = build_offline_bundle(source, RUNTIME_ID, versions, tmp_path / 'a.zip')
    b = build_offline_bundle(source, RUNTIME_ID, versions, tmp_path / 'b.zip')
    assert a.read_bytes() == b.read_bytes()
