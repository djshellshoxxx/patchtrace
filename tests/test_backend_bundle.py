"""backend_bundle runtime contract (BUNDLE 7.5): hermetic, tiny synthetic payloads only.

Synthetic fixtures are not evidence about a real Ghidra/JDK/Python payload.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from patchtrace import backend_bundle as bb
from patchtrace.backend_bundle import (
    BundleCancelled,
    BundleError,
    bundle_backend_kwargs,
    find_bundled_runtime,
    is_full_verified,
    verify_bundle,
)

VERSIONS = {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '21.0.5', 'ghidriff_revision': '4f5d895'}
LINUX_FILES = {
    'python/bin/python3': b'fake-python',
    'ghidra/Ghidra/application.properties': b'application.version=12.0.4',
    'jdk/bin/java': b'fake-java',
    'LICENSES/NOTICE.txt': b'stub notice',
    'ghidra/docs/a.txt': b'0123456789',
}
WINDOWS_FILES = {
    'python/python.exe': b'fake-python',
    'ghidra/Ghidra/application.properties': b'application.version=12.0.4',
    'jdk/bin/java.exe': b'fake-java',
    'LICENSES/NOTICE.txt': b'stub notice',
}
PLATFORMS = {
    'linux': ('python/bin/python3', LINUX_FILES),
    'windows': ('python/python.exe', WINDOWS_FILES),
}


def make_bundle(exe_dir: Path, platform='linux', files=None, **override) -> Path:
    python, default = PLATFORMS[platform]
    data = dict(default if files is None else files)
    backend = exe_dir / 'backend'
    for name, content in data.items():
        target = backend / 'payload' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    manifest = {
        'format': 'patchtrace-offline-runtime', 'schema_version': 1,
        'runtime_id': f'ghidra-12.0.4-ghidriff-4f5d895-{platform}-amd64',
        'platform': platform, 'architecture': 'amd64', 'python': python,
        'ghidra': 'ghidra', 'java': 'jdk', 'versions': dict(VERSIONS),
        'files': [{'path': n, 'size': len(c), 'sha256': hashlib.sha256(c).hexdigest()}
                  for n, c in sorted(data.items())],
    }
    manifest.update(override)
    (backend / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return backend


@pytest.fixture
def bundle(tmp_path):
    exe = tmp_path / 'app dir é'
    exe.mkdir()
    make_bundle(exe)
    return exe, find_bundled_runtime(exe, host='linux')


def codes(report):
    return sorted({p.code for p in report.problems})


def symlink_or_skip(link: Path, target: Path, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip('symlinks unavailable on this platform or account')


# ---- find_bundled_runtime ---------------------------------------------------------------

def test_find_returns_ref_with_runtime_paths(bundle):
    exe, ref = bundle
    assert ref.runtime_id == 'ghidra-12.0.4-ghidriff-4f5d895-linux-amd64'
    assert ref.root == exe / 'backend' and ref.manifest_path == exe / 'backend' / 'manifest.json'
    assert ref.python == exe / 'backend' / 'payload' / 'python' / 'bin' / 'python3'
    assert ref.ghidra == exe / 'backend' / 'payload' / 'ghidra'
    assert ref.java_home == exe / 'backend' / 'payload' / 'jdk'
    assert ref.platform == 'linux'
    raw = (exe / 'backend' / 'manifest.json').read_bytes()
    assert ref.manifest_sha256 == hashlib.sha256(raw).hexdigest()


def test_find_windows_layout(tmp_path):
    make_bundle(tmp_path, 'windows')
    ref = find_bundled_runtime(tmp_path, host='windows')
    assert ref.python.name == 'python.exe' and ref.platform == 'windows'


def test_find_none_without_backend_dir_or_location(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, 'frozen', raising=False)
    assert find_bundled_runtime(tmp_path, host='linux') is None
    assert find_bundled_runtime(None, {}, host='linux') is None


def test_find_uses_env_var_when_not_frozen(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, 'frozen', raising=False)
    make_bundle(tmp_path)
    ref = find_bundled_runtime(None, {'PATCHTRACE_BUNDLE_DIR': str(tmp_path)}, host='linux')
    assert ref is not None and ref.root == tmp_path / 'backend'


def test_find_uses_executable_dir_when_frozen(tmp_path, monkeypatch):
    make_bundle(tmp_path)
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'PatchTrace'))
    ref = find_bundled_runtime(None, {'PATCHTRACE_BUNDLE_DIR': str(tmp_path / 'other')}, host='linux')
    assert ref is not None and ref.root == tmp_path / 'backend'


def test_find_does_not_recurse(tmp_path):
    make_bundle(tmp_path / 'nested')
    assert find_bundled_runtime(tmp_path, host='linux') is None


def _break_missing(root):
    (root / 'manifest.json').unlink()


def _break_json(root):
    (root / 'manifest.json').write_text('{not json', encoding='utf-8')


def _break_duplicate_key(root):
    (root / 'manifest.json').write_text('{"format": 1, "format": 2}', encoding='utf-8')


def _break_oversize(root):
    (root / 'manifest.json').write_bytes(b'{"x": "' + b'a' * (bb.MAX_MANIFEST_BYTES + 1) + b'"}')


def _break_extra_key(root):
    data = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    data['extra'] = 1
    (root / 'manifest.json').write_text(json.dumps(data), encoding='utf-8')


def _break_traversal(root):
    data = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    data['files'][0]['path'] = '../escape'
    (root / 'manifest.json').write_text(json.dumps(data), encoding='utf-8')


def _break_marker_missing(root):
    data = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    data['files'] = [f for f in data['files'] if f['path'] != 'jdk/bin/java']
    (root / 'manifest.json').write_text(json.dumps(data), encoding='utf-8')


@pytest.mark.parametrize('breaker, code', [
    (_break_missing, 'PT-BUNDLE-MISSING'),
    (_break_json, 'PT-BUNDLE-MANIFEST'),
    (_break_duplicate_key, 'PT-BUNDLE-MANIFEST'),
    (_break_oversize, 'PT-BUNDLE-MANIFEST'),
    (_break_extra_key, 'PT-BUNDLE-MANIFEST'),
    (_break_traversal, 'PT-BUNDLE-MANIFEST'),
    (_break_marker_missing, 'PT-BUNDLE-MANIFEST'),
], ids=['no-manifest', 'bad-json', 'dup-key', 'oversize', 'extra-key', 'traversal', 'marker-missing'])
def test_find_rejects_bad_manifest(tmp_path, breaker, code):
    backend = make_bundle(tmp_path)
    breaker(backend)
    with pytest.raises(BundleError) as caught:
        find_bundled_runtime(tmp_path, host='linux')
    assert caught.value.code == code and str(caught.value).startswith(code)


def test_find_rejects_manifest_for_other_platform(tmp_path):
    make_bundle(tmp_path, 'windows')
    with pytest.raises(BundleError) as caught:
        find_bundled_runtime(tmp_path, host='linux')
    assert caught.value.code == 'PT-BUNDLE-PLATFORM'


def test_find_rejects_unknown_platform(tmp_path):
    backend = make_bundle(tmp_path)
    data = json.loads((backend / 'manifest.json').read_text(encoding='utf-8'))
    data['platform'] = 'plan9'
    (backend / 'manifest.json').write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(BundleError) as caught:
        find_bundled_runtime(tmp_path, host='linux')
    assert caught.value.code == 'PT-BUNDLE-PLATFORM'


def test_find_refuses_symlinked_backend(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    make_bundle(real)
    exe = tmp_path / 'exe'
    exe.mkdir()
    symlink_or_skip(exe / 'backend', real / 'backend', directory=True)
    with pytest.raises(BundleError) as caught:
        find_bundled_runtime(exe, host='linux')
    assert caught.value.code == 'PT-BUNDLE-LINK'


def test_find_refuses_symlinked_manifest(tmp_path):
    backend = make_bundle(tmp_path)
    (backend / 'real.json').write_bytes((backend / 'manifest.json').read_bytes())
    (backend / 'manifest.json').unlink()
    symlink_or_skip(backend / 'manifest.json', backend / 'real.json')
    with pytest.raises(BundleError) as caught:
        find_bundled_runtime(tmp_path, host='linux')
    assert caught.value.code == 'PT-BUNDLE-LINK'


# ---- fast verification ------------------------------------------------------------------

def test_fast_verify_ok(bundle):
    _, ref = bundle
    report = verify_bundle(ref)
    assert report.ok and report.checked == len(LINUX_FILES) and not report.problems
    assert report.bytes == sum(len(c) for c in LINUX_FILES.values())


def test_bundle_fast_verify_detects_extra_file(bundle):
    exe, ref = bundle
    (exe / 'backend' / 'payload' / 'jdk' / 'bin' / 'evil.dll').write_bytes(b'x')
    report = verify_bundle(ref)
    assert not report.ok and codes(report) == ['PT-BUNDLE-EXTRA']
    assert report.problems[0].path == 'jdk/bin/evil.dll'


def test_fast_verify_detects_extra_file_beside_manifest(bundle):
    exe, ref = bundle
    (exe / 'backend' / 'stray.txt').write_bytes(b'x')
    assert codes(verify_bundle(ref)) == ['PT-BUNDLE-EXTRA']


def test_fast_verify_detects_missing_file(bundle):
    exe, ref = bundle
    (exe / 'backend' / 'payload' / 'ghidra' / 'docs' / 'a.txt').unlink()
    report = verify_bundle(ref)
    assert codes(report) == ['PT-BUNDLE-MISSING'] and report.problems[0].path == 'ghidra/docs/a.txt'


def test_fast_verify_detects_missing_payload_directory(bundle):
    import shutil
    exe, ref = bundle
    shutil.rmtree(exe / 'backend' / 'payload')
    report = verify_bundle(ref)
    assert not report.ok and codes(report) == ['PT-BUNDLE-MISSING']


@pytest.mark.parametrize('content', [b'0123', b'0123456789ab'], ids=['shorter', 'longer'])
def test_fast_verify_detects_size_change(bundle, content):
    exe, ref = bundle
    (exe / 'backend' / 'payload' / 'ghidra' / 'docs' / 'a.txt').write_bytes(content)
    assert codes(verify_bundle(ref)) == ['PT-BUNDLE-SIZE']


def test_fast_verify_misses_same_size_flip_but_full_catches_it(bundle):
    exe, ref = bundle
    (exe / 'backend' / 'payload' / 'ghidra' / 'docs' / 'a.txt').write_bytes(b'0123456780')
    assert verify_bundle(ref, mode='fast').ok
    assert codes(verify_bundle(ref, mode='full')) == ['PT-BUNDLE-HASH']


def test_fast_verify_flags_symlink_inside_payload(bundle):
    exe, ref = bundle
    symlink_or_skip(exe / 'backend' / 'payload' / 'link', exe / 'backend' / 'manifest.json')
    assert 'PT-BUNDLE-LINK' in codes(verify_bundle(ref))


def test_fast_verify_flags_symlinked_directory_without_following(bundle, tmp_path):
    exe, ref = bundle
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret').write_bytes(b'x')
    symlink_or_skip(exe / 'backend' / 'payload' / 'jdk' / 'lib', outside, directory=True)
    report = verify_bundle(ref)
    assert codes(report) == ['PT-BUNDLE-LINK'] and report.problems[0].path == 'jdk/lib'


def test_fast_verify_flags_symlinked_payload_root(bundle, tmp_path):
    import shutil
    exe, ref = bundle
    moved = tmp_path / 'moved'
    shutil.move(str(exe / 'backend' / 'payload'), moved)
    symlink_or_skip(exe / 'backend' / 'payload', moved, directory=True)
    assert 'PT-BUNDLE-LINK' in codes(verify_bundle(ref))


def test_verify_detects_manifest_changed_after_find(bundle):
    exe, ref = bundle
    data = json.loads(ref.manifest_path.read_text(encoding='utf-8'))
    data['runtime_id'] = 'other-runtime'
    ref.manifest_path.write_text(json.dumps(data), encoding='utf-8')
    report = verify_bundle(ref)
    assert not report.ok and codes(report) == ['PT-BUNDLE-MANIFEST']


def test_problem_list_is_bounded(tmp_path):
    backend = make_bundle(tmp_path)
    for index in range(bb.MAX_PROBLEMS + 20):
        (backend / 'payload' / f'extra{index}').write_bytes(b'x')
    report = verify_bundle(find_bundled_runtime(tmp_path, host='linux'))
    assert len(report.problems) == bb.MAX_PROBLEMS and report.truncated


def test_verify_rejects_unknown_mode(bundle):
    with pytest.raises(ValueError):
        verify_bundle(bundle[1], mode='deep')


# ---- full verification ------------------------------------------------------------------

def test_full_verify_ok_reports_progress(bundle):
    _, ref = bundle
    events = []
    report = verify_bundle(ref, mode='full', event=events.append)
    assert report.ok and events and events[-1].endswith('100%')
    assert events[0].startswith('Verifying 5 files...')


@pytest.mark.parametrize('name, offset', [
    ('python/bin/python3', 0), ('jdk/bin/java', 7), ('ghidra/docs/a.txt', 9),
    ('LICENSES/NOTICE.txt', 3),
], ids=['python-first', 'java-mid', 'docs-last', 'notice'])
def test_full_verify_detects_any_single_byte_flip(bundle, name, offset):
    exe, ref = bundle
    target = exe / 'backend' / 'payload' / name
    data = bytearray(target.read_bytes())
    data[offset] ^= 0x01
    target.write_bytes(bytes(data))
    report = verify_bundle(ref, mode='full')
    assert codes(report) == ['PT-BUNDLE-HASH'] and report.problems[0].path == name


def test_full_verify_cancel_raises_and_changes_nothing(bundle):
    exe, ref = bundle
    cancel = threading.Event()
    cancel.set()
    before = sorted(p.name for p in (exe / 'backend').rglob('*'))
    with pytest.raises(BundleCancelled):
        verify_bundle(ref, mode='full', cancel=cancel)
    assert sorted(p.name for p in (exe / 'backend').rglob('*')) == before


def test_full_verify_cancel_midway_between_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(bb, 'CHUNK', 4)
    make_bundle(tmp_path)
    ref = find_bundled_runtime(tmp_path, host='linux')
    cancel = threading.Event()

    def stop(message):
        cancel.set()

    with pytest.raises(BundleCancelled):
        verify_bundle(ref, mode='full', cancel=cancel, event=stop)


def test_full_verify_writes_marker_only_on_success(bundle, tmp_path):
    exe, ref = bundle
    work = tmp_path / 'work'
    assert not is_full_verified(ref, work)
    target = exe / 'backend' / 'payload' / 'ghidra' / 'docs' / 'a.txt'
    target.write_bytes(b'0123456780')
    assert not verify_bundle(ref, mode='full', work_dir=work).ok
    assert not is_full_verified(ref, work)
    target.write_bytes(b'0123456789')
    assert verify_bundle(ref, mode='full', work_dir=work).ok
    assert is_full_verified(ref, work)
    assert (work / f'bundle-verified-{ref.manifest_sha256}.json').is_file()


def test_marker_is_keyed_by_manifest_hash(bundle, tmp_path):
    exe, ref = bundle
    work = tmp_path / 'work'
    verify_bundle(ref, mode='full', work_dir=work)
    changed = make_bundle(tmp_path / 'second', files={**LINUX_FILES, 'ghidra/docs/b.txt': b'b'})
    other = find_bundled_runtime(changed.parent, host='linux')
    assert other.manifest_sha256 != ref.manifest_sha256
    assert not is_full_verified(other, work)


def test_marker_rejects_garbage(bundle, tmp_path):
    _, ref = bundle
    work = tmp_path / 'work'
    work.mkdir()
    (work / f'bundle-verified-{ref.manifest_sha256}.json').write_text('not json', encoding='utf-8')
    assert not is_full_verified(ref, work)


def test_work_dir_inside_backend_is_never_written(bundle):
    exe, ref = bundle
    inside = exe / 'backend' / 'work'
    assert verify_bundle(ref, mode='full', work_dir=inside).ok
    assert not inside.exists()
    assert verify_bundle(ref).ok


# ---- backend kwargs ---------------------------------------------------------------------

def test_backend_kwargs(bundle, tmp_path):
    _, ref = bundle
    kwargs = bundle_backend_kwargs(ref, tmp_path / 'work')
    assert kwargs['python_executable'] == str(ref.python)
    assert kwargs['ghidra_dir'] == str(ref.ghidra) and kwargs['java_home'] == str(ref.java_home)
    assert kwargs['restrict_env'] is True and kwargs['bundle'] is True
    assert Path(kwargs['cache_dir']).parent == (tmp_path / 'work').resolve()


@pytest.mark.parametrize('relative', ['', 'work', 'payload/x'], ids=['root', 'child', 'deep'])
def test_backend_kwargs_rejects_work_dir_inside_install(bundle, relative):
    exe, ref = bundle
    with pytest.raises(BundleError) as caught:
        bundle_backend_kwargs(ref, exe / 'backend' / relative)
    assert caught.value.code == 'PT-BUNDLE-WORKDIR'


def test_backend_kwargs_rejects_work_dir_via_dotdot(bundle):
    exe, ref = bundle
    with pytest.raises(BundleError) as caught:
        bundle_backend_kwargs(ref, exe / 'backend' / 'payload' / '..' / 'work')
    assert caught.value.code == 'PT-BUNDLE-WORKDIR'


def test_backend_kwargs_accepts_sibling_with_shared_prefix(bundle):
    exe, ref = bundle
    assert bundle_backend_kwargs(ref, exe / 'backend-work')['bundle'] is True


# ---- hygiene and scale ------------------------------------------------------------------

def test_module_is_pure():
    import ast
    tree = ast.parse(Path(bb.__file__).read_text(encoding='utf-8'))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split('.')[0])
    assert not imported & {'PySide6', 'subprocess', 'urllib', 'socket', 'http', 'ctypes'}


def test_fast_verify_of_60k_entries_is_quick(tmp_path):
    count = 60_000
    root = tmp_path / 'backend'
    payload = root / 'payload'
    required = dict(LINUX_FILES)
    digest = hashlib.sha256(b'x').hexdigest()
    records = [{'path': n, 'size': len(c), 'sha256': hashlib.sha256(c).hexdigest()}
               for n, c in required.items()]
    for index in range(count - len(required)):
        name = f'd{index % 200}/f{index}'
        records.append({'path': name, 'size': 1, 'sha256': digest})
    for record in records:
        target = payload / record['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(required.get(record['path'], b'x'))
    records.sort(key=lambda item: item['path'])
    manifest = {
        'format': 'patchtrace-offline-runtime', 'schema_version': 1,
        'runtime_id': 'scale-test-linux-amd64', 'platform': 'linux', 'architecture': 'amd64',
        'python': 'python/bin/python3', 'ghidra': 'ghidra', 'java': 'jdk',
        'versions': dict(VERSIONS), 'files': records}
    (root / 'manifest.json').write_text(json.dumps(manifest, separators=(',', ':')), encoding='utf-8')
    assert len(records) == count
    ref = find_bundled_runtime(tmp_path, host='linux')
    started = time.perf_counter()
    report = verify_bundle(ref)
    elapsed = time.perf_counter() - started
    assert report.ok and report.checked == count
    assert elapsed < 10.0, f'fast check took {elapsed:.1f}s (budget 10 s CI, 3 s SSD)'
