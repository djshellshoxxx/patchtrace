"""Linux platform and public validate_manifest contract tests (hermetic, synthetic stubs)."""
from __future__ import annotations

import copy
import hashlib
import json
import zipfile

import pytest

from patchtrace.offline_bundle import (
    OfflineBundleError,
    build_offline_bundle,
    inspect_offline_bundle,
    install_offline_bundle,
    validate_manifest,
)

LINUX_FILES = {
    'python/bin/python3': b'fake-python',
    'ghidra/Ghidra/application.properties': b'application.version=12.0.4',
    'jdk/bin/java': b'fake-java',
    'LICENSES/NOTICE.txt': b'stub notice',
}
VERSIONS = {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '21.0.5',
            'ghidriff_revision': '4f5d895'}
LINUX = ('linux',)


def manifest(files=None, **override):
    data = dict(LINUX_FILES if files is None else files)
    result = {
        'format': 'patchtrace-offline-runtime', 'schema_version': 1,
        'runtime_id': 'ghidra-12.0.4-ghidriff-4f5d895-linux-amd64',
        'platform': 'linux', 'architecture': 'amd64', 'python': 'python/bin/python3',
        'ghidra': 'ghidra', 'java': 'jdk', 'versions': dict(VERSIONS),
        'files': [{'path': n, 'size': len(b), 'sha256': hashlib.sha256(b).hexdigest()}
                  for n, b in sorted(data.items())],
    }
    result.update(override)
    return result


def linux_zip(tmp_path, data=None):
    data = dict(LINUX_FILES if data is None else data)
    archive = tmp_path / 'linux.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr('manifest.json', json.dumps(manifest(data)))
        for name, blob in data.items():
            out.writestr('payload/' + name, blob)
    return archive


def test_linux_manifest_accepted_with_explicit_platform():
    runtime_id, files = validate_manifest(manifest(), platforms=LINUX)
    assert runtime_id.endswith('linux-amd64') and len(files) == 4


def test_linux_manifest_refused_by_default():
    with pytest.raises(OfflineBundleError, match='not a Windows x64'):
        validate_manifest(manifest())


def test_windows_manifest_refused_by_linux_loader():
    windows = manifest({'python/python.exe': b'x', 'ghidra/Ghidra/application.properties': b'x',
                        'jdk/bin/java.exe': b'x', 'LICENSES/NOTICE.txt': b'x'},
                       platform='windows', python='python/python.exe')
    assert validate_manifest(windows)[1]
    with pytest.raises(OfflineBundleError, match='accepted x64'):
        validate_manifest(windows, platforms=LINUX)


@pytest.mark.parametrize('mutate', [
    lambda m: m.update(python='python/python.exe'),
    lambda m: m.update(python='python/bin/python'),
    lambda m: m.update(architecture='arm64'),
    lambda m: m.update(platform='darwin'),
    lambda m: m.update(platform=['linux']),
    lambda m: m.update(schema_version=True),
    lambda m: m.update(extra='x'),
    lambda m: m.pop('java'),
    lambda m: m['versions'].pop('jdk'),
    lambda m: m.update(runtime_id='../evil'),
    lambda m: m['files'].append(copy.deepcopy(m['files'][0])),
    lambda m: m['files'][0].update(path='payload/../x'),
    lambda m: m['files'][0].update(path='python\\bin'),
    lambda m: m['files'][0].update(sha256='A' * 64),
    lambda m: m['files'][0].update(size=-1),
], ids=['win-python', 'wrong-python', 'arch', 'darwin', 'list-platform', 'bool-schema', 'extra-key',
        'no-java-key', 'no-jdk-version', 'traversal-id', 'dup-path', 'dotdot', 'backslash',
        'upper-hash', 'neg-size'])
def test_invalid_linux_manifests_rejected(mutate):
    data = manifest()
    mutate(data)
    with pytest.raises(OfflineBundleError):
        validate_manifest(data, platforms=LINUX)


@pytest.mark.parametrize('missing', ['python/bin/python3', 'jdk/bin/java', 'LICENSES/NOTICE.txt',
                                     'ghidra/Ghidra/application.properties'],
                         ids=['python', 'java', 'notice', 'ghidra'])
def test_linux_required_markers(missing):
    files = {n: b for n, b in LINUX_FILES.items() if n != missing}
    files['extra/one.txt'] = b'1'
    with pytest.raises(OfflineBundleError, match='missing'):
        validate_manifest(manifest(files), platforms=LINUX)


@pytest.mark.parametrize('name', ['jdk/bin/java.exe', 'CON/x', 'a/b:c', 'a/b.', 'JDK/BIN/JAVA'],
                         ids=['exe-not-marker', 'reserved', 'ads', 'trailing-dot', 'case-alias'])
def test_portable_path_rules_still_apply_on_linux(name):
    files = dict(LINUX_FILES)
    del files['jdk/bin/java']
    files[name] = b'x'
    with pytest.raises(OfflineBundleError):
        validate_manifest(manifest(files), platforms=LINUX)


@pytest.mark.parametrize('bad', [None, [], 'x', 3], ids=['none', 'list', 'str', 'int'])
def test_non_object_manifest_rejected(bad):
    with pytest.raises(OfflineBundleError):
        validate_manifest(bad)


@pytest.mark.parametrize('platforms', [('darwin',), ['linux'], 'linux', ()],
                         ids=['unknown', 'list', 'str', 'empty'])
def test_programmer_error_on_bad_platforms_argument(platforms):
    with pytest.raises(ValueError):
        validate_manifest(manifest(), platforms=platforms)


def test_zip_linux_refused_by_default_importer_and_accepted_by_linux_loader(tmp_path):
    archive = linux_zip(tmp_path)
    with pytest.raises(OfflineBundleError, match='not a Windows x64'):
        inspect_offline_bundle(archive)
    plan = inspect_offline_bundle(archive, platforms=LINUX)
    assert plan.platform == 'linux' and plan.python_relative == 'payload/python/bin/python3'
    installed = install_offline_bundle(plan, tmp_path / 'runtimes')
    assert installed.python_executable.read_bytes() == LINUX_FILES['python/bin/python3']
    assert installed.java_home.joinpath('bin', 'java').is_file()


def test_producer_roundtrip_linux_and_windows_default(tmp_path):
    src = tmp_path / 'src'
    for name, blob in LINUX_FILES.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_bytes(blob)
    out = build_offline_bundle(src, 'ghidra-12.0.4-linux-amd64', VERSIONS, tmp_path / 'o.zip',
                               platform='linux')
    assert inspect_offline_bundle(out, platforms=LINUX).runtime_id == 'ghidra-12.0.4-linux-amd64'
    with pytest.raises(OfflineBundleError):  # default producer is Windows: markers missing
        build_offline_bundle(src, 'x-windows', VERSIONS, tmp_path / 'w.zip')
    with pytest.raises(OfflineBundleError, match='platform'):
        build_offline_bundle(src, 'x', VERSIONS, tmp_path / 'z.zip', platform='plan9')
