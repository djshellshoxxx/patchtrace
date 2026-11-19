"""Owned build observations and authored consumer/process controls; no full package acceptance."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from patchtrace import buildinfo as b
from patchtrace import jobs
from patchtrace.owned_publication import OwnedPublicationError
from tools import package_buildinfo as p


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    package = root / 'src' / 'patchtrace'
    package.mkdir(parents=True)
    observer = package / 'buildinfo.py'
    observer.write_bytes(b'observed = 1\n')
    (package / '__init__.py').write_bytes(b'__version__ = "0.1.0"\n')
    monkeypatch.setattr(b, '__file__', str(observer))
    monkeypatch.setattr(b, 'git_info', lambda root: {'commit': 'unknown', 'describe': 'unknown', 'dirty': None})
    monkeypatch.setattr(p.importlib.metadata, 'version', lambda name: '6.22.3' if name == 'PyInstaller' else '6.12.0')
    return root


def package(tmp_path):
    result = tmp_path / 'distribution'
    (result / '_internal').mkdir(parents=True)
    return result


def response(raw):
    return {'contract': 'enrichment-cli/1', 'command': 'version', 'status': 'complete', 'warnings': [],
            'result': {'contract': 'build-info/1', 'basis': 'packaged-record', **json.loads(raw)}}


def process_result(raw, **kwargs):
    return jobs.ProcessResult(returncode=0, log_tail='', log_bytes=raw, **kwargs)


def test_prepared_record_has_exact_consumer_contract_and_observed_source(source, monkeypatch):
    monkeypatch.setenv('GITHUB_SHA', 'c' * 40)
    raw = p.prepare_record(source)
    record = b._validate_record(raw)
    assert set(record) == set(b.VERSION_KEYS)
    assert record['source_sha256'] == b.source_sha256(source / 'src')
    assert record['git_commit'] == 'unknown' and record['git_describe'] == 'unknown'
    assert record['dirty'] is None and record['frozen'] is True
    assert record['pyinstaller'] == '6.22.3' and record['pyside6'] == '6.12.0'
    assert record['built_utc'].endswith('Z') and len(raw) < b.MAX_BUILD_BYTES


def test_import_from_another_tree_refuses_before_observation(source, monkeypatch):
    monkeypatch.setattr(b, '__file__', str(source.parent / 'another' / 'buildinfo.py'))
    monkeypatch.setattr(b, 'git_info', lambda root: pytest.fail('wrong source must refuse before Git'))
    with pytest.raises(p.PackageBuildInfoError, match='another source tree'):
        p.prepare_record(source)


def test_missing_dependency_metadata_refuses(source, monkeypatch):
    def missing(name):
        raise p.importlib.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(p.importlib.metadata, 'version', missing)
    with pytest.raises(p.PackageBuildInfoError, match='dependency metadata'):
        p.prepare_record(source)


def test_moving_git_observation_refuses(source, monkeypatch):
    observations = iter([{'commit': 'a' * 40, 'describe': 'a', 'dirty': None},
                         {'commit': 'b' * 40, 'describe': 'b', 'dirty': None}])
    monkeypatch.setattr(b, 'git_info', lambda root: next(observations))
    with pytest.raises(p.PackageBuildInfoError, match='Git observation changed'):
        p.prepare_record(source)


def test_source_failure_cannot_become_unknown_build_provenance(source, monkeypatch):
    monkeypatch.setattr(b, 'MAX_SOURCE_BYTES', 1)
    with pytest.raises((b.BuildInfoError, OwnedPublicationError)):
        p.prepare_record(source)


def test_record_install_round_trip_through_real_frozen_consumer(source, tmp_path, monkeypatch):
    raw = p.prepare_record(source)
    target = package(tmp_path)
    installed = p.install_record(source, target, raw)
    assert installed == target / '_internal' / b.BUILD_INFO_RELATIVE
    assert installed.read_bytes() == raw
    monkeypatch.setattr(b.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(b.sys, '_MEIPASS', str(target / '_internal'), raising=False)
    monkeypatch.setattr(b, 'source_sha256', lambda *a: pytest.fail('frozen consumer cannot scan source'))
    result, warnings = b.read_info()
    assert result == response(raw)['result'] and warnings == []


@pytest.mark.parametrize('change', ['bytes', 'git', 'describe'])
def test_detected_build_input_changes_refuse_before_publication(source, tmp_path, monkeypatch, change):
    raw = p.prepare_record(source)
    target = package(tmp_path)
    if change == 'bytes':
        (source / 'src' / 'patchtrace' / 'buildinfo.py').write_bytes(b'observed = 2\n')
    else:
        git = {'commit': 'unknown', 'describe': 'unknown', 'dirty': None}
        git['commit' if change == 'git' else 'describe'] = 'a' * 40
        monkeypatch.setattr(b, 'git_info', lambda root: git)
    with pytest.raises(p.PackageBuildInfoError, match='changed during freezing'):
        p.install_record(source, target, raw)
    assert list((target / '_internal').iterdir()) == []


@pytest.mark.parametrize('edit', [{'dirty': False}, {'source_sha256': 'unknown'}, {'built_utc': None},
                                {'pyinstaller': None}, {'pyside6': None}, {'frozen': 1}, {'extra': True}])
def test_invalid_prepared_record_cannot_reach_destination(source, tmp_path, edit):
    raw = json.dumps(json.loads(p.prepare_record(source)) | edit).encode()
    target = package(tmp_path)
    with pytest.raises(p.PackageBuildInfoError):
        p.install_record(source, target, raw)
    assert list((target / '_internal').iterdir()) == []


@pytest.mark.parametrize('raw', [b' ' * (b.MAX_BUILD_BYTES + 1), b'{"frozen":true,"frozen":true}',
                                 b'{"frozen":NaN}', b'\xff'])
def test_malformed_or_oversized_prepared_record_refuses_before_io(tmp_path, raw):
    with pytest.raises(p.PackageBuildInfoError):
        p.install_record(tmp_path / 'missing', tmp_path / 'absent', raw)
    assert list(tmp_path.iterdir()) == []


def test_existing_record_is_never_overwritten(source, tmp_path):
    raw = p.prepare_record(source)
    target = package(tmp_path)
    existing = target / '_internal' / b.BUILD_INFO_RELATIVE
    existing.parent.mkdir()
    existing.write_bytes(b'previous record')
    old = existing.stat()
    with pytest.raises((OSError, OwnedPublicationError)):
        p.install_record(source, target, raw)
    assert existing.read_bytes() == b'previous record' and existing.stat().st_ino == old.st_ino


def test_linked_layout_refuses_and_preserves_external_directory(source, tmp_path):
    raw = p.prepare_record(source)
    target = tmp_path / 'distribution'
    external = tmp_path / 'external'
    target.mkdir()
    external.mkdir()
    try:
        (target / '_internal').symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip('host cannot create directory links')
    with pytest.raises((OSError, OwnedPublicationError)):
        p.install_record(source, target, raw)
    assert list(external.iterdir()) == []


def test_replaced_package_refuses_without_touching_foreign_record(source, tmp_path, monkeypatch):
    raw = p.prepare_record(source)
    target = package(tmp_path)
    publish = b.owned.publish_bytes
    def replaced(path, data, **kwargs):
        target.rename(tmp_path / 'original-package')
        foreign = target / '_internal' / b.BUILD_INFO_RELATIVE
        foreign.parent.mkdir(parents=True)
        foreign.write_bytes(b'foreign')
        return publish(path, data, **kwargs)
    monkeypatch.setattr(b.owned, 'publish_bytes', replaced)
    with pytest.raises((OSError, OwnedPublicationError)):
        p.install_record(source, target, raw)
    assert (target / '_internal' / b.BUILD_INFO_RELATIVE).read_bytes() == b'foreign'


def test_frozen_response_types_are_checked_before_python_equality(source, monkeypatch):
    raw = p.prepare_record(source)
    got = response(raw)
    got['result']['frozen'] = 1
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: process_result(json.dumps(got).encode()))
    with pytest.raises(p.PackageBuildInfoError, match='record is invalid'):
        p.check_frozen_record(Path('/authored/app'), raw, cwd=source)


@pytest.mark.parametrize('change', ['basis', 'digest', 'warning', 'extra', 'command'])
def test_frozen_mismatch_refuses(source, monkeypatch, change):
    raw = p.prepare_record(source)
    got = response(raw)
    if change == 'basis':
        got['result']['basis'] = 'source-tree'
    elif change == 'digest':
        got['result']['source_sha256'] = 'f' * 64
    elif change == 'warning':
        got['warnings'] = ['unavailable']
    elif change == 'extra':
        got['result']['extra'] = 0
    else:
        got['command'] = 'doctor'
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: process_result(json.dumps(got).encode()))
    with pytest.raises(p.PackageBuildInfoError):
        p.check_frozen_record(Path('/authored/app'), raw, cwd=source)


@pytest.mark.parametrize('output', [b'{}{}', b'[]', b'{"x":1e999}', b'{"x":1,"x":2}', b'\xff'])
def test_untrusted_process_json_refuses(source, monkeypatch, output):
    raw = p.prepare_record(source)
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: process_result(output))
    with pytest.raises(p.PackageBuildInfoError):
        p.check_frozen_record(Path('/authored/app'), raw, cwd=source)


@pytest.mark.parametrize('reason', ['timeout', 'output-limit', 'cancelled'])
def test_process_failure_never_credits_a_valid_response(source, monkeypatch, reason):
    raw = p.prepare_record(source)
    monkeypatch.setattr(jobs, 'run_process', lambda *a, **k: process_result(json.dumps(response(raw)).encode(),
                                                                        reason=reason))
    with pytest.raises(p.PackageBuildInfoError, match='process bounds'):
        p.check_frozen_record(Path('/authored/app'), raw, cwd=source)


def test_process_admission_has_fixed_bounds_and_exact_arguments(source, monkeypatch):
    raw = p.prepare_record(source)
    def run(argv, **kwargs):
        assert argv == ['/authored/app', 'version', '--json']
        assert kwargs['timeout_seconds'] == 30 and kwargs['max_output_bytes'] == b.MAX_BUILD_BYTES
        assert kwargs['log_limit'] == b.MAX_BUILD_BYTES and kwargs['stderr_limit'] == 4096
        assert kwargs['separate_streams'] is True and kwargs['cwd'] == source
        return process_result(json.dumps(response(raw)).encode())
    monkeypatch.setattr(jobs, 'run_process', run)
    p.check_frozen_record(Path('/authored/app'), raw, cwd=source)


@pytest.mark.skipif(os.name == 'nt', reason='authored POSIX executable; actual Windows package remains separate')
def test_real_authored_child_reads_actual_record_and_detects_change(source, tmp_path, monkeypatch):
    raw = p.prepare_record(source)
    target = package(tmp_path)
    installed = p.install_record(source, target, raw)
    executable = target / 'authored-consumer'
    actual_source = Path(__file__).resolve().parents[1] / 'src'
    executable.write_text(f'#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(actual_source)!r})\n'
                          f'sys.frozen=True\nsys._MEIPASS={str(target / "_internal")!r}\n'
                          'from patchtrace.cli import main\nraise SystemExit(main(sys.argv[1:]))\n')
    executable.chmod(0o700)
    p.check_frozen_record(executable, raw, cwd=source)
    changed = json.loads(raw)
    changed['source_sha256'] = 'c' * 64
    installed.write_text(json.dumps(changed))
    with pytest.raises(p.PackageBuildInfoError, match='differs'):
        p.check_frozen_record(executable, raw, cwd=source)
