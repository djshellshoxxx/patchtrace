"""tools/provision_intel_tools.py and tools/intel_tools_pin.json (SPEC-29 tools T9). Hermetic: assets come from a local
cache directory (a hit never touches the network); nothing is executed."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / 'tools' / 'intel_tools_pin.json'


@pytest.fixture(scope='module')
def prov():
    spec = importlib.util.spec_from_file_location('provision_intel_tools', ROOT / 'tools' / 'provision_intel_tools.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_pin(tmp_path: Path, members: dict[str, bytes], executable: str = 'capa', **overrides) -> tuple[Path, Path]:
    cache = tmp_path / 'cache'
    cache.mkdir()
    archive = cache / 'capa-test.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    exe = members.get(executable, b'')
    asset = {'name': archive.name, 'url': 'https://github.com/example/capa/releases/download/v1/capa-test.zip',
             'format': 'zip', 'size': archive.stat().st_size, 'sha256': sha(archive.read_bytes()),
             'executable': executable, 'executable_size': len(exe), 'executable_sha256': sha(exe), 'advisory': False}
    asset.update(overrides)
    pin = {'contract': 'intel-tools-pin/1', 'engines': {'capa': {'version': '1', 'assets': {'linux': asset}}}}
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps(pin), encoding='utf-8')
    return path, cache


def run(prov, tmp_path, pin, cache, *extra):
    status_dir = tmp_path / 'status'
    env = tmp_path / 'env'
    code = prov.main(['--os', 'linux', '--engine', 'capa', '--pin', str(pin), '--cache', str(cache),
                      '--dest', str(tmp_path / 'dest'), '--status-dir', str(status_dir), '--github-env', str(env),
                      *extra])
    status = json.loads((status_dir / 'intel-tools-provision.json').read_text(encoding='utf-8'))
    return code, status, env


def test_cached_asset_is_verified_extracted_and_exported(prov, tmp_path):
    pin, cache = make_pin(tmp_path, {'capa': b'#!/bin/true\n', 'README': b'not extracted'})
    code, status, env = run(prov, tmp_path, pin, cache)
    assert code == 0 and status['status'] == 'passed' and status['mocked'] is False
    assert (tmp_path / 'dest' / 'capa' / 'capa').read_bytes() == b'#!/bin/true\n'
    assert not (tmp_path / 'dest' / 'capa' / 'README').exists()          # member allow-list: executable only
    assert env.read_text().startswith('PATCHTRACE_CAPA=') and 'dest' in env.read_text()


def test_wrong_asset_digest_or_size_is_a_failure_even_when_advisory(prov, tmp_path, monkeypatch):
    pin, cache = make_pin(tmp_path, {'capa': b'x'}, sha256='0' * 64)
    served = (cache / 'capa-test.zip').read_bytes()

    class Response(io.BytesIO):
        def geturl(self):
            return 'https://github.com/example/capa/releases/download/v1/capa-test.zip'
        __enter__ = lambda self: self  # noqa: E731
    monkeypatch.setattr(prov.urllib.request, 'urlopen', lambda *a, **k: Response(served))   # no real network
    for flags in ((), ('--advisory',)):
        code, status, env = run(prov, tmp_path, pin, cache, *flags)
        assert code == 1 and status['status'] == 'failed' and not env.exists()


def test_executable_that_differs_from_the_pin_fails(prov, tmp_path):
    pin, cache = make_pin(tmp_path, {'capa': b'real'}, executable_sha256='1' * 64)
    code, status, _env = run(prov, tmp_path, pin, cache)
    assert code == 1 and status['status'] == 'failed' and 'pinned' in status['reason']


@pytest.mark.parametrize('value', ['UNMEASURED', '', None, 'abc'], ids=['unmeasured', 'empty', 'null', 'short'])
def test_unmeasured_pin_is_blocked_and_never_downloaded(prov, tmp_path, value):
    pin, cache = make_pin(tmp_path, {'capa': b'x'}, sha256=value)
    code, status, _env = run(prov, tmp_path, pin, cache)
    assert code == 0 and status['status'] == 'blocked' and status['reason'].startswith('pin-missing')


def test_non_release_url_is_never_trusted(prov, tmp_path):
    pin, cache = make_pin(tmp_path, {'capa': b'x'}, url='https://example.com/capa.zip')
    code, status, _env = run(prov, tmp_path, pin, cache)
    assert code == 0 and status['status'] == 'blocked'


@pytest.mark.parametrize('name', ['../escape', '/abs/path', 'C:/win'], ids=['dotdot', 'absolute', 'drive'])
def test_unsafe_member_names_are_refused(prov, tmp_path, name):
    pin, cache = make_pin(tmp_path, {name: b'x', 'capa': b'x'})
    code, status, _env = run(prov, tmp_path, pin, cache)
    assert code == 1 and status['status'] == 'failed'


def test_pin_file_is_complete_and_consistent_with_the_adapters(prov):
    from patchtrace.intelligence.tools import pins
    pin = json.loads(PIN.read_text(encoding='utf-8'))
    assert pin['contract'] == 'intel-tools-pin/1' and set(pin['engines']) == {'capa', 'floss', 'diec'}
    listed: dict[str, set[str]] = {}
    for engine, entry in pin['engines'].items():
        assert set(entry['assets']) == {'linux', 'windows'}
        for asset in entry['assets'].values():
            prov.trusted(asset)                                  # every value is a measured digest, none UNMEASURED
            assert asset['url'].startswith('https://github.com/') and asset['name'] in asset['url']
            listed.setdefault(engine, set()).add(asset['executable_sha256'])
    assert listed == {engine: set(shas) for engine, shas in pins.PINNED_EXECUTABLES.items()}
    from patchtrace.intelligence.tools import diec
    databases = {a['database_tree_sha256'] for a in pin['engines']['diec']['assets'].values()}
    assert databases == set(diec.KNOWN_DATABASES)


def test_workflow_is_advisory_and_never_required():
    text = (ROOT / '.github' / 'workflows' / 'live-intel-tools.yml').read_text(encoding='utf-8')
    assert 'workflow_dispatch' in text and 'continue-on-error' in text and 'provision_intel_tools.py' in text
    assert 'PATCHTRACE_REQUIRE_LIVE_INTEL_TOOLS' in text
