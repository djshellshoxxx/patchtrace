"""Execute Linux corpus setup scripts with inert archives and no network/engine runs."""
from __future__ import annotations

import hashlib
import io
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/corpus-tier-r.yml'
KINDS = ('rizin', 'ghidra')
BODY = b'authored inert archive member; never executed\n'


def _steps(kind):
    steps = yaml.safe_load(WORKFLOW.read_text())['jobs']['shard']['steps']
    cache = next(step for step in steps if step.get('id') == f'{kind}-cache')
    name = 'Install pinned rizin' if kind == 'rizin' else 'Install Ghidra and Ghidriff'
    install = next(step for step in steps if step.get('name', '').startswith(name))
    return cache, install


def _fixture_archive(kind):
    stream = io.BytesIO()
    if kind == 'rizin':
        with tarfile.open(fileobj=stream, mode='w:xz') as archive:
            member = tarfile.TarInfo('bin/rz-diff')
            member.size = len(BODY)
            archive.addfile(member, io.BytesIO(BODY))
    else:
        with zipfile.ZipFile(stream, 'w') as archive:
            member = zipfile.ZipInfo('ghidra_authored/support/fixture.txt', (2026, 1, 1, 0, 0, 0))
            archive.writestr(member, BODY)
    return stream.getvalue()


def _runtime_file(root, kind):
    return root / ('rizin/bin/rz-diff' if kind == 'rizin'
                   else 'ghidra-runtime/ghidra_authored/support/fixture.txt')


def _run(tmp_path, kind, *, hit, corrupt=False, bad_pin=False, existing_runtime=False, cache_object=None):
    if sys.platform != 'linux':
        pytest.skip('Actual Linux-only corpus setup shell; no Windows/native acceptance claim')
    programs = {name: shutil.which(name) for name in ('bash', 'sha256sum', 'tar', 'unzip')}
    assert all(programs.values()), programs
    cache, step = _steps(kind)
    payload = _fixture_archive(kind)
    source = tmp_path / 'download-fixture'
    source.write_bytes(payload)
    cached = tmp_path / cache['with']['path']
    archive_path = cached.suffix in {'.xz', '.zip'}
    if hit:
        if cache_object:
            cached.parent.mkdir(parents=True, exist_ok=True)
            if cache_object == 'directory':
                cached.mkdir()
            else:
                assert cache_object == 'symlink'
                cached.symlink_to(source)
        elif archive_path:
            cached.parent.mkdir(parents=True)
            cached.write_bytes(payload + b'corrupt' if corrupt else payload)
        else:  # Historical extracted-cache layout, retained for the real red replay.
            member = _runtime_file(tmp_path, kind)
            member.parent.mkdir(parents=True)
            member.write_bytes(b'corrupt' if corrupt else BODY)
    if existing_runtime:
        root = tmp_path / ('rizin' if kind == 'rizin' else 'ghidra-runtime')
        root.mkdir(exist_ok=True)
        (root / 'prior.txt').write_bytes(b'prior owned elsewhere')
    trace = tmp_path / 'trace'
    exported = tmp_path / 'environment'
    env = dict(os.environ, INPUT_ARCHIVE=str(source), TRACE=str(trace), GITHUB_ENV=str(exported),
               RIZIN_VERSION='authored', RIZIN_ASSET='authored.tar.xz',
               RIZIN_SHA256=hashlib.sha256(payload).hexdigest(),
               GHIDRA_URL='https://invalid.example/fixture',
               GHIDRA_SHA256=hashlib.sha256(payload).hexdigest(),
               GHIDRIFF_PIN='authored-not-installed', ENGINES='rizin,ghidriff')
    if bad_pin:
        env['RIZIN_SHA256' if kind == 'rizin' else 'GHIDRA_SHA256'] = 'not-a-sha256'
    condition = step.get('if')
    if condition == "steps.rizin-cache.outputs.cache-hit != 'true'" and hit:
        return subprocess.CompletedProcess([], 0, '', ''), [], exported
    assert condition in (None, "steps.rizin-cache.outputs.cache-hit != 'true'",
                         "contains(env.ENGINES, 'ghidriff')"), condition
    script = step['run'].replace('${{ steps.ghidra-cache.outputs.cache-hit }}', 'true' if hit else 'false')
    assert '${{' not in script, 'Unmodeled workflow expression'
    prefix = '''curl() {
      printf 'download\\n' >> "$TRACE"
      [[ "$1" == '-fsSL' && "$2" == '-o' ]] || return 97
      cp "$INPUT_ARCHIVE" "$3"
    }
    python() {
      [[ "$1" == '-m' && "$2" == 'pip' && "$3" == 'install' ]] || return 98
      printf 'pip-stub\\n' >> "$TRACE"
    }
    '''
    for name in ('sha256sum', 'tar', 'unzip'):
        prefix += (f'{name}() {{ printf "{name}\\n" >> "$TRACE"; '
                   f'{shlex.quote(programs[name])} "$@"; }}\n')
    result = subprocess.run([programs['bash'], '-e', '-o', 'pipefail', '-c', prefix + script],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    return result, trace.read_text().splitlines() if trace.exists() else [], exported


@pytest.mark.parametrize('kind', KINDS)
def test_cache_paths_hold_archives_and_have_a_new_namespace(kind):
    cache, _ = _steps(kind)
    assert cache['with']['path'].endswith('.tar.xz' if kind == 'rizin' else '.zip')
    assert '-archive-' in cache['with']['key']


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('hit', [False, True])
def test_valid_cold_and_restored_archives_are_verified_before_extraction(tmp_path, kind, hit):
    result, trace, _ = _run(tmp_path, kind, hit=hit)
    assert result.returncode == 0, result.stderr
    assert trace.count('download') == int(not hit)
    extractor = 'tar' if kind == 'rizin' else 'unzip'
    assert trace.count('sha256sum') == 1 and trace.count(extractor) == 1
    assert trace.index('sha256sum') < trace.index(extractor)
    assert _runtime_file(tmp_path, kind).read_bytes() == BODY
    if kind == 'ghidra':
        assert trace.index(extractor) < trace.index('pip-stub')


@pytest.mark.parametrize('kind', KINDS)
def test_corrupt_restored_bytes_fail_before_extraction_or_admission(tmp_path, kind):
    result, trace, exported = _run(tmp_path, kind, hit=True, corrupt=True)
    assert result.returncode != 0
    assert trace == ['sha256sum']
    assert not exported.exists()


@pytest.mark.parametrize('kind', KINDS)
def test_malformed_pin_refuses_a_hit_before_any_work(tmp_path, kind):
    result, trace, exported = _run(tmp_path, kind, hit=True, bad_pin=True)
    assert result.returncode != 0
    assert trace == [] and not exported.exists()


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('cache_object', ['directory', 'symlink'])
def test_nonregular_or_link_cache_is_refused_before_hashing(tmp_path, kind, cache_object):
    result, trace, exported = _run(tmp_path, kind, hit=True, cache_object=cache_object)
    assert result.returncode != 0
    assert trace == [] and not exported.exists()
    assert (tmp_path / 'download-fixture').read_bytes() == _fixture_archive(kind)


@pytest.mark.parametrize('kind', KINDS)
def test_existing_runtime_is_never_reused_or_overwritten(tmp_path, kind):
    result, trace, exported = _run(tmp_path, kind, hit=False, existing_runtime=True)
    assert result.returncode != 0
    root = tmp_path / ('rizin' if kind == 'rizin' else 'ghidra-runtime')
    assert (root / 'prior.txt').read_bytes() == b'prior owned elsewhere'
    assert 'tar' not in trace and 'unzip' not in trace and 'pip-stub' not in trace
    assert not exported.exists()
