"""Supply-chain verification tooling: deterministic Ghidriff tarball, pin digest sources, verify-mode plumbing.

Hermetic: a tiny local repository, no network, no signature tools."""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name + '_t', ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rec = _load('verify_backend_pins')
chk = _load('check_backend_pin')
builder = _load('build_backend_bundle')


def make_repo(path: Path, date: str = '2020-01-01T00:00:00Z') -> str:
    path.mkdir(parents=True)
    env = {**os.environ, 'GIT_AUTHOR_DATE': date, 'GIT_COMMITTER_DATE': date, 'GIT_AUTHOR_NAME': 'a',
           'GIT_AUTHOR_EMAIL': 'a@x', 'GIT_COMMITTER_NAME': 'a', 'GIT_COMMITTER_EMAIL': 'a@x'}

    def run_git(*args):
        # no line-ending conversion and no filesystem mode: bytes and modes come from what we stage
        return subprocess.run(['git', '-c', 'core.autocrlf=false', '-c', 'core.filemode=false', *args], cwd=path,
                              env=env, check=True, capture_output=True, text=True).stdout.strip()

    run_git('init', '-q')
    (path / 'pkg').mkdir()
    (path / 'pkg' / 'mod.py').write_bytes(b'x = 1\n')  # bytes: text mode would write CRLF on Windows
    (path / 'LICENSE').write_bytes(b'GPL\n')
    (path / 'run.sh').write_bytes(b'#!/bin/sh\n')
    run_git('add', '-A')
    run_git('update-index', '--chmod=+x', 'run.sh')
    run_git('commit', '-q', '-m', 'c')
    return run_git('rev-parse', 'HEAD')


@pytest.fixture()
def repo(tmp_path):
    return tmp_path / 'r1', make_repo(tmp_path / 'r1')


def test_rebuild_is_deterministic_across_commit_dates(tmp_path, repo):
    path, commit = repo
    first = rec.build_tarball(path, commit, tmp_path / 'a.tar.gz')
    other = tmp_path / 'r2'
    commit2 = make_repo(other, '2024-06-06T06:06:06Z')
    second = rec.build_tarball(other, commit2, tmp_path / 'b.tar.gz')
    assert first['tree'] == second['tree'] and commit != commit2
    assert rec.compare_tarballs(tmp_path / 'a.tar.gz', tmp_path / 'b.tar.gz')['identical']
    again = rec.build_tarball(path, commit, tmp_path / 'c.tar.gz')
    assert again['sha256'] == first['sha256'] == rec.sha256_file(tmp_path / 'a.tar.gz')


def test_tarball_metadata_is_normalised(tmp_path, repo):
    path, commit = repo
    out = tmp_path / 't.tar.gz'
    info = rec.build_tarball(path, commit, out)
    assert info['prefix'] == f'ghidriff-{commit[:7]}/'
    raw = out.read_bytes()
    assert raw[:3] == b'\x1f\x8b\x08' and raw[4:8] == b'\0\0\0\0'
    with tarfile.open(out) as tar:
        members = {m.name: m for m in tar}
    assert all(m.mtime == rec.FIXED_MTIME and m.uid == m.gid == 0 and not m.uname for m in members.values())
    assert members[info['prefix'] + 'run.sh'].mode == 0o755 and members[info['prefix'] + 'LICENSE'].mode == 0o644


def test_fetch_commit_checks_the_commit(tmp_path, repo):
    path, commit = repo
    tree = rec.fetch_commit(str(path), commit, tmp_path / 'f')
    expected = subprocess.run(['git', 'rev-parse', f'{commit}^{{tree}}'], cwd=path, capture_output=True, text=True,
                              check=True).stdout.strip()
    assert tree == expected
    with pytest.raises(rec.VerifyError):
        rec.fetch_commit(str(path), 'abc', tmp_path / 'g')
    with pytest.raises(rec.VerifyError):
        rec.fetch_commit(str(path), '0' * 40, tmp_path / 'h')


def _github_style(tmp_path, commit, replace=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for rel, body, mode in (('pkg/mod.py', b'x = 1\n', 0o644), ('LICENSE', b'GPL\n', 0o644),
                                ('run.sh', b'#!/bin/sh\n', 0o755)):
            if replace and replace[0] == rel:
                body = replace[1]
            info = tarfile.TarInfo(f'ghidriff-{commit}/{rel}')
            info.size, info.mode, info.mtime = len(body), mode, 1
            tar.addfile(info, io.BytesIO(body))
    out = tmp_path / 'gh.tar.gz'
    out.write_bytes(buf.getvalue())
    return out


@pytest.mark.parametrize('replace,identical', [(None, True), (('LICENSE', b'MIT\n'), False)], ids=['same', 'content'])
def test_compare_with_github_style_archive(tmp_path, repo, replace, identical):
    path, commit = repo
    rec.build_tarball(path, commit, tmp_path / 'r.tar.gz')
    result = rec.compare_tarballs(tmp_path / 'r.tar.gz', _github_style(tmp_path, commit, replace))
    assert result['identical'] is identical
    assert identical or result['different'] == ['LICENSE']


def test_builder_rebuilds_from_the_commit_and_checks_the_pin(tmp_path, repo):
    path, commit = repo
    info = rec.build_tarball(path, commit, tmp_path / 'ref.tar.gz')
    ghidriff = {'repo': str(path), 'sha': commit,
                'source_tarball': {'digest_source': 'git-rebuilt', 'sha256': info['sha256'], 'size': info['size']}}
    injected = builder.rebuild_ghidriff_tarball(ghidriff, tmp_path / 'w', lambda _repo, _sha, _work: tmp_path / 'ref.tar.gz')
    assert injected.read_bytes() == (tmp_path / 'ref.tar.gz').read_bytes()
    real = builder.rebuild_ghidriff_tarball(ghidriff, tmp_path / 'w2')  # real fetch and recipe from the local repo
    assert builder.sha256_file(real) == info['sha256']
    ghidriff['source_tarball']['sha256'] = '0' * 64
    with pytest.raises(builder.BundleBuildError) as caught:
        builder.rebuild_ghidriff_tarball(ghidriff, tmp_path / 'w3')
    assert caught.value.code == 'PT-BUNDLE-PIN-MISMATCH'


@pytest.mark.parametrize('source', ['tofu', 'none', 'vendor-file', 'sigstore-verified'])
def test_builder_refuses_other_tarball_sources(tmp_path, source):
    entry = {'digest_source': source, 'sha256': 'a' * 64, 'size': 5}
    with pytest.raises(builder.BundleBuildError) as caught:
        builder.rebuild_ghidriff_tarball({'repo': 'https://x', 'sha': 'b' * 40, 'source_tarball': entry}, tmp_path)
    assert caught.value.code == 'PT-BUNDLE-PIN'


def _pinned(source_py, source_tar):
    data = json.loads((ROOT / 'tools' / 'backend_pin.json').read_text(encoding='utf-8'))
    for entry, source in ((data['components']['python-windows'], source_py),
                          (data['ghidriff']['source_tarball'], source_tar)):
        entry.update(status='pinned', sha256='ab' * 32, size=10, digest_source=source)
    return data


@pytest.mark.parametrize('py,tar,ok', [
    ('sigstore-verified', 'git-rebuilt', True), ('gpg-verified', 'git-rebuilt', True),
    ('tofu', 'git-rebuilt', False), ('sigstore-verified', 'tofu', False), ('git-rebuilt', 'git-rebuilt', False),
    ('sigstore-verified', 'sigstore-verified', False), ('vendor-file', 'git-rebuilt', False),
], ids=['sig-git', 'gpg-git', 'py-tofu', 'tar-tofu', 'py-git', 'tar-sig', 'py-vendor'])
def test_pin_checker_digest_sources(py, tar, ok):
    assert (chk.validate_pin(_pinned(py, tar)) == []) is ok


@pytest.mark.parametrize('source', ['tofu', 'git-rebuilt', 'sigstore-verified'], ids=['tofu', 'git', 'sig'])
def test_verification_sources_do_not_fit_other_components(source):
    data = _pinned('sigstore-verified', 'git-rebuilt')
    data['components']['ghidra']['digest_source'] = source
    assert chk.validate_pin(data)


def test_verify_without_inputs_records_nothing(tmp_path, monkeypatch):
    def offline(url, dest=None, limit=0):
        raise OSError('offline')

    monkeypatch.setattr(rec, '_fetch', offline)
    args = argparse.Namespace(pin=ROOT / 'tools' / 'backend_pin.json', workdir=tmp_path / 'w', sigstore_identity='',
                              sigstore_issuer='', gpg_fingerprint='')
    evidence, problems = rec.verify_all(args)
    assert problems and evidence['result'] == 'FAILED' and evidence['record_in_pin'] is None
    assert evidence['schema'] == rec.SCHEMA and 'sigstore' in evidence['tools']


def test_bad_sigstore_signature_is_reported(tmp_path):
    calls = []

    def fake(argv, cwd):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, '', 'verification failed')

    result = rec.verify_sigstore(tmp_path / 'f', tmp_path / 'f.sigstore', 'who@x', 'https://issuer', fake)
    assert result['ok'] is False
    argv = calls[0]
    assert argv[1:5] == ['-m', 'sigstore', 'verify', 'identity'] and '--cert-identity' in argv and '--bundle' in argv


class _FakeResponse:
    def __init__(self, body: bytes, encoding: str):
        self._body, self.headers = body, {'Content-Encoding': encoding} if encoding else {}

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize('encoding', ['', 'gzip'], ids=['plain', 'gzip'])
def test_fetch_decodes_gzip_page_bodies(monkeypatch, encoding):
    import gzip as gz
    import urllib.request

    html = b'<html><body>Sigstore identity: release-manager@python.org</body></html>'
    body = gz.compress(html) if encoding else html
    monkeypatch.setattr(urllib.request, 'urlopen', lambda request, timeout=0: _FakeResponse(body, encoding))
    assert rec._fetch('https://www.python.org/downloads/', limit=1 << 20) == html
    assert 'Sigstore identity' in rec._page_text('https://www.python.org/downloads/')
