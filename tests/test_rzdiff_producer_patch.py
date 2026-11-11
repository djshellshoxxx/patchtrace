"""Compiled boundary controls, not full Rizin/native JSON acceptance."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.rzdiff.patch_producer import UPSTREAM_BLOB, UPSTREAM_SHA256, corrected, git_blob

ROOT = Path(__file__).resolve().parents[1]


def test_unverifiable_source_refused():
    for raw in (b'', b'0.9.1-patched', b'match_pair_new(fcn_b, fcn_a, similarity)'):
        with pytest.raises(ValueError, match='identity'):
            corrected(raw)


def test_pinned_source_patch_and_boundary(tmp_path):
    source = os.environ.get('PATCHTRACE_RIZIN_SIMILARITY')
    if not source:
        pytest.skip('producer source absent; CI fetches exact upstream commit')
    raw = Path(source).read_bytes()
    assert git_blob(raw) == UPSTREAM_BLOB
    assert hashlib.sha256(raw).hexdigest() == UPSTREAM_SHA256
    fixed = corrected(raw)
    with pytest.raises(ValueError, match='identity'):
        corrected(fixed)
    with pytest.raises(ValueError, match='identity'):
        corrected(raw + b'\n')
    # Verify reviewable patch and applicator produce byte-identical source.
    upstream = tmp_path / 'librz/arch'
    upstream.mkdir(parents=True)
    (upstream / 'similarity.c').write_bytes(raw)
    subprocess.run(['git', 'apply', str(
        ROOT / 'tools/rzdiff/singleton-ownership.patch')], cwd=tmp_path, check=True)
    assert (upstream / 'similarity.c').read_bytes() == fixed
    start = raw.index(b'RZ_API RZ_OWN RzAnalysisMatchResult *rz_analysis_match_functions(')
    end = raw.index(b'\n}\n', start) + 3
    start_fixed = fixed.index(b'RZ_API RZ_OWN RzAnalysisMatchResult *rz_analysis_match_functions(')
    end_fixed = fixed.index(b'\n}\n', start_fixed) + 3
    template = (ROOT / 'tools/rzdiff/boundary_control.c').read_text()
    compiler = shutil.which('cc')
    if not compiler:
        pytest.fail('C compiler required for producer boundary controls')
    # Baseline must fail the very same pointer-ownership oracle.
    for label, wrapper, expected in (
        ('stock', raw[start:end], 1),
        ('corrected', fixed[start_fixed:end_fixed], 0),
    ):
        cfile = tmp_path / f'{label}.c'
        cfile.write_text(template.replace('/* WRAPPER */', wrapper.decode()))
        exe = tmp_path / label
        subprocess.run([compiler, '-std=c99', '-Wall', '-Wextra', '-Werror',
                        str(cfile), '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], capture_output=True, text=True, check=False)
        print(label, result.returncode, result.stdout, result.stderr)
        assert result.returncode == expected


def test_git_blob_identity_alone_cannot_authorize_source(monkeypatch):
    from tools.rzdiff import patch_producer
    monkeypatch.setattr(patch_producer, 'git_blob', lambda _raw: UPSTREAM_BLOB)
    lookalike = patch_producer.OLD.encode()
    with pytest.raises(ValueError, match='identity'):
        corrected(lookalike)


def test_git_object_id_works_when_security_sha1_is_disabled(monkeypatch):
    real = hashlib.sha1

    def nonsecurity_only(*args, **kwargs):
        if kwargs.get('usedforsecurity', True):
            raise ValueError('SHA1 disabled for security use')
        return real(*args, **kwargs)

    monkeypatch.setattr(hashlib, 'sha1', nonsecurity_only)
    assert git_blob(b'') == 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'


def test_cli_refuses_source_symlink_outside_declared_checkout(tmp_path, monkeypatch):
    from tools.rzdiff import patch_producer
    pinned = os.environ.get('PATCHTRACE_RIZIN_SIMILARITY')
    if not pinned:
        pytest.skip('exact pinned source required for mutation-boundary control')
    raw = Path(pinned).read_bytes()
    checkout = tmp_path / 'checkout'
    arch = checkout / 'librz' / 'arch'
    arch.mkdir(parents=True)
    external = tmp_path / 'external-similarity.c'
    external.write_bytes(raw)
    try:
        (arch / 'similarity.c').symlink_to(external)
    except OSError:
        pytest.skip('symlink creation unavailable')
    monkeypatch.setattr(sys, 'argv', ['patch_producer.py', str(checkout)])
    with pytest.raises(ValueError, match='outside'):
        patch_producer.main()
    assert external.read_bytes() == raw


def test_cli_accepts_explicit_checkout_outside_current_directory(tmp_path, monkeypatch):
    from tools.rzdiff import patch_producer
    pinned = os.environ.get('PATCHTRACE_RIZIN_SIMILARITY')
    if not pinned:
        pytest.skip('exact pinned source required for CLI mutation control')
    raw = Path(pinned).read_bytes()
    checkout = tmp_path / 'explicit-checkout'
    arch = checkout / 'librz' / 'arch'
    arch.mkdir(parents=True)
    source = arch / 'similarity.c'
    source.write_bytes(raw)
    unrelated = tmp_path / 'unrelated-working-directory'
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    monkeypatch.setattr(sys, 'argv', ['patch_producer.py', str(checkout)])
    patch_producer.main()
    assert source.read_bytes() == corrected(raw)


def test_sha256_identity_does_not_replace_git_blob_check(monkeypatch):
    from tools.rzdiff import patch_producer
    pinned = os.environ.get('PATCHTRACE_RIZIN_SIMILARITY')
    if not pinned:
        pytest.skip('exact pinned source required for dual identity control')
    raw = Path(pinned).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == UPSTREAM_SHA256
    monkeypatch.setattr(patch_producer, 'git_blob', lambda _raw: '0' * 40)
    with pytest.raises(ValueError, match='identity'):
        corrected(raw)
