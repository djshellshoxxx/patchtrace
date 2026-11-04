"""Compiled boundary controls, not full Rizin/native JSON acceptance."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tools.rzdiff.patch_producer import UPSTREAM_BLOB, corrected, git_blob

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
