"""SPEC-31 G-U1 P1: the nuisance variants of a rebuild are pure argv transformations of the SPEC-32 build (no compiler runs)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from tools.calibration.tier_r import build as B  # noqa: E402
from tools.unified.corpus import aa  # noqa: E402

MSVC = ['lld-link', '/dll', '/Brepro', '/opt:noref', '/opt:noicf', '/out:x.dll', 'a.o']
COMPILE = ['clang', '-ffile-compilation-dir=.', '-ffile-prefix-map=/s=.', '-fdebug-prefix-map=/s=.', '-O2', '-c', 'a.c']


def test_every_kind_is_a_known_nuisance_and_link_order_is_the_other_p1_kind():
    assert aa.P1_KINDS == ('link-order', *B.NUISANCES) and len(set(aa.P1_KINDS)) == 5


def test_an_unknown_nuisance_is_refused_and_the_default_is_none(tmp_path):
    base = dict(project='p', source_root=tmp_path, files=('a.c',), output='p.dll')
    assert B.BuildSpec(**base).nuisance == ''
    with pytest.raises(B.BuildError, match='nuisance'):
        B.BuildSpec(**base, nuisance='asr')


def test_the_msvc_variants_change_exactly_one_flag():
    icf = B.nuisance_link('msvc-free', MSVC, 'icf')
    assert icf == [a.replace('noicf', 'icf') for a in MSVC]
    stamp = B.nuisance_link('msvc-free', MSVC, 'timestamp')
    assert '/Brepro' not in stamp and f'/timestamp:{B.NUISANCE_EPOCH}' in stamp and len(stamp) == len(MSVC)
    guid = B.nuisance_link('msvc-free', MSVC, 'guid')
    assert guid == [a for a in MSVC if a != '/Brepro']
    assert B.nuisance_link('msvc-free', MSVC, 'path') == MSVC and B.nuisance_link('msvc-free', MSVC, '') == MSVC


def test_the_path_variant_drops_every_path_map_from_the_compile_argv_and_nothing_else():
    assert B.nuisance_compile(COMPILE, 'path') == ['clang', '-O2', '-c', 'a.c']
    assert B.nuisance_compile(COMPILE, 'icf') == COMPILE


def test_mingw_variants_and_the_ones_a_linker_cannot_express():
    gcc = ['gcc', '-shared', '-Wl,--no-insert-timestamp']
    assert B.nuisance_link('mingw-gcc', gcc, 'timestamp') == ['gcc', '-shared']
    assert B.nuisance_link('mingw-clang', gcc, 'icf')[-1] == '-Wl,--icf=all'
    for profile, kind in (('mingw-gcc', 'guid'), ('mingw-clang', 'guid'), ('mingw-gcc', 'icf')):
        with pytest.raises(B.BuildError):
            B.nuisance_link(profile, gcc, kind)


def test_variant_of_reads_the_case_of_a_label_document():
    assert aa.variant_of({'case': {'kind': 'nuisance', 'nuisance': 'guid'}}) == 'guid'
    assert aa.variant_of({'case': {'kind': 'link-order', 'order': 'rotated'}}) == 'link-order'
    assert aa.variant_of({'case': {'kind': 'rebuild'}}) == ''
