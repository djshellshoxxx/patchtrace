"""LBL-08: the MSVC `cl` profile. Hermetic tests use fake `cl`/`link` scripts (POSIX hosts) and pure argv checks; the
real-compiler test needs a Windows host with the Visual Studio environment and records `blocked` everywhere else
(`failed` when PATCHTRACE_REQUIRE_MSVC=1, as on the windows-2022 advisory leg). Nothing here runs a built image."""
from __future__ import annotations

import os
import stat
import types
from pathlib import Path

import pytest
from tier_r_helpers import tools as probed_tools
from tier_r_helpers import write_tree

from tools.calibration.tier_r import build as B
from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r import msvc
from tools.calibration.tier_r import toolchain as T

CL_BANNER = 'Microsoft (R) C/C++ Optimizing Compiler Version 19.40.33811 for x64'
LINK_BANNER = 'Microsoft (R) Incremental Linker Version 14.40.33811.0'


def spec(**kw) -> B.BuildSpec:
    base = dict(project='p', source_root=Path('.'), files=('a.c',), output='p.dll', profile='msvc')
    return B.BuildSpec(**(base | kw))


@pytest.fixture
def posix_fakes(record_live_status):
    """The fake tools are shell scripts: a Windows host records `blocked` (the real compiler test covers it)."""
    if os.name == 'nt':
        record_live_status('tier-r-msvc-fake', 'blocked', 'fake cl/link are POSIX shell scripts')
        pytest.skip('BLOCKED (recorded, not a pass): fake cl/link are POSIX shell scripts')


def script(path: Path, body: str) -> str:
    path.write_text('#!/bin/sh\n' + body, encoding='utf-8', newline='\n')
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


# ---- pure argv and banner parsing -------------------------------------------------------------------------------

def test_banner_and_version_parsing():
    assert msvc.banner_line(f'cl : warning D9002\n{CL_BANNER}\n', msvc.CL_MARKER) == CL_BANNER
    assert msvc.banner_line('link (GNU coreutils) 9.4', msvc.LINK_MARKER) is None
    assert msvc.parse_version(CL_BANNER) == '19.40.33811'
    assert msvc.parse_version(None) is None


def test_env_extra_keeps_only_the_developer_environment_case_insensitively():
    got = msvc.env_extra({'Include': 'i', 'LIB': 'l', 'GITHUB_TOKEN': 'secret', 'HTTPS_PROXY': 'p', 'Path': 'x'})
    assert got == {'Include': 'i', 'LIB': 'l'}


@pytest.mark.parametrize('opt,flags', [('O0', ['/Od']), ('O2', ['/O2']), ('O3', ['/Ox']), ('Os', ['/O2', '/Os'])],
                         ids=['O0', 'O2', 'O3', 'Os'])
def test_compile_argv(opt, flags):
    argv = msvc.compile_argv('cl', spec(opt=opt, defines=('X=1',), std='c11', cflags=('/GS-',)), Path('S'), 'a.c',
                             '../obj/00000.obj', ['.', '_dep/z'])
    assert argv[0] == 'cl' and argv[-2:] == ['/Fo../obj/00000.obj', 'a.c']
    assert all(f in argv for f in flags + ['/c', '/Z7', '/Brepro', '/DX=1', '/I.', '/I_dep/z', '/std:c11', '/GS-'])
    assert '/d1trimfile:S\\' in argv


def test_link_argv_keeps_noicf_and_reproducible_stamp():
    argv = msvc.link_argv('link', spec(libs=('ws2_32',)), ['../obj/00000.obj'], 'p')
    assert argv[:3] == ['link', '/NOLOGO', '/DLL'] and argv[-2:] == ['../obj/00000.obj', 'ws2_32.lib']
    assert {'/Brepro', '/OPT:NOICF', '/OPT:NOREF', '/OUT:../out/p.dll', '/PDB:../out/p.pdb'} <= set(argv)


@pytest.mark.parametrize('kind,expect_in,expect_out', [
    ('icf', '/opt:icf', '/OPT:NOICF'), ('timestamp', f'/timestamp:{B.NUISANCE_EPOCH}', '/Brepro'), ('guid', None, '/Brepro')],
    ids=['icf', 'timestamp', 'guid'])
def test_msvc_nuisance_link_variants(kind, expect_in, expect_out):
    link = msvc.link_argv('link', spec(), ['x.obj'], 'p')
    out = B.nuisance_link('msvc', link, kind)
    assert (expect_in is None or expect_in in out) and expect_out not in out


def test_path_nuisance_drops_the_trim_flag_and_other_profiles_are_unchanged():
    argv = msvc.compile_argv('cl', spec(), Path('S'), 'a.c', 'o.obj', ['.'])
    assert not any(a.startswith('/d1trimfile:') for a in B.nuisance_compile(argv, 'path'))
    gnu = ['gcc', '-ffile-prefix-map=S=.', '-c', 'a.c']
    assert B.nuisance_compile(gnu, 'path') == ['gcc', '-c', 'a.c'] and B.nuisance_compile(gnu, '') == gnu
    assert B.nuisance_link('mingw-clang', ['clang', '-Wl,--no-insert-timestamp'], 'icf')[-1] == '-Wl,--icf=all'


# ---- probing and host gating ------------------------------------------------------------------------------------

def test_probe_records_the_cl_banner_and_rejects_coreutils_link(posix_fakes, tmp_path):
    script(tmp_path / 'cl', f'echo "{CL_BANNER}" >&2\necho "cl : Command line error D8003" \nexit 2\n')
    script(tmp_path / 'link', 'echo "link (GNU coreutils) 9.4"\n')
    chain = T.probe({'PATH': str(tmp_path)}, names=['cl', 'msvc-link'])
    assert chain.get('cl').ok and chain.get('cl').version == CL_BANNER
    assert not chain.get('msvc-link').ok and 'not the Microsoft tool' in chain.get('msvc-link').reason


def test_profile_status_blocks_the_msvc_profile_on_a_posix_host():
    ready = {n: T.Tool(n, f'/x/{n}', 'v') for n in T.PROFILE_TOOLS['msvc']}
    assert 'Windows host' in T.Toolchain(ready, host='posix').profile_status('msvc')
    assert T.Toolchain(ready, host='nt').profile_status('msvc') is None
    assert T.Toolchain(ready, host='posix').profile_status('msvc-free') is not None   # its own tools are absent
    with pytest.raises(T.Blocked, match='Windows host'):
        B.build(spec(source_root=Path('/nonexistent')), T.Toolchain(ready, host='posix'), Path('/nonexistent-store'))


def test_noise_variants_add_cl_only_when_it_can_build():
    base = F.BaseSource(project='p', lineage='L', family='f', source={}, root=Path('.'), files=('a.c',),
                        output='p.dll', profile='mingw-gcc')
    names = {n: T.Tool(n, f'/x/{n}', 'v') for n in T.PROFILE_TOOLS['msvc']}
    assert ('mingw-gcc', 'O2', 'msvc', 'O2') in F.noise_variants(base, T.Toolchain(names, host='nt'))
    assert ('mingw-gcc', 'O2', 'msvc', 'O2') not in F.noise_variants(base, T.Toolchain(names, host='posix'))


# ---- a build through fake tools ---------------------------------------------------------------------------------

FAKE_CL = '''for a in "$@"; do case "$a" in /Fo*) out="${a#/Fo}";; esac; done
echo "cl $*" >> "$LOG"
printf 'obj' > "$out"
'''
FAKE_LINK = '''for a in "$@"; do case "$a" in /OUT:*) out="${a#/OUT:}";; /PDB:*) pdb="${a#/PDB:}";; esac; done
echo "link $*" >> "$LOG"
printf 'MZ-image' > "$out"
printf 'pdb' > "$pdb"
'''
FAKE_STRIP = 'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; *) in="$1";; esac; shift; done\ncp "$in" "$out"\n'


def test_build_through_fake_cl_is_deterministic_and_records_the_compiler(posix_fakes, tmp_path, monkeypatch):
    log = tmp_path / 'calls.log'
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    found = {}
    for name, body in (('cl', FAKE_CL), ('msvc-link', FAKE_LINK), ('llvm-strip', FAKE_STRIP)):
        found[name] = T.Tool(name, script(bindir / name, f'LOG="{log}"\n' + body), CL_BANNER if name == 'cl' else 'v')
    for name in T.PROFILE_TOOLS['msvc']:
        found.setdefault(name, T.Tool(name, f'/x/{name}', 'v'))
    chain = T.Toolchain(found, host='nt')
    monkeypatch.setattr(B, 'read_pe', lambda p: types.SimpleNamespace(
        sha256=B._sha(Path(p).read_bytes()), data=Path(p).read_bytes(), image_base=B.IMAGE_BASE))
    monkeypatch.setattr(B, 'loaded_view', lambda img: {})
    src = write_tree(tmp_path / 'src', {'a.c': 'int f(void){return 1;}\n', 'b.c': 'int g(void){return 2;}\n'})
    s = spec(source_root=src, files=('a.c', 'b.c'), defines=('K=1',))
    first = B.build(s, chain, tmp_path / 'store1')
    second = B.build(s, chain, tmp_path / 'store2')
    assert first.compiler == 'cl' and first.compiler_version == CL_BANNER
    assert (first.recipe_digest, first.sha256) == (second.recipe_digest, second.sha256)
    calls = log.read_text(encoding='utf-8').splitlines()
    assert [c.split()[0] for c in calls[:3]] == ['cl', 'cl', 'link'] and '/OPT:NOICF' in calls[2]
    assert '00000.obj' in calls[2] and first.pdb is not None
    icf = B.build(spec(source_root=src, files=('a.c', 'b.c'), defines=('K=1',), nuisance='icf'), chain,
                  tmp_path / 'store3')
    assert icf.recipe_digest != first.recipe_digest and '/opt:icf' in log.read_text(encoding='utf-8')


# ---- real cl (Windows host with the Visual Studio environment) ----------------------------------------------------

REAL_C = '''int __declspec(noinline) helper(int v) { return v + 11; }
__declspec(dllexport) int ka_scale(int v) { return helper(v) * 3; }
__declspec(dllexport) int ka_clamp(int v, int hi) { if (v > hi) { return hi; } return v; }
'''


def test_real_cl_aa_and_nuisance_pairs(record_live_status, tmp_path):
    chain = probed_tools()
    reason = chain.profile_status('msvc')
    if reason:
        required = os.environ.get('PATCHTRACE_REQUIRE_MSVC') == '1'
        record_live_status('tier-r-msvc', 'failed' if required else 'blocked', reason)
        if required:
            pytest.fail(f'required MSVC toolchain missing: {reason}')
        pytest.skip(f'BLOCKED (recorded, not a pass): {reason}')
    root = write_tree(tmp_path / 'src', {'a.c': REAL_C})
    base = F.BaseSource(project='kamsvc', lineage='L-kamsvc', family='synthetic',
                        source={'suite': 'tests/kamsvc', 'version': 'v1', 'license_spdx': 'MIT'}, root=root,
                        files=('a.c',), output='kamsvc.dll', profile='msvc', std='c11', tag='v1')
    session = F.Session(chain, tmp_path / 'known-answer')
    docs = F.run_aa(session, base, layout=False)
    assert docs[0]['reproducibility']['byte_identical'] is True
    assert docs[0]['older']['build']['profile'] == 'msvc'
    version = docs[0]['older']['build']['compiler_version']
    assert msvc.CL_MARKER in version
    nuisance, skipped = F.run_nuisance(session, base, list(B.NUISANCES))
    assert len(nuisance) + len(skipped) == len(B.NUISANCES)
    assert {f['label'] for d in nuisance for f in d['functions']} <= {'unchanged'}
    record_live_status('tier-r-msvc', 'passed', 'cl A/A and nuisance pairs built', cl_version=version,
                       cl_semver=msvc.parse_version(version), nuisance_skipped=skipped)
