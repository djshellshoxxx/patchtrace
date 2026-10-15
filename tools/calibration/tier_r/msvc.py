"""MSVC `cl` profile (LBL-08, LBL s2/s7): compile and link argv for a windows-2022 runner, and the banner parsing that
records which compiler built an image. Nothing here runs a tool or touches the filesystem: `build.py` runs the argv
through the same allow-listed runner as every other profile. The profile builds only on a Windows host whose
environment already carries the Visual Studio variables (`vcvars64`, or a dev-command action on the runner).
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .build import BuildSpec

CL_MARKER = 'Microsoft (R) C/C++ Optimizing Compiler'
LINK_MARKER = 'Microsoft (R) Incremental Linker'
IMAGE_BASE = 0x180000000
# `cl` has no -O3: /Ox is the closest full-optimisation setting, and size mode is /O2 plus /Os [inf]. The linker
# options carry the SPEC-32 s2 stance (`/OPT:NOICF`, `/OPT:NOREF`) so that an `icf` nuisance is a real difference.
OPT_FLAGS = {'O0': ('/Od',), 'O1': ('/O1',), 'O2': ('/O2',), 'O3': ('/Ox',), 'Os': ('/O2', '/Os')}
STD_FLAGS = {'c11': '/std:c11', 'c17': '/std:c17', 'c18': '/std:c17'}
# Variables the Visual Studio developer environment sets and `cl`/`link` need to find headers, libraries and DLLs.
ENV_KEEP = ('INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR', 'VCTOOLSINSTALLDIR', 'VSINSTALLDIR', 'WINDOWSSDKDIR',
            'WINDOWSSDKVERBINPATH', 'WINDOWSSDKVERSION', 'UCRTVERSION', 'UNIVERSALCRTSDKDIR', 'PROGRAMFILES',
            'PROGRAMFILES(X86)', 'PROGRAMDATA')
_VERSION = re.compile(r'Version\s+(\d+(?:\.\d+){1,3})')


def banner_line(text: str, marker: str) -> str | None:
    """The first banner line of a `--version` probe, which `cl` prints on stderr and `link` on stdout."""
    for line in text.splitlines():
        if marker in line:
            return line.strip()[:200]
    return None


def parse_version(banner: str | None) -> str | None:
    match = _VERSION.search(banner or '')
    return match.group(1) if match else None


def env_extra(base: Mapping[str, str]) -> dict[str, str]:
    """The developer-environment variables of `base` (names matched case-insensitively, as on Windows)."""
    return {key: value for key, value in base.items() if key.upper() in ENV_KEEP}


def compile_argv(cl: str, spec: BuildSpec, src_dir: Path, rel: str, obj: str, include_dirs: Sequence[str]) -> list[str]:
    """/Z7 keeps CodeView in the object (no shared vc140.pdb), /Brepro makes the object hash-stamped and
    `/d1trimfile` keeps the scratch directory out of the recorded source paths."""
    flags = ['/nologo', '/c', *OPT_FLAGS[spec.opt], '/Z7', '/W0', '/Brepro', '/TC', f'/d1trimfile:{src_dir}\\']
    if spec.std in STD_FLAGS:
        flags.append(STD_FLAGS[spec.std])
    flags += [f'/D{d}' for d in spec.defines] + [f'/I{d}' for d in include_dirs] + list(spec.cflags)
    return [cl, *flags, f'/Fo{obj}', rel]


def link_argv(link: str, spec: BuildSpec, objs: Sequence[str], stem: str) -> list[str]:
    return [link, '/NOLOGO', '/DLL', '/MACHINE:X64', '/DEBUG:FULL', f'/PDB:../out/{stem}.pdb', '/PDBALTPATH:%_PDB%',
            '/Brepro', '/OPT:NOREF', '/OPT:NOICF', '/INCREMENTAL:NO', '/NOIMPLIB', f'/BASE:{IMAGE_BASE:#x}',
            f'/OUT:../out/{spec.output}', *objs, *[f'{name}.lib' for name in spec.libs]]
