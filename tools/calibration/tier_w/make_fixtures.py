"""Rebuild the self-made Tier-W test fixtures (SPEC-33 s13): tests/fixtures/tier_w/tiny_v{1,2}.pe/.pdb.

Inputs are MIT sources in tests/fixtures/tier_w/src/v{1,2}/ (freestanding C11 + C++, no CRT). Needs clang with the
x86_64-pc-windows-msvc target and lld-link; tests never need them (the outputs are committed and allow-listed by
SHA-256 in SELF_MADE.json, the only PDBs the repository guard accepts). The outputs are never executed. The build
is path-neutral (relative inputs, /Brepro, /pdbaltpath:%_PDB%, /pdbsourcepath, no CodeView command line) and is
refused if a build-machine path leaks into either file.

    PYTHONPATH=src python -m tools.calibration.tier_w.make_fixtures [--clang PATH] [--lld-link PATH] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

from patchtrace.jobs import run_process

from .paths import REPO_ROOT

FIXTURES = REPO_ROOT / 'tests' / 'fixtures' / 'tier_w'
VERSIONS = ('v1', 'v2')
CFLAGS = ('--target=x86_64-pc-windows-msvc', '-ffreestanding', '-O2', '-g', '-gcodeview', '-ffunction-sections',
          '-funwind-tables', '-fdebug-compilation-dir=.', '-gno-codeview-command-line')
LANG = {'.c': ('-std=c11',), '.cpp': ('-std=c++17', '-fno-exceptions', '-fno-rtti')}
LDFLAGS = ('/dll', '/noentry', '/nodefaultlib', '/debug', '/opt:ref', '/opt:icf', '/brepro', '/pdbaltpath:%_PDB%',
           '/pdbsourcepath:C:\\src')


def _run(argv: list[str], cwd: Path) -> str:
    result = run_process(argv, cwd=cwd, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, cancel=threading.Event(),
                         timeout_seconds=300, separate_streams=True)
    if result.returncode != 0 or result.reason:
        raise RuntimeError(f'{Path(argv[0]).name} failed ({result.reason or result.returncode}): '
                           f'{(result.stderr_tail or result.log_tail)[-2000:]}')
    return result.log_tail


def leaks(data: bytes, forbidden: list[str]) -> list[str]:
    """Build-machine path fragments found in an output (ASCII or UTF-16LE)."""
    found = []
    for text in forbidden:
        if text and (text.encode() in data or text.encode('utf-16-le') in data):
            found.append(text)
    return found


def build_version(version: str, out: Path, clang: str, lld: str) -> tuple[Path, Path]:
    src = FIXTURES / 'src' / version
    with tempfile.TemporaryDirectory(prefix='tierw-fixture-') as tmp:
        work = Path(tmp)
        (work / 'src').mkdir()
        objs = []
        for source in sorted(src.iterdir()):
            if source.suffix not in LANG:
                continue
            shutil.copyfile(source, work / 'src' / source.name)
            obj = f'{source.stem}{source.suffix.replace(".", "_")}.obj'
            _run([clang, *CFLAGS, *LANG[source.suffix], '-c', f'src/{source.name}', '-o', obj], work)
            objs.append(obj)
        name = f'tiny_{version}'
        _run([lld, *LDFLAGS, f'/pdb:{name}.pdb', f'/out:{name}.dll', *objs], work)
        forbidden = [str(work), str(REPO_ROOT), str(Path.home()), '/tmp/', 'claude']
        for produced in (work / f'{name}.dll', work / f'{name}.pdb'):
            bad = leaks(produced.read_bytes(), forbidden)
            if bad:
                raise RuntimeError(f'{produced.name} contains build-machine paths {bad}; refusing to commit it')
        out.mkdir(parents=True, exist_ok=True)
        pe, pdb = out / f'{name}.pe', out / f'{name}.pdb'
        shutil.copyfile(work / f'{name}.dll', pe)
        shutil.copyfile(work / f'{name}.pdb', pdb)
    return pe, pdb


def inventory(paths: list[Path], tools: dict[str, str]) -> dict:
    files = []
    for path in paths:
        data = path.read_bytes()
        files.append({'path': f'tests/fixtures/tier_w/{path.name}', 'sha256': hashlib.sha256(data).hexdigest(),
                      'size': len(data), 'kind': 'pdb' if path.suffix == '.pdb' else 'pe',
                      'source': f'tests/fixtures/tier_w/src/{path.stem.split("_")[-1]}'})
    return {'contract': 'tier-w-fixtures/1', 'tier': 'test', 'license': 'MIT',
            'purpose': 'self-made DLL + PDB pairs for Tier-W tests; the only PDBs the repository guard accepts',
            'recipe': 'PYTHONPATH=src python -m tools.calibration.tier_w.make_fixtures',
            'compile': list(CFLAGS), 'link': list(LDFLAGS), 'tools': tools, 'files': files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--clang', default=shutil.which('clang'))
    parser.add_argument('--lld-link', default=shutil.which('lld-link'))
    parser.add_argument('--out', type=Path, default=FIXTURES)
    args = parser.parse_args(argv)
    if not args.clang or not args.lld_link:
        print('BLOCKED: clang and lld-link are required to rebuild the fixtures', file=sys.stderr)
        return 3
    # absolute but NOT symlink-resolved: lld-link is a symlink to the generic `lld` driver, which dispatches on
    # the name it was invoked by.
    clang, lld = os.path.abspath(args.clang), os.path.abspath(args.lld_link)
    tools = {'clang': _run([clang, '--version'], args.out.parent).splitlines()[0][:200],
             'lld-link': _run([lld, '--version'], args.out.parent).splitlines()[0][:200]}
    outputs = []
    for version in VERSIONS:
        outputs += list(build_version(version, args.out, clang, lld))
    doc = inventory(outputs, tools)
    (args.out / 'SELF_MADE.json').write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({f['path']: f['sha256'] for f in doc['files']}, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
