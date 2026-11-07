"""R8 identity probe: compile-only PE/COFF /OPT:ICF alias test.

Never executes the produced DLLs. Stdlib only. Run in a development sandbox:
    python tools/research/r8_icf_probe.py
Output records digests, exports, versions and explicit PASS/FAIL/BLOCKED state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = (
    '__declspec(dllexport) int first(int x) { return x + 1; }\n'
    '__declspec(dllexport) int second(int x) { return x + 1; }\n'
)
EXPORT = re.compile(r'^\s*\d+\s+0x([0-9a-fA-F]+)\s+(first|second)\s*$', re.MULTILINE)


def run(argv: list[str], workdir: Path) -> str:
    env = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C', 'LC_ALL': 'C'}
    if os.name == 'nt':
        env['SystemRoot'] = os.environ.get('SystemRoot', r'C:\Windows')
    p = subprocess.run(argv, cwd=workdir, env=env, check=False, text=True, capture_output=True, timeout=60)
    if p.returncode:
        raise RuntimeError(f'{Path(argv[0]).name} exited {p.returncode}: {p.stderr[-3000:]}')
    return p.stdout


def main() -> int:
    programs = {name: shutil.which(name) for name in ('clang-cl', 'lld-link', 'llvm-objdump')}
    missing = sorted(name for name, path in programs.items() if path is None)
    if missing:
        print(json.dumps({'status': 'BLOCKED', 'missing_programs': missing}, indent=2))
        return 3
    with tempfile.TemporaryDirectory(prefix='patchtrace-r8-icf-') as root:
        temp = Path(root)
        source = temp / 'icf_pair.c'
        obj = temp / 'icf_pair.obj'
        source.write_text(SOURCE, encoding='utf-8')
        try:
            run([programs['clang-cl'], '/O2', '/Gy', '/c', '/Fo' + str(obj), str(source)], temp)
            exports = {}
            digests = {}
            for mode, flag in [('icf_on', '/opt:icf'), ('icf_off', '/opt:noicf')]:
                dll = temp / f'{mode}.dll'
                run([programs['lld-link'], '/dll', '/noentry', '/nodefaultlib', '/machine:x64',
                     flag, '/Brepro', '/out:' + str(dll), str(obj)], temp)
                table = run([programs['llvm-objdump'], '-p', str(dll)], temp)
                matches = {name: int(rva, 16) for rva, name in EXPORT.findall(table)}
                if set(matches) != {'first', 'second'}:
                    raise RuntimeError(f'{mode}: expected first and second exports, got {sorted(matches)}')
                exports[mode] = {key: hex(value) for key, value in sorted(matches.items())}
                digests[mode] = hashlib.sha256(dll.read_bytes()).hexdigest()
            versions = {name: run([program, '--version'], temp).splitlines()[0]
                        for name, program in programs.items()}
            folded = exports['icf_on']['first'] == exports['icf_on']['second']
            distinct = exports['icf_off']['first'] != exports['icf_off']['second']
            payload = {'status': 'PASS' if folded and distinct else 'FAIL',
                       'assertions': {'icf_on_same_rva': folded, 'icf_off_distinct_rvas': distinct},
                       'source_sha256': hashlib.sha256(SOURCE.encode()).hexdigest(),
                       'tool_versions': versions, 'export_rvas': exports, 'dll_sha256': digests,
                       'note': 'Static PE export inspection only; no target DLL was executed.'}
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0 if folded and distinct else 1
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({'status': 'BLOCKED', 'reason': str(exc)[:3000]}, indent=2))
            return 3


if __name__ == '__main__':
    sys.exit(main())
