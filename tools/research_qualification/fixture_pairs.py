"""RQ-03a: self-compiled old/new pairs with an independent, reproducible ground-truth manifest.

Source is authored here (no third-party code or binaries). Every function is `noinline` and the one function a
fix touches is the LAST one in the file, so at identical flags every other function is byte-identical and the
truth claim "unchanged" is checkable from the bytes (tests do this). Cases isolate one difficulty each:
identical, optimization noise (same source, -O0 vs -O2), a material fix (added bounds check), and the fix under
optimization noise. Linux ELF shared objects only: PE pairs need a Windows toolchain and are NOT produced here.
Inlining noise is deliberately not modeled (a separate, later fixture). Builds are checked to be reproducible.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

SCHEMA = 'rq-fixture-truth/1'
MUTATED = 'rq_copy_record'
SOURCE = """\
#define NI __attribute__((noinline))
volatile int sink;
NI int rq_checksum(const unsigned char *p, int n) { int s = 0; for (int i = 0; i < n; i++) s = s * 31 + p[i]; return s; }
NI int rq_clamp(int v, int lo, int hi) { if (v < lo) return lo; if (v > hi) return hi; return v; }
NI int rq_parse_len(const unsigned char *p) { return (p[0] << 8) | p[1]; }
NI int rq_mix(int a, int b) { return (a ^ (b << 3)) + (a >> 2); }
NI int rq_entry(const unsigned char *p, int n) { int l = rq_parse_len(p); return rq_mix(rq_checksum(p, n), rq_clamp(l, 0, 4096)); }
NI int rq_copy_record(unsigned char *dst, const unsigned char *src, int n) {
#ifdef FIXED
  if (n < 0 || n > 64) return -1;
#endif
  for (int i = 0; i < n; i++) dst[i] = src[i];
  return n;
}
"""
FUNCTIONS = ('rq_checksum', 'rq_clamp', 'rq_parse_len', 'rq_mix', 'rq_entry', MUTATED)
BUILD = {'identical': (('O0', False), ('O0', False)), 'opt-noise': (('O0', False), ('O2', False)),
         'material-fix': (('O0', False), ('O0', True)), 'material-fix-opt-noise': (('O0', False), ('O2', True))}
CASES = {
    'identical': {'changed': []}, 'opt-noise': {'changed': []},
    'material-fix': {'changed': [MUTATED]}, 'material-fix-opt-noise': {'changed': [MUTATED]},
}
_NM = re.compile(r'^([0-9a-f]+) ([0-9a-f]+) [tT] (\w+)$')
_FLAGS = ['-g0', '-fPIC', '-shared', '-nostdlib', '-fvisibility=hidden', '-fno-asynchronous-unwind-tables',
          '-fno-ident', '-Wl,--build-id=none']


class FixtureError(RuntimeError):
    """A toolchain problem or a violated fixture invariant (never reported as success)."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tool(name: str) -> str:
    exe = shutil.which(name)
    if not exe:
        raise FixtureError(f'{name} not found on PATH')
    return exe


def require_elf_toolchain(cc: str = 'gcc') -> None:
    """These fixtures are ELF shared objects. A compiler that targets another format (for example MinGW on
    Windows builds PE) cannot produce them, so the run is BLOCKED rather than failing or passing."""
    p = subprocess.run([_tool(cc), '-dumpmachine'], capture_output=True, text=True, timeout=30, check=False)
    target = p.stdout.strip()
    if 'linux' not in target:
        raise FixtureError(f'not an ELF target: {cc} targets {target or "unknown"}; ELF fixtures need a Linux-targeting compiler')


def elf_toolchain_available(cc: str = 'gcc') -> bool:
    try:
        require_elf_toolchain(cc)
        return bool(shutil.which('nm'))
    except (FixtureError, OSError, subprocess.SubprocessError):
        return False


def compiler_identity(cc: str = 'gcc') -> dict[str, str | None]:
    exe = _tool(cc)
    first = subprocess.run([exe, '--version'], capture_output=True, text=True, timeout=30, check=False
                           ).stdout.splitlines()[:1]
    return {'cc': cc, 'version': first[0] if first else 'unknown', 'sha256': sha256(Path(exe).resolve())}


def compile_variant(workdir: Path, opt: str, fixed: bool, name: str, cc: str = 'gcc') -> Path:
    """Compile SOURCE once. Identical inputs and flags give identical bytes (verified by the tests)."""
    workdir.mkdir(parents=True, exist_ok=True)
    src = workdir / 'mini.c'
    src.write_text(SOURCE, encoding='utf-8', newline='\n')
    out = workdir / f'{name}.so'
    cmd = [_tool(cc), f'-{opt}', *(['-DFIXED'] if fixed else []), *_FLAGS, '-o', str(out), 'mini.c']
    p = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=120, check=False,
                       env={'SOURCE_DATE_EPOCH': '0', 'PATH': _tool(cc).rsplit('/', 1)[0] + ':/usr/bin:/bin'})
    if p.returncode != 0 or not out.exists():
        raise FixtureError(f'compile failed ({name}): {p.stderr[-300:]}')
    return out


def inventory(binary: Path) -> list[dict[str, Any]]:
    """Function symbols with address and size, from `nm` (the truth survives stripping because it is by address)."""
    p = subprocess.run([_tool('nm'), '-S', '--defined-only', '-n', str(binary)], capture_output=True, text=True,
                       timeout=60, check=False)
    rows = []
    for line in p.stdout.splitlines():
        m = _NM.match(line.strip())
        if m and m.group(3) in FUNCTIONS:
            rows.append({'name': m.group(3), 'addr': int(m.group(1), 16), 'size': int(m.group(2), 16)})
    if [r['name'] for r in rows] != list(FUNCTIONS) and sorted(r['name'] for r in rows) != sorted(FUNCTIONS):
        raise FixtureError(f'unexpected function inventory in {binary.name}: {[r["name"] for r in rows]}')
    return rows


def function_bytes(binary: Path, row: dict[str, Any]) -> bytes:
    """Bytes of one function, located through the ELF64 section table (little-endian only)."""
    data = binary.read_bytes()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise FixtureError('only little-endian ELF64 is supported')
    shoff, shentsize, shnum = struct.unpack_from('<Q', data, 0x28)[0], *struct.unpack_from('<HH', data, 0x3A)
    for i in range(shnum):
        _, _, flags, addr, off, size = struct.unpack_from('<IIQQQQ', data, shoff + i * shentsize)
        if flags & 0x4 and addr <= row['addr'] < addr + size:       # SHF_EXECINSTR
            start = off + row['addr'] - addr
            return data[start:start + row['size']]
    raise FixtureError(f'{row["name"]} is not in an executable section')


def build_case(case_id: str, outdir: Path, cc: str = 'gcc') -> dict[str, Any]:
    require_elf_toolchain(cc)
    (old_opt, old_fixed), (new_opt, new_fixed) = BUILD[case_id]
    old = compile_variant(outdir / case_id / 'old', old_opt, old_fixed, 'old', cc)
    new = compile_variant(outdir / case_id / 'new', new_opt, new_fixed, 'new', cc)
    changed = CASES[case_id]['changed']
    return {
        'schema': SCHEMA, 'case': case_id, 'source_sha256': hashlib.sha256(SOURCE.encode()).hexdigest(),
        'compiler': compiler_identity(cc), 'flags': {'old': f'-{old_opt}' + (' -DFIXED' if old_fixed else ''),
                                                      'new': f'-{new_opt}' + (' -DFIXED' if new_fixed else '')},
        'older': {'sha256': sha256(old), 'functions': inventory(old)},
        'newer': {'sha256': sha256(new), 'functions': inventory(new)},
        'expected': {'matched': [[n, n] for n in FUNCTIONS], 'changed': changed, 'added': [], 'removed': []},
        'limits': ['elf-shared-object-only', 'inlining-noise-not-modeled', 'single-compiler-family'],
    }


def score_matches(truth: dict[str, Any], matches: list[dict[str, Any]]) -> dict[str, Any]:
    """Score an engine's matches ({"old": addr, "new": addr}) against the truth manifest, by address.

    Counts correct matches, false matches (a real function paired with the wrong one), omissions, entries that
    point at no known function, and flags an inverted orientation (every match valid only when old and new are
    swapped). Malformed input raises ValueError; it is never scored as zero."""
    if not isinstance(matches, list) or not all(isinstance(m, dict) and isinstance(m.get('old'), int)
                                                and isinstance(m.get('new'), int) for m in matches):
        raise ValueError('matches must be a list of {"old": int address, "new": int address}')
    old_by = {f['addr']: f['name'] for f in truth['older']['functions']}
    new_by = {f['addr']: f['name'] for f in truth['newer']['functions']}
    expected = {tuple(p) for p in truth['expected']['matched']}
    correct = false = unknown = 0
    got: set[tuple[str, str]] = set()
    swapped_valid = 0
    for m in matches:
        o, n = old_by.get(m['old']), new_by.get(m['new'])
        if o is None or n is None:
            unknown += 1
            swapped_valid += int(new_by.get(m['old']) is not None and old_by.get(m['new']) is not None)
            continue
        got.add((o, n))
        if (o, n) in expected:
            correct += 1
        else:
            false += 1
    omitted = len(expected - got)
    inverted = bool(matches) and unknown == len(matches) and swapped_valid == len(matches)
    return {'truth_pairs': len(expected), 'correct': correct, 'false_matches': false, 'omitted': omitted,
            'unknown_entries': unknown, 'orientation_inverted': inverted,
            'passed': correct == len(expected) and false == 0 and unknown == 0 and not inverted}


def verify_truth(case_id: str, truth: dict[str, Any], outdir: Path) -> list[str]:
    """Check the truth manifest against the actual bytes. Empty list means every claim held."""
    old, new = outdir / case_id / 'old' / 'old.so', outdir / case_id / 'new' / 'new.so'
    oldf = {f['name']: f for f in truth['older']['functions']}
    newf = {f['name']: f for f in truth['newer']['functions']}
    same_flags = BUILD[case_id][0][0] == BUILD[case_id][1][0]
    problems: list[str] = []
    differing = []
    for name in FUNCTIONS:
        a, b = function_bytes(old, oldf[name]), function_bytes(new, newf[name])
        if a != b:
            differing.append(name)
        if same_flags:
            declared = name in truth['expected']['changed']
            if declared and a == b:
                problems.append(f'{name} is declared changed but its bytes are identical')
            if not declared and a != b:
                problems.append(f'{name} is declared unchanged but its bytes differ')
    if not same_flags and not differing:
        problems.append('optimization-noise case produced no byte differences, so it tests nothing')
    return problems


def check_reproducible(case_id: str, outdir: Path, truth: dict[str, Any], cc: str = 'gcc') -> bool:
    """Rebuild into a fresh directory; the same source and flags must give the same bytes."""
    again = build_case(case_id, outdir / '_repro', cc)
    return again['older']['sha256'] == truth['older']['sha256'] and again['newer']['sha256'] == truth['newer']['sha256']
