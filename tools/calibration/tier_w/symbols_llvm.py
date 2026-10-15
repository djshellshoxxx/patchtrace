"""Optional `llvm-pdbutil` adapter (SPEC-33 s5.5): publics and private procedures from `dump --publics/--symbols`.

The text output is not a contract, so the parser is strict and tied to the LLVM 18 shapes recorded in
tests/fixtures/tier_w/llvm18_*.txt. Output over 256 MiB is an error, never a truncated parse. An unknown record
shape is a warning and is skipped; five consecutive malformed lines, or any malformed address, fail the export.
Segment:offset is decimal and maps through the PE section table; PDBs with OMAP are refused on this path.
The tool is never given a target binary to run: it only reads the PDB.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from . import msf
from .paths import TierWError

OUTPUT_CAP = 256 * 1024 * 1024
TIMEOUT_SECONDS = 600.0
MAX_CONSECUTIVE_BAD = 5
PROCS = frozenset({'S_GPROC32', 'S_LPROC32', 'S_GPROC32_ID', 'S_LPROC32_ID'})
THUNKS = frozenset({'S_THUNK32'})
_HEAD = re.compile(r'^\s+\d+ \| (S_[A-Z0-9_]+) \[size = \d+\](?: `(.*)`)?\s*$')
_ADDR = re.compile(r'\baddr = ([0-9]{4}):([0-9]+)')
_SIZE = re.compile(r'\bcode size = ([0-9]+)')
_FLAGS = re.compile(r'\bflags = ([^,]*)')
Run = Callable[[Sequence[str], float], Path]


def subprocess_run(argv: Sequence[str], timeout: float) -> Path:
    """Run argv with stdout redirected to a temporary file; returns the file (caller deletes it)."""
    with tempfile.NamedTemporaryFile(prefix='llvm-pdbutil-', suffix='.txt', delete=False) as out:
        path = Path(out.name)
    try:
        with path.open('wb') as handle:
            done = subprocess.run(list(argv), stdout=handle, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        path.unlink(missing_ok=True)
        raise TierWError('PT-TIERW-BLOCKED', f'llvm-pdbutil did not run: {type(exc).__name__}') from None
    if done.returncode != 0:
        path.unlink(missing_ok=True)
        raise TierWError('PT-TIERW-VERIFY', f'llvm-pdbutil exited with {done.returncode}')
    return path


def tool_version(exe: Path, run: Run = subprocess_run) -> str:
    out = run([str(exe), '--version'], 30.0)
    try:
        text = out.read_text(encoding='utf-8', errors='replace')
    finally:
        out.unlink(missing_ok=True)
    line = next((line.strip() for line in text.splitlines() if 'LLVM version' in line), None)
    if line is None:
        raise TierWError('PT-TIERW-VERIFY', 'llvm-pdbutil --version output is not recognised')
    return line[:200]


def _rva(segment: str, offset: str, sections: Sequence[msf.Section]) -> int:
    index = int(segment)
    if not 1 <= index <= len(sections):
        raise TierWError('PT-TIERW-VERIFY', f'malformed address: segment {index} is outside the section table')
    return sections[index - 1].virtual_address + int(offset)


def parse_dump(lines: Iterable[str], sections: Sequence[msf.Section], warnings: list[str]) -> list[msf.PdbSymbol]:
    """Publics and procedures from one dump, in file order."""
    out: list[msf.PdbSymbol] = []
    pending: tuple[str, str] | None = None
    bad = 0
    for line in lines:
        if pending is not None:
            kind, name = pending
            pending = None
            addr = _ADDR.search(line)
            if addr is None:
                bad += 1
                if bad >= MAX_CONSECUTIVE_BAD:
                    raise TierWError('PT-TIERW-VERIFY', 'llvm-pdbutil output: five consecutive malformed records')
                warnings.append(f'{kind}: detail line not recognised; record skipped')
                continue
            bad = 0
            rva = _rva(addr.group(1), addr.group(2), sections)
            segment, offset = int(addr.group(1)), int(addr.group(2))
            if kind == 'S_PUB32':
                flags = _FLAGS.search(line)
                out.append(msf.PdbSymbol(name, segment, offset, rva, 'public',
                                         bool(flags and 'function' in flags.group(1)), None))
                continue
            size = _SIZE.search(line)
            if size is None:
                warnings.append(f'{kind}: no code size; record skipped')
                continue
            out.append(msf.PdbSymbol(name, segment, offset, rva, 'private', True, int(size.group(1)),
                                     thunk=kind in THUNKS))
            continue
        head = _HEAD.match(line)
        if head and head.group(2) is not None and (head.group(1) == 'S_PUB32' or head.group(1) in PROCS | THUNKS):
            pending = (head.group(1), head.group(2))
    return out


def _dump(exe: Path, pdb: Path, mode: str, sections: Sequence[msf.Section], warnings: list[str],
          run: Run) -> list[msf.PdbSymbol]:
    path = run([str(exe), 'dump', mode, str(pdb)], TIMEOUT_SECONDS)
    try:
        if path.stat().st_size > OUTPUT_CAP:
            raise TierWError('PT-TIERW-LIMIT', f'llvm-pdbutil {mode} output is over {OUTPUT_CAP} bytes')
        with path.open(encoding='utf-8', errors='replace', newline='') as handle:
            return parse_dump(handle, sections, warnings)
    finally:
        path.unlink(missing_ok=True)


def llvm_index(exe: Path, pdb: Path, sections: Sequence[msf.Section], run: Run = subprocess_run
               ) -> tuple[msf.PdbIndex, str]:
    """(index, tool version). Identity comes from the stdlib reader; symbols from llvm-pdbutil."""
    exe = Path(exe)
    if not exe.is_absolute() or not exe.is_file():
        raise TierWError('PT-TIERW-BLOCKED', 'llvm-pdbutil is not installed at the given absolute path')
    try:
        info = msf.read_identity(pdb)
    except msf.MsfError as exc:
        raise TierWError('PT-TIERW-VERIFY', f'PDB identity unreadable: {exc.code}') from None
    if info.omap:
        raise TierWError('PT-TIERW-VERIFY', 'PDB has OMAP; the llvm-pdbutil path refuses it (use the stdlib reader)')
    version = tool_version(exe, run)
    warnings: list[str] = []
    publics = _dump(exe, pdb, '--publics', sections, warnings, run)
    procedures = _dump(exe, pdb, '--symbols', sections, warnings, run)
    return msf.PdbIndex(info, tuple(publics), tuple(procedures), tuple(sections), tuple(warnings)), version
