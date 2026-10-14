"""Function inventory of a debug image (SPEC-32 s5.1): DWARF (llvm-dwarfdump), PDB (llvm-pdbutil), COFF names (llvm-nm).

Text output of the LLVM tools is parsed defensively; anything unexpected is skipped and counted, never guessed.
Addresses become RVAs (VA - ImageBase). Paths are normalised to project-relative POSIX paths when the build mapped its
scratch directory to '.', otherwise the function's origin is `runtime` (CRT, libgcc, system headers).
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

from .pe import PEImage
from .toolchain import Toolchain, run_tool

_DIE = re.compile(r'^0x([0-9a-f]+):(\s+)(DW_TAG_\w+|NULL)\s*$')
_ATTR = re.compile(r'^\s+(DW_AT_\w+)\t\((.*)$')
_RANGE = re.compile(r'^\s+\[0x([0-9a-f]+), 0x([0-9a-f]+)\)')
_REF = re.compile(r'^0x([0-9a-f]+)(?: "(.*)")?\)?$')
_PROC = re.compile(r'^\s*\d+ \| S_([GL])PROC32(?:_ID)? \[size = \d+\] `(.*)`\s*$')
_PROC_ADDR = re.compile(r'addr = (\d{4}):(\d+), code size = (\d+)')
_MOD = re.compile(r'^\s*Mod ([0-9A-Fa-f]{4}) \| `(.*)`:\s*$')
_LFILE = re.compile(r'^(\S.*) \((?:MD5|SHA1|SHA256|None): ?[0-9A-Fa-f]*\)\s*$')
_LBLOCK = re.compile(r'^\s+([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})-([0-9A-Fa-f]{8}), line/addr entries = \d+')
_LENTRY = re.compile(r'(?<![0-9A-Fa-f:])(\d+) ([0-9A-Fa-f]{8})(?= |$)')
_NM = re.compile(r'^([0-9a-fA-F]+) ([tT]) (\S+)$')
_CLONE = re.compile(r'^(?P<base>[A-Za-z_$][A-Za-z0-9_$]*)\.(?P<suffix>(?:cold|part|constprop|isra|lto_priv|clone|'
                    r'localalias|str)(?:\.[0-9]+)*(?:\.(?:cold|part|constprop|isra)(?:\.[0-9]+)*)*)$')


@dataclass(frozen=True)
class ImageFunction:
    name: str
    file: str | None          # project-relative path, or None for runtime/unknown
    raw_file: str | None      # as recorded in the debug info
    line: int | None          # decl line (DWARF) or first line-table line (PDB)
    rva: int
    size: int
    variant: str | None
    unit: str | None          # compile unit / object (static-name disambiguation)
    origin: str               # 'project' | 'runtime'
    external: bool | None = None


@dataclass
class Inventory:
    functions: list[ImageFunction] = field(default_factory=list)
    inline_only: set[tuple[str, str]] = field(default_factory=set)   # (file, name) with no out-of-line code
    skipped: int = 0
    source: str = ''

    def project(self) -> list[ImageFunction]:
        return [f for f in self.functions if f.origin == 'project']

    def runtime_count(self) -> int:
        return sum(1 for f in self.functions if f.origin == 'runtime')


PDB_SOURCE_ROOT = '/ka-src'          # lld-link /pdbsourcepath: relative CodeView paths become /ka-src/<rel>
_PDB_ROOTS = ('/ka-src/', 'c:/ka-src/')


def normalize_path(raw: str | None) -> str | None:
    """'./a/b.c' -> 'a/b.c'; '/ka-src/a/b.c' -> 'a/b.c'; other absolute, drive-qualified or escaping paths -> None
    (runtime/system)."""
    if not raw:
        return None
    text = raw.replace('\\', '/')
    for root in _PDB_ROOTS:
        if text.lower().startswith(root):
            text = text[len(root):]
            break
    if text.startswith('/') or re.match(r'^[A-Za-z]:', text):
        return None
    norm = posixpath.normpath(text)
    if norm.startswith('..') or norm == '.':
        return None
    return norm


def _unquote(value: str) -> str:
    value = value.rstrip()
    if value.endswith(')'):
        value = value[:-1]
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_dwarf(text: str, image_base: int) -> Inventory:
    dies: dict[int, dict] = {}
    order: list[dict] = []
    current: dict | None = None
    cu: dict | None = None
    last_attr = None
    for line in text.splitlines():
        m = _DIE.match(line)
        if m:
            current = {'offset': int(m.group(1), 16), 'tag': m.group(3), 'attrs': {}, 'ranges': []}
            if current['tag'] == 'DW_TAG_compile_unit':
                cu = current
            current['cu'] = cu
            dies[current['offset']] = current
            order.append(current)
            last_attr = None
            continue
        if current is None:
            continue
        m = _ATTR.match(line)
        if m:
            last_attr = m.group(1)
            current['attrs'][last_attr] = m.group(2)
            continue
        r = _RANGE.match(line)
        if r and last_attr == 'DW_AT_ranges':
            lo, hi = int(r.group(1), 16), int(r.group(2), 16)
            if hi > lo:
                current['ranges'].append((lo, hi))
    inv = Inventory(source='dwarf')

    def ref(value: str | None) -> dict | None:
        if not value:
            return None
        m = _REF.match(value.strip())
        return dies.get(int(m.group(1), 16)) if m else None

    def attr(die: dict, key: str, depth: int = 0):
        if key in die['attrs']:
            return die['attrs'][key]
        if depth < 4:
            for link in ('DW_AT_abstract_origin', 'DW_AT_specification'):
                target = ref(die['attrs'].get(link))
                if target is not None:
                    found = attr(target, key, depth + 1)
                    if found is not None:
                        return found
        return None

    for die in order:
        if die['tag'] != 'DW_TAG_subprogram':
            continue
        a = die['attrs']
        name = attr(die, 'DW_AT_name')
        if name is None:
            inv.skipped += 1
            continue
        name = _unquote(name)
        raw_file = attr(die, 'DW_AT_decl_file')
        raw_file = _unquote(raw_file) if raw_file else None
        line = attr(die, 'DW_AT_decl_line')
        try:
            line_no = int(_unquote(line)) if line else None
        except ValueError:
            line_no = None
        ranges = list(die['ranges'])
        if 'DW_AT_low_pc' in a and 'DW_AT_high_pc' in a:
            try:
                lo, hi = int(_unquote(a['DW_AT_low_pc']), 16), int(_unquote(a['DW_AT_high_pc']), 16)
            except ValueError:
                inv.skipped += 1
                continue
            ranges = [(lo, hi)] if hi > lo else []
        file_rel = normalize_path(raw_file)
        unit = normalize_path(_unquote(die['cu']['attrs'].get('DW_AT_name', ''))) if die['cu'] else None
        if not ranges:
            if 'DW_AT_declaration' not in a and file_rel:
                inv.inline_only.add((file_rel, name))
            continue
        entry = a.get('DW_AT_entry_pc')
        entry_va = int(_unquote(entry), 16) if entry and _unquote(entry).startswith('0x') else ranges[0][0]
        primary = next(((lo, hi) for lo, hi in ranges if lo <= entry_va < hi), ranges[0])
        external = attr(die, 'DW_AT_external')
        for lo, hi in sorted(ranges, key=lambda r: (r != primary, r[0])):
            if lo < image_base:
                inv.skipped += 1
                continue
            inv.functions.append(ImageFunction(
                name=name, file=file_rel, raw_file=raw_file, line=line_no, rva=lo - image_base, size=hi - lo,
                variant=None if (lo, hi) == primary else 'part', unit=unit,
                origin='project' if file_rel else 'runtime', external=external is not None))
    return inv


def parse_pdb(symbols_text: str, lines_text: str, image: PEImage) -> Inventory:
    inv = Inventory(source='pdb')
    files: dict[tuple[int, int], tuple[str, int | None]] = {}   # (seg, off) of a line block -> (file, first line)
    current_file: str | None = None
    block: tuple[int, int] | None = None
    for line in lines_text.splitlines():
        m = _LFILE.match(line)
        if m:
            current_file, block = m.group(1).strip(), None
            continue
        b = _LBLOCK.match(line)
        if b and current_file is not None:
            block = (int(b.group(1), 16), int(b.group(2), 16))
            files.setdefault(block, (current_file, None))
            continue
        entries = _LENTRY.findall(line)
        if entries and block is not None and files[block][0] == current_file:
            first = min(int(n) for n, _ in entries)
            path, known = files[block]
            if known is None or first < known:
                files[block] = (path, first)
    module = None
    pending_proc: tuple[str, str] | None = None
    for line in symbols_text.splitlines():
        m = _MOD.match(line)
        if m:
            module = m.group(2)
            continue
        p = _PROC.match(line)
        if p:
            pending_proc = (p.group(1), p.group(2))
            continue
        a = _PROC_ADDR.search(line)
        if a and pending_proc is not None:
            # llvm-pdbutil prints `addr = SSSS:OOOO` in DECIMAL (formatSegmentOffset); line blocks are hex
            seg, off, size = int(a.group(1), 10), int(a.group(2), 10), int(a.group(3))
            kind, name = pending_proc
            pending_proc = None
            if not 1 <= seg <= len(image.sections):
                inv.skipped += 1
                continue
            rva = image.sections[seg - 1].virtual_address + off
            raw_file, line_no = files.get((seg, off), (None, None))
            file_rel = normalize_path(raw_file)
            unit = normalize_path(Path(module).name if module else None)
            inv.functions.append(ImageFunction(
                name=name, file=file_rel, raw_file=raw_file, line=line_no, rva=rva, size=size, variant=None,
                unit=unit, origin='project' if file_rel else 'runtime', external=kind == 'G'))
    return inv


def parse_nm(text: str, image_base: int) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for line in text.splitlines():
        m = _NM.match(line.strip())
        if m:
            va = int(m.group(1), 16)
            if va >= image_base:
                out.setdefault(va - image_base, []).append(m.group(3))
    return out


def apply_clone_names(inv: Inventory, names: dict[int, list[str]]) -> Inventory:
    """Give compiler clones and split parts their linkage-name suffix as `variant` (foo.constprop.0, foo.cold)."""
    out = []
    for f in inv.functions:
        variant = f.variant
        for linkage in names.get(f.rva, ()):
            m = _CLONE.match(linkage)
            if m and m.group('base') == f.name:
                variant = m.group('suffix')
                break
        out.append(f if variant == f.variant else ImageFunction(**{**f.__dict__, 'variant': variant}))
    inv.functions = out
    return inv


def inventory(image: PEImage, tools: Toolchain, *, pdb: Path | None = None, timeout: float = 600) -> Inventory:
    """Function inventory of a debug image: PDB when given, else DWARF; COFF names refine variants."""
    if pdb is not None:
        exe = tools.path('llvm-pdbutil')
        syms = run_tool([exe, 'dump', '--symbols', str(pdb)], timeout=timeout, check=True).log_tail
        lines = run_tool([exe, 'dump', '-l', str(pdb)], timeout=timeout, check=True).log_tail
        inv = parse_pdb(syms, lines, image)
    else:
        exe = tools.path('llvm-dwarfdump')
        text = run_tool([exe, '--debug-info', '--recurse-depth=1', str(image.path)], timeout=timeout,
                        check=True).log_tail
        inv = parse_dwarf(text, image.image_base)
    if tools.get('llvm-nm').ok:
        nm = run_tool([tools.path('llvm-nm'), '--numeric-sort', '--defined-only', str(image.path)], timeout=timeout)
        if nm.returncode == 0:
            inv = apply_clone_names(inv, parse_nm(nm.log_tail, image.image_base))
    # ICF or aliases can give two debug entries one address: keep the first, count the rest
    seen: dict[int, ImageFunction] = {}
    kept = []
    for f in sorted(inv.functions, key=lambda f: (f.rva, f.origin != 'project', f.name)):
        if f.rva in seen:
            inv.skipped += 1
            continue
        seen[f.rva] = f
        kept.append(f)
    inv.functions = kept
    return inv
