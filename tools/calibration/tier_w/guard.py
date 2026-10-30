"""Tier-W repository guard rules (SPEC-33 s12), called from `tools.calibration.corpus.guard`.

Decision O1 (local-only): no Microsoft image, no PDB, no Tier-W manifest and no Tier-W label or derived file may
appear in git. The only PDBs accepted are the self-made fixtures listed by SHA-256 in
tests/fixtures/tier_w/SELF_MADE.json whose producer strings name LLVM/clang and no Microsoft compiler.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from ..corpus import executable_magic
from .catalogue import FAMILIES
from .msf import is_pdb_magic

SELF_MADE = 'tests/fixtures/tier_w/SELF_MADE.json'
SCAN_LIMIT = 64 * 1024 * 1024
JSONL_LINES = 50
MS_MARKERS = (b'Microsoft Corporation', b'Microsoft Windows')
MS_MARKERS_U16 = tuple(m.decode().encode('utf-16-le') for m in MS_MARKERS)
MSVC_COMPILER = b'Microsoft (R) Optimizing Compiler'
LLVM_PRODUCERS = (b'LLD PDB', b'clang version')
WINDOWS_PDBS = frozenset({
    'ntkrnlmp.pdb', 'ntoskrnl.pdb', 'ntkrpamp.pdb', 'ntkrnlpa.pdb', 'ntdll.pdb', 'kernel32.pdb', 'kernelbase.pdb',
    'afd.pdb', 'clfs.pdb', 'http.pdb', 'tcpip.pdb', 'ntfs.pdb', 'win32kfull.pdb', 'rpcrt4.pdb', 'ucrtbase.pdb',
    'msvcrt.pdb', 'ole32.pdb'})
TIER_W_CONTRACTS = frozenset({
    'tier-w-catalogue/1', 'tier-w-pairs/1', 'tier-w-fetch/1', 'ghidra-symbols/1', 'symbol-map/1',
    'tier-w-label-detail/1', 'tier-w-review/1', 'tier-w-audit-key/1', 'tier-w-audit-report/1', 'tier-w-matches/1',
    'tier-w-run/1', 'tier-w-evaluation/1', 'tier-w-aggregate/1'})
LABEL_KEYS = frozenset({'pair', 'match_id', 'A', 'source'})


def allowed_pdbs(worktree: Path) -> dict[str, str]:
    """{relative path: sha256} of the self-made PDB fixtures; empty when the inventory is missing or bad."""
    try:
        doc = json.loads((Path(worktree) / SELF_MADE).read_text(encoding='utf-8'))
        return {f['path']: f['sha256'] for f in doc['files'] if f.get('kind') == 'pdb'
                and str(f['path']).startswith('tests/fixtures/tier_w/')}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def _json_findings(rel: str, data: bytes) -> list[str]:
    def check(doc) -> str | None:
        if not isinstance(doc, dict):
            return None
        if doc.get('contract') == 'calibration-corpus/1' and any(
                isinstance(b, dict) and b.get('tier') == 'W' for b in doc.get('binaries') or ()):
            return f'{rel}: Tier-W manifest (local-only, decision O1)'
        if doc.get('contract') in TIER_W_CONTRACTS and doc.get('tier') == 'W':
            return f'{rel}: Tier-W derived document {doc.get("contract")} (local-only, decision O1)'
        if LABEL_KEYS <= set(doc) and str(doc.get('pair', '')).startswith('tw.'):
            return f'{rel}: Tier-W label record (local-only, decision O1)'
        return None
    try:
        found = check(json.loads(data))
        return [found] if found else []
    except ValueError:
        pass
    lines = [line for line in data.splitlines() if line.strip()][:JSONL_LINES]
    for line in lines:
        try:
            found = check(json.loads(line))
        except ValueError:
            continue
        if found:
            return [found]
    return []


def _pe_findings(rel: str, data: bytes) -> list[str]:
    if any(m in data for m in MS_MARKERS + MS_MARKERS_U16):
        return [f'{rel}: PE image with Microsoft vendor strings (Microsoft images never enter git)']
    pos = data.find(b'RSDS')
    while 0 <= pos < len(data) and pos < SCAN_LIMIT:
        name = data[pos + 24:pos + 24 + 260].split(b'\0', 1)[0].replace(b'\\', b'/').rsplit(b'/', 1)[-1]
        if name.decode('latin-1').lower() in WINDOWS_PDBS:
            return [f'{rel}: PE image referencing a Windows PDB ({name.decode("latin-1")})']
        pos = data.find(b'RSDS', pos + 4)
    return []


def tier_w_problems(worktree: Path, files: Iterable[str]) -> list[str]:
    """Findings that must block a commit/CI run (empty list = clean)."""
    worktree = Path(worktree)
    allow = allowed_pdbs(worktree)
    problems = []
    for rel in files:
        path = worktree / rel
        if not path.is_file() or path.is_symlink():
            continue
        base = rel.rsplit('/', 1)[-1].lower()
        if base in FAMILIES:
            problems.append(f'{rel}: file named like a Tier-W Microsoft binary (never commit)')
            continue
        try:
            size = path.stat().st_size
            with open(path, 'rb') as handle:
                head = handle.read(4096)
                data = head if size <= 4096 else head + handle.read(SCAN_LIMIT - len(head))
        except OSError:
            continue
        if is_pdb_magic(head) or base.endswith(('.pdb', '.pd_')):
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if size <= SCAN_LIMIT else ''
            self_made = (allow.get(rel) == digest and any(p in data for p in LLVM_PRODUCERS)
                         and MSVC_COMPILER not in data)
            if not self_made:
                problems.append(f'{rel}: PDB file (only self-made fixtures listed in {SELF_MADE} are allowed)')
            continue
        if executable_magic(head) == 'pe':
            problems += _pe_findings(rel, data)
            continue
        if head.lstrip()[:1] in (b'{', b'['):
            if size > SCAN_LIMIT:
                problems.append(f'{rel}: JSON larger than {SCAN_LIMIT} bytes cannot be checked for Tier-W data')
            else:
                problems += _json_findings(rel, data)
    return problems
