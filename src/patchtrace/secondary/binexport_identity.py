"""BinExport2 identity, pair orientation and address basis (SPEC-10b §6.6). Pure."""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .binexport_limits import err
from .contracts import SecondaryError, check_pair

IdBinding = Literal['sha256', 'md5', 'empty', 'other']
AddressBasis = Literal['va', 'rva', 'unknown']
_SHA256 = re.compile(r'[0-9A-Fa-f]{64}')
_MD5 = re.compile(r'[0-9A-Fa-f]{32}')
# Ghidra architecture_name prefixes vs PE Machine labels (advisory only; exporter naming is unverified live, U6).
ARCH_FOR_MACHINE = {'IMAGE_FILE_MACHINE_AMD64': 'x86-64', 'IMAGE_FILE_MACHINE_I386': 'x86-32',
                    'IMAGE_FILE_MACHINE_ARM64': 'aarch64-64', 'IMAGE_FILE_MACHINE_ARMNT': 'arm-32'}


@dataclass(frozen=True, slots=True)
class PeLayout:
    """Taken from the existing PE overview: OptionalHeader ImageBase/SizeOfImage, COFF Machine label."""
    image_base: int
    size_of_image: int
    machine: str | None = None


def classify_identity(executable_id: str, artifact_sha256: str, accept_unbound: bool) -> IdBinding:
    if not re.fullmatch(r'[0-9a-f]{64}', artifact_sha256 or ''):
        raise ValueError('artifact_sha256 must be 64 lowercase hex')
    x = (executable_id or '').strip()
    if _SHA256.fullmatch(x):
        if x.lower() != artifact_sha256:
            raise err('PT-SECONDARY-PAIR', 'executable_id_mismatch',
                      'BinExport executable_id does not match the artifact SHA-256')
        return 'sha256'
    kind: IdBinding = 'md5' if _MD5.fullmatch(x) else 'empty' if not x else 'other'
    if not accept_unbound:
        raise err('PT-SECONDARY-INPUT', f'executable_id_{kind}',
                  f'BinExport executable_id is {kind}, not a SHA-256: re-export with SHA-256 ids or confirm '
                  'explicitly that this file belongs to the artifact')
    return kind


def detect_address_basis(addresses: Sequence[int], layout: PeLayout | None) -> AddressBasis:
    if layout is None or not addresses:
        return 'unknown'
    lo, hi = addresses[0], addresses[-1]
    if layout.image_base <= lo and hi < layout.image_base + layout.size_of_image:
        return 'va'
    if hi < layout.size_of_image:
        return 'rva'  # "Subtract Imagebase" was chosen at export
    return 'unknown'


def architecture_warning(architecture_name: str, layout: PeLayout | None) -> str | None:
    if layout is None or not layout.machine or layout.machine not in ARCH_FOR_MACHINE:
        return None
    return None if architecture_name.lower().startswith(ARCH_FOR_MACHINE[layout.machine]) else \
        'architecture_mismatch'


def accept_pair(older, newer, older_sha256: str, newer_sha256: str) -> None:
    """Pair guards over two AcceptedBinExport values; raises SecondaryError."""
    if older_sha256 == newer_sha256:
        raise err('PT-SECONDARY-PAIR', 'identical_pair', 'older and newer artifacts are identical')
    a, b = older.summary, newer.summary
    if a.file_sha256 == b.file_sha256:
        raise err('PT-SECONDARY-PAIR', 'same_file_twice', 'the same BinExport file was given for both sides')
    if (a.role, b.role) != ('older', 'newer'):
        raise err('PT-SECONDARY-ORIENTATION', 'orientation_swapped', 'BinExport roles are not (older, newer)')
    if a.id_binding == 'sha256' and b.id_binding == 'sha256':
        try:
            check_pair(a.executable_id, b.executable_id, older_sha256, newer_sha256)
        except SecondaryError as exc:  # re-raise with a reason slug, same code
            reason = 'orientation_swapped' if exc.code == 'PT-SECONDARY-ORIENTATION' else 'executable_id_mismatch'
            raise err(exc.code, reason, exc.message) from None
    if {a.address_basis, b.address_basis} == {'va', 'rva'}:
        raise err('PT-SECONDARY-PAIR', 'address_basis_mixed',
                  'one BinExport uses virtual addresses and the other subtracted the image base')
