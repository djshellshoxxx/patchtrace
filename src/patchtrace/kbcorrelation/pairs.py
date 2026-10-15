"""Manual pairs (KB-integration-plan 7.2 pair rules, 8.2 KB9 copy; slice K3, E0). Pure.

E0 has two files the analyst already holds and no release index, so the three proofs are:

* ``bytes_state``: ``verified`` (both files were hashed here) or ``incompatible`` (not an AMD64 PE file);
* ``lineage_state``: always ``user-asserted``; nothing here can say the files are adjacent builds;
* ``fix_boundary``: always ``unverified``; only a vendor-stated fixed build plus an index row could support it.

so a usable manual pair is grade B at most, tier E, and carries ``ORDER_UNVERIFIED`` (older and newer are the
analyst's choice). A hard block (identical bytes, a non-AMD64 file, two names without a confirmation) is grade X.
"""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import HARD_BLOCKS, Arch, BinaryRef, PairProposal, domain_id

WINDOW_ID = 'manual'
SUPPORTED_ARCH = 'amd64'

# Exact copy of KB9 (plan 8.2); ``{arch}`` and ``{k}`` are filled from data.
REASON_TEXT = {
    'IDENTICAL_CONTENT': 'These two files are byte-identical; this file did not change between them.',
    'DELTA_ONLY': 'Only a delta payload was found. A complete PE file is required; import one.',
    'ARCH': 'PatchTrace compares AMD64 PE files; this file is {arch}.',
    'CROSS_PRODUCT': 'The two builds belong to different products and are not compared automatically.',
    'ORDER_UNVERIFIED': 'The release order of these builds could not be established, so older and newer are your '
                        'choice. Swap if needed.',
    'DIGEST_MISMATCH': 'The downloaded file does not match the expected SHA-256; no project was created.',
    'NO_OLDER': 'No earlier build of this file is listed for this product.',
    'WINDOW_CONFOUNDED': '{k} other updates ship between these builds; differences may belong to any of them.',
    'SERVER_NOT_COVERED': 'The file index covers Windows 10/11 client updates only; Server-only builds are not '
                          'listed.',
    'NAME_MISMATCH': 'The two files have different names. Confirm they are the same component to continue.',
}


@dataclass(frozen=True)
class LocalFile:
    """What was learned from a file the analyst supplied: hashes and header facts only, never executed."""
    sha256: str
    size: int
    basename: str
    machine: Arch


def binary_ref(file: LocalFile) -> BinaryRef:
    return BinaryRef(sha256=file.sha256, size=file.size, basename=file.basename, machine=file.machine,
                     origin='local-file', availability='local', authenticity='unverified-local-file')


def reason_text(code: str, *, arch: str = 'not AMD64', k: int = 0) -> str:
    return REASON_TEXT[code].format(arch=arch, k=k)


def propose_manual(older: LocalFile, newer: LocalFile, *, scope_id: str,
                   confirm_same_component: bool = False) -> PairProposal:
    """Grade a pair of local files. Never raises for a bad pair: the block is the grade and its reason codes."""
    reasons = {'ORDER_UNVERIFIED'}
    if older.sha256 == newer.sha256:
        reasons.add('IDENTICAL_CONTENT')
    if SUPPORTED_ARCH != older.machine or SUPPORTED_ARCH != newer.machine:
        reasons.add('ARCH')
    if older.basename != newer.basename and not confirm_same_component:
        reasons.add('NAME_MISMATCH')
    blocked = bool(HARD_BLOCKS & reasons)
    key = {'older': older.sha256, 'newer': newer.sha256, 'scope_id': scope_id, 'window_id': WINDOW_ID}
    return PairProposal(
        pair_id=domain_id('kbc.pair', 1, key), older=binary_ref(older), newer=binary_ref(newer), scope_id=scope_id,
        window_id=WINDOW_ID, bytes_state='incompatible' if 'ARCH' in reasons else 'verified',
        lineage_state='user-asserted', fix_boundary='unverified', window=(), window_complete=None,
        reason_codes=tuple(sorted(reasons)), grade='X' if blocked else 'B', tier='E')


def blocking_reasons(pair: PairProposal) -> tuple[str, ...]:
    return tuple(code for code in pair.reason_codes if code in HARD_BLOCKS)


def blocking_text(pair: PairProposal) -> str:
    """The KB9 sentences for every hard block, in reason-code order."""
    arch_name = next((f.machine for f in (pair.older, pair.newer) if f.machine != SUPPORTED_ARCH), 'not AMD64')
    return ' '.join(reason_text(code, arch=arch_name) for code in blocking_reasons(pair))
