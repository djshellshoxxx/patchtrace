"""The closed set of signature wording shown in the UI and exports (SPEC-51 7.4).

No label says a file is valid, a publisher verified, or anything safe: a digest match means the bytes equal what a
container claims, and chain trust exists only where the OS evaluated it.
"""
from __future__ import annotations

from .models import SignatureInfo

NOT_SIGNED = 'Not signed'
UNREADABLE = 'Signature present, structure unreadable'
MISMATCH = 'Signature present, digest does NOT match file'
MATCH = 'Signature present, digest matches file; trust not evaluated on this platform'
NOT_COMPUTED = 'Signature present, digest not computed'
WINDOWS_TRUSTED = 'embedded signature chains to a trusted root (revocation NOT checked)'
EMBEDDED_LABELS = (NOT_SIGNED, UNREADABLE, MISMATCH, MATCH, NOT_COMPUTED, WINDOWS_TRUSTED)

CATALOG_LABELS_BY_STATE = {
    'present_trusted_no_revocation_check': 'Catalog signature present (no revocation check)',
    'present_untrusted': 'Catalog signature present (no revocation check)',
    'absent': 'No catalog signature found',
    'not_checked': 'Not checked',
    'unavailable': 'Not checked',
}
CATALOG_LABELS = tuple(dict.fromkeys(CATALOG_LABELS_BY_STATE.values()))


def embedded_label(signatures: tuple[SignatureInfo, ...], trust_status: str | None = None) -> str:
    """Worst case first: a mismatch outranks unreadable structure, which outranks a digest that was not computed."""
    if not signatures:
        return NOT_SIGNED
    if any(s.digest_match is False for s in signatures):
        return MISMATCH
    if any(s.structure != 'ok' for s in signatures):
        return UNREADABLE
    if any(s.digest_match is None for s in signatures):
        return NOT_COMPUTED
    return WINDOWS_TRUSTED if trust_status == 'trusted_no_revocation_check' else MATCH


def catalog_label(state: str) -> str:
    return CATALOG_LABELS_BY_STATE.get(state, CATALOG_LABELS_BY_STATE['not_checked'])
