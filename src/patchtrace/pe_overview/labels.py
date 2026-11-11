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
MATH_OK = 'Signature present, digest matches file; signature math ok, chain not evaluated'
MATH_FAILED = 'Signature present, signature math does NOT verify'
WINDOWS_TRUSTED = 'embedded signature chains to a trusted root (revocation NOT checked)'
EMBEDDED_LABELS = (NOT_SIGNED, UNREADABLE, MISMATCH, MATCH, NOT_COMPUTED, MATH_OK, MATH_FAILED, WINDOWS_TRUSTED)

CATALOG_LABELS_BY_STATE = {
    'present_trusted_no_revocation_check': 'Catalog signature present (no revocation check)',
    'present_untrusted': 'Catalog signature present (no revocation check)',
    'absent': 'No catalog signature found',
    'not_checked': 'Not checked',
    'unavailable': 'Not checked',
}
CATALOG_LABELS = tuple(dict.fromkeys(CATALOG_LABELS_BY_STATE.values()))


def embedded_label(signatures: tuple[SignatureInfo, ...], trust_status: str | None = None) -> str:
    """Worst case first: a digest mismatch, then unreadable structure, then failed signature math, then a digest that
    was not computed; only then the match labels."""
    if not signatures:
        return NOT_SIGNED
    if any(s.digest_match is False for s in signatures):
        return MISMATCH
    if any(s.structure != 'ok' for s in signatures):
        return UNREADABLE
    if any(s.signature_math == 'failed' for s in signatures):
        return MATH_FAILED
    if any(s.digest_match is None for s in signatures):
        return NOT_COMPUTED
    if trust_status == 'trusted_no_revocation_check':
        return WINDOWS_TRUSTED
    return MATH_OK if all(s.signature_math == 'ok_chain_not_evaluated' for s in signatures) else MATCH


def catalog_label(state: str) -> str:
    return CATALOG_LABELS_BY_STATE.get(state, CATALOG_LABELS_BY_STATE['not_checked'])
