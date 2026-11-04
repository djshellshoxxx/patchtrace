"""Pure view-model of the "Version and signing" tab (SPEC-51 section 8): exact state copy, the signature tree, the
manifest text and the TSV a Ctrl+C copies. Qt-free; `ui_inspection` draws it. Every string that came from a file is
already display-safe (the readers clean it) and is shown as plain text only.
"""
from __future__ import annotations

import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from .labels import embedded_label
from .metadata import PeMetadata
from .models import CertificateSummary, SignatureInfo, SignerInfo, TimestampClaim

TITLE = 'Version and signing'
LOADING = 'Reading version, manifest and signature (read-only)...'
EMPTY = 'This file has no version resource.'
NO_MANIFEST = 'No embedded manifest was found. Sidecar .manifest files are not read.'
BLOCKED = ('Certificate chain trust is only evaluated on Windows. This platform reports the signature structure and '
           'whether the file digest matches the signature.')
ERROR = 'Could not read this section: {code}. Other sections are unaffected.'
HEADERS = ('Field', 'OLDER', 'NEWER', 'Status', 'Provenance')
TREE_HEADERS = ('Item', 'Value')
SIDES = ('older', 'newer')
_MATH_TEXT = {'ok_chain_not_evaluated': 'signature math ok, chain not evaluated', 'failed': 'signature math does NOT verify',
              'not_evaluated': 'not evaluated'}
_MATCH_TEXT = {True: 'matches the file', False: 'does NOT match the file', None: 'not computed'}


@dataclass(frozen=True, slots=True)
class TreeNode:
    label: str
    value: str = ''
    children: tuple[TreeNode, ...] = ()


def blocked_note(platform: str | None = None) -> str | None:
    """The chain-trust notice, shown wherever trust is not evaluated (everything but Windows)."""
    return None if (platform or sys.platform) == 'win32' else BLOCKED


def error_text(code: str) -> str:
    return ERROR.format(code=code)


def has_version(metas: Mapping[str, PeMetadata | None]) -> bool:
    return any(m is not None and m.version is not None and m.version.blocks for m in metas.values())


def tsv(rows: Iterable[Sequence[str]]) -> str:
    """Tab-separated rows for the clipboard; tabs and line breaks inside a cell become spaces."""
    def cell(text: str) -> str:
        return ' '.join(str(text).replace('\t', ' ').splitlines())
    return '\n'.join('\t'.join(cell(c) for c in row) for row in rows)


def manifest_text(metas: Mapping[str, PeMetadata | None]) -> str:
    """Plain text of what each side's manifest declares (parsed facts, never the raw XML)."""
    blocks = []
    for side in SIDES:
        meta = metas.get(side)
        lines = [side.upper()]
        if meta is None:
            lines.append('unavailable')
        elif not meta.manifests:
            lines.append(NO_MANIFEST)
        else:
            lines += _manifest_lines(meta)
        blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks)


def _manifest_lines(meta: PeMetadata) -> list[str]:
    found = meta.manifests[0]
    identity = found.identity
    pairs = [
        ('Assembly', ' '.join(p for p in (identity.name, identity.version, identity.arch) if p) if identity else None),
        ('Requested execution level', found.execution_level),
        ('UI access', None if found.ui_access is None else str(found.ui_access).lower()),
        ('Supported OS', ', '.join(found.supported_os) or None),
        ('Dependent assemblies', ', '.join(f'{d.name} {d.version}'.strip() for d in found.dependencies) or None),
        ('Long path aware', None if found.long_path_aware is None else str(found.long_path_aware).lower()),
        ('DPI awareness', found.dpi_awareness),
        ('Active code page', found.active_code_page),
        ('Notes', ', '.join(found.warnings) or None),
    ]
    return [f'{name}: {value}' for name, value in pairs if value]


def signature_tree(metas: Mapping[str, PeMetadata | None],
                   trust: Mapping[str, str | None] | None = None) -> tuple[TreeNode, ...]:
    """One top node per side; below it signatures (nested ones as children), signers, certificates, timestamps."""
    trust = trust or {}
    nodes = []
    for side in SIDES:
        meta = metas.get(side)
        if meta is None:
            nodes.append(TreeNode(side.upper(), 'unavailable'))
            continue
        nodes.append(TreeNode(side.upper(), embedded_label(meta.signatures, trust.get(side)),
                              _signature_nodes(meta.signatures)))
    return tuple(nodes)


def _signature_nodes(signatures: tuple[SignatureInfo, ...]) -> tuple[TreeNode, ...]:
    """Flattened signatures back into a tree: a nested signature goes under the shallower one before it."""
    roots: list = []
    stack: list[tuple[int, list]] = []
    for sig in signatures:
        entry = (_signature_node(sig), [])
        while stack and stack[-1][0] >= sig.nested_depth:
            stack.pop()
        (stack[-1][1] if stack else roots).append(entry)
        stack.append((sig.nested_depth, entry[1]))
    return tuple(_freeze(entry) for entry in roots)


def _freeze(entry: tuple[TreeNode, list]) -> TreeNode:
    node, nested = entry
    return TreeNode(node.label, node.value, (*node.children, *(_freeze(n) for n in nested)))


def _signature_node(sig: SignatureInfo) -> TreeNode:
    title = f'Signature {sig.index + 1}' + (f' (nested, level {sig.nested_depth})' if sig.nested_depth else '')
    children = [
        TreeNode('Structure', sig.structure),
        TreeNode('Digest algorithm', sig.digest_algorithm + (' (weak)' if sig.weak_digest else '')),
        TreeNode('Digest claimed by the signature', sig.digest_claimed_hex or '(none)'),
        TreeNode('Digest computed from the file', sig.digest_computed_hex or '(not computed)'),
        TreeNode('Digest vs file', _MATCH_TEXT[sig.digest_match]),
        TreeNode('Signature math', _MATH_TEXT[sig.signature_math]),
        TreeNode('Certificate chain', sig.chain.replace('_', ' ')),
        TreeNode('Revocation', sig.revocation.replace('_', ' ')),
        *(_signer_node(i, s) for i, s in enumerate(sig.signers, 1)),
        *(_certificate_node(i, c) for i, c in enumerate(sig.certificates, 1)),
        *(_timestamp_node(t) for t in sig.timestamps),
    ]
    if sig.warnings:
        children.append(TreeNode('Notes', ', '.join(sig.warnings)))
    return TreeNode(title, _MATCH_TEXT[sig.digest_match] if sig.structure == 'ok' else sig.structure,
                    tuple(children))


def _signer_node(number: int, signer: SignerInfo) -> TreeNode:
    return TreeNode(f'Signer {number}', signer.subject_cn or signer.issuer_cn or '(unnamed)', (
        TreeNode('Subject', signer.subject_dn or '(certificate not in the signature)'),
        TreeNode('Issuer', signer.issuer_dn),
        TreeNode('Serial number', signer.serial_hex),
        TreeNode('Valid from (as stated in the certificate)', signer.not_before or '(unknown)'),
        TreeNode('Valid to (as stated in the certificate)', signer.not_after or '(unknown)'),
        TreeNode('Lists code signing use', {True: 'yes', False: 'no', None: 'not stated'}[signer.eku_code_signing]),
        TreeNode('Digest algorithm', signer.digest_alg)))


def _certificate_node(number: int, cert: CertificateSummary) -> TreeNode:
    return TreeNode(f'Certificate {number}', cert.subject_cn or '(unnamed)', (
        TreeNode('Subject', cert.subject_dn), TreeNode('Issuer', cert.issuer_dn),
        TreeNode('Valid', f'{cert.not_before or "?"} to {cert.not_after or "?"} (as stated)')))


def _timestamp_node(claim: TimestampClaim) -> TreeNode:
    return TreeNode('Claimed signing time (not verified)', claim.claimed_time_utc or '(unreadable)', (
        TreeNode('Kind', claim.kind.replace('_', ' ')), TreeNode('Note', claim.note)))
