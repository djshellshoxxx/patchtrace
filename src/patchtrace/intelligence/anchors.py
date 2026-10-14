"""Search anchors (SPEC-28 section H): module, API, string, feature, component and PDB hints as labelled data.

Every anchor names where it came from (advisory title, note or product name with its JSON pointer, a patch
rule, or verified artifact bytes) and its quality. Anchors are search hints for the analyst and for SPEC-30;
this module never looks at diff results, functions or engine output, so no anchor is ever presented as a
located change.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from ..enrichment.identity import domain_id
from .contracts import AdvisoryFacts, Anchor, AnchorSet, ArtifactIdentity, HypothesisSet

MAX_ANCHORS = 200
_MODULE = re.compile(r'(?<![A-Za-z0-9_.\-])([A-Za-z0-9_\-]{1,64}\.(?:sys|dll|exe|drv|ocx|cpl|efi|mui|scr|winmd|tlb))'
                     r'(?![A-Za-z0-9_\-])', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"<>\n]{3,80})"|“([^”<>\n]{3,80})”')
_TAG = re.compile(r'<[^<>]{0,200}>')
FEATURES: tuple[str, ...] = (
    'IPv6', 'IPv4', 'TCP/IP', 'ICMP', 'SMB', 'SMBv1', 'SMBv2', 'SMBv3', 'RDP', 'Remote Desktop', 'Kerberos',
    'NTLM', 'LDAP', 'DNS', 'DHCP', 'RPC', 'ALPC', 'HTTP.sys', 'HTTP/2', 'Hyper-V', 'BitLocker', 'Print Spooler',
    'Win32k', 'Common Log File System', 'CLFS', 'MSHTML', 'OLE', 'NTFS', 'ReFS', 'Bluetooth', 'Wi-Fi', 'IKE',
    'IPsec', 'PPTP', 'L2TP', 'SNMP', 'WebDAV', 'Windows Installer', 'Kernel Streaming', 'DirectX', 'Secure Boot',
    'TPM', 'Netlogon', 'LSASS', 'Active Directory', 'Message Queuing', 'MSMQ', 'DCOM', 'WMI', 'Task Scheduler')
_FEATURES = tuple((name, re.compile(r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])',
                                    0 if name.isupper() or any(c.isdigit() for c in name) else re.IGNORECASE))
                  for name in FEATURES)
_IMPACTS = ('remote code execution', 'elevation of privilege', 'denial of service', 'information disclosure',
            'security feature bypass', 'spoofing', 'tampering')
_TITLE = re.compile(r'^(?P<component>.+?)\s+(?:' + '|'.join(_IMPACTS) + r')\s+vulnerability\s*$', re.IGNORECASE)
LIMITATIONS = ('Anchors are search hints labelled with source and quality; they are never linked to diff results '
               'or functions.',
               'Module and feature names come from advisory text and may describe the product, not this file.')


def _anchor(kind: str, value: str, source: str, pointer: str | None, quality: str, label: str) -> Anchor:
    value = ' '.join(value.split())[:512]
    return Anchor(anchor_id=domain_id('anchor', 1, {'kind': kind, 'value': value, 'source': source,
                                                    'pointer': pointer}),
                  kind=kind, value=value, source=source, pointer=pointer, quality=quality, label=label[:300])


def _text_anchors(text: str, source: str, pointer: str) -> Iterable[Anchor]:
    plain = _TAG.sub(' ', text)  # markup is never an anchor; matching only
    for match in _MODULE.finditer(plain):
        yield _anchor('module', match.group(1).lower(), source, pointer, 'explicit', 'module named in the advisory')
    for name, pattern in _FEATURES:
        if pattern.search(plain):
            yield _anchor('feature', name, source, pointer, 'derived', 'feature or protocol named in the advisory')
    if source == 'csaf-note':
        for match in _QUOTED.finditer(plain):
            quoted = (match.group(1) or match.group(2)).strip()
            if quoted:
                yield _anchor('string', quoted, source, pointer, 'derived',
                              'quoted text in the advisory; it may or may not occur in the binary')


def anchors_for(cve: str, documents: Sequence[AdvisoryFacts], identities: Sequence[ArtifactIdentity] = (),
                hypotheses: HypothesisSet | None = None) -> AnchorSet:
    found: dict[tuple, Anchor] = {}

    def add(items: Iterable[Anchor]) -> None:
        for item in items:
            found.setdefault((item.kind, item.value, item.source, item.pointer or ''), item)

    for facts in documents:
        item = facts.vulnerability(cve)
        if item is None:
            continue
        if item.title:
            title_pointer = f'{item.pointer}/title'
            add(_text_anchors(item.title, 'csaf-title', title_pointer))
            match = _TITLE.match(_TAG.sub(' ', item.title))
            if match:
                add([_anchor('component', match.group('component'), 'csaf-title', title_pointer, 'derived',
                             'component part of a "<component> <impact> Vulnerability" title')])
        for note in item.notes:
            if note.category != 'legal_disclaimer':
                add(_text_anchors(note.text, 'csaf-note', note.pointer))
        for remediation in item.remediations:
            add(a for a in _text_anchors(remediation.details, 'csaf-remediation', f'{remediation.pointer}/details')
                if a.kind == 'module')
        named = {claim.product_id for claim in item.product_status}
        for product in facts.products:
            if product.product_id in named:
                add(a for a in _text_anchors(product.name, 'csaf-product', f'{product.pointer}/name')
                    if a.kind == 'module')
    for identity in identities:
        if identity.pdb_identity is not None:
            add([_anchor('pdb', identity.pdb_identity.name, 'artifact-identity', None, 'verified-bytes',
                         f'{identity.side} artifact CodeView PDB name (verified bytes)')])
    if hypotheses is not None:
        for hypothesis in hypotheses.hypotheses:
            add(_anchor('api', api, 'hypothesis-rule', None, 'rule',
                        f'API often involved in {hypothesis.family} fixes ({hypothesis.rule_id})')
                for api in hypothesis.api_hints)
    ordered = sorted(found.values(), key=lambda a: (a.kind, a.value, a.source, a.pointer or ''))
    limitations = LIMITATIONS
    if len(ordered) > MAX_ANCHORS:
        rank = {'explicit': 0, 'verified-bytes': 1, 'derived': 2, 'rule': 3}
        kept = sorted(ordered, key=lambda a: (rank[a.quality], a.kind, a.value, a.source, a.pointer or ''))
        ordered = sorted(kept[:MAX_ANCHORS], key=lambda a: (a.kind, a.value, a.source, a.pointer or ''))
        limitations = (*LIMITATIONS, f'only the first {MAX_ANCHORS} anchors by quality are kept')
    return AnchorSet(cve=cve, anchors=tuple(ordered), limitations=limitations)
