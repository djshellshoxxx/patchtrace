"""Builders for the fabric tests (FAB-0): synthetic anchors only; no binaries, no network, no Microsoft data."""
from __future__ import annotations

import hashlib

from patchtrace.fabric import ids, origins
from patchtrace.fabric.contracts import Anchor, PairRef, Witness

OLDER = 'a' * 64
NEWER = 'b' * 64
F_OLD, F_NEW = 0x1000, 0x1040
G_OLD, G_NEW = 0x2000, 0x2040


def digest(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def side_sha(side: str) -> str | None:
    return {'older': OLDER, 'newer': NEWER}.get(side)


def wit(producer: str = 'cap', source: str = 'capa', *, batch: str = 'run1', label: str = 'evidence', facets=(),
        input_sha: str | None = None, origin=None, tool: str | None = None, tool_version: str | None = None,
        ref=None) -> Witness:
    """A witness whose origin tags are the registry's tags of `source` unless `origin` says otherwise."""
    tags = origins.SOURCE_TAGS[source] if origin is None else origin
    return ids.make_witness(producer=producer, batch=batch, source=source, origins=tags, label=label, facets=facets,
                            tool=tool, tool_version=tool_version, input_sha256=input_sha, ref=ref)


def anchor(kind: str, key: str | None, side: str, role: str, *, subject: str | None = None,
           pair: PairRef | None = None, **w) -> Anchor:
    """A one-witness anchor; one-sided observed anchors get the input hash of their side unless `input_sha` is given."""
    if role == 'observed' and 'input_sha' not in w:
        w['input_sha'] = side_sha(side)
    return ids.make_anchor(kind=kind, key=key, side=side, role=role, subject=subject, pair=pair,
                           witnesses=(wit(**w),))


def pair_ref(older=(F_OLD,), newer=(F_NEW,), older_sha: str = OLDER, newer_sha: str = NEWER) -> PairRef:
    return PairRef(older_sha256=older_sha, newer_sha256=newer_sha, older_rvas=tuple(sorted(older)),
                   newer_rvas=tuple(sorted(newer)))


def pair_anchor(older=(F_OLD,), newer=(F_NEW,), *, producer: str = 'ue', source: str = 'pairing', **w) -> Anchor:
    return anchor('function', None, 'both', 'observed', pair=pair_ref(older, newer), producer=producer,
                  source=source, **w)


def pair_key(older=(F_OLD,), newer=(F_NEW,)) -> str:
    return ids.pair_key(OLDER, NEWER, older, newer)


def image_anchor(side: str, rva: int, **w) -> Anchor:
    w.setdefault('producer', 'ue')
    w.setdefault('source', 'pairing')
    return anchor('function', ids.image_key(side_sha(side), rva), side, 'observed', **w)


def import_anchor(name: str, side: str = 'newer', role: str = 'observed', *, subject: str | None = None,
                  producer: str = 'cap', source: str = 'capa', **w) -> Anchor:
    side = 'none' if role == 'hint' else side
    return anchor('import', ids.api_key(name), side, role, subject=subject, producer=producer, source=source, **w)


def cwe_anchor(number: int = 190, *, producer: str = 'kb', source: str = 'advisory-text', role: str = 'stated',
               side: str = 'none', **w) -> Anchor:
    return anchor('cwe', f'CWE-{number}', side, role, producer=producer, source=source, **w)


def cve_anchor(text: str = 'CVE-2099-0001', *, producer: str = 'kb', source: str = 'advisory-text', **w) -> Anchor:
    return anchor('cve', ids.cve_key(text), 'none', 'stated', producer=producer, source=source, **w)
