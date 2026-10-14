"""Product scopes from product-tree names (KB-integration-plan 7.2 `ProductScope`, slice K1). Pure.

A source product is identified by `(doc_id, product_id)`; its display name is untrusted text. This module turns the
name (plus the optional `family`/`architecture` hints some dialects carry) into a `ProductScope` using the versioned
`alias_catalog`. Rules that keep claims honest:

* a scope derived from strings is `candidate` (or `unknown`/`conflicted`), never `verified`; `verified` is reserved
  for an analyst decision recorded by a later slice;
* a hint that contradicts the name makes the scope `conflicted` and the contradicting attribute `unknown`;
* products are never matched by display name alone across documents unless every derived attribute agrees: the
  `scope_id` is a digest of the derived attributes (plus the normalised name when the attributes are not enough to
  tell two products apart);
* also home of the text hygiene shared by the source parsers (`clean_text`, `safe_label`).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from . import alias_catalog as catalog
from .contracts import ProductRef, ProductScope, domain_id

_BIDI = dict.fromkeys(map(ord, '‎‏؜‪‫‬‭‮⁦⁧⁨⁩'))
_SPACE = re.compile(r'\s+')

_FAMILY = [(f, re.compile(p)) for f, p in catalog.FAMILY_PATTERNS]
_CLIENT_VERSION = re.compile(catalog.CLIENT_VERSION_PATTERN)
_RELEASE = [re.compile(p) for p in catalog.RELEASE_PATTERNS]
_SERVER_YEAR = re.compile(catalog.SERVER_YEAR_PATTERN)
_ARCH = [(v, re.compile(p)) for v, p in catalog.ARCH_PATTERNS]
_EDITION = [(v, re.compile(p)) for v, p in catalog.EDITION_PATTERNS]
_CHANNEL = [(v, re.compile(p)) for v, p in catalog.CHANNEL_PATTERNS]
_KEYABLE = re.compile(r'^(?:[0-9]{2}H[12]|[0-9]{4})$')


def clean_text(value: object, limit: int = 1000) -> str:
    """Untrusted advisory text as plain text: C0/C1 controls (newline and tab become a space) and bidirectional
    formatting characters are removed, surrogates are replaced, the result is cut to ``limit`` characters. Markup is
    kept verbatim (it is data; renderers must treat it as plain text)."""
    if not isinstance(value, str):
        return ''
    out = []
    for ch in value.translate(_BIDI):
        code = ord(ch)
        if ch in '\n\r\t':
            out.append(' ')
        elif code < 0x20 or 0x7f <= code < 0xa0:
            continue
        elif 0xd800 <= code <= 0xdfff:
            out.append('�')
        else:
            out.append(ch)
    return ''.join(out)[:limit]


def safe_label(value: object, limit: int = 60) -> str:
    """Short printable rendering of an advisory-supplied identifier for messages (never full text)."""
    text = value if isinstance(value, str) else repr(value)
    text = ''.join(ch if ch.isprintable() and ord(ch) not in _BIDI else f'\\u{ord(ch):04x}' for ch in text)
    return text if len(text) <= limit else text[:limit - 1] + '…'


def normal_name(name: str) -> str:
    return _SPACE.sub(' ', clean_text(name).strip().lower())


@dataclass(frozen=True)
class ProductFacts:
    family: str
    release: str | None
    architecture: str
    channel: str | None
    edition: str | None
    winbindex_key: str | None
    name_key: str
    conflicts: tuple[str, ...]

    @property
    def mapping(self) -> str:
        if self.conflicts:
            return 'conflicted'
        return 'candidate' if self.family in ('windows-client', 'windows-server') else 'unknown'


def _first(patterns, text: str):
    for value, pattern in patterns:
        if pattern.search(text):
            return value
    return None


def derive(name: str, *, family_hint: str | None = None, arch_hint: str | None = None) -> ProductFacts:
    """Attributes of a product name. Pure and order-independent; the same inputs give the same facts."""
    text = normal_name(name)
    family = next((f for f, pattern in _FAMILY if pattern.search(text)), 'unknown')
    conflicts: list[str] = []
    hint_family = family_hint if family_hint in catalog.FAMILY_VALUES and family_hint != 'unknown' else None
    if hint_family is not None:
        if family == 'unknown':
            family = hint_family
        elif family != hint_family:
            conflicts.append('family')
            family = 'unknown'
    release = None
    for pattern in _RELEASE:
        match = pattern.search(text)
        if match:
            release = match.group(1).upper()
            break
    if release is None:
        match = _SERVER_YEAR.search(text)
        if match:
            release = match.group(1).upper()
    archs = sorted({v for v, pattern in _ARCH if pattern.search(text)})
    arch = archs[0] if len(archs) == 1 else 'unknown'
    hint_arch = arch_hint if arch_hint in catalog.ARCH_VALUES and arch_hint != 'unknown' else None
    if hint_arch is not None:
        if arch == 'unknown' and (not archs or hint_arch in archs):
            arch = hint_arch
        elif arch != hint_arch:
            conflicts.append('architecture')
            arch = 'unknown'
    key = None
    if family in catalog.WINBINDEX_FAMILIES and release and _KEYABLE.fullmatch(release):
        version = _CLIENT_VERSION.search(text)
        key = f'{version.group(1)}-{release}' if version else None
    return ProductFacts(family=family, release=release, architecture=arch, channel=_first(_CHANNEL, text),
                        edition=_first(_EDITION, text), winbindex_key=key, name_key=text,
                        conflicts=tuple(conflicts))


def scope_id_for(facts: ProductFacts) -> str:
    """Digest of the derived attributes. The normalised name joins the key when the attributes cannot tell two
    products apart (unknown family or no release), so two unrelated products never merge."""
    informative = facts.family != 'unknown' and facts.release is not None and not facts.conflicts
    key = {'family': facts.family, 'release': facts.release, 'architecture': facts.architecture,
           'channel': facts.channel, 'edition': facts.edition, 'build': None,
           'name': None if informative else facts.name_key}
    return domain_id('kbc.scope', 1, key)


def scope_for(doc_id: str, product_id: str, name: str, *, family_hint: str | None = None,
              arch_hint: str | None = None) -> ProductScope:
    facts = derive(name, family_hint=family_hint, arch_hint=arch_hint)
    display = clean_text(name).strip() or safe_label(product_id)
    return ProductScope(
        scope_id=scope_id_for(facts), family=facts.family, release=facts.release, architecture=facts.architecture,
        channel=facts.channel, edition=facts.edition, build=None, display_name=display,
        source_product_ids=(ProductRef(doc_id=doc_id, product_id=product_id),),
        winbindex_key=facts.winbindex_key, mapping=facts.mapping, alias_catalog_version=catalog.ALIAS_CATALOG_VERSION)


def merge_scopes(scopes: Iterable[ProductScope]) -> tuple[ProductScope, ...]:
    """One record per ``scope_id``: the union of source product ids, the smallest display name, sorted by scope id.
    Two records with the same id but different derived attributes cannot occur (the id derives from them)."""
    merged: dict[str, ProductScope] = {}
    for scope in scopes:
        have = merged.get(scope.scope_id)
        if have is None:
            merged[scope.scope_id] = scope
            continue
        refs = {(r.doc_id, r.product_id): r for r in (*have.source_product_ids, *scope.source_product_ids)}
        merged[scope.scope_id] = have.model_copy(update={
            'source_product_ids': tuple(refs[k] for k in sorted(refs)),
            'display_name': min(have.display_name, scope.display_name)})
    return tuple(merged[k] for k in sorted(merged))


def find_scopes(scopes: Iterable[ProductScope], query: str) -> tuple[ProductScope, ...]:
    """Scopes selected by a user query: an exact or prefix ``scope_id`` (8+ hex digits), a source product id, or a
    case-insensitive substring of the display name. Never picks one for the caller: an ambiguous query returns
    several scopes."""
    text = query.strip()
    needle = text.lower()
    out = []
    for scope in scopes:
        by_id = len(needle) >= 8 and scope.scope_id.startswith(needle)
        by_product = any(r.product_id == text for r in scope.source_product_ids)
        if by_id or by_product or (needle and needle in scope.display_name.lower()):
            out.append(scope)
    return tuple(sorted(out, key=lambda s: (s.display_name, s.scope_id)))


def catalog_digest() -> str:
    """Digest of every plain-data constant in ``alias_catalog``: editing a pattern changes it without a version bump."""
    payload = {name: getattr(catalog, name) for name in sorted(vars(catalog))
               if name.isupper() and isinstance(getattr(catalog, name), (str, int, tuple))}
    data = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(b'kbc.alias_catalog\x00' + data).hexdigest()
