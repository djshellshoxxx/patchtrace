"""Application manifest (RT_MANIFEST) facts, parsed without entity expansion, files or network (WBQ S2).

A manifest is untrusted XML. The stdlib parser is used under the rules defusedxml enforces, without the dependency:

1. Size: leaves over `max_manifest_bytes` (2 MiB) are reported, not read or parsed; the manifests of one file may
   read at most `max_hash_bytes` in total.
2. Encoding: UTF-8 (BOM optional) and UTF-16 (BOM, or the NUL pattern of a leading '<') only. The bytes are decoded
   strictly here and the document is handed to the parser as text, which makes the parser ignore any encoding
   declaration inside it. What is scanned is therefore exactly what is parsed. UTF-32 and other encodings are
   unsupported, not guessed.
3. DTDs: any '<!DOCTYPE' or '<!ENTITY' (case-insensitive, anywhere in the text, comments and CDATA included) refuses
   the manifest before the parser sees it. ElementTree does expand entities declared in a DTD (measured on expat
   2.6.1: three declarations expand to 100,000 characters), and CPython documents entity expansion and large-token
   denial of service as live on older or system libexpat. A manifest never needs a DTD, so none is ever parsed.
4. No network, no files: ElementTree resolves no external entity, schema or include; a schemaLocation or XInclude
   href stays inert text. An undefined entity reference is a parse error, not an expansion.
5. One-shot parse of one string, which avoids the quadratic re-parse of large tokens split over buffer fills.
6. Any failure is a warning code on the observation, never an exception.

Facts are read from documented element paths in their documented namespaces only (a setting in the wrong namespace
is ignored by Windows, so it is ignored here), first occurrence wins, and every string is cleaned and capped. The
root's children are classified in one pass, because a hostile manifest can hold hundreds of thousands of them.
"""
from __future__ import annotations

import codecs
import hashlib
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import cache
from itertools import islice

from ._common import Ctx
from .models import SectionMap
from .resources import (
    DEFAULT_RESOURCE_LIMITS,
    RT_MANIFEST,
    ResourceInventory,
    ResourceLeaf,
    ResourceLimits,
    leaves_of_type,
    read_leaf,
    sanitize_text,
)

MAX_ITEMS = 256
MAX_SETTING_CHARS = 64
_ASM_V1_URI = 'urn:schemas-microsoft-com:asm.v1'
_ASM_V1 = frozenset({_ASM_V1_URI})
_TRUST = frozenset({'urn:schemas-microsoft-com:asm.v2', 'urn:schemas-microsoft-com:asm.v3'})
_ASM_V3 = frozenset({'urn:schemas-microsoft-com:asm.v3'})
_COMPAT = frozenset({'urn:schemas-microsoft-com:compatibility.v1'})
_SETTINGS_2005 = frozenset({'http://schemas.microsoft.com/SMI/2005/WindowsSettings'})
_SETTINGS_2016 = frozenset({'http://schemas.microsoft.com/SMI/2016/WindowsSettings'})
_SETTINGS_2019 = frozenset({'http://schemas.microsoft.com/SMI/2019/WindowsSettings'})
_GUID = re.compile(r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}')
_UTF32_BOMS = (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)
_MESSAGES = {
    'manifest_dtd_rejected': 'a manifest declares a document type definition (DTD) or entity; refused, not parsed',
    'manifest_over_cap': 'a manifest exceeded a size or count limit; the values shown are partial',
    'manifest_encoding_unsupported': 'a manifest is not UTF-8 or UTF-16 text; not parsed',
    'manifest_xml_invalid': 'a manifest is not well-formed XML or its data is not backed by file bytes',
}


@dataclass(frozen=True, slots=True)
class AssemblyIdentity:
    name: str | None
    version: str | None
    arch: str | None
    token: str | None
    type: str | None


@dataclass(frozen=True, slots=True)
class ManifestFile:
    name: str | None
    hash: str | None
    hashalg: str | None


@dataclass(frozen=True, slots=True)
class ManifestObservation:
    """Facts of one RT_MANIFEST leaf; absent or unreadable values are None or empty, never guessed.

    `sha256` covers the stored bytes (None when they were not fully read). `warnings` are warning codes.
    """

    leaf: ResourceLeaf
    sha256: str | None
    execution_level: str | None = None
    ui_access: bool | None = None
    supported_os: tuple[str, ...] = ()
    dpi_awareness: str | None = None
    long_path_aware: bool | None = None
    active_code_page: str | None = None
    identity: AssemblyIdentity | None = None
    dependencies: tuple[AssemblyIdentity, ...] = ()
    files: tuple[ManifestFile, ...] = ()
    warnings: tuple[str, ...] = ()


def parse_manifests(ctx: Ctx, smap: SectionMap, inventory: ResourceInventory,
                    limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS) -> tuple[ManifestObservation, ...]:
    """One observation per RT_MANIFEST leaf (at most `max_manifests`), in resource order."""
    started = time.monotonic()
    leaves = leaves_of_type(inventory, RT_MANIFEST)
    if len(leaves) > limits.max_manifests:
        ctx.warn('manifest_over_cap', f'more than {limits.max_manifests} manifests; the rest are not read')
        leaves = leaves[:limits.max_manifests]
    budget = limits.max_hash_bytes
    found: list[ManifestObservation] = []
    for leaf in leaves:
        ctx.check()
        if time.monotonic() - started >= limits.time_budget_s:
            ctx.warn('metadata_time_budget', f'manifest reading stopped after {limits.time_budget_s} s')
            break
        if leaf.size > limits.max_manifest_bytes or leaf.size > budget:
            observation = ManifestObservation(leaf, None, warnings=('manifest_over_cap',))
        else:
            raw = read_leaf(ctx, smap, leaf, leaf.size)
            budget -= len(raw)
            observation = observe_manifest(leaf, raw, complete=len(raw) == leaf.size, limits=limits)
        for code in observation.warnings:
            ctx.warn(code, _MESSAGES[code])
        found.append(observation)
    return tuple(found)


def observe_manifest(leaf: ResourceLeaf, raw: bytes, *, complete: bool = True,
                     limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS) -> ManifestObservation:
    """Parse the stored bytes of one manifest. `complete` says `raw` is the whole leaf (it is hashed only then)."""
    digest = hashlib.sha256(raw).hexdigest() if complete else None
    if len(raw) > limits.max_manifest_bytes:
        return ManifestObservation(leaf, digest, warnings=('manifest_over_cap',))
    text = _decode(raw)
    if text is None:
        return ManifestObservation(leaf, digest, warnings=('manifest_encoding_unsupported',))
    lowered = text.lower()
    if '<!doctype' in lowered or '<!entity' in lowered:
        return ManifestObservation(leaf, digest, warnings=('manifest_dtd_rejected',))
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        return ManifestObservation(leaf, digest, warnings=('manifest_xml_invalid',))
    if _qname(root.tag) != (_ASM_V1_URI, 'assembly'):
        return ManifestObservation(leaf, digest, warnings=('manifest_xml_invalid',))
    return _facts(leaf, digest, root)


def _decode(raw: bytes) -> str | None:
    """Text of `raw` as UTF-8 or UTF-16 (strict, BOM removed, trailing NUL padding dropped), else None."""
    try:
        if raw.startswith(_UTF32_BOMS):
            return None
        if raw.startswith(codecs.BOM_UTF8):
            return raw[len(codecs.BOM_UTF8):].decode('utf-8').rstrip('\0')
        if raw.startswith(codecs.BOM_UTF16_LE):
            return raw[2:].decode('utf-16-le').rstrip('\0')
        if raw.startswith(codecs.BOM_UTF16_BE):
            return raw[2:].decode('utf-16-be').rstrip('\0')
        if raw[:2] == b'<\0':
            return raw.decode('utf-16-le').rstrip('\0')
        if raw[:2] == b'\0<':
            return raw.decode('utf-16-be').rstrip('\0')
        return raw.decode('utf-8').rstrip('\0')
    except UnicodeDecodeError:
        return None


def _qname(tag: str) -> tuple[str, str]:
    """(namespace, local name) of an ElementTree tag; the namespace is '' when there is none."""
    if tag.startswith('{'):
        namespace, _, local = tag[1:].partition('}')
        return namespace, local
    return '', tag


@cache
def _wanted(namespaces: frozenset[str], local: str) -> frozenset[str]:
    return frozenset(f'{{{namespace}}}{local}' for namespace in namespaces)


def _children(element: ET.Element, namespaces: frozenset[str], local: str) -> Iterator[ET.Element]:
    wanted = _wanted(namespaces, local)
    for child in element:
        if child.tag in wanted:
            yield child


def _first(element: ET.Element | None, namespaces: frozenset[str], local: str) -> ET.Element | None:
    if element is None:
        return None
    return next(_children(element, namespaces, local), None)


def _chain(element: ET.Element | None, *path: tuple[frozenset[str], str]) -> ET.Element | None:
    for namespaces, local in path:
        element = _first(element, namespaces, local)
    return element


def _attr(element: ET.Element | None, name: str, cap: int = 256) -> str | None:
    value = element.get(name) if element is not None else None
    return sanitize_text(value.strip())[:cap] if value is not None else None


def _text(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    return sanitize_text((element.text or '').strip())[:MAX_SETTING_CHARS]


def _bool(value: str | None) -> bool | None:
    return {'true': True, 'false': False}.get((value or '').lower())


def _identity(element: ET.Element | None) -> AssemblyIdentity | None:
    if element is None:
        return None
    return AssemblyIdentity(_attr(element, 'name'), _attr(element, 'version'), _attr(element, 'processorArchitecture'),
                            _attr(element, 'publicKeyToken'), _attr(element, 'type'))


_ROOT_KINDS = {tag: kind for kind, namespaces, local in (
    ('identity', _ASM_V1, 'assemblyIdentity'), ('dependency', _ASM_V1, 'dependency'), ('file', _ASM_V1, 'file'),
    ('compatibility', _COMPAT, 'compatibility'), ('trust', _TRUST, 'trustInfo'), ('application', _ASM_V3, 'application'),
) for tag in _wanted(namespaces, local)}


def _root_children(root: ET.Element) -> dict[str, list[ET.Element]]:
    groups: dict[str, list[ET.Element]] = {}
    for child in root:
        kind = _ROOT_KINDS.get(child.tag)
        if kind is not None:
            groups.setdefault(kind, []).append(child)
    return groups


def _bounded(items: Iterable) -> tuple[list, bool]:
    """Up to MAX_ITEMS items and whether there were more."""
    taken = list(islice(items, MAX_ITEMS + 1))
    return taken[:MAX_ITEMS], len(taken) > MAX_ITEMS


def _dependent_identities(dependencies: list[ET.Element]) -> Iterator[ET.Element | None]:
    for dependency in dependencies:
        for assembly in _children(dependency, _ASM_V1, 'dependentAssembly'):
            yield _first(assembly, _ASM_V1, 'assemblyIdentity')


def _supported_os(compatibilities: list[ET.Element]) -> Iterator[ET.Element]:
    for compatibility in compatibilities:
        for application in _children(compatibility, _COMPAT, 'application'):
            yield from _children(application, _COMPAT, 'supportedOS')


def _facts(leaf: ResourceLeaf, digest: str | None, root: ET.Element) -> ManifestObservation:
    groups = _root_children(root)
    dependencies, more_dependencies = _bounded(_dependent_identities(groups.get('dependency', [])))
    files, more_files = _bounded(groups.get('file', []))
    systems, more_systems = _bounded(_supported_os(groups.get('compatibility', [])))
    guids = {(item.get('Id') or '').strip().lower() for item in systems}
    level = _chain(next(iter(groups.get('trust', [])), None), (_TRUST, 'security'), (_TRUST, 'requestedPrivileges'),
                   (_TRUST, 'requestedExecutionLevel'))
    settings = _chain(next(iter(groups.get('application', [])), None), (_ASM_V3, 'windowsSettings'))
    awareness = _first(settings, _SETTINGS_2016, 'dpiAwareness')
    if awareness is None:
        awareness = _first(settings, _SETTINGS_2005, 'dpiAware')
    return ManifestObservation(
        leaf, digest, _attr(level, 'level'), _bool(_attr(level, 'uiAccess')),
        tuple(sorted(guid for guid in guids if _GUID.fullmatch(guid))), _text(awareness),
        _bool(_text(_first(settings, _SETTINGS_2016, 'longPathAware'))),
        _text(_first(settings, _SETTINGS_2019, 'activeCodePage')),
        _identity(next(iter(groups.get('identity', [])), None)),
        tuple(_identity(item) for item in dependencies if item is not None),
        tuple(ManifestFile(_attr(item, 'name'), _attr(item, 'hash'), _attr(item, 'hashalg')) for item in files),
        ('manifest_over_cap',) if more_dependencies or more_files or more_systems else ())
