"""Saved Tier-W previews and separately confirmed binary/PDB acquisition.

The offline plan design is recovered from c0255b78/f44454ad/5b7b2591, adapted to
current contracts and held-file readers. CLI network adapters remain separate.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from pydantic import BaseModel, ValidationError

from patchtrace import owned_publication as owned
from patchtrace.acquisition.contracts import AcquisitionError, symbol_server_url
from patchtrace.acquisition.transport import MAX_DOWNLOAD_BYTES, SYMBOL_HOST, AcquisitionConsent
from patchtrace.ingestion import _validate_pe_prefix
from patchtrace.pe_overview.inspect import inspect_pe

from .contracts import (
    DOC_LIMIT,
    MAX_FETCH_ITEMS,
    Catalogue,
    FetchExclusion,
    FetchInput,
    FetchItem,
    FetchPlan,
    PairsDoc,
    load_fetch_plan,
)
from .fetch import pdb_name, pdb_url
from .paths import TierWError, check_root
from .transport import DEFAULT_PDB_CAP_MIB, pdb_cap_bytes

FETCH_PLAN_LIMIT = DOC_LIMIT
_SHA = re.compile(r'[0-9a-f]{64}\Z')


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _checked(model: type[BaseModel], value):
    try:
        if not isinstance(value, model):
            raise ValueError('unexpected document type')
        return model.model_validate(value.model_dump(mode='python'))
    except (ValidationError, ValueError, TypeError, RecursionError):
        raise TierWError('PT-TIERW-INPUT', 'fetch input does not satisfy its strict contract') from None


def _model_bytes(model: BaseModel) -> bytes:
    out = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, indent=1, ensure_ascii=False, allow_nan=False)
    try:
        for chunk in encoder.iterencode(model.model_dump(mode='json')):
            encoded = chunk.encode('utf-8')
            if len(out) + len(encoded) + 1 > FETCH_PLAN_LIMIT:
                raise TierWError('PT-TIERW-LIMIT', 'fetch document exceeds its 64 MiB byte budget')
            out.extend(encoded)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise TierWError('PT-TIERW-INPUT', 'fetch document cannot be represented as strict JSON') from None
    out.extend(b'\n')
    return bytes(out)


def plan_bytes(plan: FetchPlan) -> bytes:
    return _model_bytes(_checked(FetchPlan, plan))


def plan_sha256(plan: FetchPlan) -> str:
    return _digest(plan_bytes(plan))


def _exact(expected: bytes):
    def validate(actual: bytes) -> None:
        if actual != expected:
            raise TierWError('PT-TIERW-VERIFY', 'existing fetch evidence has conflicting bytes')
    return validate


def save_plan(plan: FetchPlan, destination: Path) -> str:
    """Exclusively save the canonical preview; only byte-identical existing evidence may be reused."""
    data = plan_bytes(plan)
    destination = Path(destination)
    check_root(destination.parent)
    try:
        owned.publish_bytes(destination, data, validate_existing=_exact(data), maximum=len(data))
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-VERIFY', 'fetch plan could not be safely retained') from None
    return _digest(data)


def read_plan(source: Path) -> tuple[FetchPlan, bytes]:
    try:
        raw = owned.read_bytes(source, maximum=FETCH_PLAN_LIMIT)
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-INPUT', 'fetch plan must be a bounded ordinary local file') from None
    plan = load_fetch_plan(raw)
    if plan_bytes(plan) != raw:
        raise TierWError('PT-TIERW-INPUT', 'fetch plan is not in canonical preview form')
    return plan, raw


def _file_limit(max_files: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= MAX_FETCH_ITEMS:
        raise TierWError('PT-TIERW-INPUT', 'max_files must be an integer from 1 through 100000')


def _selection(pair_ids: Iterable[str]) -> tuple[str, ...]:
    selected = set()
    for index, pair_id in enumerate(pair_ids):
        if index >= MAX_FETCH_ITEMS:
            raise TierWError('PT-TIERW-LIMIT', 'too many pair selections for one fetch plan')
        if not isinstance(pair_id, str) or not pair_id.startswith('tw.'):
            raise TierWError('PT-TIERW-INPUT', 'select explicit Tier-W pair ids')
        selected.add(pair_id)
    if not selected:
        raise TierWError('PT-TIERW-INPUT', 'select at least one Tier-W pair')
    return tuple(sorted(selected))


def _exclusions(items: Sequence[FetchExclusion]) -> tuple[FetchExclusion, ...]:
    return tuple(sorted(items, key=lambda item: (item.file_name, item.sha256 or '', item.reason)))


def build_binary_plan(pairs: PairsDoc, catalogues: Sequence[Catalogue], pair_ids: Iterable[str], *,
                      max_files: int = MAX_FETCH_ITEMS) -> FetchPlan:
    """Derive only the selected public requests from freshly validated local source documents."""
    _file_limit(max_files)
    selected = _selection(pair_ids)
    if (not isinstance(pairs, PairsDoc) or len(pairs.pairs) > MAX_FETCH_ITEMS or
            len(pairs.binaries) > 2 * MAX_FETCH_ITEMS or len(catalogues) > MAX_FETCH_ITEMS or
            any(not isinstance(cat, Catalogue) for cat in catalogues) or
            sum(len(cat.builds) for cat in catalogues) > 2 * MAX_FETCH_ITEMS):
        raise TierWError('PT-TIERW-LIMIT', 'fetch source inventory exceeds its record budget')
    pairs = _checked(PairsDoc, pairs)
    catalogues = [_checked(Catalogue, cat) for cat in catalogues]
    by_pair, by_binary = {pair.id: pair for pair in pairs.pairs}, {binary.id: binary for binary in pairs.binaries}
    by_name = {cat.file_name: cat for cat in catalogues}
    if (len(by_pair) != len(pairs.pairs) or len(by_binary) != len(pairs.binaries) or
            len(by_name) != len(catalogues)):
        raise TierWError('PT-TIERW-INPUT', 'fetch source identifiers must be unique')
    if not set(selected) <= by_pair.keys():
        raise TierWError('PT-TIERW-INPUT', 'fetch selection names an unknown pair')
    uses, binaries = defaultdict(set), {}
    for pair_id in selected:
        pair = by_pair[pair_id]
        for binary_id in (pair.older, pair.newer):
            binary = by_binary.get(binary_id)
            if binary is None or binary.file_name != pair.file_name:
                raise TierWError('PT-TIERW-INPUT', 'pair references a missing or foreign binary')
            previous = binaries.setdefault(binary.sha256, binary)
            if (previous.file_name, previous.record_sha256, previous.family) != (
                    binary.file_name, binary.record_sha256, binary.family):
                raise TierWError('PT-TIERW-INPUT', 'one binary digest has conflicting catalogue identity')
            uses[binary.sha256].add(pair_id)
    builds = {name: {build.sha256: build for build in cat.builds} for name, cat in by_name.items()}
    entries, exclusions = [], []
    for digest, binary in sorted(binaries.items()):
        cat, build = by_name.get(binary.file_name), builds.get(binary.file_name, {}).get(digest)
        if cat is None or build is None or (build.record_sha256, cat.family) != (binary.record_sha256, binary.family):
            raise TierWError('PT-TIERW-INPUT', 'catalogue does not verify a selected pair binary')
        reason = ('not-x64' if build.machine != 0x8664 else 'unavailable' if build.download == 'unavailable'
                  else 'unresolved-size' if build.size_of_image is None else
                  'oversized' if build.size > MAX_DOWNLOAD_BYTES else None)
        if reason:
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=digest, reason=reason))
            continue
        entries.append(FetchItem(kind='binary', file_name=binary.file_name,
                                 source_url=symbol_server_url(binary.file_name, build.timestamp, build.size_of_image),
                                 sha256=digest, record_sha256=build.record_sha256, size=build.size, cap_bytes=build.size,
                                 timestamp=build.timestamp, size_of_image=build.size_of_image,
                                 pair_ids=tuple(sorted(uses[digest]))))
    exclusions.extend(FetchExclusion(file_name=item.file_name, sha256=item.sha256, reason='deferred')
                      for item in entries[max_files:])
    sources = [FetchInput(source='pairs', sha256=_digest(_model_bytes(pairs)))]
    sources.extend(FetchInput(source=f'catalogue:{name}', sha256=_digest(_model_bytes(cat)))
                   for name, cat in sorted(by_name.items()))
    result = FetchPlan(contract='tier-w-fetch-plan/1', tier='W', operation='binary', corpus_id=pairs.corpus_id,
                       selected_pairs=selected, max_files=max_files,
                       source_digests=tuple(sorted(sources, key=lambda item: item.source)),
                       entries=tuple(entries[:max_files]), exclusions=_exclusions(exclusions))
    plan_bytes(result)  # Enforce the complete preview budget before returning an executable plan.
    return result


def _binary_snapshot(snapshot: owned.FileSnapshot, item: FetchItem) -> None:
    if snapshot.size != item.size or snapshot.sha256 != item.sha256:
        raise TierWError('PT-TIERW-VERIFY', 'local binary size or digest differs from its plan')
    try:
        header = snapshot.read(0, 64)
        _validate_pe_prefix(header, snapshot.size)
        offset = struct.unpack_from('<I', header, 0x3C)[0]
        pe = snapshot.read(offset, 26, clip=False)
        sections, optional_size = struct.unpack_from('<H', pe, 6)[0], struct.unpack_from('<H', pe, 20)[0]
        table = offset + 24 + optional_size
        if (pe[:4] != b'PE\0\0' or struct.unpack_from('<H', pe, 4)[0] != 0x8664 or optional_size < 112 or
                struct.unpack_from('<H', pe, 24)[0] != 0x20B or sections < 1 or table + sections * 40 > snapshot.size):
            raise ValueError('PE optional header or section table is invalid')
        directories = struct.unpack('<I', snapshot.read(offset + 24 + 108, 4, clip=False))[0]
        if directories > (optional_size - 112) // 8:
            raise ValueError('directory table exceeds its header')
        for index in range(sections):
            size, start = struct.unpack('<II', snapshot.read(table + index * 40 + 16, 8, clip=False))
            if size and (start > snapshot.size or size > snapshot.size - start):
                raise ValueError('section exceeds its file')
    except (ValueError, struct.error):
        raise TierWError('PT-TIERW-VERIFY', 'planned binary is not a valid AMD64 PE') from None


def _local_binary(root: Path, item: FetchItem) -> Path:
    return root / 'binaries' / item.sha256 / item.file_name


def build_pdb_plan(root: Path, binary_plan: FetchPlan, *, max_files: int = MAX_FETCH_ITEMS,
                   pdb_cap_mib: int = DEFAULT_PDB_CAP_MIB) -> FetchPlan:
    """Derive PDB requests from the exact verified local binary snapshots; no network is used."""
    _file_limit(max_files)
    try:
        cap = pdb_cap_bytes(pdb_cap_mib)
    except AcquisitionError:
        raise TierWError('PT-TIERW-INPUT', 'PDB plan cap must be an integer from 1 through 2048 MiB') from None
    binary_plan = _checked(FetchPlan, binary_plan)
    if binary_plan.operation != 'binary':
        raise TierWError('PT-TIERW-INPUT', 'PDB planning requires a binary plan')
    root = check_root(root)
    digest = plan_sha256(binary_plan)
    sources, entries, exclusions = [FetchInput(source='binary-plan', sha256=digest)], [], []
    for binary in binary_plan.entries:
        def codeview_for(snapshot, item=binary):
            _binary_snapshot(snapshot, item)
            return inspect_pe(snapshot).codeview

        try:
            codeview = owned.inspect_file(_local_binary(root, binary), maximum=binary.size, inspect=codeview_for)
        except (OSError, owned.OwnedPublicationError):
            raise TierWError('PT-TIERW-VERIFY', 'a verified local binary is missing or changed') from None
        sources.append(FetchInput(source=f'binary:{binary.sha256}', sha256=binary.sha256))
        try:
            if codeview is None:
                raise ValueError('no CodeView')
            name = pdb_name(codeview.pdb_path).lower()
            guid = str(uuid.UUID(codeview.guid))
            item = FetchItem(kind='pdb', file_name=name, source_url=pdb_url(name, guid, codeview.age),
                             cap_bytes=cap, binary_sha256=binary.sha256, binary_size=binary.size,
                             guid=guid, age=codeview.age, pair_ids=binary.pair_ids)
        except (ValueError, TierWError):
            exclusions.append(FetchExclusion(file_name=binary.file_name, sha256=binary.sha256, reason='no-codeview'))
            continue
        entries.append(item)
    exclusions.extend(FetchExclusion(file_name=item.file_name, sha256=item.binary_sha256, reason='deferred')
                      for item in entries[max_files:])
    result = FetchPlan(contract='tier-w-fetch-plan/1', tier='W', operation='pdb', corpus_id=binary_plan.corpus_id,
                       selected_pairs=binary_plan.selected_pairs, max_files=max_files,
                       source_digests=tuple(sorted(sources, key=lambda item: item.source)),
                       input_plan_sha256=digest, entries=tuple(entries[:max_files]), exclusions=_exclusions(exclusions))
    plan_bytes(result)
    return result


def confirm_plan(source: Path, expected_sha256: str, recompute: Callable[[], FetchPlan], *,
                 consent_hosts: Iterable[str]) -> tuple[FetchPlan, str, AcquisitionConsent]:
    """Call the offline recomputation now, bind exact saved bytes and require the exact host set."""
    if not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256):
        raise TierWError('PT-TIERW-CONFIG', 'confirmation must be the displayed lowercase plan SHA-256')
    plan, raw = read_plan(source)
    digest = _digest(raw)
    if digest != expected_sha256 or raw != plan_bytes(recompute()):
        raise TierWError('PT-TIERW-CONFIG', 'saved fetch confirmation is stale or differs from the current preview')
    urls = frozenset(item.source_url for item in plan.entries)
    required = frozenset({SYMBOL_HOST}) if urls else frozenset()
    if frozenset(consent_hosts) != required:
        raise TierWError('PT-TIERW-CONFIG', 'consent hosts must exactly match the displayed plan')
    return plan, digest, AcquisitionConsent(hosts=required, urls=urls)
