"""Saved Tier-W previews and separately confirmed binary/PDB acquisition.

The offline plan design is recovered from c0255b78/f44454ad/5b7b2591, adapted to
current contracts and held-file readers. CLI network adapters remain separate.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import struct
import tempfile
import threading
import time
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from patchtrace import owned_publication as owned
from patchtrace.acquisition import transport as acquisition
from patchtrace.acquisition.contracts import AcquisitionError, PlannedDownload, symbol_server_url
from patchtrace.acquisition.transport import MAX_DOWNLOAD_BYTES, SYMBOL_HOST, AcquisitionConsent, Downloaded
from patchtrace.ingestion import _validate_pe_prefix
from patchtrace.pe_overview.inspect import inspect_pe

from ..common import canonical_json
from ..label import GENESIS
from . import msf
from .contracts import (
    DOC_LIMIT,
    MAX_FETCH_ITEMS,
    Catalogue,
    FetchExclusion,
    FetchInput,
    FetchItem,
    FetchPlan,
    PairsDoc,
    PdbFetchReceipt,
    load_fetch_plan,
    load_pdb_fetch_receipt,
)
from .fetch import MARGIN, guid_age, pdb_name, pdb_url
from .paths import Layout, TierWError, check_root
from .transport import DEFAULT_PDB_CAP_MIB, SymbolTransport, pdb_cap_bytes

FETCH_PLAN_LIMIT = DOC_LIMIT
_SHA = re.compile(r'[0-9a-f]{64}\Z')
LEDGER_EVENT_LIMIT = 64 * 1024
LEDGER_LIMIT = DOC_LIMIT
PDB_RECEIPT_LIMIT = 64 * 1024


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


def _ordinary_directories(path: Path, *, allow_missing: bool) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    if '..' in absolute.parts:
        raise TierWError('PT-TIERW-CONFIG', 'saved fetch paths cannot contain parent traversal components')
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise TierWError('PT-TIERW-CONFIG', 'saved fetch requires an existing ordinary corpus root') from None
        except OSError:
            raise TierWError('PT-TIERW-CONFIG', 'saved fetch parent is unreadable') from None
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                getattr(info, 'st_file_attributes', 0) & 0x400):
            raise TierWError('PT-TIERW-CONFIG', 'saved fetch parent is linked, reparse or not a directory')


def _root_anchor(root: Path) -> tuple[Path, owned.DirectoryAnchor]:
    original = Path(root).expanduser()
    _ordinary_directories(original, allow_missing=False)
    root = check_root(original)
    if root != Path(os.path.abspath(original)):
        raise TierWError('PT-TIERW-CONFIG', 'saved fetch root resolves to a different pathname')
    try:
        return root, owned.directory_anchor(root)
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-CONFIG', 'saved fetch root cannot be held as an ordinary directory') from None


def save_plan(plan: FetchPlan, destination: Path) -> str:
    """Exclusively save the canonical preview; only byte-identical existing evidence may be reused."""
    data = plan_bytes(plan)
    destination = Path(destination)
    _ordinary_directories(destination.parent, allow_missing=True)
    check_root(destination.parent)
    try:
        owned.publish_bytes(destination, data, validate_existing=_exact(data), maximum=len(data))
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-VERIFY', 'fetch plan could not be safely retained') from None
    return _digest(data)


def read_plan(source: Path) -> tuple[FetchPlan, bytes]:
    _ordinary_directories(Path(source).parent, allow_missing=False)
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
    root, anchor = _root_anchor(root)
    digest = plan_sha256(binary_plan)
    sources, entries, exclusions = [FetchInput(source='binary-plan', sha256=digest)], [], []
    for binary in binary_plan.entries:
        def codeview_for(snapshot, item=binary):
            _binary_snapshot(snapshot, item)
            return inspect_pe(snapshot).codeview

        try:
            codeview = owned.inspect_file(_local_binary(root, binary), maximum=binary.size,
                                         inspect=codeview_for, anchor=anchor)
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
    hosts = []
    for host in consent_hosts:
        if len(hosts) >= 2 or not isinstance(host, str):
            raise TierWError('PT-TIERW-CONFIG', 'consent hosts must be the bounded displayed host list')
        hosts.append(host)
    if frozenset(hosts) != required:
        raise TierWError('PT-TIERW-CONFIG', 'consent hosts must exactly match the displayed plan')
    return plan, digest, AcquisitionConsent(hosts=required, urls=urls)


@dataclass(frozen=True)
class FetchExecution:
    """An attempt's observed outcomes and immutable event prefix, not a CLI authorization."""
    status: str
    operation: str
    plan_sha256: str
    results: tuple[dict, ...]
    remaining: int
    excluded: int
    attempt_ledger: Path
    ledger_head_sha256: str


class _Stop:
    def __init__(self, layout: Layout, *events):
        self.path, self.events = layout.cancel_file, tuple(event for event in events if event is not None)
        self._waiter = threading.Event()

    def is_set(self) -> bool:
        if any(event.is_set() for event in self.events):
            return True
        try:
            self.path.lstat()  # Any observed switch, including a dangling link, stops the operation.
            return True
        except FileNotFoundError:
            return False
        except OSError:
            raise TierWError('PT-TIERW-VERIFY', 'the local cancellation switch cannot be checked') from None

    def check(self) -> None:
        acquisition._cancelled(self)

    def wait(self, seconds: float) -> bool:
        deadline = time.monotonic() + max(0, seconds)
        while not self.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._waiter.wait(min(acquisition.SLICE, remaining))
        return self.is_set()


def _publish_small(target: Path, data: bytes, anchor: owned.DirectoryAnchor, *,
                   reuse: Callable[[owned.FileSnapshot], None] | None = None) -> None:
    """Use the same owned cleanup path for bounded metadata and downloaded artifacts."""
    handle, primary = tempfile.TemporaryFile(mode='w+b', buffering=0), None
    try:
        if handle.write(data) != len(data):
            raise TierWError('PT-TIERW-VERIFY', 'short fetch evidence staging write')
        handle.flush()
        os.fsync(handle.fileno())
        with owned.FileSnapshot(handle.fileno(), maximum=len(data), expected_size=len(data),
                                expected_sha256=_digest(data)) as snapshot:
            owned.publish_stream(target, snapshot, anchor=anchor, validate_existing=reuse,
                                 maximum=len(data) if reuse is not None else 0)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            handle.close()
        except BaseException as exc:
            if primary is None:
                raise
            primary.add_note(f'Fetch evidence cleanup also failed: {type(exc).__name__}')


class _AttemptLedger:
    def __init__(self, anchor: owned.DirectoryAnchor, plan: FetchPlan, digest: str):
        self.anchor, self.plan, self.digest = anchor, plan, digest
        self.path = anchor.path / 'tier-w' / 'ledger' / f'{plan.corpus_id}.fetch' / digest / secrets.token_hex(16)
        self.seq, self.head, self.total = 0, GENESIS, 0

    def record(self, event: str, **fields) -> None:
        record = dict(contract='tier-w-fetch/1', tier='W', corpus_id=self.plan.corpus_id,
                      operation=self.plan.operation, plan_sha256=self.digest, event=event, **fields)
        record.update(seq=self.seq + 1, prev_sha256=self.head)
        record['sha256'] = _digest(canonical_json(record))
        data = canonical_json(record) + b'\n'
        if len(data) > LEDGER_EVENT_LIMIT or self.total + len(data) > LEDGER_LIMIT:
            raise TierWError('PT-TIERW-LIMIT', 'saved fetch attempt ledger exceeds its byte budget')
        try:
            _publish_small(self.path / f'{self.seq + 1:06d}.jsonl', data, self.anchor)
        except (OSError, owned.OwnedPublicationError):
            raise TierWError('PT-TIERW-VERIFY', 'saved fetch outcome could not be safely retained') from None
        self.seq, self.head, self.total = self.seq + 1, record['sha256'], self.total + len(data)


def _destination(root: Path, item: FetchItem) -> Path:
    if item.kind == 'binary':
        return _local_binary(root, item)
    return Layout(root).pdb(item.file_name, guid_age(item.guid, item.age))


def _item_identity(snapshot: owned.FileSnapshot, item: FetchItem, stop: _Stop) -> dict:
    stop.check()
    if item.kind == 'binary':
        _binary_snapshot(snapshot, item)
    else:
        try:
            identity = msf.read_identity_snapshot(snapshot, stop.is_set)
        except msf.MsfError:
            stop.check()
            raise TierWError('PT-TIERW-VERIFY', 'PDB structure does not satisfy the saved plan') from None
        if (identity.guid, identity.age) != (item.guid, item.age):
            raise TierWError('PT-TIERW-VERIFY', 'PDB GUID or age differs from the saved plan')
    return {'file_sha256': snapshot.sha256, 'size': snapshot.size}


def _existing_artifact(target: Path, item: FetchItem, anchor: owned.DirectoryAnchor, stop: _Stop) -> dict | None:
    entered = False

    def inspect(snapshot):
        nonlocal entered
        entered = True
        return _item_identity(snapshot, item, stop)

    try:
        return owned.inspect_file(target, maximum=item.cap_bytes, inspect=inspect, anchor=anchor, check=stop.check)
    except FileNotFoundError:
        # Missing parent/initial leaf is admissible; loss after inspection began is a refusal.
        if entered:
            raise TierWError('PT-TIERW-VERIFY', 'existing fetch evidence disappeared during verification') from None
        owned.verify_anchor(anchor)
        return None
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-VERIFY', 'existing fetch evidence is linked, changed or unreadable') from None


def _receipt_path(target: Path) -> Path:
    return target.with_name(target.name + '.fetch-receipt.json')


def _receipt_state(path: Path) -> tuple:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or
            getattr(info, 'st_file_attributes', 0) & 0x400):
        raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt must be an ordinary singly linked file')
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink


def _parse_receipt(snapshot: owned.FileSnapshot, target: Path, item: FetchItem,
                   anchor: owned.DirectoryAnchor) -> PdbFetchReceipt:
    raw = snapshot.read(0, snapshot.size, clip=False)
    try:
        receipt = load_pdb_fetch_receipt(raw)
    except TierWError:
        raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt does not satisfy its strict contract') from None
    if (raw != _model_bytes(receipt) or receipt.destination != target.relative_to(anchor.path).as_posix() or
            (receipt.file_name, receipt.source_url, receipt.guid, receipt.age) !=
            (item.file_name, item.source_url, item.guid, item.age) or receipt.size > item.cap_bytes):
        raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt differs from the saved target or current cap')
    return receipt


def _with_receipt(target: Path, item: FetchItem, anchor: owned.DirectoryAnchor, stop: _Stop,
                  use: Callable[[PdbFetchReceipt], object], *, optional: bool = False):
    path = _receipt_path(target)
    try:
        _ordinary_directories(path.parent, allow_missing=True)
        try:
            before = _receipt_state(path)
        except FileNotFoundError:
            owned.verify_anchor(anchor)
            if optional:
                return None
            raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt disappeared before use') from None

        def inspect(snapshot):
            result = use(_parse_receipt(snapshot, target, item, anchor))
            if _receipt_state(path) != before:
                raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt changed during use')
            return result

        result = owned.inspect_file(path, maximum=PDB_RECEIPT_LIMIT, inspect=inspect, anchor=anchor, check=stop.check)
        if _receipt_state(path) != before:
            raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt changed after verification')
        return result
    except (OSError, owned.OwnedPublicationError):
        raise TierWError('PT-TIERW-VERIFY', 'PDB fetch receipt is missing, linked, changed or unreadable') from None


def _existing(target: Path, item: FetchItem, anchor: owned.DirectoryAnchor, stop: _Stop) -> dict | None:
    if item.kind == 'binary':
        return _existing_artifact(target, item, anchor, stop)
    used_receipt = False

    def use(receipt):
        nonlocal used_receipt
        used_receipt = True
        actual = _existing_artifact(target, item, anchor, stop)
        if actual is not None and (actual['file_sha256'], actual['size']) != (receipt.file_sha256, receipt.size):
            raise TierWError('PT-TIERW-VERIFY', 'existing PDB bytes differ from their verified download receipt')
        return actual

    result = _with_receipt(target, item, anchor, stop, use, optional=True)
    if not used_receipt:
        try:
            target.lstat()
        except FileNotFoundError:
            owned.verify_anchor(anchor)
            return None
        except OSError:
            raise TierWError('PT-TIERW-VERIFY', 'PDB destination cannot be checked') from None
        raise TierWError('PT-TIERW-VERIFY', 'existing PDB has no verified download receipt; prior bytes are preserved')
    return result


def _bind_pdb_receipt(target: Path, item: FetchItem, snapshot: owned.FileSnapshot,
                      anchor: owned.DirectoryAnchor) -> PdbFetchReceipt:
    expected = PdbFetchReceipt(contract='tier-w-pdb-receipt/1', tier='W',
                               destination=target.relative_to(anchor.path).as_posix(), file_name=item.file_name,
                               source_url=item.source_url, guid=item.guid, age=item.age,
                               file_sha256=snapshot.sha256, size=snapshot.size)
    path, data = _receipt_path(target), _model_bytes(expected)

    def same(existing):
        _receipt_state(path)
        if existing.read(0, existing.size, clip=False) != data:
            raise TierWError('PT-TIERW-VERIFY', 'another writer retained a conflicting PDB byte receipt')

    _publish_small(path, data, anchor, reuse=same)
    return expected


def _disk(root: Path, pending_bytes: int, free: Callable[[Path], int]) -> None:
    if not pending_bytes:
        return
    needed = 2 * pending_bytes + MARGIN
    try:
        available = free(root)
    except OSError:
        raise TierWError('PT-TIERW-CONFIG', 'available corpus space cannot be checked') from None
    if type(available) is not int or available < needed:
        raise TierWError('PT-TIERW-CONFIG', 'insufficient space for the retained stages, outputs and 1 GiB margin')


def _download_metadata(got: Downloaded, item: FetchItem, stage: owned.DirectoryAnchor) -> dict:
    if (not isinstance(got, Downloaded) or not isinstance(got.path, Path) or got.path.parent != stage.path or
            not got.path.is_absolute() or type(got.size) is not int or not 1 <= got.size <= item.cap_bytes or
            not isinstance(got.sha256, str) or not _SHA.fullmatch(got.sha256) or got.source_url != item.source_url):
        raise TierWError('PT-TIERW-VERIFY', 'download receipt does not identify the planned owned stage')
    if got.redirect_host is not None:
        host = got.redirect_host
        if (not isinstance(host, str) or not re.fullmatch(r'[a-z0-9.-]{1,253}', host) or
                not host.endswith(acquisition.BLOB_SUFFIX) or len(host) <= len(acquisition.BLOB_SUFFIX)):
            raise TierWError('PT-TIERW-VERIFY', 'download receipt contains an invalid redirect hostname')
    try:
        if not isinstance(got.retrieved_at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', got.retrieved_at):
            raise ValueError('not a canonical timestamp')
        datetime.fromisoformat(got.retrieved_at)
    except ValueError:
        raise TierWError('PT-TIERW-VERIFY', 'download receipt contains an invalid retrieval time') from None
    return {'source_url': item.source_url, 'redirect_host': got.redirect_host, 'retrieved_at': got.retrieved_at}


def _item_fields(root: Path, item: FetchItem) -> dict:
    return {'kind': item.kind, 'file_name': item.file_name, 'binary_sha256': item.sha256 or item.binary_sha256,
            'destination': _destination(root, item).relative_to(root).as_posix(), 'source_url': item.source_url}


def _fetch_item(root: Path, anchor: owned.DirectoryAnchor, item: FetchItem, initial: dict | None,
                consent: AcquisitionConsent, subject: SymbolTransport, stop: _Stop, digest: str,
                pending_bytes: int, free: Callable[[Path], int], progress) -> dict:
    stop.check()
    target = _destination(root, item)
    existing = _existing(target, item, anchor, stop)
    fields = _item_fields(root, item)
    if initial is not None and existing != initial:
        raise TierWError('PT-TIERW-VERIFY', 'previously verified destination changed before reuse')
    if existing is not None:
        return dict(fields, status='reused', requested=False, origin='local-verified', **existing)
    _disk(root, pending_bytes, free)
    stage_path = Layout(root).staging / secrets.token_hex(16)
    request = canonical_json({'tier': 'W', 'plan_sha256': digest, 'source_url': item.source_url}) + b'\n'
    _publish_small(stage_path / 'request.json', request, anchor)
    stage = owned.directory_anchor(stage_path)
    owned.verify_anchor(anchor)
    stop.check()
    callback = (lambda size, total: progress(item, size, total)) if progress is not None else None
    if item.kind == 'binary':
        planned = PlannedDownload(side='older', file_name=item.file_name, sha256=item.sha256, size=item.size,
                                  url=item.source_url, record_sha256=item.record_sha256)
        got = subject.download(planned, consent, stage.path, progress=callback)
    else:
        got = subject.download_pdb(item.source_url, consent, stage.path, item.cap_bytes,
                                   expected_guid=item.guid, expected_age=item.age, progress=callback)
    metadata = _download_metadata(got, item, stage)
    stop.check()

    def promote(snapshot):
        if snapshot.size != got.size or snapshot.sha256 != got.sha256:
            raise TierWError('PT-TIERW-VERIFY', 'download stage bytes differ from their transport receipt')
        observed = _item_identity(snapshot, item, stop)

        def same(existing):
            if (existing.size, existing.sha256) != (snapshot.size, snapshot.sha256):
                raise TierWError('PT-TIERW-VERIFY', 'another writer published conflicting fetch evidence')

        def publish():
            return owned.publish_stream(target, snapshot, anchor=anchor,
                                        validate_existing=same, maximum=item.cap_bytes)

        if item.kind == 'pdb':
            expected = _bind_pdb_receipt(target, item, snapshot, anchor)

            def matching(receipt):
                if receipt != expected:
                    raise TierWError('PT-TIERW-VERIFY', 'PDB receipt changed before artifact publication')
                return publish()

            published = _with_receipt(target, item, anchor, stop, matching)
        else:
            published = publish()
        return dict(fields, **observed, status='fetched' if published else 'reused', requested=True,
                    origin='symbol-server' if published else 'local-verified', **{
                        key: value for key, value in metadata.items() if key != 'source_url'})

    result = owned.inspect_file(got.path, maximum=got.size, inspect=promote, anchor=stage, check=stop.check)
    owned.verify_anchor(anchor)
    return result


def fetch_saved_plan(source: Path, expected_sha256: str, *, root: Path, recompute: Callable[[], FetchPlan],
                     consent_hosts: Iterable[str], transport: SymbolTransport | None = None,
                     cancel: threading.Event | None = None,
                     disk_free: Callable[[Path], int] = lambda path: shutil.disk_usage(path).free,
                     progress: Callable[[FetchItem, int, int], None] | None = None) -> FetchExecution:
    """Execute only the freshly confirmed preview; never overwrite conflicting artifacts or receipt history."""
    root, anchor = _root_anchor(root)
    plan, digest, consent = confirm_plan(source, expected_sha256, recompute, consent_hosts=consent_hosts)
    subject = transport if transport is not None else SymbolTransport()
    if not isinstance(subject, SymbolTransport):
        raise TierWError('PT-TIERW-CONFIG', 'saved fetch requires the reviewed SymbolTransport')
    try:
        subject._interval()
    except AcquisitionError:
        raise TierWError('PT-TIERW-CONFIG', 'saved fetch request interval is invalid') from None
    stop = _Stop(Layout(root), cancel, subject.cancel)
    try:
        stop.check()
        initial = [_existing(_destination(root, item), item, anchor, stop) for item in plan.entries]
    except AcquisitionError as exc:
        if exc.code == 'PT-ACQ-CANCEL':
            raise TierWError('PT-TIERW-CANCEL', 'saved fetch was cancelled before requests') from None
        raise
    pending_bytes = sum(item.cap_bytes for item, observed in zip(plan.entries, initial, strict=True) if observed is None)
    _disk(root, pending_bytes, disk_free)
    ledger = _AttemptLedger(anchor, plan, digest)
    ledger.record('fetch-started', selected=len(plan.entries), exclusions=len(plan.exclusions))
    results, previous_cancel = [], subject.cancel
    subject.cancel = stop
    try:
        for item, before in zip(plan.entries, initial, strict=True):
            try:
                result = _fetch_item(root, anchor, item, before, consent, subject, stop, digest,
                                     pending_bytes, disk_free, progress)
            except AcquisitionError as exc:
                status = ('cancelled' if exc.code == 'PT-ACQ-CANCEL' else 'not-found' if exc.code == 'PT-ACQ-NOTFOUND'
                          else 'rejected' if exc.code in {'PT-ACQ-VERIFY', 'PT-ACQ-LIMIT', 'PT-ACQ-UNSUPPORTED'} else 'failed')
                result = dict(_item_fields(root, item), status=status,
                              error_code='PT-TIERW-CANCEL' if status == 'cancelled' else
                              'PT-TIERW-VERIFY' if status in {'rejected', 'not-found'} else 'PT-TIERW-NETWORK')
            except (TierWError, OSError, owned.OwnedPublicationError) as exc:
                code = 'PT-TIERW-CONFIG' if isinstance(exc, TierWError) and exc.code == 'PT-TIERW-CONFIG' else 'PT-TIERW-VERIFY'
                result = dict(_item_fields(root, item), status='failed', error_code=code)
            ledger.record(f'{item.kind}-{result["status"]}', **result)
            results.append(result)
            if before is None:
                pending_bytes -= item.cap_bytes
            if result['status'] == 'cancelled' or result.get('error_code') == 'PT-TIERW-CONFIG':
                break
        remaining = len(plan.entries) - len(results)
        status = ('cancelled' if any(row['status'] == 'cancelled' for row in results) else
                  'partial' if remaining or plan.exclusions or any(row['status'] not in {'fetched', 'reused'} for row in results)
                  else 'completed')
        ledger.record('fetch-finished', status=status, remaining=remaining,
                      outcomes=dict(Counter(row['status'] for row in results)), exclusions=len(plan.exclusions))
        return FetchExecution(status, plan.operation, digest, tuple(results), remaining, len(plan.exclusions),
                              ledger.path, ledger.head)
    except BaseException as exc:
        try:
            ledger.record('fetch-interrupted', status='cancelled' if isinstance(exc, KeyboardInterrupt) else 'failed',
                          completed=len(results), remaining=len(plan.entries) - len(results))
        except BaseException as secondary:
            exc.add_note(f'Fetch interruption receipt also failed: {type(secondary).__name__}')
        raise
    finally:
        subject.cancel = previous_cancel
