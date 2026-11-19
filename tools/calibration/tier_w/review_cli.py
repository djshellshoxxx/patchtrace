"""Bounded offline Tier-W audit and human-review adapters (SPEC-33 sections 7 and 11).

The sampler/statistics and terminal workflow stay in their existing libraries.
This module admits their local files and binds a human log to one blind queue.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import math
import stat
import sys
from collections import Counter
from contextlib import ExitStack
from functools import wraps
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from patchtrace import owned_publication as owned

from .. import label
from ..common import canonical_json, det_uniform, strict_json
from . import audit as A
from . import fetch
from .contracts import (
    DOC_LIMIT,
    SYMBOL_MAP_LIMIT,
    Ident,
    LabelDetail,
    Sha256,
    load_audit_key,
    load_jsonl,
    load_pairs,
    load_symbol_map,
)
from .paths import OK, PARTIAL, Layout, TierWError, write_json
from .pe_tables import PeView, masked_body_sha256

KEY, QUEUE, LOG, REPORT = 'audit-key.json', 'queue.jsonl', 'annotations.jsonl', 'audit-report.json'
POPULATION_BYTES = LOG_LIMIT = DOC_LIMIT
EVENT_LIMIT = 1024 * 1024


def positive(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('expected a finite positive number') from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('expected a finite positive number')
    return number


def short_text(value: str) -> str:
    if not value.strip() or len(value) > 64 or any(ord(c) < 32 for c in value):
        raise argparse.ArgumentTypeError('expected 1 to 64 characters without control characters')
    return value


def _fail(message: str) -> TierWError:
    return TierWError('PT-TIERW-INPUT', message)


def _checked(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (owned.OwnedPublicationError, ValidationError, ValueError, TypeError, KeyError, RecursionError):
            raise _fail('audit data are invalid or changed; restore the matching audit files') from None
    return call


def _cancel(layout: Layout) -> None:
    if fetch.cancelled(layout):
        raise TierWError('PT-TIERW-CANCEL', 'audit or review cancelled')


def _present(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _read(path: Path, layout: Layout, maximum: int = DOC_LIMIT) -> bytes:
    return owned.read_bytes(path, maximum=maximum, anchor=owned.directory_anchor(layout.root))


def _ordinary_write_target(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise _fail('audit write target is not one ordinary owned file')


def _encode(document) -> bytes:
    stream = io.BytesIO()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    for piece in encoder.iterencode(document):
        raw = piece.encode('utf-8')
        if stream.tell() + len(raw) > DOC_LIMIT:
            raise TierWError('PT-TIERW-LIMIT', 'audit document exceeds the 64 MiB byte budget')
        stream.write(raw)
    return stream.getvalue()


def _queue_bytes(records) -> bytes:
    stream = io.BytesIO()
    for record in records:
        raw = _encode(record) + b'\n'
        if stream.tell() + len(raw) > DOC_LIMIT:
            raise TierWError('PT-TIERW-LIMIT', 'audit queue exceeds the 64 MiB byte budget')
        stream.write(raw)
    return stream.getvalue()


def _pairs(layout: Layout, corpus_id: str):
    path = layout.pairs(corpus_id)
    if not _present(path):
        raise _fail('no pairs document for this corpus id; run pairs first')
    sidecar = load_pairs(_read(path, layout))
    binaries = {binary.id: binary for binary in sidecar.binaries}
    pairs = {pair.id: pair for pair in sidecar.pairs}
    if (sidecar.corpus_id != corpus_id or len(binaries) != len(sidecar.binaries) or
            len(pairs) != len(sidecar.pairs) or
            any(pair.older not in binaries or pair.newer not in binaries for pair in sidecar.pairs)):
        raise _fail('audit pairs have foreign or ambiguous corpus/binary ownership')
    return sidecar


def _population(layout: Layout, sidecar):
    candidates, truth, missing = {}, {}, 0
    binding, consumed = hashlib.sha256(), 0
    for pair in sorted(sidecar.pairs, key=lambda item: item.id):
        _cancel(layout)
        path = layout.labels_dir(sidecar.corpus_id) / f'{pair.id}.detail.jsonl'
        if not _present(path):
            missing += 1
            binding.update(canonical_json([pair.id, None]) + b'\n')
            continue
        raw = _read(path, layout, min(SYMBOL_MAP_LIMIT, POPULATION_BYTES - consumed))
        consumed += len(raw)
        binding.update(canonical_json([pair.id, hashlib.sha256(raw).hexdigest()]) + b'\n')
        for row in load_jsonl(LabelDetail, raw, 'audit label detail'):
            if row.pair != pair.id:
                raise _fail('audit label detail belongs to another pair')
            if row.A is None:
                continue
            if row.older.rva is None or row.newer.rva is None or (row.kind == 'truth' and row.A != 'same'):
                raise _fail('audit label detail has contradictory labelled sides')
            value = A.AuditCandidate(row.pair, row.match_id, row.A, row.older.rva, row.newer.rva,
                                    row.older.size, row.newer.size)
            target = candidates if row.kind == 'candidate' else truth
            identity = row.pair, row.match_id
            if identity in target and target[identity] != value:
                raise _fail('audit label detail has conflicting duplicate ownership')
            target[identity] = value
    return list(candidates.values()), list(truth.values()), missing, binding.hexdigest()


def _pairs_digest(sidecar) -> str:
    return hashlib.sha256(_encode(sidecar.model_dump(mode='json'))).hexdigest()


def _views(layout: Layout, sidecar, selected, producer: str):
    binaries = {binary.id: binary for binary in sidecar.binaries}
    pairs = {pair.id: pair for pair in sidecar.pairs}
    result, by_pair = {}, {}
    for row in selected:
        by_pair.setdefault(row.pair, []).append(row)

    def cancelled() -> bool:
        _cancel(layout)  # retain the typed cancellation when the verified reader closes its held input
        return False

    for pair_id in sorted(by_pair):
        _cancel(layout)
        pair = pairs[pair_id]
        with ExitStack() as stack:
            for side in ('older', 'newer'):
                binary = binaries[getattr(pair, side)]
                symbols = load_symbol_map(_read(layout.symbols(binary.sha256, producer), layout, SYMBOL_MAP_LIMIT))
                if (symbols.image.sha256 != binary.sha256 or symbols.image.file_name != binary.file_name or
                        symbols.producer.tool != producer or symbols.tier not in {'W', 'test'}):
                    raise _fail('audit symbol map has foreign binary or producer ownership')
                view = stack.enter_context(PeView(layout.root / 'binaries' / binary.sha256 / binary.file_name,
                                                  expected_sha256=binary.sha256,
                                                  cancel=cancelled))
                by_rva = {symbol.rva: symbol for symbol in symbols.symbols}
                relocations = view.relocations()
                for row in by_pair[pair_id]:
                    _cancel(layout)
                    rva, size = getattr(row, side + '_rva'), getattr(row, side + '_size')
                    symbol = by_rva.get(rva)
                    if (symbol.size if symbol is not None else None) != size:
                        raise _fail('audit labels and selected symbol map have different body sizes')
                    identity = pair_id, side, rva
                    if identity in result:
                        continue
                    if rva is None or view.size_of_image is None or rva >= view.size_of_image:
                        raise _fail('audit side has no admitted image address')
                    ranges = symbol.ranges if symbol is not None else ()
                    if any(end > view.size_of_image for _start, end in ranges):
                        raise _fail('audit body range exceeds the selected image')
                    body = masked_body_sha256(view, ranges, relocations) if ranges else None
                    preview = bytearray()
                    for start, end in ranges or ((rva, min(view.size_of_image, rva + A.PREVIEW_BYTES)),):
                        preview.extend(view.read_rva(start, min(end - start, A.PREVIEW_BYTES - len(preview))))
                        if len(preview) == A.PREVIEW_BYTES:
                            break
                    result[identity] = A.SideView(size, body, bytes(preview))
    return result


class _Reader:
    def __init__(self, views):
        self.views = views

    def read(self, pair, side, rva):
        return self.views[pair, side, rva]


def _same(expected: bytes):
    def validate(raw: bytes) -> None:
        if raw != expected:
            raise _fail('a different audit already exists; preserve it before creating another audit')
    return validate


@_checked
def audit(args, layout: Layout, corpus_id: str):
    sidecar = _pairs(layout, corpus_id)
    candidates, truth, missing, labels_sha = _population(layout, sidecar)
    population = candidates or truth
    if not population:
        return PARTIAL, {'sampled': 0, 'missing_labels': missing, 'reason': 'no labelled audit population'}
    folder = layout.review_dir(corpus_id)
    key_path, queue_path = folder / KEY, folder / QUEUE
    reused = _present(key_path) and _present(queue_path)
    if _present(queue_path) and not _present(key_path):
        raise _fail('the prior audit queue has no matching hidden key')
    if any(_present(folder / name) for name in (LOG, REPORT)) and not reused:
        raise _fail('incomplete audit ownership cannot adopt existing reviews or reports')
    created = dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    if _present(key_path):
        previous = load_audit_key(_read(key_path, layout))
        if previous.corpus_id != corpus_id:
            raise _fail('the hidden audit key belongs to another corpus')
        created = previous.created
    key = A.sample_audit(candidates, truth, corpus_id=corpus_id, seed=args.seed, rate=args.rate,
                         size_change=args.size_change, created=created)
    key_raw = _encode(key.model_dump(mode='json'))
    chosen = {(item.pair, item.match_id) for item in key.items}
    selected = [row for row in population if (row.pair, row.match_id) in chosen]
    views = _views(layout, sidecar, selected, args.producer)
    sides = {(row.pair, row.match_id): (row.older_rva, row.newer_rva) for row in selected}
    header = {**A.queue_header(key), 'audit_sha256': hashlib.sha256(key_raw).hexdigest(),
              'pairs_sha256': _pairs_digest(sidecar), 'labels_sha256': labels_sha, 'producer': args.producer}
    queue_raw = _queue_bytes([header, *A.queue_records(key, sides, _Reader(views))])
    for path, raw in ((key_path, key_raw), (queue_path, queue_raw)):
        if _present(path):
            _same(raw)(_read(path, layout))
    _cancel(layout)
    anchor = owned.directory_anchor(layout.root)
    for path, raw in ((key_path, key_raw), (queue_path, queue_raw)):
        _cancel(layout)
        owned.publish_bytes(path, raw, maximum=DOC_LIMIT, validate_existing=_same(raw), anchor=anchor)
    _cancel(layout)
    return (PARTIAL if missing or not key.items else OK), {
        'population': key.population, 'population_counts': key.population_counts, 'sampled': len(key.items),
        'missing_labels': missing, 'reused': reused}


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, allow_inf_nan=False)


class AuditQueueHeader(_Strict):
    contract: Literal['tier-w-review/1']
    tier: Literal['W']
    corpus_id: str = Field(max_length=64)
    population: Literal['candidates', 'truth']
    items: int = Field(ge=0)
    single_annotator: Literal[True]
    audit_sha256: Sha256
    pairs_sha256: Sha256
    labels_sha256: Sha256
    producer: Literal['msf', 'ghidra', 'llvm-pdbutil']


class AuditQueueSide(_Strict):
    rva: int | None = Field(ge=0, le=2**32 - 1)
    size: int | None = Field(ge=0, le=2**32 - 1)
    body_sha256: Sha256 | None
    preview_hex: str = Field(max_length=256, pattern=r'^(?:[0-9a-f]{2})*$')


class AuditQueueItem(_Strict):
    pair: Ident
    match_id: str = Field(min_length=1, max_length=200)
    stratum: Literal['census', 'random']
    older: AuditQueueSide
    newer: AuditQueueSide


class AuditAnnotation(_Strict):
    tier: Literal['W']
    corpus_id: str = Field(max_length=64)
    audit_sha256: Sha256
    queue_sha256: Sha256
    pair: Ident
    match_id: str = Field(min_length=1, max_length=200)
    annotator: str = Field(min_length=1, max_length=64)
    phase: Literal['blind']
    A: Literal['same', 'different', 'no-counterpart', 'indeterminate']
    subtype: str | None = Field(pattern=r'^N(?:[1-9]|1[0-2])$')
    guideline: Literal['g1']
    ts: str = Field(max_length=40)
    time_spent_s: float = Field(ge=0)
    seq: int = Field(ge=1)
    prev_sha256: Sha256
    sha256: Sha256


def _bundle(layout: Layout, corpus_id: str):
    sidecar = _pairs(layout, corpus_id)
    folder = layout.review_dir(corpus_id)
    key_raw, queue_raw = _read(folder / KEY, layout), _read(folder / QUEUE, layout)
    key = load_audit_key(key_raw)
    if not math.isfinite(key.size_change):
        raise _fail('hidden audit key has a nonfinite size-change threshold')
    candidates, truth, _missing, labels_sha = _population(layout, sidecar)
    expected = A.sample_audit(candidates, truth, corpus_id=corpus_id, seed=key.seed, rate=key.rate,
                             size_change=key.size_change, created=key.created)
    counts = Counter(item.stratum for item in key.items)
    identities = {(item.pair, item.match_id) for item in key.items}
    known = {pair.id for pair in sidecar.pairs}
    if (key != expected or key.corpus_id != corpus_id or key.tier != 'W' or len(identities) != len(key.items) or
            any(item.pair not in known for item in key.items) or set(key.population_counts) != set(A.STRATA) or
            any(key.population_counts[name] < counts[name] for name in A.STRATA) or
            any(item.p_incl != (1.0 if item.stratum == 'census' else key.rate) for item in key.items)):
        raise _fail('hidden audit key has foreign or inconsistent population ownership')
    lines = queue_raw.splitlines()
    if not lines or len(lines) != len(key.items) + 1:
        raise _fail('audit queue does not cover exactly the selected population')
    strict_json(lines[0])
    header = AuditQueueHeader.model_validate_json(lines[0])
    if (header.corpus_id, header.population, header.items, header.audit_sha256) != (
            corpus_id, key.population, len(key.items), hashlib.sha256(key_raw).hexdigest()):
        raise _fail('audit queue does not match its hidden key')
    if (header.pairs_sha256, header.labels_sha256) != (_pairs_digest(sidecar), labels_sha):
        raise _fail('audit population inputs have changed; preserve the prior audit before starting another')
    rows = load_jsonl(AuditQueueItem, b'\n'.join(lines[1:]), 'blind review queue')
    ordered = sorted(key.items, key=lambda item: det_uniform(key.seed, 'order', item.pair, item.match_id))
    if [(row.pair, row.match_id, row.stratum) for row in rows] != [
            (item.pair, item.match_id, item.stratum) for item in ordered]:
        raise _fail('audit queue identities, order or strata differ from the hidden key')
    selected = [row for row in candidates or truth if (row.pair, row.match_id) in identities]
    sides = {(row.pair, row.match_id): (row.older_rva, row.newer_rva) for row in selected}
    expected_rows = A.queue_records(key, sides, _Reader(_views(layout, sidecar, selected, header.producer)))
    documents = [row.model_dump(mode='json') for row in rows]
    if documents != expected_rows:
        raise _fail('audit queue sides differ from the verified image and symbol inputs')
    return key, documents, key_raw, queue_raw


class _AuditLog(label.AnnotationLog):
    def __init__(self, layout: Layout, corpus_id: str, key, key_raw: bytes, queue_raw: bytes):
        super().__init__(layout.review_dir(corpus_id) / LOG)
        self.layout = layout
        self.binding = {'tier': 'W', 'corpus_id': corpus_id,
                        'audit_sha256': hashlib.sha256(key_raw).hexdigest(),
                        'queue_sha256': hashlib.sha256(queue_raw).hexdigest()}
        self.selected = {(item.pair, item.match_id) for item in key.items}
        self.extra_bytes = 0

    def events(self) -> list[dict]:
        raw = _read(self.path, self.layout, LOG_LIMIT) if _present(self.path) else b''
        if len(raw) + self.extra_bytes > LOG_LIMIT:
            raise TierWError('PT-TIERW-LIMIT', 'audit annotation log exceeds the 64 MiB byte budget')
        events, seen, annotators, previous = [], set(), set(), label.GENESIS
        for number, line in enumerate(raw.splitlines(), 1):
            if len(line) > EVENT_LIMIT:
                raise TierWError('PT-TIERW-LIMIT', 'audit annotation event exceeds the 1 MiB byte budget')
            event = strict_json(line)
            AuditAnnotation.model_validate_json(line)
            claimed = event.pop('sha256')
            identity = event['pair'], event['match_id']
            if (event['seq'] != number or event['prev_sha256'] != previous or
                    hashlib.sha256(canonical_json(event)).hexdigest() != claimed or
                    any(event[name] != value for name, value in self.binding.items()) or
                    identity not in self.selected or identity in seen):
                raise _fail('audit annotations have changed or belong to another audit item')
            event['sha256'] = claimed
            seen.add(identity)
            annotators.add(event['annotator'])
            events.append(event)
            previous = claimed
        if len(annotators) > 1:
            raise _fail('this audit admits one annotator; mixed human passes cannot be pooled')
        return events

    def append(self, **fields):
        _cancel(self.layout)
        _ordinary_write_target(self.path)
        fields = {**fields, **self.binding}
        # AnnotationLog adds three bounded chain fields (seq and two 64-byte digests).
        self.extra_bytes = len(canonical_json(fields)) + 256
        try:
            return super().append(**fields)
        finally:
            self.extra_bytes = 0


@_checked
def review(args, layout: Layout, corpus_id: str):
    if not sys.stdin.isatty():
        raise TierWError('PT-TIERW-BLOCKED', 'human review requires an interactive terminal; no answers were recorded')
    key, rows, key_raw, queue_raw = _bundle(layout, corpus_id)
    log = _AuditLog(layout, corpus_id, key, key_raw, queue_raw)
    events = log.events()
    if events and events[0]['annotator'] != args.annotator:
        raise _fail('the existing audit belongs to another annotator')

    def ask(prompt: str) -> str:
        _cancel(layout)
        print(prompt, end='', file=sys.stderr, flush=True)
        try:
            return input()
        except EOFError:
            return 'q'

    recorded = label.run_terminal(rows, log, args.annotator, input_fn=ask,
                                  output_fn=lambda text: print(text, file=sys.stderr))
    reviewed = len(log.events())
    _cancel(layout)
    remaining = len(rows) - reviewed
    return (PARTIAL if remaining or not rows else OK), {
        'recorded': recorded, 'reviewed': reviewed, 'remaining': remaining, 'single_annotator': True}


def _current_report(layout: Layout, corpus_id: str):
    key, _rows, key_raw, queue_raw = _bundle(layout, corpus_id)
    log = _AuditLog(layout, corpus_id, key, key_raw, queue_raw)
    answers = {(event['pair'], event['match_id']): event['A'] for event in log.events()}
    return A.audit_report(key, answers)


@_checked
def audit_report(args, layout: Layout, corpus_id: str):
    path = layout.review_dir(corpus_id) / REPORT
    _ordinary_write_target(path)
    report = _current_report(layout, corpus_id)
    _saved_report(layout, corpus_id)
    _encode(report.model_dump(mode='json'))
    _cancel(layout)
    _ordinary_write_target(path)
    write_json(path, report.model_dump(mode='json'))
    _cancel(layout)
    return (OK if report.status == 'ok' else PARTIAL), {
        'audit_status': report.status, 'reviewed': report.reviewed, 'indeterminate': report.indeterminate,
        'symbol_audit_error': report.symbol_audit_error, 'symbol_audit_error_upper': report.symbol_audit_error_upper}


def _saved_report(layout: Layout, corpus_id: str) -> A.AuditReport | None:
    folder = layout.review_dir(corpus_id)
    path = folder / REPORT
    if not _present(path):
        return None
    raw = _read(path, layout)
    strict_json(raw)
    report = A.AuditReport.model_validate_json(raw)
    if report.corpus_id != corpus_id:
        raise _fail('audit report belongs to another corpus')
    return report


@_checked
def load_report(layout: Layout, corpus_id: str) -> A.AuditReport | None:
    report = _saved_report(layout, corpus_id)
    if report is None:
        return None
    folder = layout.review_dir(corpus_id)
    if any(_present(folder / name) for name in (KEY, QUEUE, LOG)) and report != _current_report(layout, corpus_id):
        raise _fail('audit report is stale; run audit-report after completing review')
    return report
