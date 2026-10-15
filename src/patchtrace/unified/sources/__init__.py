"""SPEC-31 source adapters (06 s1, s10): stored engine outputs -> tier-labelled `Atom`s. Pure readers of LOADED inputs.

An adapter never runs a tool and never opens the project database (the worker has no access to it): the owner
thread copies what the adapters need into `SourceInputs` (this module also holds the snapshot lines it writes,
`s0-match/1`). Adapters sort their output, so the order of the inputs never changes it (G-U4). In-process types
only; nothing here is persisted.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..addressing import AddressMap, parse_va_text
from ..contracts import Atom, SourceRef
from ..limits import DEFAULT_LIMITS, Budget, UnifiedError, UnifiedLimits

MAX_CALLS = 4096
MAX_FUNCTIONS_PER_SIDE = 1024
LINE_MAX_BYTES = 256 * 1024 * 1024
Category = Literal['modified', 'added', 'removed', 'unmatched', 'ambiguous', 'split', 'merged', 'unchanged']
Short = Annotated[str, Field(max_length=64)]
DEGRADING = frozenset({'raw-missing', 'raw-hash-mismatch', 'raw-unparsable', 'ladder-partial'})


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class SnapshotFunction(_Strict):
    """One Ghidriff function record as the unified engine needs it (bounded; `code` is dropped over L-29)."""
    name: str = Field(max_length=512)
    address: str | None = Field(default=None, max_length=40)
    code: str | None = None
    code_omitted: bool = False
    callees: tuple[Annotated[str, Field(max_length=512)], ...] = Field(default=(), max_length=MAX_CALLS)
    callers: tuple[Annotated[str, Field(max_length=512)], ...] = Field(default=(), max_length=MAX_CALLS)
    diff_types: tuple[Annotated[str, Field(max_length=32)], ...] = Field(default=(), max_length=16)
    ratio_text: str | None = Field(default=None, max_length=32)


class SnapshotMatch(_Strict):
    """Line type `s0-match/1` of `matches.jsonl`: one `FunctionMatch` of the current run."""
    contract: Literal['s0-match/1'] = 's0-match/1'
    id: str = Field(min_length=1, max_length=128)
    category: Category
    manual: bool
    match_types: tuple[Short, ...] = Field(default=(), max_length=16)
    older: tuple[SnapshotFunction, ...] = Field(default=(), max_length=MAX_FUNCTIONS_PER_SIDE)
    newer: tuple[SnapshotFunction, ...] = Field(default=(), max_length=MAX_FUNCTIONS_PER_SIDE)


@dataclass(frozen=True)
class RawGhidriff:
    """The preserved raw PDiff `matches.address_matches` table, or why it is not usable."""
    status: Literal['ok', 'missing', 'hash-mismatch', 'unparsable']
    address_matches: Mapping[str, Any] | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class GhidriffRun:
    run_id: str
    backend_version: str
    raw: RawGhidriff


@dataclass(frozen=True)
class LoadedSecondary:
    entry_id: str
    match_set: Any  # secondary.contracts.SecondaryMatchSet


@dataclass(frozen=True)
class SourceInputs:
    older_sha256: str
    newer_sha256: str
    run: GhidriffRun
    matches: tuple[SnapshotMatch, ...]
    secondary: tuple[LoadedSecondary, ...] = ()


@dataclass(frozen=True)
class NodeRecord:
    side: Literal['older', 'newer']
    rva: int
    name: str | None
    kind: Literal['function', 'thunk', 'import', 'external', 'unknown'] = 'function'


@dataclass(frozen=True)
class SourceGroup:
    """An N:M relation that is kept whole (never cross-multiplied). `decision` is what the row says:
    `ambiguous` for engine groups, `matched` for an analyst's split/merge (analyst control)."""
    kind: str
    source: str
    older: tuple[int, ...]
    newer: tuple[int, ...]
    decision: Literal['ambiguous', 'matched']
    reason: str
    atoms: tuple[Atom, ...]


@dataclass(frozen=True)
class Availability:
    state: Literal['ok', 'missing', 'stale']
    reason: str | None = None


@dataclass(frozen=True)
class AdapterOutput:
    atoms: tuple[Atom, ...] = ()
    groups: tuple[SourceGroup, ...] = ()
    nodes: tuple[NodeRecord, ...] = ()
    limitations: tuple[str, ...] = ()
    source_refs: tuple[SourceRef, ...] = ()


@runtime_checkable
class SourceAdapter(Protocol):
    """Adding a source = one adapter + one `SourceSpec` row (D-08)."""
    id: str

    def available(self, inputs: SourceInputs) -> Availability: ...

    def atoms(self, inputs: SourceInputs, addr: AddressMap, budget: Budget) -> AdapterOutput: ...


class Ledger:
    """Counts of skipped things, rendered as fixed-template limitations (`slug:count`, sorted)."""

    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._flags: set[str] = set()

    def count(self, slug: str, n: int = 1) -> None:
        if n:
            self._counts[slug] += n

    def flag(self, slug: str) -> None:
        self._flags.add(slug)

    def render(self) -> tuple[str, ...]:
        return tuple(sorted({*self._flags, *(f'{slug}:{n}' for slug, n in self._counts.items())}))


def clean_name(value: object, limit: int = 256) -> str | None:
    """Plain-text name for display (controls and bidi characters removed); empty -> None."""
    from ...secondary.evidence_view import sanitize_text
    text = sanitize_text(value, limit) if value is not None else ''
    return text or None


def native(*pairs: tuple[str, str | None]) -> tuple[tuple[str, str], ...]:
    """Upstream display text only (<= 4 labelled values, 120 characters each); no rule ever reads it."""
    from ...secondary.evidence_view import sanitize_text
    return tuple((label[:32], sanitize_text(text, 120)) for label, text in pairs if text)[:4]


def function_rva(function: SnapshotFunction, side: str, addr: AddressMap, basis: str, ledger: Ledger) -> int | None:
    """RVA of a snapshot function, or None (counted as `no-address` when the record has no usable address)."""
    value = parse_va_text(function.address)
    if value is None:
        ledger.count('no-address')
        return None
    return addr.to_rva(side, value, basis)


def atom_order(atom: Atom) -> tuple:
    return (-1 if atom.older_rva is None else atom.older_rva, -1 if atom.newer_rva is None else atom.newer_rva,
            atom.source, atom.step, atom.tier, atom.cardinality, atom.cls, atom.ref or '')


# --- snapshot lines (owner writes, worker reads) --------------------------------------------------------------------

def _function(record, limits: UnifiedLimits) -> SnapshotFunction:
    code = record.code
    omitted = False
    if code is not None and (len(code) > limits.l29_pseudo_chars or code.count('\n') + 1 > limits.l29_pseudo_lines):
        code, omitted = None, True
    metadata = record.metadata if isinstance(record.metadata, dict) else {}
    types = metadata.get('diff_types')
    types = tuple(t[:32] for t in types[:16] if isinstance(t, str)) if isinstance(types, list) else ()
    ratio = metadata.get('upstream_similarity')
    ratio_text = repr(ratio)[:32] if isinstance(ratio, int | float) and not isinstance(ratio, bool) else None
    return SnapshotFunction(
        name=str(record.name)[:512], address=None if record.address is None else str(record.address)[:40],
        code=code, code_omitted=omitted,
        callees=tuple(str(x)[:512] for x in record.callees[:MAX_CALLS]),
        callers=tuple(str(x)[:512] for x in record.callers[:MAX_CALLS]), diff_types=types, ratio_text=ratio_text)


def snapshot_from_project(project, run_id: str, limits: UnifiedLimits = DEFAULT_LIMITS, *,
                          manual_only: bool = False) -> tuple[SnapshotMatch, ...]:
    """The matches of one run in id order (owner thread; pure given the aggregate). `manual_only` keeps just the
    analyst's corrections, which is all the result identity needs (a cheap plan for `status`)."""
    if len(project.matches) > limits.l38_rows_per_result:
        raise UnifiedError('PT-UNIFIED-LIMIT', 'The project has more matches than L-38 allows', reason='rows-cap')
    out = [SnapshotMatch(id=m.id, category=m.category, manual=bool(m.manual),
                         match_types=tuple(str(t)[:64] for t in m.match_types[:16]),
                         older=tuple(_function(f, limits) for f in m.older[:MAX_FUNCTIONS_PER_SIDE]),
                         newer=tuple(_function(f, limits) for f in m.newer[:MAX_FUNCTIONS_PER_SIDE]))
           for m in project.matches if m.run_id == run_id and (m.manual or not manual_only)]
    return tuple(sorted(out, key=lambda s: s.id))


def write_snapshot(path: Path, matches: Iterable[SnapshotMatch]) -> tuple[str, int, int]:
    """JSON Lines, sorted keys; returns (sha256, bytes, lines)."""
    digest, size, count = hashlib.sha256(), 0, 0
    with open(path, 'wb') as handle:
        for item in matches:
            line = json.dumps(item.model_dump(mode='json'), sort_keys=True, separators=(',', ':'),
                              ensure_ascii=False, allow_nan=False).encode('utf-8') + b'\n'
            digest.update(line)
            handle.write(line)
            size += len(line)
            count += 1
    return digest.hexdigest(), size, count


def read_snapshot(path: Path, *, expected_sha256: str, expected_lines: int,
                  limits: UnifiedLimits = DEFAULT_LIMITS) -> tuple[SnapshotMatch, ...]:
    """Re-hash while reading; any mismatch is `PT-UNIFIED-INPUT` (the worker's input is untrusted)."""
    digest, out = hashlib.sha256(), []
    try:
        with open(path, 'rb') as handle:
            for line in handle:
                if len(line) > LINE_MAX_BYTES or len(out) >= limits.l38_rows_per_result:
                    raise UnifiedError('PT-UNIFIED-LIMIT', 'The match snapshot exceeds its limits', reason='rows-cap')
                digest.update(line)
                out.append(SnapshotMatch.model_validate_json(line))
    except (OSError, ValidationError, ValueError) as exc:
        if isinstance(exc, UnifiedError):
            raise
        raise UnifiedError('PT-UNIFIED-INPUT', 'The match snapshot is unreadable', reason='snapshot-invalid') from None
    if digest.hexdigest() != expected_sha256 or len(out) != expected_lines:
        raise UnifiedError('PT-UNIFIED-INPUT', 'The match snapshot does not match its request',
                           reason='snapshot-hash-mismatch')
    return tuple(out)
