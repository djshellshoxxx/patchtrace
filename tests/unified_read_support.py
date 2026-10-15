"""Builders for the SPEC-31 read-model tests: valid rows, facts and published result directories. Everything here is
made up in code (no engine, tool or Microsoft binary was run), so nothing built from it is live evidence."""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from patchtrace.unified import keys, store
from patchtrace.unified.contracts import (
    Atom,
    ChangeFacts,
    Contest,
    Delta,
    SideRef,
    SourceRef,
    Support,
    UnifiedMatch,
)
from patchtrace.unified.read_model import UnifiedLoadRequest

OLD, NEW = 'a' * 64, 'b' * 64
CHANNELS = ('C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8')
HOSTILE = ['<b>pwn</b>', '<img src=x onerror=1>', '&lt;', '{0}', '%s', '\x1b[31m', '\u202erev', 'file:///C:/x']
HOSTILE_IDS = ['bold', 'img', 'entity', 'brace', 'percent', 'escape', 'bidi', 'file']


def atom(source: str = 'ghidriff', step: str = 'SymbolsHash', tier: str = 'A', cls: str = 'E-NAME',
         older: int | None = 0x1000, newer: int | None = 0x1080, native: Iterable[tuple[str, str]] = (),
         cardinality: str = '1:1', ref: str | None = None) -> Atom:
    return Atom(source=source, step=step, tier=tier, cardinality=cardinality, cls=cls, older_rva=older,
                newer_rva=newer, native=tuple(native), ref=ref)


def make_row(older: Sequence[tuple[int, str | None]] = (), newer: Sequence[tuple[int, str | None]] = (), *,
             decision: str = 'matched', atoms: Sequence[Atom] | None = None, support: Sequence[Support] | None = None,
             contest: Contest | None = None, materiality: str = 'unknown', classes: Sequence[str] = (),
             flags: Sequence[str] = (), hints: Sequence[str] = (), match_id: str | None = None) -> UnifiedMatch:
    """`older` and `newer` are (rva, name) pairs sorted by rva. Without `atoms` one Ghidriff atom pairs the first
    functions of both sides and supports the row as component K1."""
    if atoms is None:
        atoms = [atom(older=older[0][0] if older else None, newer=newer[0][0] if newer else None)]
    if support is None:
        support = [Support(component='K1', tier=atoms[0].tier, atom_index=0)] if decision in (
            'matched', 'tentative') else []
    return UnifiedMatch(
        row_id=keys.row_id(OLD, NEW, [r for r, _ in older], [r for r, _ in newer]),
        older=tuple(SideRef(rva=r, name=n, kind='function') for r, n in older),
        newer=tuple(SideRef(rva=r, name=n, kind='function') for r, n in newer), decision=decision,
        support=tuple(support), contest=contest, atoms=tuple(atoms), ghidriff_match_id=match_id,
        materiality=materiality, change_classes=tuple(classes), flags=tuple(flags), hints=tuple(hints))


def contested_row(older_rva: int = 0x1000, newer_rva: int = 0x1080, name: str = 'contested_fn',
                  materiality: str = 'unknown') -> UnifiedMatch:
    """Ghidriff pairs the functions; BinDiff pairs the older one with another newer function (a strong contest)."""
    atoms = [atom(older=older_rva, newer=newer_rva), atom('bindiff', 'name hash matching', older=older_rva,
                                                          newer=newer_rva + 0x100, native=[('similarity', '0.97')])]
    return make_row([(older_rva, name)], [(newer_rva, name)], decision='contested', atoms=atoms,
                    contest=Contest(strength='strong', against=(1,)), materiality=materiality, hints=['uncontested:matched'])


def make_facts(row: UnifiedMatch, verdict: str, *, proof: str | None = None, second: str | None = None,
               deltas: Iterable[Delta] = (), eh: str = 'equal', **states: str) -> ChangeFacts:
    """Valid `ChangeFacts` for the verdict: the proof's own channel is `equal`, the second channel `differs`."""
    state = dict.fromkeys(CHANNELS, 'unavailable') | states
    needed = {'UNCH/1': 'C0', 'COS-ADDR/1': 'C1', 'COS-PSEUDO/1': 'C6'}.get(proof or '')
    if needed:
        state[needed] = 'equal'
    if second:
        state[second] = 'differs'
    return ChangeFacts(row_id=row.row_id, verdict=verdict, proof=proof, second_channel=second,
                       channels=tuple(state.items()), targets=(1, 0, 0) if proof else (0, 0, 0), eh=eh,
                       deltas=tuple(deltas))


def delta(cls: str = 'callee', *, older: int | None = 0x1000, newer: int | None = 0x1080, old: str | None = None,
          new: str | None = 'target_fn', channel: str = 'C4') -> Delta:
    return Delta(cls=cls, channel=channel, older_rva=older, newer_rva=newer, old=old, new=new)


def material(row_args: dict, *, cls: str = 'callee', old: str | None = None, new: str | None = 'target_fn',
             **extra) -> tuple[UnifiedMatch, ChangeFacts]:
    """A matched row with a material verdict (a semantic delta and an anchored second channel C6)."""
    row = make_row(materiality='material', classes=[cls], **row_args, **extra)
    o = row_args['older'][0][0] if row_args.get('older') else None
    n = row_args['newer'][0][0] if row_args.get('newer') else None
    return row, make_facts(row, 'material', second='C6', deltas=[delta(cls, older=o, newer=n, old=old, new=new)])


def publish(directory: Path, rows: Sequence[UnifiedMatch], facts: Sequence[ChangeFacts] = (), *,
            status: str = 'complete', limitations: Sequence[str] = ('ir-not-extracted',),
            sources: Sequence[SourceRef] = (), keep_order: bool = False) -> store.LoadedResult:
    """Write a verified result directory and return it the way the pointer row would: a current `LoadedResult`.
    Rows are written in the arbiter's order (min older rva, min newer rva, row id) unless `keep_order`."""
    directory.mkdir(parents=True, exist_ok=True)
    ordered = list(rows) if keep_order else sorted(
        rows, key=lambda r: (r.older[0].rva if r.older else 2**33, r.newer[0].rva if r.newer else 2**33, r.row_id))
    manifest = store.write_result(
        directory, older_sha256=OLD, newer_sha256=NEW, ghidriff_run_id='run-1', ghidriff_raw_sha256='c' * 64,
        ir_older=None, ir_newer=None, sources=sources, manual_digest='d' * 64, config_digest='e' * 64, status=status,
        limitations=limitations, rows=ordered, facts=facts)
    return store.LoadedResult('current', None, None, None, manifest, directory)


def source_ref(source: str, version: str = '1', entry: str | None = None) -> SourceRef:
    return SourceRef(source=source, entry_id=entry or f'entry-{source}', file_sha256='f' * 64, version=version)


def request(loaded: store.LoadedResult | None, **kw) -> UnifiedLoadRequest:
    return UnifiedLoadRequest('project-1', 'run-1', 7, loaded, **kw)
