"""Synthetic ProgramIR builder for SPEC-31 tests (hand-built IR tables, 04 s9; no Ghidra, no real binary).

Two layers, both implementing the ladder's `IrSide` port (`patchtrace.unified.ladder.ports`):

* `SyntheticIr` - small, readable, tag-addressed functions for unit tests. A body is a list of `Insn` records;
  the six key levels of 02 s3 are derived from it exactly the way the real ingest derives them from masks:
  `h0` all fields, `h1` address fields masked, `h2` immediates masked too, `h3` register names masked too,
  `hm` ordered mnemonics, `hms` sorted mnemonics (so equal `h0` implies equal `h1` ... `hms`). Any key can be
  overridden to build hand-made collisions. CFG shape gives `n_bb`, `n_edge`, `md_td`, `md_bu`.
* `generate_pair` - a fast columnar generator for 10k/60k-function performance tests (G-U5) with a power-law
  call graph, address-shifted, edited, duplicate, added and removed functions and a ground-truth map.

Everything here is deterministic (no `hash()`, no set iteration order, no wall clock). These are SYNTHETIC
fixtures: they prove the algorithms, never live compatibility with Ghidra or BinDiff.

`md_index` below is a TEST-SUPPORT stand-in for BinDiff's flow-graph MD index so that P10 keys are
isomorphism-invariant like the real ones. Portions derived from google/bindiff v8 (Apache-2.0), Copyright
2011-2023 Google LLC; re-expressed in Python and modified for PatchTrace (see third_party/notices). The
top-down vector for the diamond CFG is checked (0.277559753195558); the bottom-up convention is NOT
validated against BinDiff - slice S1 owns the real `ir/mdindex.py` and its parity tests.
"""
from __future__ import annotations

import math
import random
from collections import deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from hashlib import blake2b, sha256
from typing import NamedTuple

from patchtrace.unified.ladder.ports import (
    KIND_EXTERNAL,
    KIND_NORMAL,
    KIND_THUNK,
    BlockRow,
    CallRow,
    CstRow,
    FnRow,
    RowsIrSide,
    StrRow,
)

SIGNED64 = (1 << 63) - 1
_SQ = (math.sqrt(2), math.sqrt(3), math.sqrt(5), math.sqrt(7), math.sqrt(11), math.sqrt(13))
MNEMONICS = ('mov', 'lea', 'add', 'sub', 'xor', 'cmp', 'test', 'push', 'pop', 'call', 'jmp', 'jne', 'je', 'ret',
             'and', 'or', 'shl', 'shr', 'imul', 'movzx')
REGISTERS = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9')
INSN_BYTES = 4  # surrogate encoded length of one instruction (size = 4 * n_insn)


def h64(data: bytes) -> int:
    """64-bit blake2b as a signed integer, like the IR key columns (02 s3)."""
    return int.from_bytes(blake2b(data, digest_size=8).digest(), 'big', signed=True)


def sha_hex(text: str) -> str:
    return sha256(text.encode('utf-8')).hexdigest()


# --- instruction bodies and key levels ---------------------------------------------------------------------------

class Insn(NamedTuple):
    mnem: str
    regs: tuple[str, ...] = ()
    imm: int | None = None
    addr: int | None = None   # value of the located address field (rel32/disp32) of an address operand


def make_body(seed: int, n_insn: int) -> tuple[Insn, ...]:
    """A deterministic body that differs for every seed (different seeds collide only with negligible chance)."""
    rng = random.Random(f'body:{seed}')
    out = []
    for _ in range(n_insn):
        mnem = rng.choice(MNEMONICS)
        regs = tuple(rng.choice(REGISTERS) for _ in range(rng.randint(0, 2)))
        imm = rng.randint(0, 0xFFFF) if rng.random() < 0.4 else None
        addr = rng.randint(0x100, 0xFFFFF) if mnem in ('call', 'jmp', 'lea', 'jne', 'je') else None
        out.append(Insn(mnem, regs, imm, addr))
    return tuple(out)


def _enc(i: Insn, *, addr: bool, imm: bool, regs: bool) -> str:
    reg_text = '+'.join(i.regs) if regs else 'R' * len(i.regs)
    imm_text = i.imm if imm else ('I' if i.imm is not None else '-')
    addr_text = i.addr if addr else ('A' if i.addr is not None else '-')
    return f'{i.mnem},{reg_text},{imm_text},{addr_text}'


def body_keys(body: Sequence[Insn]) -> dict[str, int]:
    """The six key levels (nested: equal h0 => equal h1 => h2 => h3 => hm => hms)."""
    def join(parts):
        return '|'.join(parts).encode('utf-8')
    return {
        'h0': h64(join(_enc(i, addr=True, imm=True, regs=True) for i in body)),
        'h1': h64(b'1:' + join(_enc(i, addr=False, imm=True, regs=True) for i in body)),
        'h2': h64(b'2:' + join(_enc(i, addr=False, imm=False, regs=True) for i in body)),
        'h3': h64(b'3:' + join(_enc(i, addr=False, imm=False, regs=False) for i in body)),
        'hm': h64(b'm:' + join(i.mnem for i in body)),
        'hms': h64(b's:' + join(sorted(i.mnem for i in body))),
    }


def block_h1(insns: Sequence[Insn]) -> int:
    return h64(b'bb:' + '|'.join(_enc(i, addr=False, imm=True, regs=True) for i in insns).encode('utf-8'))


# --- MD index (test-support stand-in, see module docstring) -----------------------------------------------------------

def md_index(n_vertices: int, edges: Sequence[tuple[int, int]], *, bottom_up: bool = False) -> float:
    if bottom_up:
        edges = [(t, s) for s, t in edges]
    indeg = [0] * n_vertices
    outdeg = [0] * n_vertices
    adj: list[list[int]] = [[] for _ in range(n_vertices)]
    for s, t in edges:
        outdeg[s] += 1
        indeg[t] += 1
        adj[s].append(t)
    level = [0] * n_vertices
    seen = [False] * n_vertices
    queue = deque(v for v in range(n_vertices) if indeg[v] == 0)
    for v in queue:
        seen[v] = True
    while queue:
        v = queue.popleft()
        for w in adj[v]:
            if not seen[w]:
                seen[w] = True
                level[w] = level[v] + 1
                queue.append(w)
    terms = sorted(1.0 / (_SQ[0] * indeg[s] + _SQ[1] * outdeg[s] + _SQ[2] * indeg[t] + _SQ[3] * outdeg[t]
                          + _SQ[4] * level[s] + _SQ[5] * level[t]) for s, t in edges)
    return plain_sum(terms)


def plain_sum(terms: Sequence[float]) -> float:
    """Left-to-right float accumulation exactly like the C++ loop: Python 3.12+ `sum()` of floats is compensated
    and would give other last digits (04 s2, C-16)."""
    total = 0.0
    for term in terms:
        total += term
    return total


def md_key(value: float) -> int:
    return round(value * 10 ** 12)


def cfg_keys(cfg: Sequence[Sequence[int]]) -> dict[str, int | None]:
    edges = [(s, t) for s, succ in enumerate(cfg) for t in succ]
    if not edges:
        return {'md_td': None, 'md_bu': None}
    n = len(cfg)
    return {'md_td': md_key(md_index(n, edges)), 'md_bu': md_key(md_index(n, edges, bottom_up=True))}


def linear_cfg(n_bb: int) -> tuple[tuple[int, ...], ...]:
    return tuple((i + 1,) if i + 1 < n_bb else () for i in range(n_bb))


def seed_cfg(seed: int) -> tuple[tuple[int, ...], ...]:
    """A deterministic forward-edge CFG per seed (4..14 blocks): different seeds get different md keys with high
    probability, equal seeds the same ones, so unrelated synthetic functions do not collide on P10 by accident."""
    rng = random.Random(f'cfg:{seed}')
    n_bb = rng.randint(4, 14)
    succ: list[list[int]] = [[] for _ in range(n_bb)]
    for i in range(n_bb - 1):
        succ[i].append(i + 1)
        if rng.random() < 0.45 and i + 2 < n_bb:
            succ[i].append(rng.randint(i + 2, n_bb - 1))
    return tuple(tuple(s) for s in succ)


def diamond_chain_cfg(n_bb: int) -> tuple[tuple[int, ...], ...]:
    """Branchy CFG family (more blocks => more diamonds) so different n_bb give different md keys."""
    succ: list[list[int]] = [[] for _ in range(n_bb)]
    for i in range(n_bb - 1):
        succ[i].append(i + 1)
        if i + 2 < n_bb and i % 2 == 0:
            succ[i].append(i + 2)
    return tuple(tuple(s) for s in succ)


# --- hand-built functions ---------------------------------------------------------------------------------------------

@dataclass
class FnSpec:
    """One synthetic function. `calls` entries: a tag (str) of a function of the SAME IR, `'imp:<key>'` for an
    import called by key, `None` for an indirect call, or `('jump', <target>)` for a tail jump."""
    tag: str
    seed: int | None = None
    n_insn: int = 12
    body: tuple[Insn, ...] | None = None
    n_bb: int | None = None                 # None: a CFG derived from the seed (see `seed_cfg`)
    cfg: tuple[tuple[int, ...], ...] | None = None
    blocks: tuple[tuple[Insn, ...], ...] | None = None    # explicit basic blocks: the body is their concatenation
    kind: str = KIND_NORMAL
    name: str | None = None
    name_src: str | None = None
    aliases: tuple[str, ...] = ()
    import_key: str | None = None
    thunk_target: str | None = None
    calls: tuple = ()
    strings: tuple[str, ...] = ()
    consts: tuple[int, ...] = ()
    pdata: bool = True
    oversize: bool = False
    rva: int | None = None
    keys: dict = field(default_factory=dict)   # key overrides, e.g. {'h2': 7, 'md_td': None, 'size': 99}

    def resolved_seed(self) -> int:
        return self.seed if self.seed is not None else int.from_bytes(sha256(self.tag.encode()).digest()[:4], 'big')

    def resolved_cfg(self) -> tuple[tuple[int, ...], ...]:
        if self.cfg is not None:
            return self.cfg
        if self.blocks is not None:
            return diamond_chain_cfg(len(self.blocks))
        return diamond_chain_cfg(self.n_bb) if self.n_bb is not None else seed_cfg(self.resolved_seed())

    def resolved_body(self) -> tuple[Insn, ...]:
        if self.body is not None:
            return self.body
        if self.blocks is not None:
            return tuple(i for block in self.blocks for i in block)
        return make_body(self.resolved_seed(), self.n_insn)


class SyntheticIr:
    """A tag-addressed synthetic side implementing `IrSide`. `row_order` (int seed) permutes the ORDER of the
    emitted rows of every table (the ladder must not care)."""

    def __init__(self, *, row_order: int | None = None):
        self.specs: list[FnSpec] = []
        self.row_order = row_order
        self._layout: tuple[dict[str, int], list[FnSpec]] | None = None

    def add(self, tag: str, **fields) -> FnSpec:
        if any(s.tag == tag for s in self.specs):
            raise ValueError(f'duplicate tag {tag!r}')
        spec = FnSpec(tag=tag, **fields)
        self.specs.append(spec)
        self._layout = None
        return spec

    def copy(self, *, row_order: int | None = None) -> SyntheticIr:
        """Deep-enough copy (specs are copied, call targets stay tags)."""
        other = SyntheticIr(row_order=self.row_order if row_order is None else row_order)
        for s in self.specs:
            other.specs.append(FnSpec(**{**s.__dict__, 'keys': dict(s.keys)}))
        return other

    # layout ----------------------------------------------------------------------------------------------------------
    def layout(self) -> tuple[dict[str, int], list[FnSpec]]:
        if self._layout is None:
            auto = 0
            used: set[int] = set()
            for s in self.specs:
                if s.rva is not None:
                    used.add(s.rva)
            placed = []
            ext = 0
            for s in self.specs:
                if s.rva is not None:
                    rva = s.rva
                elif s.kind == KIND_EXTERNAL:
                    ext += 1
                    rva = 0x10 + ext
                else:
                    auto += 1
                    rva = 0x1000 + 0x40 * auto
                while rva in used and s.rva is None:
                    rva += 1
                used.add(rva)
                placed.append((rva, s))
            placed.sort(key=lambda item: item[0])
            if len({rva for rva, _ in placed}) != len(placed):
                raise ValueError('duplicate rva in synthetic IR')
            ordered = [s for _, s in placed]
            self._rvas = {s.tag: rva for rva, s in placed}
            self._layout = ({s.tag: fid for fid, s in enumerate(ordered)}, ordered)
        return self._layout

    def fid(self, tag: str) -> int:
        return self.layout()[0][tag]

    def tag_of(self, fid: int) -> str:
        return self.layout()[1][fid].tag

    def rva_of(self, tag: str) -> int:
        self.layout()
        return self._rvas[tag]

    # row emission ---------------------------------------------------------------------------------------------------
    def _maybe_shuffle(self, rows: list) -> list:
        if self.row_order is not None:
            random.Random(self.row_order).shuffle(rows)
        return rows

    def _spec_keys(self, s: FnSpec) -> dict:
        out: dict = {'size': 0, 'n_insn': 0, 'n_bb': 0, 'n_edge': 0, 'h0': None, 'h1': None, 'h2': None, 'h3': None,
                     'hm': None, 'hms': None, 'md_td': None, 'md_bu': None}
        if s.kind == KIND_NORMAL and not s.oversize:
            body = s.resolved_body()
            cfg = s.resolved_cfg()
            out.update(body_keys(body))
            out.update(cfg_keys(cfg))
            out.update(size=INSN_BYTES * len(body), n_insn=len(body), n_bb=len(cfg),
                       n_edge=sum(len(x) for x in cfg))
        elif s.kind == KIND_THUNK:
            out.update(size=5, n_insn=1, n_bb=1)
        out.update(s.keys)
        return out

    def function_rows(self) -> Iterator[FnRow]:
        index, ordered = self.layout()
        rows = []
        for fid, s in enumerate(ordered):
            k = self._spec_keys(s)
            name_src = s.name_src or ('USER_DEFINED' if s.name else 'DEFAULT')
            target = index[s.thunk_target] if s.thunk_target is not None else None
            rows.append(FnRow(
                fid=fid, rva=self._rvas[s.tag], size=k['size'], kind=s.kind, name=s.name, name_src=name_src,
                aliases=tuple(s.aliases), import_key=s.import_key, thunk_target=target, n_bb=k['n_bb'],
                n_edge=k['n_edge'], n_insn=k['n_insn'], h0=k['h0'], h1=k['h1'], h2=k['h2'], h3=k['h3'], hm=k['hm'],
                hms=k['hms'], md_td=k['md_td'], md_bu=k['md_bu'], pdata_confirmed=s.pdata, oversize=s.oversize))
        return iter(self._maybe_shuffle(rows))

    def call_rows(self) -> Iterator[CallRow]:
        index, ordered = self.layout()
        rows = []
        for fid, s in enumerate(ordered):
            site = self._rvas[s.tag]
            for call in s.calls:
                site += 5
                jump = False
                if isinstance(call, tuple) and call and call[0] == 'jump':
                    jump, call = True, call[1]
                if call is None:
                    rows.append(CallRow(fid, site, None, None, jump))
                elif isinstance(call, str) and call.startswith('imp:'):
                    rows.append(CallRow(fid, site, None, call[4:], jump))
                else:
                    rows.append(CallRow(fid, site, index[call], None, jump))
        return iter(self._maybe_shuffle(rows))

    def string_rows(self) -> Iterator[StrRow]:
        _, ordered = self.layout()
        rows = [StrRow(fid, sha_hex(text), len(text)) for fid, s in enumerate(ordered) for text in s.strings]
        return iter(self._maybe_shuffle(rows))

    def constant_rows(self) -> Iterator[CstRow]:
        _, ordered = self.layout()
        rows = [CstRow(fid, value) for fid, s in enumerate(ordered) for value in s.consts]
        return iter(self._maybe_shuffle(rows))

    def block_rows(self) -> Iterator[BlockRow]:
        _, ordered = self.layout()
        rows = []
        for fid, s in enumerate(ordered):
            if s.kind != KIND_NORMAL or s.oversize:
                continue
            if s.blocks is not None:
                for ord_, chunk in enumerate(s.blocks):
                    rows.append(BlockRow(fid, ord_, block_h1(chunk) if chunk else None, len(chunk)))
                continue
            body = s.resolved_body()
            n_bb = max(1, len(s.resolved_cfg()))
            per = max(1, len(body) // n_bb)
            for ord_ in range(n_bb):
                chunk = body[ord_ * per:(ord_ + 1) * per] if ord_ + 1 < n_bb else body[ord_ * per:]
                rows.append(BlockRow(fid, ord_, block_h1(chunk) if chunk else None, len(chunk)))
        return iter(self._maybe_shuffle(rows))


# --- ladder-result helpers ---------------------------------------------------------------------------------------------

def pairs_by_tag(corr, older: SyntheticIr, newer: SyntheticIr) -> dict[tuple[str, str], object]:
    return {(older.tag_of(p.older_fid), newer.tag_of(p.newer_fid)): p for p in corr.pairs}


def tag_pairs(corr, older: SyntheticIr, newer: SyntheticIr) -> set[tuple[str, str]]:
    return set(pairs_by_tag(corr, older, newer))


def mirror(corr_pairs) -> set[tuple]:
    """Comparable (older_fid, newer_fid, pass, tier, round, votes) tuples without `seq`."""
    return {(p.older_fid, p.newer_fid, p.pass_id, p.tier, p.round, p.votes) for p in corr_pairs}


def mirrored(corr_pairs) -> set[tuple]:
    return {(p.newer_fid, p.older_fid, p.pass_id, p.tier, p.round, p.votes) for p in corr_pairs}


def assert_partition(corr, n_older: int, n_newer: int):
    """Invariant I1: every function of each side is in exactly one of pair / group / leftover. For containment groups
    (`inlined-into`, `outlined-from`) only the contained (otherwise unmatched) side is exclusive."""
    where_a: dict[int, str] = {}
    where_b: dict[int, str] = {}

    def put(table, fid, label):
        assert fid not in table, f'function {fid} placed twice: {table[fid]} and {label}'
        table[fid] = label
    for p in corr.pairs:
        put(where_a, p.older_fid, 'pair')
        put(where_b, p.newer_fid, 'pair')
    for g in corr.groups:
        if g.kind == 'inlined-into':
            put(where_a, g.older_fids[0], g.kind)
        elif g.kind == 'outlined-from':
            put(where_b, g.newer_fids[0], g.kind)
        else:
            for f in g.older_fids:
                put(where_a, f, g.kind)
            for f in g.newer_fids:
                put(where_b, f, g.kind)
    for item in corr.older_only:
        put(where_a, item.fid, 'leftover')
    for item in corr.newer_only:
        put(where_b, item.fid, 'leftover')
    if corr.status == 'complete':
        assert sorted(where_a) == list(range(n_older)) and sorted(where_b) == list(range(n_newer))
    return where_a, where_b


def random_world(seed: int, n: int, *, row_order_old: int | None = None,
                 row_order_new: int | None = None) -> tuple[SyntheticIr, SyntheticIr]:
    """A small random older/newer pair with duplicates, names, imports, thunks, strings, constants, a call graph,
    unchanged / address-shifted / edited / removed / added functions (for property tests)."""
    rng = random.Random(f'world:{seed}:{n}')
    pool = max(2, n // 3)
    descs = []
    for i in range(n):
        roll = rng.random()
        d: dict = {'tag': f'f{i}'}
        if roll < 0.08:
            d.update(kind=KIND_EXTERNAL, import_key=f'lib!api{rng.randrange(max(3, n // 8))}')
        elif roll < 0.15:
            d.update(kind=KIND_THUNK, thunk_target=f'f{rng.randrange(n)}')
        else:
            seed_i = rng.randrange(pool) if rng.random() < 0.3 else 1000 + i
            d.update(seed=seed_i, n_insn=(4, 12, 12, 20)[seed_i % 4],          # same seed => identical body
                     strings=tuple(f'str-{rng.randrange(n)}-xyz' for _ in range(rng.randrange(3))),
                     consts=tuple(0x2000 + rng.randrange(n) * 8 for _ in range(rng.randrange(3))),
                     calls=tuple(f'f{rng.randrange(n)}' for _ in range(rng.randrange(4))))
            if rng.random() < 0.3:
                d['name'] = f'Name{rng.randrange(n)}'
                if rng.random() < 0.3:
                    d['aliases'] = (f'Alias{rng.randrange(n // 4 + 1)}',)
        descs.append(d)
    fate = [rng.random() for _ in range(n)]
    by_tag = {d['tag']: d for d in descs}

    def valid(alive: set[str]) -> set[str]:
        out = set()
        for tag in alive:
            d = by_tag.get(tag)
            if d is None or d.get('kind') != KIND_THUNK:
                out.add(tag)
            elif d['thunk_target'] in alive and by_tag[d['thunk_target']].get('kind') != KIND_THUNK:
                out.add(tag)                        # thunks stay one level deep and need their target
        return out

    added = {f'new{j}' for j in range(max(1, n // 10))}
    old_alive = valid({d['tag'] for d in descs})
    new_alive = valid({d['tag'] for d, f in zip(descs, fate, strict=True) if f >= 0.15} | added)
    older, newer = SyntheticIr(row_order=row_order_old), SyntheticIr(row_order=row_order_new)

    def add(ir, d, alive, mutate):
        d = dict(d)
        d['calls'] = tuple(c for c in d.get('calls', ()) if c in alive)
        if mutate == 'shift' and 'seed' in d:
            d['body'] = tuple(i._replace(addr=(i.addr or 0) + 64) if i.addr is not None else i
                              for i in make_body(d.pop('seed'), d.pop('n_insn')))
        elif mutate == 'edit' and 'seed' in d:
            d['seed'] = d['seed'] + 50_000
            d['n_insn'] = d['n_insn'] + rng.choice([0, 0, 30])
        ir.add(d.pop('tag'), **d)

    for d in descs:
        if d['tag'] in old_alive:
            add(older, d, old_alive, None)
    for d, f in zip(descs, fate, strict=True):
        if d['tag'] in new_alive:
            add(newer, d, new_alive, 'shift' if f < 0.35 else 'edit' if f < 0.5 else None)
    for j in range(max(1, n // 10)):
        target = f'f{rng.randrange(n)}'
        newer.add(f'new{j}', seed=90_000 + j, n_insn=12, calls=(target,) if target in new_alive else ())
    return older, newer


# --- twin worlds: an older and a newer side generated together -------------------------------------------------------

def twin(tags: Sequence[str], **fields) -> tuple[SyntheticIr, SyntheticIr]:
    """Two sides with the same tags and bodies (seed = tag), so every function matches itself by P04."""
    older, newer = SyntheticIr(), SyntheticIr()
    for tag in tags:
        older.add(tag, **dict(fields))
        newer.add(tag, **dict(fields))
    return older, newer


# --- fast generator for performance tests (G-U5) -------------------------------------------------------------------

GeneratedSide = RowsIrSide                      # the generator fills the same row container an S1 adapter would


@dataclass
class GeneratedPair:
    older: GeneratedSide
    newer: GeneratedSide
    truth: dict[int, int]            # older RVA -> newer RVA of the true successor
    kinds: dict[int, str]            # older RVA -> mutation class ('same', 'shift', 'const', 'body', 'struct', 'removed')
    stats: dict[str, int]


def _mix(x: int, salt: int) -> int:
    v = (x ^ (salt * 0x9E3779B97F4A7C15)) & 0xFFFFFFFFFFFFFFFF
    v = (v * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    v ^= v >> 31
    v = (v * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    v ^= v >> 29
    return v - (1 << 64) if v >= 1 << 63 else v


def generate_pair(n: int, *, seed: int = 1, changed: float = 0.03, shifted: float = 0.35, duplicates: float = 0.005,
                  named: float = 0.2, added: float = 0.01, removed: float = 0.01, mean_calls: int = 5,
                  hubs: int = 12) -> GeneratedPair:
    """`n` older functions and a plausible newer build of them (see module docstring). Deterministic per seed."""
    rng = random.Random(f'gen:{seed}:{n}')
    # ---- base population -------------------------------------------------------------------------------------------
    base = []                                    # per function: dict of columns
    dup_pool: list[int] = []
    for i in range(n):
        if dup_pool and rng.random() < duplicates:
            src = base[rng.choice(dup_pool)]
            seed_i = src['seed']
        else:
            seed_i = rng.getrandbits(62)
            if rng.random() < duplicates * 2:
                dup_pool.append(i)
        n_insn = 6 + int(rng.expovariate(1 / 30.0))
        n_bb = 1 + (seed_i % 24)
        base.append({'seed': seed_i, 'n_insn': min(n_insn, 4000), 'n_bb': n_bb, 'n_edge': n_bb + (seed_i >> 5) % 6,
                     'name': f'fn_{i:06d}' if rng.random() < named else None})
    # ---- call graph (preferential attachment) --------------------------------------------------------------------------
    pool = list(range(min(hubs, n))) * 8
    callees: list[list[int]] = [[] for _ in range(n)]
    for i in range(n):
        k = min(int(rng.expovariate(1 / mean_calls)), 24)
        for _ in range(k):
            j = rng.choice(pool) if pool and rng.random() < 0.6 else rng.randrange(n)
            callees[i].append(j)
            pool.append(j)
    # ---- mutation classes --------------------------------------------------------------------------------------------------
    kinds: dict[int, str] = {}
    keep: list[int] = []
    for i in range(n):
        r = rng.random()
        if r < removed:
            kinds[i] = 'removed'
            continue
        keep.append(i)
        r = rng.random()
        if r < changed * 0.5:
            kinds[i] = 'body'
        elif r < changed * 0.8:
            kinds[i] = 'const'
        elif r < changed:
            kinds[i] = 'struct'
        elif r < changed + shifted:
            kinds[i] = 'shift'
        else:
            kinds[i] = 'same'

    def fn_row(fid, rva, b, kind, side):
        s = b['seed']
        h0, h1, h2, h3, hm, hms = (_mix(s, k) for k in range(6))
        md_td, md_bu = _mix(s, 11), _mix(s, 12)
        n_bb, n_edge = b['n_bb'], b['n_edge']
        n_insn = b['n_insn']
        if side == 'new':
            if kind == 'shift':
                h0 = _mix(s, 100)
            elif kind == 'const':
                h0, h1 = _mix(s, 100), _mix(s, 101)
            elif kind == 'body':
                h0, h1, h2, h3, hm = (_mix(s, 100 + k) for k in range(5))
                n_insn += 2
            elif kind == 'struct':
                h0, h1, h2, h3, hm, hms = (_mix(s, 100 + k) for k in range(6))
                md_td, md_bu, n_bb, n_edge = _mix(s, 111), _mix(s, 112), n_bb + 1, n_edge + 2
                n_insn += 9
        return FnRow(fid, rva, n_insn * INSN_BYTES, KIND_NORMAL, b['name'],
                     'USER_DEFINED' if b['name'] else 'DEFAULT', (), None, None, n_bb, n_edge, n_insn, h0, h1, h2, h3,
                     hm, hms, md_td if n_bb >= 5 else None, md_bu if n_bb >= 5 else None, True, False)

    # ---- older side --------------------------------------------------------------------------------------------------------
    older_rva = [0x1000 + 0x40 * i for i in range(n)]
    o_fns = [fn_row(i, older_rva[i], base[i], kinds[i], 'old') for i in range(n)]
    o_calls = [CallRow(i, older_rva[i] + 5 * (k + 1), j, None, False) for i in range(n) for k, j in enumerate(callees[i])]
    # ---- newer side ----------------------------------------------------------------------------------------------------------
    n_added = int(n * added)
    order = [('o', i) for i in keep] + [('n', j) for j in range(n_added)]
    # local reorder: swap a fraction of neighbours so fid ranks differ between the builds
    for pos in range(0, len(order) - 1, 17):
        order[pos], order[pos + 1] = order[pos + 1], order[pos]
    new_rva_of: dict[int, int] = {}
    new_specs = []
    for fid, (tag, idx) in enumerate(order):
        rva = 0x2000 + 0x48 * fid
        if tag == 'o':
            new_rva_of[idx] = fid
            new_specs.append((fid, rva, base[idx], kinds[idx], idx))
        else:
            sb = {'seed': rng.getrandbits(62), 'n_insn': 8 + rng.randrange(60), 'n_bb': 1 + rng.randrange(20),
                  'n_edge': 3 + rng.randrange(20), 'name': None}
            new_specs.append((fid, rva, sb, 'same', None))
    n_fns = [fn_row(fid, rva, b, kind, 'new') for fid, rva, b, kind, _ in new_specs]
    n_calls = []
    for fid, rva, _b, kind, idx in new_specs:
        if idx is None:
            for k in range(rng.randrange(6)):
                n_calls.append(CallRow(fid, rva + 5 * (k + 1), rng.randrange(len(new_specs)), None, False))
            continue
        targets = [new_rva_of[j] for j in callees[idx] if j in new_rva_of]
        if kind == 'struct' and targets:
            targets[0] = rng.randrange(len(new_specs))
        for k, j in enumerate(targets):
            n_calls.append(CallRow(fid, rva + 5 * (k + 1), j, None, False))
    # ---- strings, constants, blocks (sparse; enough to exercise P12/P14 and the inline hints) ---------------------------
    def extras(fns, side_specs, newer_side):
        strs, csts, blks = [], [], []
        for row in fns:
            if row.n_insn >= 12 and (row.h1 or 0) % 5 == 0:
                token = row.h1 if not newer_side else row.h1
                strs.append(StrRow(row.fid, sha_hex(f's:{token}'), 12))
                csts.append(CstRow(row.fid, 0x2000 + (token & 0xFFFF) * 3))
            if row.n_insn >= 40:
                for ord_ in range(2):
                    blks.append(BlockRow(row.fid, ord_, _mix(row.h1 or 0, 500 + ord_), 6))
        return strs, csts, blks
    o_strs, o_csts, o_blks = extras(o_fns, None, False)
    n_strs, n_csts, n_blks = extras(n_fns, None, True)
    truth = {older_rva[i]: 0x2000 + 0x48 * new_rva_of[i] for i in keep}
    stat = {'functions': n, 'newer_functions': len(n_fns), 'edges': len(o_calls),
            **{f'kind_{k}': sum(1 for v in kinds.values() if v == k) for k in ('same', 'shift', 'const', 'body', 'struct',
                                                                               'removed')}}
    return GeneratedPair(RowsIrSide(o_fns, o_calls, o_strs, o_csts, o_blks),
                         RowsIrSide(n_fns, n_calls, n_strs, n_csts, n_blks), truth,
                         {older_rva[i]: kinds[i] for i in range(n)}, stat)
