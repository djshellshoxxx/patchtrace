"""Columnar snapshot of one IR side (the ladder's anti-corruption layer over the `IrSide` port).

`SideData.from_ir` reads the five port tables exactly once and builds plain Python columns indexed by `fid`
(no per-instruction objects, R04 s7), the call graph (CSR-like tuples), hub flags and the filtered per-function
string/constant/block sets. Everything is deterministic: ascending fids, sorted tuples, no set iteration.
The ladder never touches the port again, so a slow or SQLite-backed reader costs one pass.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from ..limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits
from .ports import KIND_EXTERNAL, KIND_NORMAL, KIND_THUNK, NAME_SOURCES, IrSide

K_NORMAL, K_THUNK, K_EXTERNAL = 0, 1, 2
_KIND_CODE = {KIND_NORMAL: K_NORMAL, KIND_THUNK: K_THUNK, KIND_EXTERNAL: K_EXTERNAL}
_TRUSTED_NAME_SOURCES = ('IMPORTED', 'USER_DEFINED')
_AUTO_NAME = re.compile(r'^(?:thunk_)?(?:FUN|LAB|DAT|PTR|UNK|SUB|sub|nullsub|loc|off)_[0-9A-Fa-f]+$')
_MASK64 = (1 << 64) - 1
MAX_ALIASES = 16


def _ir_error(reason: str) -> UnifiedError:
    return UnifiedError('PT-UNIFIED-IR', 'ladder input rejected: IR rows are inconsistent', reason=reason)


def contiguous_ones(value: int) -> bool:
    """True for 0xFF00, 0xFFFF, 0x1000 ... (one run of set bits, a single bit included)."""
    return value > 0 and ((value + (value & -value)) & value) == 0


def usable_constant(value: int, limits: UnifiedLimits = DEFAULT_LIMITS) -> bool:
    """L-15 key filter (Diaphora idea, own code): abs >= 0x1000, not a bit mask, not a single bit."""
    magnitude = abs(value)
    return (magnitude >= limits.l15_const_min_abs and not contiguous_ones(magnitude)
            and not contiguous_ones(value & _MASK64))


def usable_name(name: str | None) -> bool:
    return bool(name) and len(name) >= 3 and not _AUTO_NAME.match(name)


class SideData:
    """Read-only snapshot. Attribute names mirror the columns of `program-ir/1` (02 s3)."""

    def __init__(self) -> None:
        self.n = 0
        self.cache: dict[str, Any] = {}

    @classmethod
    def from_ir(cls, ir: IrSide, limits: UnifiedLimits = DEFAULT_LIMITS, *,
                exports: Mapping[int, str] | None = None) -> SideData:
        rows = list(ir.function_rows())
        return cls._build(rows, ir, limits, exports)

    @classmethod
    def _build(cls, rows: list, ir: IrSide, limits: UnifiedLimits, exports: Mapping[int, str] | None) -> SideData:
        n = len(rows)
        if n > limits.l01_functions_per_side:
            raise UnifiedError('PT-UNIFIED-LIMIT', 'ladder input exceeds the function cap', reason='functions-cap')
        self = cls()
        self.n = n
        self.rva = [0] * n
        self.size = [0] * n
        self.n_insn = [0] * n
        self.n_bb = [0] * n
        self.n_edge = [0] * n
        self.kind = [K_NORMAL] * n
        self.name: list[str | None] = [None] * n
        self.names: list[tuple[str, ...]] = [()] * n
        self.import_key: list[str | None] = [None] * n
        self.thunk_target = [-1] * n
        self.h0: list[int | None] = [None] * n
        self.h1: list[int | None] = [None] * n
        self.h2: list[int | None] = [None] * n
        self.h3: list[int | None] = [None] * n
        self.hm: list[int | None] = [None] * n
        self.hms: list[int | None] = [None] * n
        self.md_td: list[int | None] = [None] * n
        self.md_bu: list[int | None] = [None] * n
        self.pdata = [False] * n
        self.oversize = [False] * n
        seen = bytearray(n)
        for r in rows:
            fid = r.fid
            if type(fid) is not int or not 0 <= fid < n or seen[fid]:
                raise _ir_error('fid-range')
            seen[fid] = 1
            code = _KIND_CODE.get(r.kind)
            if code is None or r.name_src not in NAME_SOURCES:
                raise _ir_error('fn-enum')
            if len(r.aliases) > MAX_ALIASES:
                raise _ir_error('alias-cap')
            self.rva[fid] = r.rva
            self.size[fid] = r.size
            self.n_insn[fid] = r.n_insn
            self.n_bb[fid] = r.n_bb
            self.n_edge[fid] = r.n_edge
            self.kind[fid] = code
            self.name[fid] = r.name
            self.import_key[fid] = r.import_key
            if r.thunk_target is not None:
                if not 0 <= r.thunk_target < n:
                    raise _ir_error('thunk-range')
                self.thunk_target[fid] = r.thunk_target
            self.h0[fid], self.h1[fid], self.h2[fid], self.h3[fid] = r.h0, r.h1, r.h2, r.h3
            self.hm[fid], self.hms[fid], self.md_td[fid], self.md_bu[fid] = r.hm, r.hms, r.md_td, r.md_bu
            self.pdata[fid] = bool(r.pdata_confirmed)
            self.oversize[fid] = bool(r.oversize)
            names = {a for a in r.aliases if usable_name(a)}
            if r.name_src in _TRUSTED_NAME_SOURCES and usable_name(r.name):
                names.add(r.name)
            self.names[fid] = tuple(sorted(names))
        rva_list = self.rva
        if any(rva_list[i] >= rva_list[i + 1] for i in range(n - 1)):
            raise _ir_error('fn-order')           # fid is the rank by rva
        # ---- call graph -------------------------------------------------------------------------------------------------
        per_fid: list[list[tuple[int, int, str | None, bool]]] = [[] for _ in range(n)]
        for c in ir.call_rows():
            fid = c.fid
            if not 0 <= fid < n or (c.callee is not None and not 0 <= c.callee < n):
                raise _ir_error('call-range')
            per_fid[fid].append((c.site, -1 if c.callee is None else c.callee, c.import_key, bool(c.jump)))
        callers_acc: list[list[int]] = [[] for _ in range(n)]
        self.sites: list[tuple[tuple[int, str | None, bool], ...]] = []
        self.callees: list[tuple[int, ...]] = []
        for fid in range(n):
            lst = sorted(per_fid[fid], key=lambda t: (t[0], t[1], t[2] or '', t[3]))
            # a call to an external function IS a call to its import: the site carries the import key (P13, votes, P15)
            self.sites.append(tuple((t[1], t[2] or (self.import_key[t[1]] if t[1] >= 0 and self.kind[t[1]] == K_EXTERNAL
                                                    else None), t[3]) for t in lst))
            distinct = sorted({t[1] for t in lst if t[1] >= 0 and t[1] != fid})
            self.callees.append(tuple(distinct))
            for callee in distinct:
                callers_acc[callee].append(fid)           # fid ascends, so every callers list is ascending
        self.callers: list[tuple[int, ...]] = [tuple(c) for c in callers_acc]
        fan_in_cap = limits.l17_hub_fan_in
        self.hub = [len(c) > fan_in_cap for c in self.callers]
        thunks: dict[int, list[int]] = {}
        for fid in range(n):
            if self.kind[fid] == K_THUNK and self.thunk_target[fid] >= 0 and self.thunk_target[fid] != fid:
                thunks.setdefault(self.thunk_target[fid], []).append(fid)
        self.thunks_of: dict[int, tuple[int, ...]] = {t: tuple(v) for t, v in sorted(thunks.items())}
        # ---- strings, constants, blocks (filtered by the ladder's own rarity inputs, 02 s6) ---------------------------
        strs: list[set[int]] = [set() for _ in range(n)]
        for s in ir.string_rows():
            if not 0 <= s.fid < n:
                raise _ir_error('string-range')
            if s.length >= limits.l13_string_min_length:
                try:
                    strs[s.fid].add(int(s.sha[:16], 16))
                except ValueError:
                    raise _ir_error('string-sha') from None
        csts: list[set[int]] = [set() for _ in range(n)]
        for c in ir.constant_rows():
            if not 0 <= c.fid < n:
                raise _ir_error('const-range')
            if usable_constant(c.value, limits):
                csts[c.fid].add(c.value)
        blks: list[set[int]] = [set() for _ in range(n)]
        for b in ir.block_rows():
            if not 0 <= b.fid < n:
                raise _ir_error('block-range')
            if b.h1 is not None and b.n_insn >= limits.l25_bb_min_instructions:
                blks[b.fid].add(b.h1)
        self.strs: list[tuple[int, ...]] = [tuple(sorted(x)) for x in strs]
        self.consts: list[tuple[int, ...]] = [tuple(sorted(x)) for x in csts]
        self.blocks: list[tuple[int, ...]] = [tuple(sorted(x)) for x in blks]
        # ---- exports (P02 input) -----------------------------------------------------------------------------------------
        by_rva = dict(exports or {})
        self.export_key: list[str | None] = [by_rva.get(self.rva[f]) if self.kind[f] != K_EXTERNAL else None
                                             for f in range(n)]
        # ---- static content gates (04 s4: I6, L-09, L-10, L-12) -------------------------------------------------------
        self.content_ok = [self.kind[f] == K_NORMAL and not self.oversize[f] and self.size[f] >= limits.l09_min_body_bytes
                           and self.n_insn[f] > limits.l10_tiny_instructions for f in range(n)]
        self.multiset_ok = [self.content_ok[f] and self.n_insn[f] >= limits.l12_multiset_min_instructions
                            for f in range(n)]
        return self

    # ---- helpers shared by the passes ------------------------------------------------------------------------------------
    def cached(self, name: str, build: Callable[[], Any]) -> Any:
        try:
            return self.cache[name]
        except KeyError:
            value = self.cache[name] = build()
            return value

    def name_index(self) -> dict[str, tuple[int, ...]]:
        """name -> fids that carry it as primary or alias (usable names only), ascending."""
        def build() -> dict[str, tuple[int, ...]]:
            acc: dict[str, list[int]] = {}
            for fid in range(self.n):
                for name in self.names[fid]:
                    acc.setdefault(name, []).append(fid)
            return {k: tuple(v) for k, v in sorted(acc.items())}
        return self.cached('name_index', build)

