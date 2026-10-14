"""Test support for the S5 residual stage (SPEC-31 04 s6): mnemonic sources, state builders, residual worlds.

Sits next to `unified_ir_builder.py` and only uses its public pieces. Everything is SYNTHETIC and deterministic.
`BodyMnemonics` is the test double of the `MnemonicSource` port (blocking.py): the real one reads `ins` blobs of the
IR sidecar; here the mnemonics come from the synthetic function bodies the IR keys were derived from.
"""
from __future__ import annotations

import random
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import INSN_BYTES, Insn, SyntheticIr, h64, make_body, sha_hex  # noqa: E402

from patchtrace.unified.ladder.ports import KIND_NORMAL, CallRow, FnRow, RowsIrSide, StrRow  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.ladder.state import State  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402


class BodyMnemonics:
    """`MnemonicSource` over a `SyntheticIr`: records every function it was asked about (on-demand reading)."""

    def __init__(self, ir: SyntheticIr):
        self.ir = ir
        self.reads: list[int] = []

    def mnemonics(self, fid: int) -> list[str]:
        self.reads.append(fid)
        return [i.mnem for i in self.ir.layout()[1][fid].resolved_body()]


def make_state(older: SyntheticIr, newer: SyntheticIr, anchors=(), *, limits=DEFAULT_LIMITS, budget=None) -> State:
    """A ladder `State` over two synthetic sides with tier-M anchors given as (older tag, newer tag) pairs."""
    state = State(SideData.from_ir(older, limits), SideData.from_ir(newer, limits), limits, budget or Budget())
    for old_tag, new_tag in anchors:
        state.accept(older.fid(old_tag), newer.fid(new_tag), pass_id='P00', step='P00-manual', tier='M',
                     family='F-MANUAL', cls='E-MANUAL', rnd=0)
    return state


def edited(body: tuple[Insn, ...], *, extra: int = 2, seed: int = 0) -> tuple[Insn, ...]:
    """A close variant of `body`: one instruction replaced and `extra` appended. The instruction count differs, so
    none of the six key levels (h0..hms) of the two functions agree, while almost every 3-gram survives."""
    rng = random.Random(f'edit:{seed}')
    out = list(body)
    out[len(out) // 2] = Insn('movzx', ('rax',), 7, None)
    for _ in range(extra):
        out.append(Insn(rng.choice(('imul', 'shl', 'shr', 'and', 'or')), ('rdx',), rng.randint(1, 9), None))
    return tuple(out)


def random_residual_world(seed: int, n: int, *, row_order_old: int | None = None,
                          row_order_new: int | None = None) -> tuple[SyntheticIr, SyntheticIr]:
    """`n` older functions and a newer build in which about 30 % are unchanged, 45 % edited (a close body, so every key
    level differs), 10 % dropped and a few new: the residual stage has work by construction. Three shapes of function:
    plain bodies with random references; leaf functions made of explicit basic blocks (an edit swaps one block and adds
    one: block votes); and leaf string-heavy ones (an edit changes one string and one constant: token similarity).
    Nothing calls a leaf of the last two shapes, so only the residual stage can pair them."""
    rng = random.Random(f'residual-world:{seed}:{n}')
    older = SyntheticIr(row_order=row_order_old)
    newer = SyntheticIr(row_order=row_order_new)
    shapes = [rng.choices(('plain', 'blocky', 'texty'), (5, 2, 2))[0] for _ in range(n)]
    callable_ids = [i for i, shape in enumerate(shapes) if shape == 'plain'] or [0]
    specs = []
    for i, shape in enumerate(shapes):
        leaf = shape != 'plain'
        specs.append({
            'shape': shape,
            'body': make_body(2000 + i + 1000 * seed, rng.choice((12, 20, 40))),
            'blocks': tuple(make_body(5000 + 37 * i + b + 1000 * seed, 5) for b in range(rng.randint(3, 6))),
            'strings': tuple(f'unique-text-{i}-{k}' for k in range(5)) if shape == 'texty' else (
                tuple(f'text-{rng.randrange(max(2, n // 2))}-s' for _ in range(rng.randrange(3)))
                if rng.random() < 0.6 and not leaf else ()),
            'consts': (0x2468 + 16 * i, 0x3579 + 16 * i) if shape == 'texty' else (
                () if leaf else tuple(0x2468 + 16 * rng.randrange(n) for _ in range(rng.randrange(2)))),
            'imports': () if leaf else tuple(f'imp:lib!api{rng.randrange(max(2, n // 6))}' for _ in range(rng.randrange(3))),
            'callees': [] if leaf else [rng.choice(callable_ids) for _ in range(rng.randrange(4))],
            'fate': rng.random()})
    alive_older = set(range(n))
    alive_newer = {i for i, spec in enumerate(specs) if spec['fate'] >= 0.1}

    def add(ir, i, alive, *, edit):
        spec = specs[i]
        fields = {'blocks': spec['blocks']} if spec['shape'] == 'blocky' else {'body': spec['body']}
        strings, consts = spec['strings'], spec['consts']
        if edit and spec['shape'] == 'blocky':
            fields = {'blocks': (*spec['blocks'][:-1], make_body(8000 + i, 5), make_body(8500 + i, 5))}
        elif edit:
            fields = {'body': edited(spec['body'], extra=1 + i % 3, seed=i)}
            if spec['shape'] == 'texty':
                strings, consts = (*strings[:-1], f'changed-text-{i}'), (consts[0], 0x4680 + 16 * i)
        calls = tuple(f'f{j}' for j in spec['callees'] if j in alive and j != i) + spec['imports']
        ir.add(f'f{i}', n_bb=7 if edit else 6, strings=strings, consts=consts, calls=calls, **fields)
    for i in sorted(alive_older):
        add(older, i, alive_older, edit=False)
    for i in sorted(alive_newer):
        add(newer, i, alive_newer, edit=specs[i]['fate'] >= 0.4)
    for j in range(max(1, n // 10)):
        target = rng.choice(callable_ids)
        newer.add(f'g{j}', body=make_body(90_000 + j, 20), n_bb=5,
                  calls=(f'f{target}',) if target in alive_newer else ())
    return older, newer


# --- mnemonic streams for the generated (G-U5) worlds ------------------------------------------------------------------------

VOCABULARY = ('mov', 'lea', 'add', 'sub', 'xor', 'cmp', 'test', 'push', 'pop', 'call', 'jmp', 'jne', 'je', 'ret', 'and',
              'or', 'shl', 'shr', 'imul', 'movzx')
WEIGHTS = (30, 12, 8, 6, 5, 5, 4, 4, 3, 3, 3, 3, 2, 2, 2, 1, 1, 1, 1, 1)       # skewed like real code: common 3-grams
INSERTED = {'body': 2, 'struct': 9}                                              # instructions the generator adds


def stream(seed: str, length: int) -> list[str]:
    return random.Random(seed).choices(VOCABULARY, WEIGHTS, k=length)


class GeneratedMnemonics:
    """`MnemonicSource` for a `generate_pair` world, derived from its ground truth (the generator has no bodies): a newer
    function of a true pair reads its older function's stream (edited per mutation class: 'body' appends 2 instructions,
    'struct' rewrites 12 % of the positions and appends 9), every other function reads a stream of its own.
    SYNTHETIC: it models how much of an edited function's text survives, nothing about real compilers."""

    def __init__(self, world, side: str):
        self._rows = world.older.functions if side == 'older' else world.newer.functions
        self._older = side == 'older'
        self._origin = {new: old for old, new in world.truth.items()}
        self._kinds = world.kinds

    def mnemonics(self, fid: int) -> list[str]:
        row = self._rows[fid]
        if self._older:
            return stream(f'm:{row.rva}', row.n_insn)
        old = self._origin.get(row.rva)
        if old is None:
            return stream(f'n:{row.rva}', row.n_insn)
        kind = self._kinds[old]
        base = stream(f'm:{old}', max(row.n_insn - INSERTED.get(kind, 0), 1))
        if kind == 'body':
            return [*base, 'xor', 'ret']
        if kind == 'struct':
            rng = random.Random(f'e:{old}')
            return [*(rng.choice(VOCABULARY) if rng.random() < 0.12 else m for m in base),
                    *rng.choices(VOCABULARY, k=INSERTED['struct'])]
        return base


# --- the all-residual worst case (G-U5) --------------------------------------------------------------------------------------

COMMON_IMPORTS = 10                    # every function calls 3 of these: their token buckets hold thousands of functions


@dataclass
class DenseWorld:
    older: RowsIrSide
    newer: RowsIrSide
    identity_older: dict[int, int]     # rva -> function identity
    identity_newer: dict[int, int]


def dense_world(n: int, seed: int = 1) -> DenseWorld:
    """`n` functions per side and NONE of them matchable by content (every key differs between the sides): the newer
    side is shuffled, each function calls 3 of 10 common imports (buckets of thousands) and has 2 rare strings that
    only its twin shares. The whole image is residual and every token bucket is far above the L-23 cap."""
    rng = random.Random(f'dense:{seed}:{n}')
    shapes = [(rng.choice((8, 12, 20, 40, 80, 160)), rng.randint(1, 24)) for _ in range(n)]
    imports = [[f'lib!common{k}' for k in rng.sample(range(COMMON_IMPORTS), 3)] for _ in range(n)]
    order_newer = list(range(n))
    rng.shuffle(order_newer)

    def side(order: list[int], tag: str) -> tuple[RowsIrSide, dict[int, int]]:
        functions, calls, strings = [], [], []
        for fid, identity in enumerate(order):
            n_insn, n_bb = shapes[identity]
            n_insn += tag == 'new'
            keys = [h64(f'{tag}:{identity}:{level}'.encode()) for level in range(8)]
            rva = 0x1000 + 0x40 * fid
            functions.append(FnRow(fid, rva, n_insn * INSN_BYTES, KIND_NORMAL, None, 'DEFAULT', (), None, None, n_bb,
                                   n_bb + 2, n_insn, *keys[:6], keys[6] if n_bb >= 5 else None,
                                   keys[7] if n_bb >= 5 else None, True, False))
            calls.extend(CallRow(fid, rva + 5 * (k + 1), None, key, False) for k, key in enumerate(imports[identity]))
            strings.extend(StrRow(fid, sha_hex(f'unique-{identity}-{k}'), 12) for k in range(2))
        return RowsIrSide(functions, calls, strings), {0x1000 + 0x40 * fid: identity for fid, identity in enumerate(order)}

    older, identity_older = side(list(range(n)), 'old')
    newer, identity_newer = side(order_newer, 'new')
    return DenseWorld(older, newer, identity_older, identity_newer)


class DenseMnemonics:
    """Streams of the dense world: the newer function is its twin's stream with 10 % of the positions rewritten."""

    def __init__(self, world: DenseWorld, side: str):
        self._older = side == 'older'
        self._rows = world.older.functions if self._older else world.newer.functions
        self._identity = world.identity_older if self._older else world.identity_newer

    def mnemonics(self, fid: int) -> list[str]:
        row = self._rows[fid]
        identity = self._identity[row.rva]
        base = stream(f's:{identity}', row.n_insn - (not self._older))
        if self._older:
            return base
        rng = random.Random(f'e:{identity}')
        return [*(rng.choice(VOCABULARY) if rng.random() < 0.1 else m for m in base), 'ret']
