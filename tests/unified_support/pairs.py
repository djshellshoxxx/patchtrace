"""Known-by-construction pair corpus. UNVERIFIED: byte encodings and parser integration are not run.

Relations describe source transformations, not a claim that an automatic engine must accept an N:M match.
Names are fixture-local identity keys and never supplied as hidden engine ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from pe_builder import align
from unified_support.assembler import Assembler
from unified_support.synthetic_pe import Function, Image, build_image

KINDS = ("unchanged", "moved", "renamed", "inlined", "split", "merged", "constant-changed",
         "condition-changed", "added-check", "removed-code")


@dataclass(frozen=True)
class Relation:
    older: tuple[str, ...]
    newer: tuple[str, ...]
    change: str


@dataclass(frozen=True)
class Pair:
    kind: str
    seed: int
    older: Image
    newer: Image
    relations: tuple[Relation, ...]

    @property
    def digests(self) -> tuple[str, str]:
        return sha256(self.older.data).hexdigest(), sha256(self.newer.data).hexdigest()

    def rva_relations(self) -> tuple[tuple[tuple[int, ...], tuple[int, ...], str], ...]:
        old, new = dict(self.older.functions), dict(self.newer.functions)
        return tuple((tuple(old[n] for n in r.older), tuple(new[n] for n in r.newer), r.change)
                     for r in self.relations)


def program(entries: tuple[tuple[str, Assembler], ...], *, padding: int = 0) -> Image:
    offset = padding
    addresses: dict[str, int] = {}
    for name, code in entries:
        offset = align(offset, 16)
        addresses[name] = 0x1000 + offset
        offset += len(code.data)
    functions = tuple(Function(name, code.assemble(addresses[name],
                      {k: v for k, v in addresses.items() if k not in code.labels})) for name, code in entries)
    return build_image(functions, prefix_padding=padding, exports=tuple(name for name, _ in entries))


def branch(condition: str, constant: int, *, reordered: bool = False) -> Assembler:
    code = Assembler().cmp("rcx", constant)
    if reordered:
        # Logical "below" path falls through after inverting the branch; return values stay attached to predicates.
        inverse = {"b": "ae", "ae": "b", "l": "ge", "ge": "l"}[condition]
        code.jcc(inverse, "high").mov("rax", 1).ret().label("high").mov("rax", 2).ret()
    else:
        code.jcc(condition, "low").mov("rax", 2).ret().label("low").mov("rax", 1).ret()
    return code


def pair_for(kind: str, seed: int = 0) -> Pair:
    if kind not in KINDS:
        raise ValueError("unknown pair kind")
    if type(seed) is not int or not 0 <= seed < 10000:
        raise ValueError("fixture seed out of range")
    constant = 17 + seed
    old = (("entry", Assembler().mov("rax", constant).add("rax", 3).ret()),)
    new = (("entry", Assembler().mov("rax", constant).add("rax", 3).ret()),)
    relations = (Relation(("entry",), ("entry",), kind),)
    padding = 0
    if kind == "moved":
        padding = 64
    elif kind == "renamed":
        new = (("renamed_entry", new[0][1]),)
        relations = (Relation(("entry",), ("renamed_entry",), kind),)
    elif kind == "constant-changed":
        new = (("entry", Assembler().mov("rax", constant + 1).add("rax", 3).ret()),)
    elif kind == "condition-changed":
        old = (("entry", branch("b", constant)),)
        new = (("entry", branch("ae", constant)),)
    elif kind == "added-check":
        new = (("entry", Assembler().cmp("rcx", 0).jcc("e", "zero")
                .mov("rax", constant).add("rax", 3).ret().label("zero").mov("rax", 0).ret()),)
    elif kind == "removed-code":
        new = (("entry", Assembler().mov("rax", constant).ret()),)
    elif kind == "inlined":
        old = (("entry", Assembler().call("helper").ret()),
               ("helper", Assembler().mov("rax", constant).add("rax", 3).ret()))
        relations = (Relation(("entry", "helper"), ("entry",), kind),)
    elif kind == "split":
        new = (("entry", Assembler().call("head").call("tail").ret()),
               ("head", Assembler().mov("rax", constant).ret()),
               ("tail", Assembler().add("rax", 3).ret()))
        relations = (Relation(("entry",), ("entry", "head", "tail"), kind),)
    elif kind == "merged":
        old = (("entry", Assembler().call("head").call("tail").ret()),
               ("head", Assembler().mov("rax", constant).ret()),
               ("tail", Assembler().add("rax", 3).ret()))
        relations = (Relation(("entry", "head", "tail"), ("entry",), kind),)
    return Pair(kind, seed, program(old), program(new, padding=padding), relations)


def corpus(per_kind: int = 20) -> tuple[Pair, ...]:
    if type(per_kind) is not int or not 1 <= per_kind <= 100:
        raise ValueError("per-kind count out of range")
    return tuple(pair_for(kind, seed) for kind in KINDS for seed in range(per_kind))
