"""Source-authored recompile-noise analogues, not output of any named compiler.

UNVERIFIED: no independent decoder or engine has run these bytes. All transformations preserve the return
value for the documented abstract inputs, including branch predicates. Register-only cases are allowed to
remain review under SPEC-31; semantic equivalence here is not permission to hide a row.
"""
from __future__ import annotations

from unified_support.assembler import Assembler
from unified_support.pairs import Pair, Relation, branch, program

KINDS = ("register-reallocation", "instruction-scheduling", "basic-block-reordering", "padding", "address-shift")


def nuisance_pair(kind: str, seed: int = 0) -> Pair:
    if kind not in KINDS:
        raise ValueError("unknown nuisance")
    if type(seed) is not int or not 0 <= seed < 10000:
        raise ValueError("seed out of range")
    constant = 17 + seed
    older = Assembler().mov("rax", constant).add("rax", 3).ret()
    newer = Assembler().mov("rax", constant).add("rax", 3).ret()
    shift = 0
    if kind == "register-reallocation":
        # RDX is volatile under the Windows x64 ABI; copy the result into RAX before returning.
        newer = Assembler().mov("rdx", constant).add("rdx", 3).mov("rax", "rdx").ret()
    elif kind == "instruction-scheduling":
        older = Assembler().mov("rax", constant).mov("rdx", 3).add("rax", "rdx").ret()
        newer = Assembler().mov("rdx", 3).mov("rax", constant).add("rax", "rdx").ret()
    elif kind == "basic-block-reordering":
        older, newer = branch("b", constant), branch("b", constant, reordered=True)
    elif kind == "padding":
        newer = Assembler().mov("rax", constant).nop(1 + seed % 15).add("rax", 3).ret()
    elif kind == "address-shift":
        # A rel32 caller and target move together; the call still resolves to the same named helper.
        old_entries = (("entry", Assembler().call("helper").ret()), ("helper", older))
        new_entries = (("entry", Assembler().call("helper").ret()), ("helper", newer))
        return Pair(kind, seed, program(old_entries), program(new_entries, padding=64),
                    (Relation(("entry",), ("entry",), "nuisance"),
                     Relation(("helper",), ("helper",), "nuisance")))
    return Pair(kind, seed, program((("entry", older),)),
                program((("entry", newer),), padding=shift),
                (Relation(("entry",), ("entry",), "nuisance"),))
