"""SPEC-32 s7 labelling rule for planted mutations, as a pure function (no I/O, no images).

The target function gets the operator's label (`changed(op)` for semantic, `cosmetic(op)` for cosmetic operators). A
semantic mutant counts only if the target's masked body differs (`semantic_accepted`); under a semantic operator any
other function whose masked body differs becomes `ambiguous` ("induced by <target>", e.g. inlining); planted helper
functions and functions present on one side only are `no-counterpart`; everything else is `unchanged`.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .contracts import kind_of


@dataclass(frozen=True)
class FunctionFact:
    """What the images say about one function: presence per side and whether the address-masked bodies are equal
    (`None` when not both sides present or not comparable)."""
    name: str
    in_old: bool
    in_new: bool
    masked_equal: bool | None


@dataclass(frozen=True)
class Decision:
    name: str
    label: str            # unchanged | changed | cosmetic | no-counterpart | ambiguous
    change_kind: str | None
    check: str            # ok | disagree
    note: str = ''


def target_label(operator: str) -> tuple[str, str]:
    """(label, change_kind) of the target function."""
    kind = kind_of(operator)
    return ('changed' if kind == 'semantic' else 'cosmetic'), operator


def semantic_accepted(masked_equal: bool | None) -> bool:
    """A semantic mutant is accepted only if the target's masked body is known to differ."""
    return masked_equal is False


def label_mutation(operator: str, target: str, facts: Iterable[FunctionFact], *,
                   helpers: Iterable[str] = ()) -> list[Decision]:
    semantic = kind_of(operator) == 'semantic'
    helper_names = frozenset(helpers)
    out: list[Decision] = []
    for f in sorted(facts, key=lambda x: x.name):
        if f.in_old != f.in_new:
            planted = f.name in helper_names and f.in_new
            check = 'disagree' if f.name == target else 'ok'
            out.append(Decision(f.name, 'no-counterpart', None, check,
                                'planted helper' if planted else
                                ('target function absent on one side' if f.name == target else
                                 'present in only one image')))
        elif not f.in_old:
            continue
        elif f.name == target:
            label, kind = target_label(operator)
            if semantic and not semantic_accepted(f.masked_equal):
                out.append(Decision(f.name, label, kind, 'disagree',
                                    'planted semantic change left the masked body unchanged'))
            else:
                out.append(Decision(f.name, label, kind, 'ok'))
        elif semantic and f.masked_equal is False:
            out.append(Decision(f.name, 'ambiguous', None, 'ok', f'code differs although the source is unchanged '
                                                                  f'(induced by {target})'))
        else:
            out.append(Decision(f.name, 'unchanged', None, 'ok'))
    return out
