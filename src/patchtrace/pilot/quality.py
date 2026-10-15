"""Evidence quality: which observations describe a change, which only suggest another explanation and which could not
be assessed (SPEC-30 `quality.py`; PIL-integration-plan.md s6 "Compiler-only rebuild yields a mechanism", s7 tier step 4).

Whatever CVE it is read for, an observation falls in exactly one of four groups:

* `counter`: its role says it argues against a change (a named cosmetic or unchanged proof);
* `alternative`: it explains the change another way (compiler churn, a build fact, a function that is a likely false
  lead) and never raises anything;
* `unknown`: evidence that was cut, missing, or that no function owns (data-quality flags, capa findings without a
  function); it is recorded as not assessed, never as a negative vote;
* `support`: everything else, the shape evidence that can meet an expected change and the context that only says a
  function changed.

The vocabularies are literals mirrored from the adapters (`sources.unified`, `sources.tools`) so that this module
imports no other feature; tests pin them. Pure and total: a kind it does not know is plain support context.
"""
from __future__ import annotations

import re
from typing import Literal

from .contracts import Observation

Category = Literal['support', 'counter', 'unknown', 'alternative']

# SPEC-31 change classes that are noise, not edits (`sources.unified.NUISANCE_CLASSES`).
NUISANCE_CLASSES = frozenset({'address-only', 'frame', 'layout-only', 'name-only', 'refcount-only', 'register-only',
                              'size-only'})
# Row flags: a function that is a likely false lead, and evidence that is cut or missing for it.
NUISANCE_FLAGS = frozenset({'hub', 'icf', 'import', 'library', 'thunk', 'tiny'})
QUALITY_FLAGS = frozenset({'ir-missing', 'mask-missing', 'mask-unlocated', 'oversize', 'truncated'})
# capa findings that no function owns (`sources.tools`).
UNASSESSED_CAPA = frozenset({'limitation', 'recovery-shift', 'unlocalized-added', 'unlocalized-removed'})
# A different toolchain, or a packed binary, can turn lexical decompiler differences into a "patch" (s7 step 4).
TOOLCHAIN_KINDS = frozenset({'die:toolchain-changed', 'die:packed'})
CHANGE_PREFIXES = frozenset({'cf', 'call', 'str'})
TYPED_PREFIXES = frozenset({'cf', 'ir'})  # SPEC-31 ChangeFacts or ProgramIR based; B1 and call labels are lexical
SECOND_CHANNEL = 'second-channel'  # the unmet obligation of a ChangeFacts `review` row (no anchored second channel)
_PLACEHOLDER = re.compile(r'(?:thunk_)?(?:FUN|sub)_[0-9a-f]+', re.IGNORECASE)  # Ghidra's default function names


def parts(kind: str) -> tuple[str, str]:
    """`prefix:name` of an observation kind (the contract pattern guarantees the colon)."""
    prefix, _, name = kind.partition(':')
    return prefix, name


def category(observation: Observation) -> Category:
    if observation.role in ('conflict', 'counter'):
        return 'counter'
    prefix, name = parts(observation.kind)
    if prefix == 'die' or (prefix == 'cf' and name in NUISANCE_CLASSES) or (prefix == 'pair' and name in NUISANCE_FLAGS):
        return 'alternative'
    if prefix == 'pair' or (prefix == 'capa' and name in UNASSESSED_CAPA):
        return 'unknown'  # a quality flag, or a pairing fact PIL does not know: not assessed rather than a vote
    return 'support'


def is_change(observation: Observation) -> bool:
    """True when the observation says the function changed: shape evidence, or context that names an edit. Locality,
    advisory statements, noise and flags do not."""
    if category(observation) != 'support':
        return False
    if observation.role == 'shape':
        return True
    prefix, name = parts(observation.kind)
    return observation.role == 'context' and (prefix in CHANGE_PREFIXES or (prefix == 'capa' and name in ('added', 'removed')))


def is_toolchain(observation: Observation) -> bool:
    return observation.kind in TOOLCHAIN_KINDS


def is_typed(observation: Observation) -> bool:
    return parts(observation.kind)[0] in TYPED_PREFIXES


def is_material(observation: Observation) -> bool:
    """Typed evidence that no obligation holds back: a ChangeFacts delta of a `material` row (an anchored second channel
    saw it), not of a `review` row."""
    return is_typed(observation) and SECOND_CHANNEL not in observation.obligations


def is_placeholder(name: str) -> bool:
    """A Ghidra default name (`FUN_...`, `sub_...`, `thunk_FUN_...`): it says nothing about the code."""
    return _PLACEHOLDER.fullmatch(name) is not None
