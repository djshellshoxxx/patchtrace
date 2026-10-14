"""The closed vocabulary and the validated records of the patch-intent rule table (PIL-integration-plan.md s7).

A `PilotRule` belongs to one K rule (id and revision) and lists the changes a fix of that weakness is expected to show.
A `ChangeSpec` is met when any of its *leaves* matches an observation. Leaves are strings from a closed vocabulary,
parsed and checked once, when the record is built, so a defective table fails at import with `PT-PILOT-RULES` and a
reason slug. The vocabulary tables below are literals; tests pin them to B1 (`enrichment.signals`) and to SPEC-31
(`unified.contracts`) so that nothing is imported from those features here.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from types import MappingProxyType

from pydantic import TypeAdapter, ValidationError

from ...enrichment.identity import domain_id
from ..contracts import KIND_CHANNEL, ExpectedChange, RuleId
from ..limits import DEFAULT_LIMITS, PilotError

PILOT_RULES_VERSION = 'pilot-rules/1'  # bump when the meaning of a leaf or of the evaluation changes
DOMAIN = 'pilot-rules'
TEACH_PREFIX = 'pilot.change.'

LEVELS = ('weak', 'moderate', 'strong')  # B1 signal confidence, weakest first
# The highest confidence each B1 detector reports today: its default, except `INT`, whose strictness flip on identical
# operands is `moderate`. A floor above it could never be met, so it is refused. `strong` needs typed IR.
B1_CEILING = MappingProxyType({'BND': 'moderate', 'ERR': 'weak', 'INT': 'moderate', 'OVF': 'moderate',
                               'SCRUB': 'moderate', 'SIZE': 'moderate', 'VAL': 'weak'})
# SPEC-31 semantic change classes (noise classes such as `address-only` are never evidence of a fix) and the two
# materiality verdicts that argue against any change.
CF_SHAPE = ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
            'struct-offset', 'string')
CF_CONFLICT = ('cosmetic', 'unchanged')

_B1 = re.compile(r'b1:([A-Z]+)@([a-z]+)')
_CF = re.compile(r'cf:([a-z]+(?:-[a-z]+)*)')
_CALL = re.compile(r'call:(added|removed)@api_hints')
_CAPA = re.compile(r'capa:ns=([a-z0-9][a-z0-9-]*(?:/[a-z0-9][a-z0-9-]*)*)')
_STR = re.compile(r'str:\*')
_RULE_ID = TypeAdapter(RuleId)
_ANY_ID, _ANY_TEACH = 'x', 'pilot.change.x'  # valid stand-ins, so each field of `ExpectedChange` is judged alone
_LIMITS = DEFAULT_LIMITS


def _defect(reason: str, message: str) -> PilotError:
    return PilotError('PT-PILOT-RULES', message, reason=reason)


@dataclass(frozen=True)
class Leaf:
    """One parsed leaf. `role` is where it may stand: `shape` in `any_of`, `conflict` in a rule's counters."""
    text: str
    prefix: str  # b1, cf, call, capa or str
    name: str  # detector id, change class, call direction, capability namespace or `*`
    floor: str | None  # b1 only: the weakest accepted signal confidence
    role: str  # shape, conflict or context

    @property
    def kind(self) -> str | None:
        """The exact observation kind this leaf reads; `capa` and `str` leaves read a whole kind family."""
        return f'{self.prefix}:{self.name}' if self.prefix in ('b1', 'cf', 'call') else None


def parse_leaf(text: str) -> Leaf:
    """Parse one leaf of the closed vocabulary; any other spelling is refused (`bad-leaf` and more specific reasons)."""
    if not isinstance(text, str):
        raise _defect('bad-leaf', 'A rule leaf must be text')
    if match := _B1.fullmatch(text):
        return _b1_leaf(text, *match.groups())
    if match := _CF.fullmatch(text):
        return _cf_leaf(text, match.group(1))
    if match := _CALL.fullmatch(text):
        return Leaf(text, 'call', match.group(1), None, 'shape')
    if match := _CAPA.fullmatch(text):
        return Leaf(text, 'capa', match.group(1), None, 'shape')
    if _STR.fullmatch(text):
        return Leaf(text, 'str', '*', None, 'context')
    raise _defect('bad-leaf', f'Leaf {text[:60]!r} is not in the closed leaf vocabulary')


def _b1_leaf(text: str, detector: str, floor: str) -> Leaf:
    ceiling = B1_CEILING.get(detector)
    if ceiling is None:
        raise _defect('unknown-detector', f'Leaf {text} names B1 detector {detector}, which does not exist')
    if floor not in LEVELS:
        raise _defect('bad-leaf', f'Leaf {text} names the unknown confidence {floor!r}')
    if LEVELS.index(floor) > LEVELS.index(ceiling):
        raise _defect('unreachable-level', f'Leaf {text} asks for {floor} but {detector} reports at most {ceiling}')
    return Leaf(text, 'b1', detector, floor, 'shape')


def _cf_leaf(text: str, name: str) -> Leaf:
    if name in CF_SHAPE:
        return Leaf(text, 'cf', name, None, 'shape')
    if name in CF_CONFLICT:
        return Leaf(text, 'cf', name, None, 'conflict')
    raise _defect('unknown-change-class', f'Leaf {text} is not a semantic change class or a conflict verdict')


def _sequence(value, what: str) -> tuple:
    if isinstance(value, str) or not isinstance(value, (tuple, list)):
        raise _defect('bad-shape', f'{what} must be a tuple')
    return tuple(value)


def _in_position(leaf: Leaf, wanted: str) -> Leaf:
    if leaf.role == 'context':
        raise _defect('context-leaf', f'Leaf {leaf.text} reads context-only evidence, which never meets or '
                                      'contradicts a change')
    if leaf.role != wanted:
        raise _defect('leaf-position', f'Leaf {leaf.text} is a {leaf.role} leaf and cannot stand as a {wanted} leaf')
    return leaf


def _distinct(leaves: Iterable[Leaf], where: str) -> None:
    """One observation kind appears once per rule, so one observation never meets two changes."""
    seen = set()
    for leaf in leaves:
        key = (leaf.prefix, leaf.name)
        if key in seen:
            raise _defect('duplicate-leaf', f'{where}: leaf {leaf.text} repeats {leaf.prefix}:{leaf.name}')
        seen.add(key)


def _check_ids(id_: str, teach_id: str) -> None:
    try:
        ExpectedChange(id=id_, state='not-observed', required=False, teach_id=_ANY_TEACH)
    except ValidationError:
        raise _defect('bad-change-id', 'A change id is a slug of lower-case letters, digits and hyphens') from None
    try:
        ExpectedChange(id=_ANY_ID, state='not-observed', required=False, teach_id=teach_id)
    except ValidationError:
        raise _defect('bad-teach-id', f'Teach id of change {id_} is not a pilot.<kind>.<slug> id') from None
    if not teach_id.startswith(TEACH_PREFIX):
        raise _defect('bad-teach-id', f'Teach id of change {id_} must start with {TEACH_PREFIX}')


@dataclass(frozen=True)
class ChangeSpec:
    """One expected change: met when any leaf matches shape evidence. `teach_id` is the guided-RE lesson hook."""
    id: str
    required: bool
    any_of: tuple[str, ...]
    teach_id: str
    leaves: tuple[Leaf, ...] = field(init=False, repr=False, compare=False)
    channels: tuple[str, ...] = field(init=False, repr=False, compare=False)  # evidence channels its leaves read

    def __post_init__(self) -> None:
        any_of = _sequence(self.any_of, 'any_of')
        if type(self.required) is not bool:
            raise _defect('bad-required', 'A change says whether it is required with true or false')
        _check_ids(self.id, self.teach_id)
        if not any_of:
            raise _defect('no-leaves', f'Change {self.id} has no leaves')
        if len(any_of) > _LIMITS.p07_leaves_per_change:
            raise _defect('too-many-leaves', f'Change {self.id} has more than {_LIMITS.p07_leaves_per_change} leaves')
        leaves = tuple(_in_position(parse_leaf(text), 'shape') for text in any_of)
        _distinct(leaves, f'change {self.id}')
        object.__setattr__(self, 'any_of', any_of)
        object.__setattr__(self, 'leaves', leaves)
        object.__setattr__(self, 'channels', tuple(sorted({KIND_CHANNEL[leaf.prefix] for leaf in leaves})))


@dataclass(frozen=True)
class PilotRule:
    """The expected changes of one K rule (`rule_id`, `revision`), required changes first, plus conflict leaves."""
    rule_id: str
    revision: int
    changes: tuple[ChangeSpec, ...]
    counters: tuple[str, ...]  # conflict leaves (`cf:cosmetic`, `cf:unchanged`): evidence against any change
    conflicts: tuple[Leaf, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        changes, counters = _sequence(self.changes, 'changes'), _sequence(self.counters, 'counters')
        try:
            _RULE_ID.validate_python(self.rule_id)
        except ValidationError:
            raise _defect('bad-rule-id', 'A rule id looks like R-NAME (the K rule id)') from None
        if type(self.revision) is not int or self.revision < 1:
            raise _defect('bad-revision', f'Rule {self.rule_id} needs a K revision of 1 or more')
        _check_changes(self.rule_id, changes)
        if len(counters) > _LIMITS.p07_leaves_per_change:
            raise _defect('too-many-leaves', f'Rule {self.rule_id} has too many conflict leaves')
        conflicts = tuple(_in_position(parse_leaf(text), 'conflict') for text in counters)
        _distinct(conflicts, f'rule {self.rule_id} conflicts')
        object.__setattr__(self, 'changes', changes)
        object.__setattr__(self, 'counters', counters)
        object.__setattr__(self, 'conflicts', conflicts)

    @property
    def detectors(self) -> tuple[str, ...]:
        """Sorted B1 detector ids the rule reads; none means the row has no lexical B1 backing."""
        return tuple(sorted({leaf.name for change in self.changes for leaf in change.leaves if leaf.prefix == 'b1'}))


def _check_changes(rule_id: str, changes: tuple) -> None:
    if not all(isinstance(change, ChangeSpec) for change in changes):
        raise _defect('bad-shape', f'Rule {rule_id} lists something that is not a ChangeSpec')
    if not changes:
        raise _defect('no-changes', f'Rule {rule_id} has no expected changes')
    if len(changes) > _LIMITS.p07_changes_per_rule:
        raise _defect('too-many-changes', f'Rule {rule_id} has more than {_LIMITS.p07_changes_per_rule} changes')
    ids = [change.id for change in changes]
    if len(set(ids)) != len(ids):
        raise _defect('duplicate-change', f'Rule {rule_id} repeats a change id')
    flags = [change.required for change in changes]
    if not any(flags):
        raise _defect('no-required-change', f'Rule {rule_id} has no required change')
    if flags != sorted(flags, reverse=True):
        raise _defect('required-after-optional', f'Rule {rule_id} lists a required change after an optional one')
    _distinct((leaf for change in changes for leaf in change.leaves), f'rule {rule_id}')


@dataclass(frozen=True)
class RuleTable:
    """A validated set of rules sorted by (K rule id, revision), looked up by that key."""
    rules: tuple[PilotRule, ...]
    _index: dict = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        items = _sequence(self.rules, 'rules')
        if not all(isinstance(item, PilotRule) for item in items):
            raise _defect('bad-shape', 'The rule table lists something that is not a PilotRule')
        if len(items) > _LIMITS.p07_rules:
            raise _defect('too-many-rules', f'The rule table has more than {_LIMITS.p07_rules} rules')
        ordered = tuple(sorted(items, key=lambda r: (r.rule_id, r.revision)))
        index = {(r.rule_id, r.revision): r for r in ordered}
        if len(index) != len(ordered):
            raise _defect('duplicate-rule', 'The rule table lists a K rule revision twice')
        object.__setattr__(self, 'rules', ordered)
        object.__setattr__(self, '_index', index)

    def find(self, rule_id: str, revision: int) -> PilotRule | None:
        """The row of a K rule revision; None means PIL has no expected changes for it (the lead fails closed)."""
        return self._index.get((rule_id, revision))

    def digest(self) -> str:
        """Identity of the table and of the vocabulary it is read with (`PilotInputs.pilot_rules_digest`).
        Rules are ordered by key and leaves sorted inside a change; the order of changes is kept (display order)."""
        vocabulary = {'levels': list(LEVELS), 'b1_ceiling': dict(sorted(B1_CEILING.items())),
                      'cf_shape': sorted(CF_SHAPE), 'cf_conflict': sorted(CF_CONFLICT)}
        rules = [{'rule_id': r.rule_id, 'revision': r.revision, 'counters': sorted(r.counters),
                  'changes': [{'id': c.id, 'required': c.required, 'any_of': sorted(c.any_of),
                               'teach_id': c.teach_id} for c in r.changes]} for r in self.rules]
        return domain_id(DOMAIN, 1, {'version': PILOT_RULES_VERSION, 'vocabulary': vocabulary, 'rules': rules})
