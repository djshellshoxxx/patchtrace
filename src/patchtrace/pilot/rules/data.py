"""The patch-intent rule table: expected changes for every K rule, as Python literals (plan s7 "Rule data").

No files and no eval: the literals are validated when this module is imported, so a defective row stops the import with
`PT-PILOT-RULES` instead of producing a wrong lead. Rows are keyed by the K rule id and revision; a K rule revision
without a row here fails closed to an unexplained lead (`find_rule` returns None). The first change of a row is its only
required one. Changes are met by B1 detector signals (`b1:`), ChangeFacts classes (`cf:`) and calls whose API is one of
the hypothesis's own K `api_hints` (`call:`); `cf:cosmetic` and `cf:unchanged` are the proofs against any of them.
Capability leaves (`capa:ns=`) are not used yet: plan s4 keeps the namespace map empty in v1, and a later revision of
this table that fills it changes the digest, which makes stored results stale.
"""
from __future__ import annotations

from .contracts import ChangeSpec, PilotRule, RuleTable

_CONFLICT = ('cf:cosmetic', 'cf:unchanged')


def _change(id_: str, *leaves: str, required: bool = False) -> ChangeSpec:
    return ChangeSpec(id_, required, leaves, f'pilot.change.{id_}')


def _rule(rule_id: str, *changes: ChangeSpec) -> PilotRule:
    return PilotRule(rule_id, 1, changes, _CONFLICT)


# Memory safety: one row for MEMORY-WRITE, MEMORY-READ and BOUNDS. `call:added@api_hints` reads each K rule's own hints.
_GUARD = _change('guard-added', 'b1:BND@moderate', 'cf:comparison', 'cf:condition', required=True)
_SIZE = _change('size-recomputed', 'b1:SIZE@moderate', 'cf:constant')
_ARITHMETIC = _change('checked-arithmetic', 'b1:OVF@moderate', 'call:added@api_hints')
_ZEROED = _change('zeroed', 'b1:SCRUB@moderate', 'call:added@api_hints', required=True)
# NULL-DEREF has no K api_hints, so its row reads no call leaf; POINTER and TYPE read their Probe*/ObReference* hints.
_CHECK = _change('check-or-probe', 'cf:comparison', 'cf:condition', required=True)
_CHECK_OR_PROBE = _change('check-or-probe', 'cf:comparison', 'cf:condition', 'call:added@api_hints', required=True)
# The API-level rows (no lexical B1 detector fits them): a call to a hinted API appears or goes away, the callee is
# swapped, or a constant (for example load flags) changes. DESERIALIZATION has no K api_hints.
_API_LEVEL = _change('api-level', 'call:added@api_hints', 'call:removed@api_hints', 'cf:callee', 'cf:constant',
                     required=True)
_API_LEVEL_NO_HINTS = _change('api-level', 'cf:callee', 'cf:constant', required=True)

_ROWS = (
    _rule('R-MEMORY-WRITE', _GUARD, _SIZE, _ARITHMETIC),
    _rule('R-MEMORY-READ', _GUARD, _SIZE, _ARITHMETIC),
    _rule('R-BOUNDS', _GUARD, _SIZE, _ARITHMETIC),
    _rule('R-INTEGER',
          _change('overflow-check', 'b1:OVF@moderate', 'call:added@api_hints', required=True),
          _change('range-check', 'b1:BND@moderate', 'b1:INT@weak')),
    _rule('R-INFO', _ZEROED),
    _rule('R-UNINIT', _ZEROED),
    # BND is accepted too: B3 maps CWE-1284 (validation of a specified quantity) to (VAL, BND).
    _rule('R-INPUT', _change('validation-added', 'b1:VAL@weak', 'b1:ERR@weak', 'b1:BND@moderate', 'cf:comparison',
                             required=True)),
    _rule('R-LIFETIME',
          _change('ref-release', 'call:added@api_hints', 'call:removed@api_hints', required=True),
          _change('state-check', 'cf:condition')),
    _rule('R-NULL-DEREF', _CHECK),
    _rule('R-POINTER', _CHECK_OR_PROBE),
    _rule('R-TYPE', _CHECK_OR_PROBE),
    _rule('R-RACE', _API_LEVEL),
    _rule('R-AUTHN', _API_LEVEL),
    _rule('R-AUTHZ', _API_LEVEL),
    _rule('R-PATH', _API_LEVEL),
    _rule('R-RESOURCE', _API_LEVEL),
    _rule('R-INJECTION', _API_LEVEL),
    _rule('R-DESERIALIZATION', _API_LEVEL_NO_HINTS),
    _rule('R-SEARCH-PATH', _API_LEVEL),
    _rule('R-CRYPTO-VERIFY', _API_LEVEL),
    # The next two rows are not in the plan's draft table; they come from the K rule text. The format literal is the
    # decisive observable of a format-string fix; a strictness flip on identical operands is that of an off-by-one fix.
    _rule('R-FORMAT-STRING',
          _change('constant-format', 'cf:string', 'cf:callee', 'call:added@api_hints', 'call:removed@api_hints',
                  required=True)),
    _rule('R-OFF-BY-ONE',
          _change('bound-adjusted', 'b1:INT@moderate', 'b1:BND@moderate', 'cf:comparison', 'cf:constant',
                  required=True)),
)

TABLE = RuleTable(_ROWS)
RULES = TABLE.rules


def find_rule(rule_id: str, revision: int) -> PilotRule | None:
    """The row of a K rule revision, or None (PIL-B2 then leaves the lead unexplained)."""
    return TABLE.find(rule_id, revision)


def pilot_rules_digest() -> str:
    """`PilotInputs.pilot_rules_digest`: identity of this table and of the vocabulary it is read with."""
    return TABLE.digest()
