"""The tier of a lead: a pure function of a few facts (PIL-integration-plan.md s7 "Tier derivation", first match wins).

Everything the derivation reads is a count or a flag, so there is nothing to average and no order of arrival; each
fact is monotone (more support never lowers a tier, more doubt never raises one), which the tests check over the whole
fact space. The mechanism `strong` is never assigned: it needs a typed dominance or dataflow channel that PatchTrace
does not have (`contracts.STRONG_REACHABLE`).

1. No advisory: nothing is assessed (the class is `code` when the function changed, else `queue`).
2. `moderate`: a hypothesis whose required changes are all met (`eligible`, see `fusion.Fit`: also firm and backed by
   two independent components), unless a cap holds it at `tentative`:
   - a confounded window (two or more CVEs fixed on the newer build) with no locality;
   - a toolchain change or a packed binary with no typed, material support;
   - an unverified CVE gate;
   - the configuration allowing no `moderate` from lexical evidence alone.
   Still moderate, it becomes `contested` when the pairing is contested, a proof argues against the met change, or the
   CVE gate conflicts.
3. `tentative`: some expected change is met, or the function changed and its name is local to the advisory.
4. `unexplained`: the function changed and nothing fits; otherwise `not-assessed`.
"""
from __future__ import annotations

from dataclasses import dataclass

TIERS_VERSION = 1  # part of every result identity: bump when a rule above changes
WINDOW_CAP = 'confounded-window-needs-locality'
TOOLCHAIN_CAP = 'toolchain-changed-lexical-only'
UNVERIFIED_CAP = 'cve-unverified'
CONFLICT_CAP = 'cve-conflict'


@dataclass(frozen=True, slots=True)
class TierFacts:
    """What the derivation reads about one candidate in one context."""
    gate: str  # applies, asserted, unverified, conflict or none (no advisory)
    identity: str  # corroborated, contested or unassessed
    eligible: bool  # the best hypothesis could carry a moderate tier
    met_any: bool  # some expected change of the best hypothesis is met
    change: bool  # the function changed (change evidence exists)
    local: bool  # the function name is local to the advisory's component
    typed: bool  # a supporting observation is typed (ChangeFacts or IR)
    material: bool  # a supporting observation is typed and anchored by a second channel
    conflict: bool  # a named proof argues against the met required change
    confounded: bool  # two or more CVEs are fixed on the newer build
    toolchain: bool  # a toolchain change or a packed binary was flagged
    lexical_moderate: bool  # the configuration allows moderate on lexical evidence alone


@dataclass(frozen=True, slots=True)
class Tier:
    mechanism: str
    caps: tuple[str, ...]  # the caps that held a would-be moderate lead back, sorted


def derive(facts: TierFacts) -> Tier:
    if facts.gate == 'none':
        return Tier('not-assessed', ())
    if facts.eligible:
        return _moderate(facts)
    if facts.met_any or (facts.local and facts.change):
        return Tier('tentative', ())
    return Tier('unexplained' if facts.change else 'not-assessed', ())


def _moderate(facts: TierFacts) -> Tier:
    holds = []
    if facts.confounded and not facts.local:
        holds.append(WINDOW_CAP)
    if facts.toolchain and not facts.material:
        holds.append(TOOLCHAIN_CAP)
    if facts.gate == 'unverified':
        holds.append(UNVERIFIED_CAP)
    if holds or (not facts.lexical_moderate and not facts.typed):
        return Tier('tentative', tuple(sorted(holds)))
    if facts.gate == 'conflict':
        return Tier('contested', (CONFLICT_CAP,))
    if facts.identity == 'contested' or facts.conflict:
        return Tier('contested', ())
    return Tier('moderate', ())


def lead_class(mechanism: str, gate: str, change: bool) -> str:
    """fit = moderate, review = contested, partial = tentative; the rest is `code` (no advisory, changed) or `queue`."""
    if mechanism == 'moderate':
        return 'fit'
    if mechanism == 'contested':
        return 'review'
    if mechanism == 'tentative':
        return 'partial'
    return 'code' if gate == 'none' and change else 'queue'
