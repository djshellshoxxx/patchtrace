"""Why this function: the plain-text explanation of a lead (PIL-integration-plan.md s5 "Why this function", s8 detail pane).

A pure function of a stored assessment and one of its leads, nothing recomputed from the sources, so `intelligence why`
(which reads the stored result) and the Leads dock say the same thing. Fixed headers in a fixed order (Summary, Expected
changes, Independent evidence, Against, Unknown, Alternatives, Pairing, Provenance, Limitations); every line is plain
text of at most 300 characters, at most P-05 lines. Enum slugs never reach the text: each is mapped to words here, and
no sentence claims a probability, a likelihood or that the function contains or fixes a CVE. The wording avoids the
words the UI sweeps for (the standing footer and "absence says nothing about exploitation" are the sanctioned phrases).

Each expected change and state carries a `teach_id` and a `next_step` sentence, the hooks of the guided-reverse-engineering
lessons (E-5): `next_step(teach_id)`.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from .contracts import (
    CveContext,
    ExpectedChange,
    HypothesisFit,
    Lead,
    Observation,
    PilotAssessment,
    clean_line,
)
from .limits import DEFAULT_LIMITS
from .origins import components
from .quality import parts
from .rules.data import find_rule

FOOTER = ('Leads are ordered by explainable rules, not by likelihood. A lead does not show that this function '
          'contains or fixes any CVE. Tied leads have equal evidence.')
CHANNEL_LABELS = MappingProxyType({'advisory': 'Advisory', 'code': 'Code', 'calls': 'Calls', 'strings': 'Strings',
                                   'capa': 'Capa', 'build': 'Build', 'pairing': 'Pairing'})
STATE_WORDS = MappingProxyType({'not-run': 'not run', 'unsupported': 'unsupported', 'failed': 'failed',
                                'stale': 'out of date', 'partial': 'partial'})
CLASS_WORDS = MappingProxyType({'fit': 'fits advisory', 'review': 'needs review', 'partial': 'partial fit',
                                'code': 'code change'})
QUEUE_WORDS = MappingProxyType({'unexplained': 'changed, no fit', 'not-assessed': 'not assessed'})
IDENTITY_WORDS = MappingProxyType({
    'corroborated': 'The pairing of the two functions is corroborated by more than one engine.',
    'contested': 'The pairing of the two functions is contested between engines.',
    'unassessed': 'The pairing of the two functions was not assessed by a second engine.'})
VERIFICATION_WORDS = MappingProxyType({
    'verified-bytes': 'read from the file bytes', 'tool-reported': 'reported by a tool', 'label-only': 'label only',
    'advisory-claim': 'stated by the advisory', 'rule-hypothesis': 'rule hypothesis',
    'analyst-assertion': 'analyst statement'})
ORIGIN_WORDS = MappingProxyType({
    'D_vendor_text': 'Advisory text', 'D_ghidra': 'Ghidra-derived code', 'D_ghidra_decode': 'Ghidra-derived decoding',
    'D_pe_tables': 'PE tables of the file', 'D_vivisect': 'capa analysis', 'D_bytes': 'file bytes',
    'D_compiler': 'build facts', 'D_symbols': 'function names', 'D_analyst': 'analyst statement',
    'D_callgraph': 'call graph', 'D_hexrays': 'Hex-Rays output', 'D_ida': 'IDA output', 'D_rizin': 'rizin output'})
SOURCE_WORDS = MappingProxyType({'csaf-fact': 'CSAF', 'nvd-record': 'NVD', 'msrc-entry': 'MSRC',
                                 'kev-entry': 'CISA KEV', 'cve-record': 'CVE record'})
BASIS_WORDS = MappingProxyType({'explicit-csaf-cwe': 'as stated by the advisory',
                                'cwe-id-in-text': 'named in the advisory text',
                                'curated-vocabulary': 'inferred from the advisory wording'})
CHANGE_WORDS = MappingProxyType({
    'guard-added': 'guard added', 'size-recomputed': 'size recomputed', 'checked-arithmetic': 'checked arithmetic',
    'zeroed': 'zeroing or initialization added', 'overflow-check': 'overflow check added',
    'range-check': 'range check added', 'validation-added': 'validation added', 'ref-release': 'reference or release changed',
    'state-check': 'state check added', 'check-or-probe': 'check or probe added', 'api-level': 'API-level change',
    'constant-format': 'format made constant', 'bound-adjusted': 'bound adjusted by one'})
GATE_WORDS = MappingProxyType({
    'asserted': 'The analyst assumed that this CVE applies to these builds.',
    'unverified': 'This advisory could not be tied to these builds; the file name is never used. Leads for it are '
                  'capped at Partial fit.',
    'conflict': 'The advisory conflicts with itself or with the build order. Leads for it are capped at Needs review.'})
CAP_WORDS = MappingProxyType({
    'confounded-window-needs-locality': 'Held at partial fit: the function name does not single this CVE out.',
    'toolchain-changed-lexical-only': 'Held at partial fit: the toolchain changed between the builds and only '
                                      'decompiler text supports this lead.',
    'cve-unverified': 'Held at partial fit: the advisory could not be tied to these builds.',
    'cve-conflict': 'Held at needs review: the advisory conflicts with itself or with the build order.'})
NEXT_STEPS = MappingProxyType({
    'pilot.change.guard-added': 'Open the newer function and check that the new comparison runs before the copy or '
                                'index.',
    'pilot.change.size-recomputed': 'Compare the allocation or copy size in both functions and check that the new size '
                                    'follows from the destination capacity.',
    'pilot.change.checked-arithmetic': 'Check that the size arithmetic now goes through a checked helper and that its '
                                       'failure path returns before the copy.',
    'pilot.change.zeroed': 'Check that the buffer or structure is cleared or fully initialized before it is copied out.',
    'pilot.change.overflow-check': 'Look for the new overflow test on the arithmetic that feeds a size, count or index.',
    'pilot.change.range-check': 'Compare the range or bound that is checked in both functions.',
    'pilot.change.validation-added': 'Check what the new validation rejects and whether the unchecked value reached a '
                                     'copy or an index before.',
    'pilot.change.ref-release': 'Compare where the object is referenced and released in both functions and look for a '
                                'use after the release.',
    'pilot.change.state-check': 'Look for the new state test before the object is used again.',
    'pilot.change.check-or-probe': 'Check that the new test or probe runs before the pointer is dereferenced.',
    'pilot.change.api-level': 'Open the changed call or flag and check what it now enforces.',
    'pilot.change.constant-format': 'Check that the format string is now constant and that untrusted text only appears '
                                    'as an argument.',
    'pilot.change.bound-adjusted': 'Compare the bound before and after and check whether the comparison or constant '
                                   'moved by one.',
    'pilot.state.contested': 'Open both functions and decide yourself which pairing is right before relying on this '
                             'lead.',
    'pilot.state.unknown-channel': 'Run the missing tool, or accept that this lead rests on the other channels only.',
    'pilot.state.tie': 'Tied leads have equal evidence; look at each of them.',
    'pilot.state.confounded-window': 'Look for evidence that belongs to this CVE alone: a name, a string or a call the '
                                     'advisory mentions.',
    'pilot.context.kev': 'KEV only orders CVEs; it says nothing about which function changed.'})
_LIMIT = DEFAULT_LIMITS.p05_explanation_lines


def next_step(teach_id: str) -> str | None:
    """The sentence that tells an analyst what to look at next for a change or a state; None for an unknown hook."""
    return NEXT_STEPS.get(teach_id)


def _list(items: Iterable[str]) -> str:
    return ', '.join(sorted(set(items)))


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:] + ('' if text.endswith('.') else '.')


def kind_label(observation: Observation) -> str:
    """A short name for what an observation is, without its free text: `B1 BND`, `ChangeFacts comparison`."""
    prefix, name = parts(observation.kind)
    if prefix == 'b1':
        return f'B1 {name}'
    if prefix == 'cf':
        return f'ChangeFacts {name}'
    if prefix == 'call':
        how = 'label only' if observation.verification == 'label-only' else 'import table'
        return f'{observation.ref.id} call {name}, {how}'
    return {'str': 'string', 'capa': 'capa', 'die': 'build fact', 'pair': 'pairing fact', 'loc': 'function names',
            'adv': 'advisory text'}.get(prefix, prefix) + f' {name}'


class Explainer:
    """Explains the leads of one assessment; the indexes are built once, so a whole table of leads stays cheap."""

    def __init__(self, assessment: PilotAssessment):
        self.assessment = assessment
        self.pool: Mapping[str, Observation] = {o.obs_id: o for o in assessment.observations}
        self.contexts: Mapping[str, CveContext] = {c.cve: c for c in assessment.cves}
        self._available = {c.channel for c in assessment.channels if c.state == 'available'}
        self.leads_of: dict[str, list[Lead]] = {}
        for lead in assessment.leads:
            self.leads_of.setdefault(lead.candidate_key, []).append(lead)

    def explain(self, lead: Lead) -> tuple[str, ...]:
        context = self.contexts.get(lead.cve) if lead.cve else None
        lines = [*self._summary(lead, context), *self._changes(lead), *self._evidence(lead), *self._against(lead),
                 *self._unknown(lead, context), *self._alternatives(lead), *self._pairing(lead),
                 *self._provenance(lead, context), *self._limitations(context)]
        lines = [clean_line(line) for line in lines]
        if len(lines) > _LIMIT:
            lines = [*lines[:_LIMIT - 1], clean_line(f'{len(lines) - _LIMIT + 1} further lines were left out.')]
        return tuple(lines)

    def observations(self, ids: Iterable[str]) -> list[Observation]:
        return [self.pool[i] for i in ids if i in self.pool]

    # -- Summary ---------------------------------------------------------------------------------------------------

    def _summary(self, lead: Lead, context: CveContext | None) -> list[str]:
        lines = ['Summary', '- ' + self._headline(lead) + '.']
        if lead.depth == 'lexical':
            lines.append('- Text evidence only: decompiler text, no typed ChangeFacts.')
        if context is not None and lead.gate in GATE_WORDS:
            lines.append('- ' + GATE_WORDS[lead.gate])
        lines += [f'- {CAP_WORDS[cap]}' for cap in lead.caps]
        if (reason := self._reason(lead)) is not None:
            lines.append(f'- {reason}')
        if lead.tie.size > 1:
            lines += [f'- Positions {lead.tie.first}-{lead.tie.last} are tied: equal evidence.',
                      f'- Next step: {NEXT_STEPS["pilot.state.tie"]}']
        return lines

    @staticmethod
    def _headline(lead: Lead) -> str:
        facts = [QUEUE_WORDS[lead.mechanism] if lead.lead_class == 'queue' else CLASS_WORDS[lead.lead_class]]
        if lead.fits:
            fit = lead.fits[0]
            required = [c for c in fit.expected_changes if c.required]
            facts.append(f'expected changes seen {fit.met} of {fit.total} '
                         f'(required {sum(c.state == "met" for c in required)} of {len(required)})')
        count = lead.components.count
        return '; '.join([*facts, f'{count} independent {"group" if count == 1 else "groups"}',
                          f'evidence depth {lead.depth}'])

    def _reason(self, lead: Lead) -> str | None:
        """Why a lead is a review or a partial fit, when the stored fields hide it (a cap already says its own)."""
        if lead.lead_class == 'review':
            why = [text for text, hit in (('the pairing of the two functions is contested', lead.identity == 'contested'),
                                          ('a named proof argues against the change that was seen',
                                           bool(lead.counter_ids))) if hit]
            return f'Needs review because {_list(why)}.' if why else None
        if lead.lead_class != 'partial' or lead.caps:
            return None
        fit = lead.fits[0] if lead.fits else None
        if fit is None or not fit.met:
            return 'No expected change was seen; the function changed and its name matches the advisory.'
        held = self._held(fit, lead)
        return f'Held at partial fit: {held}.'

    def _held(self, fit: HypothesisFit, lead: Lead) -> str:
        required = [c for c in fit.expected_changes if c.required]
        unmet = {c.state for c in required if c.state != 'met'}
        if unmet:
            return ('a required change is contradicted by a named proof' if 'contradicted' in unmet
                    else 'a required change could not be checked' if 'unknown' in unmet
                    else 'a required change was not seen')
        if any(self._label_only(c) for c in required):
            return 'a required change rests on call labels only'
        rule = find_rule(fit.rule_id, fit.rule_revision)
        if rule is not None and not rule.detectors and lead.components.count < 3:
            return 'no second independent code source agrees, and this kind of change has no B1 detector'
        return 'the configuration does not allow a fit on text evidence alone'

    def _label_only(self, change: ExpectedChange) -> bool:
        observed = self.observations(change.observation_ids)
        return bool(observed) and all(o.verification == 'label-only' for o in observed)

    # -- Expected changes -------------------------------------------------------------------------------------------

    def _changes(self, lead: Lead) -> list[str]:
        if not lead.fits:
            return []
        fit = lead.fits[0]
        lines = ['Expected changes', f'- {fit.rule_id} revision {fit.rule_revision}, {fit.cwe_id} {BASIS_WORDS[fit.basis]}.']
        for change in fit.expected_changes:
            lines += self._change(fit, change)
        return lines

    def _change(self, fit: HypothesisFit, change: ExpectedChange) -> list[str]:
        words = CHANGE_WORDS.get(change.id, change.id.replace('-', ' '))
        observed = self.observations(change.observation_ids)
        if change.state == 'met':
            where = next((f'go to {o.nav.side} line {o.nav.start_line}' for o in observed
                          if o.nav and o.nav.start_line), None)
            lines = [f'- Seen: {words} ({_list(map(kind_label, observed))}{"; " + where if where else ""}).']
            step = next_step(change.teach_id)
            return lines + ([f'  Next step: {step}'] if step else [])
        if change.state == 'contradicted':
            return [f'- Contradicted: {words} (a named proof argues against any change).']
        if change.state == 'unknown':
            return [f'- Unknown: {words}' + self._not_complete(fit, change) + '.']
        return [f'- Not seen: {words}.']

    def _not_complete(self, fit: HypothesisFit, change: ExpectedChange) -> str:
        rule = find_rule(fit.rule_id, fit.rule_revision)
        spec = next((c for c in rule.changes if c.id == change.id), None) if rule else None
        names = [CHANNEL_LABELS[n] for n in spec.channels if n not in self._available] if spec else []
        return f' (evidence not complete: {_list(names)})' if names else ''

    # -- Independent evidence, Against ----------------------------------------------------------------------------------

    def _witnesses(self, lead: Lead) -> list[Observation]:
        """What is counted as independent evidence: the observations that meet an expected change of the best
        hypothesis plus the advisory's own entries, or, with no hypothesis, the lead's shape evidence."""
        support = self.observations(lead.support_ids)
        if not lead.fits:
            return [o for o in support if o.role == 'shape']
        met = {i for c in lead.fits[0].expected_changes if c.state == 'met' for i in c.observation_ids}
        code = [o for o in support if o.obs_id in met]
        return [*code, *(o for o in support if o.kind.startswith('adv:'))] if code else []

    def _evidence(self, lead: Lead) -> list[str]:
        witnesses = self._witnesses(lead)
        lines = ['Independent evidence']
        for component in components(o.origins for o in witnesses):
            members = [o for o in witnesses if set(o.origins) & set(component)]
            names = _list(SOURCE_WORDS.get(o.ref.kind, 'advisory source') if o.kind.startswith('adv:')
                          else kind_label(o) for o in members)
            lines.append(f'- {ORIGIN_WORDS.get(component[0], "Other origin")}: {names}'
                         + (' (same origin, counted once).' if len(members) > 1 else '.'))
        return lines if witnesses else [*lines, '- None: no observation meets an expected change.']

    def _against(self, lead: Lead) -> list[str]:
        counter = self.observations(lead.counter_ids)
        return ['Against', *(f'- {kind_label(o)}: {_sentence(o.detail)}' for o in counter)] if counter else [
            'Against', '- None.']

    # -- Unknown, Alternatives ----------------------------------------------------------------------------------------------

    def _unknown(self, lead: Lead, context: CveContext | None) -> list[str]:
        lines = ['Unknown']
        plain: dict[str, list[str]] = {}
        for channel in self.assessment.channels:
            label = CHANNEL_LABELS[channel.channel]
            if channel.state == 'available':
                continue
            if channel.reason:
                lines.append(f'- {label}: {STATE_WORDS[channel.state]} ({channel.reason}).')
            else:
                plain.setdefault(channel.state, []).append(label)
        lines += [f'- {_list(names)}: {STATE_WORDS[state]}.' for state, names in plain.items()]
        if any(c.state == 'not-run' for c in self.assessment.channels):
            lines.append(f'- Next step: {NEXT_STEPS["pilot.state.unknown-channel"]}')
        if context is not None:
            window = context.confounding
            if window.state == 'yes':
                local = [o.detail for o in self.observations(lead.support_ids) if o.kind == 'loc:names']
                lines += [f'- The advisory lists {len(window.cves)} CVEs fixed in this build. A change that fits the '
                          'expected shape may belong to another CVE; only advisory-specific evidence can separate '
                          'them.', *(f'- {_sentence(d)}' for d in local[:1]),
                          f'- Next step: {NEXT_STEPS["pilot.state.confounded-window"]}']
            elif window.state == 'unknown':
                lines.append('- Whether other CVEs are fixed in this build is unknown.')
        lines += [f'- {o.detail}' for o in self.observations(lead.unknown_ids)]
        return lines if len(lines) > 1 else [*lines, '- Nothing is known to be missing.']

    def _alternatives(self, lead: Lead) -> list[str]:
        lines = ['Alternatives']
        for other in self.leads_of.get(lead.candidate_key, ()):
            if other.cve and other.cve != lead.cve and other.lead_class in ('fit', 'review', 'partial'):
                lines.append(f'- {CLASS_WORDS[other.lead_class].capitalize()} for {other.cve}.')
        lines += [f'- Another explanation: {o.detail}' for o in self.observations(lead.alternative_ids)]
        return lines if len(lines) > 1 else [*lines, '- None.']

    # -- Pairing, Provenance, Limitations ----------------------------------------------------------------------------------

    def _pairing(self, lead: Lead) -> list[str]:
        def sides(refs) -> str:
            return _list(r.name or f'0x{r.rva:x}' for r in refs[:3]) or 'none'
        lines = ['Pairing', f'- {IDENTITY_WORDS[lead.identity]}', f'- Older: {sides(lead.older)}. Newer: {sides(lead.newer)}.']
        if lead.identity == 'contested':
            lines.append(f'- Next step: {NEXT_STEPS["pilot.state.contested"]}')
        return lines

    def _provenance(self, lead: Lead, context: CveContext | None) -> list[str]:
        ids = {*lead.support_ids, *lead.counter_ids, *lead.unknown_ids, *lead.alternative_ids}
        counts: dict[str, int] = {}
        for o in self.observations(sorted(ids)):
            counts[o.verification] = counts.get(o.verification, 0) + 1
        a = self.assessment
        lines = ['Provenance']
        if counts:
            lines.append('- Evidence: ' + ', '.join(f'{n} {VERIFICATION_WORDS[v]}' for v, n in sorted(counts.items())) + '.')
        lines.append(f'- Result {a.result_id[:16]}; older build {a.older_sha256[:12]}, newer build {a.newer_sha256[:12]}.')
        if context is not None:
            lines.append('- ' + self._kev(context))
        return lines

    @staticmethod
    def _kev(context: CveContext) -> str:
        kev = context.kev
        if kev.state == 'listed':
            return f'CISA KEV: listed (added {kev.date_added}). {NEXT_STEPS["pilot.context.kev"]}'
        if kev.state == 'not-in-snapshot':
            return 'CISA KEV: not in the snapshot; absence says nothing about exploitation.'
        return 'CISA KEV: unknown.'

    def _limitations(self, context: CveContext | None) -> list[str]:
        notes = [*(context.limitations if context else ()), *self.assessment.limitations]
        return ['Limitations', *(f'- {note}' for note in dict.fromkeys(notes)), f'- {FOOTER}']


def explain(assessment: PilotAssessment, lead: Lead) -> tuple[str, ...]:
    """The explanation lines of one lead (build an `Explainer` to explain many)."""
    return Explainer(assessment).explain(lead)

