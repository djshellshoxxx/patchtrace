"""Builders for the PIL-B2 tests (fusion, ranking, properties): synthetic candidates, observations, hypotheses and the
`LocalizeInputs` bundle, over the fake ports of the PIL-T oracle. Synthetic data only; nothing here is live evidence.

Observations are real `pilot/1` records (ids through `patchtrace.pilot.keys`); hypotheses are real K `PatchHypothesis`
values built from K's own rule table; only the advisory report is a stand-in (`localize` reads just
`report.hypotheses.hypotheses` and `report.anchors.anchors`), so a test can state a hypothesis without a CSAF document.
"""
from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace

from pilot_synergy_support import StaticAdvisory, StaticEvidence, StaticKev, StaticPairing, StaticTools

from patchtrace.intelligence.contracts import Anchor, PatchHypothesis
from patchtrace.intelligence.hypotheses import RULES
from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys
from patchtrace.pilot.service import localize

OLDER = hashlib.sha256(b'pilot-b2 older').hexdigest()
NEWER = hashlib.sha256(b'pilot-b2 newer').hexdigest()
RUN_RAW = hashlib.sha256(b'pilot-b2 raw').hexdigest()
CVE_A, CVE_B = 'CVE-2099-40001', 'CVE-2099-40002'
IMAGE_RVA = 0x1000
K_RULES = {rule.id: rule for rule in RULES}
DEFAULT_ORIGINS = {'b1': ('D_ghidra',), 'cf': ('D_ghidra',), 'call': ('D_ghidra',), 'str': ('D_bytes',),
                   'capa': ('D_vivisect',), 'die': ('D_compiler',), 'pair': ('D_ghidra',), 'adv': ('D_vendor_text',)}
CLASS_FOR_PREFIX = {'b1': 'E-DECOMP', 'cf': 'E-BODY', 'call': 'E-CALL', 'str': 'E-DATA', 'capa': 'E-CAPA',
                    'die': 'E-BUILD', 'pair': 'E-BODY', 'adv': 'E-TEXT'}


def sha(*parts) -> str:
    return hashlib.sha256('|'.join(map(str, parts)).encode()).hexdigest()


def observation(kind: str, *, role: str = 'shape', verification: str = 'tool-reported', origins=None, ref: str = '',
                obligations: Iterable[str] = (), channel: str | None = None, detail: str | None = None,
                line: int | None = None, nav: c.Nav | None = None, ref_kind: str | None = None) -> c.Observation:
    """A pilot/1 observation with plain defaults; `ref` tells two otherwise equal observations apart."""
    prefix = kind.split(':', 1)[0]
    where = nav if nav is not None else (
        c.Nav(side='newer', rva=IMAGE_RVA, start_line=line, end_line=line) if line else None)
    return keys.make_observation(
        channel=channel or c.KIND_CHANNEL[prefix], kind=kind, role=role, verification=verification,
        origins=tuple(origins or DEFAULT_ORIGINS[prefix]), evidence_class=CLASS_FOR_PREFIX[prefix],
        obligations=tuple(sorted(obligations)), ref=c.ObsRef(kind=ref_kind or f'{prefix}-ref', id=ref or kind),
        nav=where, detail=detail or f'{kind} {ref}'.strip())


def call(api: str, change: str = 'added', *, verification: str = 'label-only', origins=None) -> c.Observation:
    return observation(f'call:{change}', verification=verification, origins=origins, ref=api,
                       ref_kind='call-label' if verification == 'label-only' else 'pe-import')


def candidate(index: int, name: str | None = None, *, identity: str = 'corroborated', other: str | None = None,
              older_only: bool = False, newer_only: bool = False) -> c.Candidate:
    """Candidate `index` (RVAs 0x1000 + 0x40 * index); `name` is both sides' name unless `other` names the newer."""
    old = 0x100000 + 0x40 * index
    new = 0x200000 + 0x40 * index
    name = name or f'Func{index:05d}'
    older = () if newer_only else (c.FunctionRef(rva=old, name=name),)
    newer = () if older_only else (c.FunctionRef(rva=new, name=other or name),)
    key = keys.candidate_key(OLDER, NEWER, [r.rva for r in older], [r.rva for r in newer])
    return c.Candidate(candidate_key=key, older=older, newer=newer, identity=identity)


def hypothesis(rule_id: str = 'R-MEMORY-WRITE', cwe: str = 'CWE-787', basis: str = 'explicit-csaf-cwe',
               cve: str = CVE_A) -> PatchHypothesis:
    rule = K_RULES[rule_id]
    return PatchHypothesis(
        hypothesis_id=sha('hypothesis', cve, rule_id, cwe, basis), cwe_id=cwe, family=rule.family, rule_id=rule.id,
        rule_revision=rule.revision, basis=basis, expected_operations=rule.expected_operations, sources=rule.sources,
        sinks=rule.sinks, guards=rule.guards, api_hints=rule.api_hints, counterexamples=rule.counterexamples,
        required_observations=rule.required_observations, contradictions=rule.contradictions, caveat=rule.caveat)


def anchor(kind: str, value: str) -> Anchor:
    return Anchor(anchor_id=sha('anchor', kind, value), kind=kind, value=value, source='csaf-title', quality='derived',
                  label=f'{kind} {value}')


def advisory_entry(cve: str = CVE_A, source: str = 'csaf-fact') -> c.Observation:
    return observation('adv:cwe-stated', role='context', verification='advisory-claim', ref=cve, ref_kind=source,
                       detail=f'CWE as stated by {source}')


def context(cve: str = CVE_A, *, gate: str = 'applies', window: str = 'no', window_cves: Sequence[str] = (),
            kev: c.Kev | None = None) -> c.CveContext:
    older, newer = {'applies': ('affected', 'fixed'), 'asserted': ('unknown', 'unknown'),
                    'unverified': ('unknown', 'unknown'), 'conflict': ('contradictory', 'fixed'),
                    'not-applicable': ('fixed', 'fixed')}[gate]
    mapping = 'unknown' if gate in ('asserted', 'unverified') else 'candidate'
    confounding = (c.Confounding(state='yes', cves=tuple(sorted(window_cves))) if window == 'yes'
                   else c.Confounding(state=window))
    return c.CveContext(
        cve=cve, source_ids=(sha('source', cve),), gate=gate,
        applicability=c.ApplicabilitySummary(older=older, newer=newer, older_mapping=mapping, newer_mapping=mapping),
        cwe=c.CweSummary(status='explicit', ids=('CWE-787',)), kev=kev or c.Kev(state='unknown'),
        confounding=confounding, counts=c.LeadCounts(fit=0, review=0, partial=0, code=0, queue=0))


@dataclass(frozen=True)
class Inputs:
    """A `LocalizeInputs` bundle (the oracle's `Sources` has the same attributes)."""
    advisory: StaticAdvisory
    changes: StaticEvidence
    tools: StaticTools
    kev: StaticKev
    calls: StaticEvidence
    pairing: StaticPairing
    contexts: tuple[c.CveContext, ...] = ()
    advisory_observations: Mapping[str, tuple[c.Observation, ...]] = field(default_factory=dict)
    project_id: str = 'pilot-b2-tests'
    revision: int = 1
    older_sha256: str = OLDER
    newer_sha256: str = NEWER
    ghidriff_run_id: str = 'run-1'
    raw_sha256: str = RUN_RAW


def status(channel: str, state: str = 'available', reason: str | None = None) -> c.ChannelStatus:
    return c.ChannelStatus(channel=channel, state=state, reason=reason)


class Advisory(StaticAdvisory):
    """An advisory port that also reports its channel (as the stored-advisory adapter does)."""

    def __init__(self, reports, facts_ids, state: c.ChannelStatus):
        super().__init__(reports, facts_ids)
        self._state = state

    def status(self) -> c.ChannelStatus:
        return self._state


class Pairing(StaticPairing):
    """A candidate universe whose channel state is chosen by the test."""

    def __init__(self, candidates, state: str = 'available'):
        super().__init__(candidates)
        self._channel = status('pairing', state)

    def status(self) -> c.ChannelStatus:
        return self._channel


def build(candidates: Sequence[c.Candidate], evidence: Iterable[tuple[c.Candidate, c.Observation]] = (), *,
          cves: Mapping[str, tuple[PatchHypothesis, ...]] | None = None, contexts: Sequence[c.CveContext] = (),
          anchors: Sequence[Anchor] = (), entries: Mapping[str, Sequence[c.Observation]] | None = None,
          code: str = 'available', calls: str = 'partial', capa: str = 'not-run', strings: str = 'not-run',
          build_state: str = 'not-run', pairing: str = 'available', binary: Sequence[c.Observation] = (),
          advisory_state: c.ChannelStatus | None = None) -> Inputs:
    """Inputs for `candidates`: `evidence` pairs go to the code, call or tool port by kind prefix; `cves` maps a CVE to
    its hypotheses (a context is made for it unless `contexts` gives one)."""
    cves = dict(cves or {})
    found = {ctx.cve: ctx for ctx in contexts}
    contexts = tuple(sorted(found.values() if found else (context(cve) for cve in cves), key=lambda x: x.cve))
    reports = {cve: SimpleNamespace(hypotheses=SimpleNamespace(hypotheses=tuple(hyps)),
                                    anchors=SimpleNamespace(anchors=tuple(anchors))) for cve, hyps in cves.items()}
    by_port: dict[str, list[tuple[str, c.Observation]]] = {'changes': [], 'calls': [], 'tools': []}
    for cand, obs in evidence:
        prefix = obs.kind.split(':', 1)[0]
        port = {'call': 'calls', 'str': 'tools', 'capa': 'tools', 'die': 'tools'}.get(prefix, 'changes')
        by_port[port].append((cand.candidate_key, obs))
    advisory = StaticAdvisory(reports, ()) if advisory_state is None else Advisory(reports, (), advisory_state)
    tools = StaticTools([status('strings', strings), status('capa', capa), status('build', build_state)],
                        by_port['tools'], binary, ())
    return Inputs(
        advisory=advisory, changes=StaticEvidence(status('code', code), by_port['changes']), tools=tools,
        kev=StaticKev(None, {}), calls=StaticEvidence(status('calls', calls), by_port['calls']),
        pairing=Pairing(candidates, pairing),
        contexts=contexts, advisory_observations={cve: tuple(v) for cve, v in (entries or {}).items()})


def run(inputs, config: c.PilotConfig | None = None, cancel: threading.Event | None = None, **kw) -> c.PilotAssessment:
    return localize(inputs, config or keys.default_config(), cancel or threading.Event(), **kw)


def leads_of(assessment: c.PilotAssessment, cve: str | None) -> dict[str, c.Lead]:
    """Candidate key -> lead of one context."""
    return {lead.candidate_key: lead for lead in assessment.leads if lead.cve == cve}


def order_of(assessment: c.PilotAssessment, cve: str | None) -> list[str]:
    return [lead.candidate_key for lead in sorted((x for x in assessment.leads if x.cve == cve), key=lambda x: x.rank)]
