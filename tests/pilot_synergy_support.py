"""Shared pieces of the PIL-T oracle (docs/specs/program-e/PIL-integration-plan.md s5, s9): the synergy ledger as fake
ports, the nine arms, and the one seam to the fusion and ranking engine (PIL-B2, not built yet).

Synthetic data only (CVE-2099-*, invented digests). The ledger lives in ``tests/fixtures/pilot/synergy-1/``; a generator
there produces it from the s5 tables.

The seam. ``localize`` below is the only place that names ``patchtrace.pilot.service``. It hands the engine a ``Sources``
bundle (the six A1 ports, per-CVE contexts as PIL-A2 will report them, and the ``adv:*`` observations of every source that
repeats the CWE) plus a ``PilotConfig`` and a cancel event, and expects a ``PilotAssessment``. When PIL-B2 lands:

* if its input bundle differs, adapt ``localize`` (and nothing else): the tests only read the returned assessment;
* delete ``PIL_B2`` or its decorators. Every test marked with it is ``xfail(strict=True)``, so the first green run reports
  XPASS as a failure and tells you which markers to remove. A real defect (a wrong class or rank) is a plain failure,
  because the marker only expects ``EngineMissing``: it never hides an assertion.
"""
from __future__ import annotations

import dataclasses
import functools
import hashlib
import importlib
import importlib.util
import json
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from patchtrace.intelligence.contracts import ArtifactIdentity, IntelligenceReport
from patchtrace.intelligence.csaf import normalize as norm
from patchtrace.intelligence.csaf.identity import record_only
from patchtrace.intelligence.csaf.validate import load_document
from patchtrace.intelligence.explain import build_report
from patchtrace.intelligence.storage import StoredAdvisory
from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'pilot' / 'synergy-1'
ZERO_COUNTS = c.LeadCounts(fit=0, review=0, partial=0, code=0, queue=0)
SOURCE_OF_PREFIX = {'b1': 'b1', 'cf': 'cf', 'call': 'calls', 'str': 'floss', 'capa': 'capa',
                    'die': 'die'}  # observation kind prefix -> evidence source of an arm (the ports carry no others)
ENGINE_OF_SOURCE = {'capa': 'capa', 'floss': 'floss', 'die': 'diec'}
ADVISORY_SOURCES = frozenset({'stated', 'nvd', 'msrc', 'kev'})  # who states the CWE of CVE-2099-20001 (all one origin)


class EngineMissing(Exception):
    """PIL-B2 (``patchtrace.pilot.service.localize``) is not built yet. The only failure ``PIL_B2`` expects."""


PIL_B2 = pytest.mark.xfail(strict=True, reason='PIL-B2', raises=EngineMissing)


def engine_available() -> bool:
    return importlib.util.find_spec('patchtrace.pilot.service') is not None


def assert_strictly_pending(*tests) -> None:
    """While PIL-B2 is missing, every given test still exists and carries the strict marker (none was renamed away,
    weakened or left unmarked). Once the engine exists the markers are being removed, and XPASS(strict) says so."""
    mark = PIL_B2.mark
    assert (mark.kwargs['strict'], mark.kwargs['reason'], mark.kwargs['raises']) == (True, 'PIL-B2', EngineMissing)
    if not engine_available():
        for test in tests:
            assert mark in getattr(test, 'pytestmark', ()), f'{test.__name__} must carry {mark}'


# --- the ledger ---------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Function:
    id: str
    key: str
    older: c.FunctionRef
    newer: c.FunctionRef
    identity: str
    plan_evidence: str


@dataclass(frozen=True)
class Ledger:
    builds: Mapping[str, str | int]
    functions: tuple[Function, ...]
    observations: tuple[tuple[str, c.Observation], ...]  # (function id, observation)
    advisory: Mapping[str, tuple[tuple[str, c.Observation], ...]]  # CVE -> (source, adv:* observation)
    contexts: tuple[c.CveContext, ...]
    tool_keys: tuple[c.ToolKey, ...]
    secondary_set_ids: tuple[str, ...]
    kev_snapshot_id: str
    kev_listed: Mapping[str, str]  # CVE -> date added
    csaf: bytes
    csaf_sha256: str

    def function_of(self) -> dict[str, str]:
        """Candidate key -> function id (F1..F9)."""
        return {f.key: f.id for f in self.functions}

    def key_of(self, function_id: str) -> str:
        return next(f.key for f in self.functions if f.id == function_id)


def _read_json(name: str):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def _observation(document: dict) -> c.Observation:
    return c.Observation.model_validate_json(json.dumps(document))


@functools.cache
def expected() -> dict:
    return _read_json('expected.json')


@functools.cache
def load_ledger() -> Ledger:
    data = _read_json('ledger.json')
    functions = tuple(
        Function(id=item['id'], key=item['key'], identity=item['identity'], plan_evidence=item['plan_evidence'],
                 older=c.FunctionRef(**item['older']), newer=c.FunctionRef(**item['newer']))
        for item in data['candidates'])
    kev = data['kev']
    csaf = (FIXTURES / data['csaf']['file']).read_bytes()
    return Ledger(
        builds=data['builds'], functions=functions,
        observations=tuple((item['candidate'], _observation(item['observation'])) for item in data['observations']),
        advisory={cve: tuple((item['source'], _observation(item['observation'])) for item in items)
                  for cve, items in data['advisory_observations'].items()},
        contexts=tuple(c.CveContext.model_validate_json(json.dumps(item)) for item in data['cve_contexts']),
        tool_keys=tuple(c.ToolKey(**item) for item in data['tool_keys']),
        secondary_set_ids=tuple(data['secondary_set_ids']), kev_snapshot_id=kev['snapshot_id'],
        kev_listed={cve: entry['date_added'] for cve, entry in kev['entries'].items()},
        csaf=csaf, csaf_sha256=data['csaf']['sha256'])


# --- K: the advisory side, built by the real validator, normalizer and report builder ----------------------------------

def identities(older_sha256: str, newer_sha256: str) -> tuple[ArtifactIdentity, ArtifactIdentity]:
    """Record-only identities: no binary exists, so only the recorded SHA-256 maps a build to an advisory product."""
    note = 'synthetic fixture: no binary exists'
    return record_only('older', older_sha256, note), record_only('newer', newer_sha256, note)


def reports_for(raw: bytes, older: ArtifactIdentity, newer: ArtifactIdentity) -> dict[str, IntelligenceReport]:
    """The explain report of every CVE of one CSAF document (the real K pipeline, nothing stubbed)."""
    doc, validation = load_document(raw)
    assert validation.valid and not validation.warnings, 'the fixture advisory must be validator-clean'
    facts = norm.normalize(doc, validation, hashlib.sha256(raw).hexdigest())
    source = norm.make_source(doc, raw, origin='local-import', uri=None, file_name='advisory.json',
                              retrieved_at='2099-02-11T00:00:00Z')
    stored = StoredAdvisory(source=source, facts=facts, superseded=False, retrievals=1)
    return {cve: build_report(cve, [stored], older, newer) for cve in facts.cves()}


@functools.cache
def ledger_reports() -> dict[str, IntelligenceReport]:
    ledger = load_ledger()
    return reports_for(ledger.csaf, *identities(ledger.builds['older_sha256'], ledger.builds['newer_sha256']))


def window_from_reports(reports: Mapping[str, IntelligenceReport]) -> c.Confounding:
    """Several CVEs fixed on the newer build: shape alone cannot isolate one of them (s7; the CSAF-derived count)."""
    fixed = tuple(sorted(cve for cve, r in reports.items() if r.applicability.newer.resolution == 'fixed'))
    return c.Confounding(state='yes' if len(fixed) >= 2 else 'no', cves=fixed if len(fixed) >= 2 else ())


def derive_context(report: IntelligenceReport, kev: c.Kev, confounding: c.Confounding) -> c.CveContext:
    """The CVE context PIL-A2 will report for an advisory that applies (older affected, newer fixed, no contradiction).
    The oracle's advisories apply by construction; any other gate is a fixture bug and fails here."""
    a = report.applicability
    assert (a.older.resolution, a.newer.resolution) == ('affected', 'fixed') and not a.contradictions
    cwes = sorted({x.cwe_id for x in report.cwe_profile.classifications if x.confidence != 'weak'})
    return c.CveContext(
        cve=report.cve, source_ids=tuple(sorted(s.source.source_id for s in report.sources)), gate='applies',
        applicability=c.ApplicabilitySummary(older=a.older.resolution, newer=a.newer.resolution,
                                             older_mapping=a.older.product_mapping_status,
                                             newer_mapping=a.newer.product_mapping_status),
        cwe=c.CweSummary(status=report.cwe_profile.status, ids=tuple(cwes)), kev=kev, confounding=confounding,
        counts=ZERO_COUNTS)


# --- fake ports over plain data ---------------------------------------------------------------------------------------

class StaticPairing:
    """``PairingSource`` over a fixed candidate list; no unified result exists, the verdicts come from secondary sets."""

    def __init__(self, candidates: Sequence[c.Candidate], *, secondary_set_ids: Sequence[str] = ()):
        self._candidates = tuple(candidates)
        self._secondary = tuple(sorted(secondary_set_ids))

    def status(self) -> c.ChannelStatus:
        return c.ChannelStatus(channel='pairing', state='available')

    def candidates(self) -> Iterator[c.Candidate]:
        return iter(self._candidates)

    def unified_result_id(self) -> str | None:
        return None

    def secondary_set_ids(self) -> Sequence[str]:
        return self._secondary


class StaticEvidence:
    """``ChangeEvidenceSource`` and ``CallDeltaSource`` (one shape) over fixed (candidate key, observation) pairs."""

    def __init__(self, status: c.ChannelStatus, pairs: Sequence[tuple[str, c.Observation]]):
        self._status = status
        self._pairs = tuple(pairs)

    def status(self) -> c.ChannelStatus:
        return self._status

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, c.Observation]]:
        wanted = set(candidate_keys)
        return iter([(key, obs) for key, obs in self._pairs if key in wanted])


class StaticTools:
    """``ToolEvidenceSource``: capa, FLOSS and DiE as the T track will report them (function-attributed pairs, binary-level
    observations that apply to every lead, and the cache keys that identify the tool results)."""

    def __init__(self, statuses: Sequence[c.ChannelStatus], pairs: Sequence[tuple[str, c.Observation]],
                 pair_level: Sequence[c.Observation], tool_keys: Sequence[c.ToolKey]):
        self._statuses = tuple(statuses)
        self._pairs = tuple(pairs)
        self._pair_level = tuple(pair_level)
        self._keys = tuple(sorted(tool_keys, key=lambda k: (k.engine, k.side)))

    def statuses(self) -> Sequence[c.ChannelStatus]:
        return self._statuses

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, c.Observation]]:
        wanted = set(candidate_keys)
        return iter([(key, obs) for key, obs in self._pairs if key in wanted])

    def pair_observations(self) -> Sequence[c.Observation]:
        return self._pair_level

    def cache_keys(self) -> Sequence[c.ToolKey]:
        return self._keys


class StaticKev:
    """``KevSource`` over a snapshot: ``listed`` CVEs carry their date, other CVEs are absent from the snapshot (which says
    nothing about exploitation); without a snapshot every answer is ``unknown``."""

    def __init__(self, snapshot_id: str | None, listed: Mapping[str, str]):
        self._snapshot = snapshot_id
        self._listed = dict(listed)

    def lookup(self, cve: str) -> c.Kev:
        if self._snapshot is None:
            return c.Kev(state='unknown')
        if cve in self._listed:
            return c.Kev(state='listed', date_added=self._listed[cve], snapshot_id=self._snapshot)
        return c.Kev(state='not-in-snapshot', snapshot_id=self._snapshot)

    def snapshot_id(self) -> str | None:
        return self._snapshot


class StaticAdvisory:
    """``AdvisorySource`` over K reports (``intelligence/1`` ``IntelligenceReport``)."""

    def __init__(self, reports: Mapping[str, IntelligenceReport], facts_ids: Sequence[str]):
        self._reports = dict(reports)
        self._facts_ids = tuple(sorted(facts_ids))

    def cves(self) -> Sequence[str]:
        return tuple(sorted(self._reports))

    def report(self, cve: str) -> IntelligenceReport | None:
        return self._reports.get(cve)

    def facts_ids(self) -> Sequence[str]:
        return self._facts_ids


@dataclass(frozen=True)
class Sources:
    """Everything ``localize`` reads. The six ports are the A1 Protocols (provisional until PIL-A2/A3/B2); ``contexts`` are
    the per-CVE gate, CWE summary, KEV state and window as the A2 adapters report them (counts are zero: localization
    fills them); ``advisory_observations`` are the ``adv:*`` observations of every source that repeats the CWE."""
    project_id: str
    revision: int
    older_sha256: str
    newer_sha256: str
    ghidriff_run_id: str
    raw_sha256: str
    advisory: StaticAdvisory
    changes: StaticEvidence
    tools: StaticTools
    kev: StaticKev
    calls: StaticEvidence
    pairing: StaticPairing
    contexts: tuple[c.CveContext, ...]
    advisory_observations: Mapping[str, tuple[c.Observation, ...]]


# --- the arms ---------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Arm:
    """One run of the synergy ledger. ``sources`` are the evidence sources let through (advisory, b1, cf, calls, floss,
    capa, die, pairing); ``names`` False hides function names behind Ghidra placeholders (no locality); ``window`` is the
    state of the confounded window; the remaining fields are the knobs of single tests."""
    id: str
    sources: frozenset[str]
    names: bool = True
    window: str = 'yes'
    advisory_sources: frozenset[str] = ADVISORY_SOURCES
    kev: str = 'ledger'  # 'ledger': as the fixture; 'other': the other CVE is listed; 'unknown': no snapshot loaded
    binary_toolchain_flag: bool = False  # a binary-level DiE flag (applies to every lead) through pair_observations()
    dropped: frozenset[str] = frozenset()  # obs_ids removed from the ledger

    @property
    def code_only(self) -> bool:
        return 'advisory' not in self.sources

    def with_(self, **changes) -> Arm:
        return dataclasses.replace(self, **changes)


@functools.cache
def arms() -> dict[str, Arm]:
    return {arm_id: Arm(id=arm_id, sources=frozenset(item['sources']), names=item['names'], window=item['window'])
            for arm_id, item in expected()['arms'].items()}


def channel_statuses(arm: Arm) -> tuple[c.ChannelStatus, ...]:
    """Channel states of an arm: an excluded source is ``not-run`` (unknown, never a negative vote)."""
    s = arm.sources

    def one(channel: str, state: str, reason: str | None = None) -> c.ChannelStatus:
        return c.ChannelStatus(channel=channel, state=state, reason=reason)

    if {'b1', 'cf'} <= s:
        code = one('code', 'available')
    elif 'b1' in s:
        code = one('code', 'partial', 'ChangeFacts were not run')
    elif 'cf' in s:
        code = one('code', 'partial', 'B1 signals were not run')
    else:
        code = one('code', 'not-run', 'Neither B1 nor ChangeFacts was run')
    tools = {'floss': one('strings', 'available') if 'floss' in s else one('strings', 'not-run', 'FLOSS was not run'),
             'capa': one('capa', 'available') if 'capa' in s else one('capa', 'not-run', 'capa was not run'),
             'die': one('build', 'available') if 'die' in s else one('build', 'not-run', 'Detect It Easy was not run')}
    return (one('advisory', 'available') if 'advisory' in s else one('advisory', 'not-run', 'No advisory is loaded'),
            code,
            one('calls', 'partial', 'Ghidriff call labels only; no import delta') if 'calls' in s
            else one('calls', 'not-run', 'Call labels were not read'),
            tools['floss'], tools['capa'], tools['die'], one('pairing', 'available'))


def binary_toolchain_flag() -> c.Observation:
    return keys.make_observation(
        channel='build', kind='die:toolchain-changed', role='context', verification='tool-reported',
        origins=('D_compiler',), evidence_class='E-BUILD', ref=c.ObsRef(kind='die-flag', id='toolchain-changed-binary'),
        detail='Detect It Easy reports a different compiler or linker version for the two builds as a whole')


def _hidden_name(ledger: Ledger, rva: int) -> str:
    return f'FUN_{ledger.builds["image_base"] + rva:x}'  # a Ghidra placeholder: it says nothing about the code


def sources_for(arm: Arm, ledger: Ledger | None = None) -> Sources:
    """The ledger seen through an arm: a fake port per source, with the arm's excluded sources reported as ``not-run``."""
    ledger = ledger or load_ledger()
    candidates = []
    for f in sorted(ledger.functions, key=lambda item: item.older.rva):
        older, newer = (f.older, f.newer) if arm.names else (
            c.FunctionRef(rva=f.older.rva, name=_hidden_name(ledger, f.older.rva)),
            c.FunctionRef(rva=f.newer.rva, name=_hidden_name(ledger, f.newer.rva)))
        candidates.append(c.Candidate(candidate_key=f.key, older=(older,), newer=(newer,), identity=f.identity))
    by_source: dict[str, list[tuple[str, c.Observation]]] = {}
    for fid, obs in ledger.observations:
        source = SOURCE_OF_PREFIX[obs.kind.split(':', 1)[0]]
        if source in arm.sources and obs.obs_id not in arm.dropped:
            by_source.setdefault(source, []).append((ledger.key_of(fid), obs))
    statuses = {s.channel: s for s in channel_statuses(arm)}
    reports = {} if arm.code_only else ledger_reports()
    listed = {'ledger': dict(ledger.kev_listed), 'other': {'CVE-2099-20002': '2099-02-10'}, 'unknown': {}}[arm.kev]
    kev = StaticKev(None if arm.kev == 'unknown' else ledger.kev_snapshot_id, listed)
    contexts = () if arm.code_only else tuple(
        ctx.model_copy(update={'kev': kev.lookup(ctx.cve), 'confounding': (
            c.Confounding(state='unknown') if arm.window == 'unknown' else ctx.confounding)})
        for ctx in ledger.contexts)
    tool_sources = [s for s in ('capa', 'floss', 'die') if s in arm.sources]
    tools = StaticTools(
        [statuses['strings'], statuses['capa'], statuses['build']],
        [pair for s in tool_sources for pair in by_source.get(s, [])],
        [binary_toolchain_flag()] if arm.binary_toolchain_flag else [],
        [k for k in ledger.tool_keys if any(ENGINE_OF_SOURCE[s] == k.engine for s in tool_sources)])
    changes = [pair for s in ('b1', 'cf') for pair in by_source.get(s, [])]
    advisory_observations = {
        cve: tuple(obs for source, obs in items if source in arm.advisory_sources)
        for cve, items in ledger.advisory.items()} if not arm.code_only else {}
    return Sources(
        project_id=ledger.builds['project_id'], revision=ledger.builds['revision'],
        older_sha256=ledger.builds['older_sha256'], newer_sha256=ledger.builds['newer_sha256'],
        ghidriff_run_id=ledger.builds['ghidriff_run_id'], raw_sha256=ledger.builds['raw_sha256'],
        advisory=StaticAdvisory(reports, {s.facts_id for r in reports.values() for s in r.sources}),
        changes=StaticEvidence(statuses['code'], changes), tools=tools, kev=kev,
        calls=StaticEvidence(statuses['calls'], by_source.get('calls', [])),
        pairing=StaticPairing(candidates, secondary_set_ids=ledger.secondary_set_ids),
        contexts=contexts, advisory_observations=advisory_observations)


# --- the seam to PIL-B2 -----------------------------------------------------------------------------------------------

def engine():
    """``patchtrace.pilot.service.localize``; ``EngineMissing`` while PIL-B2 is not built. Any other import error is real."""
    try:
        module = importlib.import_module('patchtrace.pilot.service')
    except ModuleNotFoundError as exc:
        if exc.name != 'patchtrace.pilot.service':
            raise
        raise EngineMissing('PIL-B2 (patchtrace.pilot.service.localize) is not built yet') from exc
    return module.localize


def localize(sources: Sources, config: c.PilotConfig | None = None,
             cancel: threading.Event | None = None) -> c.PilotAssessment:
    """THE seam: adapt this one function to PIL-B2's input bundle if it differs from ``Sources``."""
    run = engine()
    return run(sources, config or keys.default_config(), cancel or threading.Event())


def run_arm(arm: Arm | str, ledger: Ledger | None = None) -> c.PilotAssessment:
    arm = arms()[arm] if isinstance(arm, str) else arm
    ledger = ledger or load_ledger()
    return localize(sources_for(arm, ledger))


# --- reading an assessment --------------------------------------------------------------------------------------------

def lead_map(assessment: c.PilotAssessment, cve: str | None, ledger: Ledger | None = None) -> dict[str, c.Lead]:
    """Function id (F1..F9) -> the lead of one context (a CVE, or None for code evidence only)."""
    function_of = (ledger or load_ledger()).function_of()
    out = {function_of[lead.candidate_key]: lead for lead in assessment.leads if lead.cve == cve}
    assert len(out) == sum(1 for lead in assessment.leads if lead.cve == cve), 'one lead per candidate and context'
    return out


def ranked(leads: Mapping[str, c.Lead]) -> list[str]:
    return [fid for fid, _ in sorted(leads.items(), key=lambda item: item[1].rank)]


def tie_partners(leads: Mapping[str, c.Lead], fid: str) -> list[str]:
    """The other leads that share this lead's tie group."""
    return sorted(other for other, lead in leads.items() if other != fid and lead.tie == leads[fid].tie)


def classes(leads: Mapping[str, c.Lead], name: str) -> list[str]:
    return sorted(fid for fid, lead in leads.items() if lead.lead_class == name)
