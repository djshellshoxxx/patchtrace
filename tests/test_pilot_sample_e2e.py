"""PIL-T: the patch-intent oracle on the committed sample project (docs/specs/program-e/PIL-integration-plan.md s5, s9).

The sample (`patchtrace.sample`) is a synthetic PE pair whose `read_item` gained a bounds check, `get_version` changed a
constant, `report_invalid_index` was added and `debug_dump` deleted. With a CWE-125 CSAF advisory
(`tests/fixtures/pilot/synergy-1/sample-cwe125-advisory.json`) the plan expects: `read_item` FITS ADVISORY on text
evidence only, `get_version` CHANGED, NO FIT, and the added `report_invalid_index` only as context on its caller.

What passes today: the advisory and the B1 evidence the scenario rests on are real (the K validator and applicability,
B1 `signals.detect` on the project's own decompiled code) and the ledger built from them is valid pilot/1 data. The
verdict itself needs PIL-B2 (``PIL_B2``: xfail strict, expects only ``EngineMissing``). Synthetic data only.
"""
from __future__ import annotations

import hashlib
import struct

import pytest
from pilot_synergy_support import (
    FIXTURES,
    PIL_B2,
    ZERO_COUNTS,
    Sources,
    StaticAdvisory,
    StaticEvidence,
    StaticKev,
    StaticPairing,
    StaticTools,
    assert_strictly_pending,
    derive_context,
    localize,
    reports_for,
    window_from_reports,
)

from patchtrace.enrichment import signals
from patchtrace.enrichment.views import build_views
from patchtrace.intelligence.csaf.identity import project_identities
from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, ports
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.unified import keys as unified_keys

CVE = 'CVE-2099-30001'
CSAF = FIXTURES / 'sample-cwe125-advisory.json'
IMAGE_BASE = 0x180000000  # the ImageBase of `synthetic_pe` (asserted against the PE header below)


@pytest.fixture
def project(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        yield service


def advisory_reports(service):
    raw = CSAF.read_bytes()
    return raw, reports_for(raw, *project_identities(service.project.artifacts, service.root))


def rvas(functions) -> list[int]:
    return [f.address - IMAGE_BASE for f in functions]


def b1_observation(view, signal) -> c.Observation:
    """A B1 signal as a ledger observation: the shape of a guard, read from decompiled text (tool-reported, lexical)."""
    where = next(loc for loc in signal.locations if loc.side == 'newer')
    return keys.make_observation(
        channel='code', kind=f'b1:{signal.detector}', role='shape', verification='tool-reported',
        origins=('D_ghidra',), evidence_class='E-DECOMP', ref=c.ObsRef(kind='b1-signal', id=signal.signal_id),
        nav=c.Nav(side='newer', rva=rvas(view.newer)[0], start_line=where.start_line, end_line=where.end_line),
        detail=c.clean_line(signal.rationale))


def call_observation(callee: str) -> c.Observation:
    """A callee that exists only on the newer side, from Ghidriff's `called` labels (no import or IR proof)."""
    return keys.make_observation(
        channel='calls', kind='call:added', role='context', verification='label-only', origins=('D_ghidra',),
        evidence_class='E-CALL', ref=c.ObsRef(kind='call-label', id=callee),
        detail=c.clean_line(f'call to {callee} added (label only)'))


def sample_sources(service) -> tuple[Sources, dict[str, str], dict[str, c.Observation]]:
    """The sample project through the ports, from its own B1 signals and Ghidriff labels (a stand-in for PIL-A3)."""
    run = build_views(service.project)
    older_sha, newer_sha = run.older_sha256, run.newer_sha256
    by_id = {m.id: m for m in service.project.matches}
    candidates, names, evidence, calls = [], {}, [], []
    for view in run.matches:
        older, newer = rvas(view.older), rvas(view.newer)
        key = keys.candidate_key(older_sha, newer_sha, older, newer)
        name = (view.newer or view.older)[0].name
        names[key] = name
        candidates.append(c.Candidate(
            candidate_key=key, identity='unassessed',  # neither a unified result nor a secondary verdict exists
            older=tuple(c.FunctionRef(rva=r, name=f.name) for r, f in zip(older, view.older, strict=True)),
            newer=tuple(c.FunctionRef(rva=r, name=f.name) for r, f in zip(newer, view.newer, strict=True))))
        evidence += [(key, b1_observation(view, s)) for s in signals.detect(view).signals]
        match = by_id[view.match_id]
        if match.older and match.newer:
            added = sorted(set(match.newer[0].callees) - set(match.older[0].callees))
            calls += [(key, call_observation(callee)) for callee in added]
    raw, reports = advisory_reports(service)
    csaf_sha = hashlib.sha256(raw).hexdigest()
    context = derive_context(reports[CVE], c.Kev(state='unknown'), window_from_reports(reports))
    stated = keys.make_observation(
        channel='advisory', kind='adv:cwe-stated', role='context', verification='advisory-claim',
        origins=('D_vendor_text',), evidence_class='E-TEXT',
        ref=c.ObsRef(kind='csaf-fact', id=CVE, pointer='/vulnerabilities/0/cwe', sha256=csaf_sha),
        detail='CWE-125 as stated by the advisory')
    not_run = [c.ChannelStatus(channel=ch, state='not-run', reason=f'{tool} was not run')
               for ch, tool in (('strings', 'FLOSS'), ('capa', 'capa'), ('build', 'Detect It Easy'))]
    sources = Sources(
        project_id=service.project.id, revision=service.project.revision, older_sha256=older_sha,
        newer_sha256=newer_sha, ghidriff_run_id=run.run_id, raw_sha256=run.raw_sha256,
        advisory=StaticAdvisory(reports, {s.facts_id for r in reports.values() for s in r.sources}),
        changes=StaticEvidence(c.ChannelStatus(channel='code', state='partial', reason='ChangeFacts were not run'),
                               evidence),
        tools=StaticTools(not_run, [], [], []), kev=StaticKev(None, {}),
        calls=StaticEvidence(c.ChannelStatus(channel='calls', state='partial',
                                             reason='Ghidriff call labels only; no import delta'), calls),
        pairing=StaticPairing(candidates), contexts=(context,), advisory_observations={CVE: (stated,)})
    return sources, names, {'adv': stated, **{obs.ref.id: obs for _, obs in calls}}


# --- the premises of the scenario are real -------------------------------------------------------------------------------

def test_the_sample_advisory_is_validator_clean_and_maps_the_sample_builds(project):
    raw, reports = advisory_reports(project)
    sides = {a.side: a.sha256 for a in project.project.artifacts}
    assert sides == {'older': hashlib.sha256(synthetic_pe(0)).hexdigest(), 'newer': hashlib.sha256(synthetic_pe(1)).hexdigest()}
    report = reports[CVE]
    assert list(reports) == [CVE]  # one CVE fixed on the newer build: no confounded window
    window = window_from_reports(reports)
    assert (window.state, window.cves) == ('no', ())
    a = report.applicability
    assert (a.older.resolution, a.newer.resolution) == ('affected', 'fixed') and not a.contradictions
    assert (a.older.product_mapping_status, a.newer.product_mapping_status) == ('verified', 'verified')  # real bytes
    assert report.cwe_profile.status == 'explicit' and report.cwe_profile.classifications[0].cwe_id == 'CWE-125'
    assert report.hypotheses.hypotheses[0].rule_id == 'R-MEMORY-READ'
    assert hashlib.sha256(raw).hexdigest() == report.sources[0].source.sha256


def test_the_image_base_is_the_one_of_the_synthetic_pe():
    image = synthetic_pe(0)
    optional = 0x98  # the optional header of `synthetic_pe`
    assert struct.unpack_from('<Q', image, optional + 24)[0] == IMAGE_BASE


def test_b1_finds_the_bounds_check_in_read_item_and_nothing_in_get_version(project):
    run = build_views(project.project)
    found = {}
    for view in run.matches:
        result = signals.detect(view)
        found[(view.newer or view.older)[0].name] = (view.category, [s.detector for s in result.signals], result.status)
    assert found['read_item'] == ('modified', ['BND'], 'complete')
    assert found['get_version'] == ('modified', [], 'complete')
    assert found['report_invalid_index'][0] == 'added' and found['report_invalid_index'][1] == []
    assert found['debug_dump'][0] == 'removed' and found['debug_dump'][1] == []  # one-sided: nothing to compare
    (signal,) = [s for v in run.matches if v.category == 'modified' and v.newer[0].name == 'read_item'
                 for s in signals.detect(v).signals]
    assert signal.confidence == 'moderate' and signal.typed_evidence is False  # lexical: "text evidence only"


def test_the_sample_ledger_is_valid_pilot_data(project):
    sources, names, extra = sample_sources(project)
    older, newer = sources.older_sha256, sources.newer_sha256
    candidates = list(sources.pairing.candidates())
    assert sorted(names.values()) == ['debug_dump', 'get_version', 'read_item', 'report_invalid_index']
    for cand in candidates:
        old, new = [f.rva for f in cand.older], [f.rva for f in cand.newer]
        assert cand.candidate_key == keys.candidate_key(older, newer, old, new)
        assert cand.candidate_key == unified_keys.row_id(older, newer, old, new)
        assert cand.identity == 'unassessed'
    by_name = {names[x.candidate_key]: x for x in candidates}
    assert [f.rva for f in by_name['read_item'].older] == [0x1000] and [f.rva for f in by_name['read_item'].newer] == [0x1080]
    assert [f.rva for f in by_name['report_invalid_index'].newer] == [0x1200] and not by_name['report_invalid_index'].older
    keys_ = [x.candidate_key for x in candidates]
    shape = [(names[key], obs.kind, obs.role) for key, obs in sources.changes.observations(keys_)]
    assert shape == [('read_item', 'b1:BND', 'shape')]
    calls = [(names[key], obs.kind, obs.ref.id, obs.role) for key, obs in sources.calls.observations(keys_)]
    assert calls == [('read_item', 'call:added', 'report_invalid_index', 'context')]  # context on its caller
    assert extra['report_invalid_index'].verification == 'label-only'
    for port, protocol in ((sources.advisory, ports.AdvisorySource), (sources.changes, ports.ChangeEvidenceSource),
                           (sources.tools, ports.ToolEvidenceSource), (sources.kev, ports.KevSource),
                           (sources.calls, ports.CallDeltaSource), (sources.pairing, ports.PairingSource)):
        assert isinstance(port, protocol)
    (context,) = sources.contexts
    assert (context.gate, context.confounding.state, context.counts) == ('applies', 'no', ZERO_COUNTS)
    assert context.kev.state == 'unknown' and context.cwe.ids == ('CWE-125',)
    assert {s.state for s in sources.tools.statuses()} == {'not-run'}  # unknown, never a negative vote


# --- the verdict: PIL-B2 ------------------------------------------------------------------------------------------------

def referenced(lead: c.Lead) -> set[str]:
    return {*lead.support_ids, *lead.counter_ids, *lead.unknown_ids, *lead.alternative_ids}


@PIL_B2
def test_pilot_sample_project_end_to_end(project):
    sources, names, extra = sample_sources(project)
    assessment = localize(sources)
    keys.verify_assessment(assessment)
    leads = {names[lead.candidate_key]: lead for lead in assessment.leads if lead.cve == CVE}
    assert sorted(leads) == ['debug_dump', 'get_version', 'read_item', 'report_invalid_index']
    read_item = leads['read_item']
    assert (read_item.lead_class, read_item.mechanism, read_item.rank) == ('fit', 'moderate', 1)  # FITS ADVISORY
    assert read_item.depth == 'lexical'  # text evidence only: B1 reads decompiled text, no typed ChangeFacts
    assert (read_item.gate, read_item.identity, read_item.components.count) == ('applies', 'unassessed', 2)
    best = read_item.fits[0]
    assert (best.rule_id, best.cwe_id, best.basis, best.met) == ('R-MEMORY-READ', 'CWE-125', 'explicit-csaf-cwe', 1)
    guard = next(e for e in best.expected_changes if e.id == 'guard-added')
    assert guard.state == 'met' and guard.required
    pool = {o.obs_id: o for o in assessment.observations}
    assert [pool[i].kind for i in guard.observation_ids] == ['b1:BND']
    assert leads['get_version'].lead_class == 'queue'  # CHANGED, NO FIT
    for name in ('debug_dump', 'report_invalid_index'):  # one-sided functions never fit on their own
        assert leads[name].lead_class not in ('fit', 'review', 'partial'), name
    added = extra['report_invalid_index']  # the added function is context on its caller, and only there
    assert pool[added.obs_id].role == 'context' and added.obs_id in referenced(read_item)
    assert all(added.obs_id not in referenced(lead) for name, lead in leads.items() if name != 'read_item')
    (context,) = assessment.cves
    assert context.counts.fit == 1 and context.confounding.state == 'no' and context.kev.state == 'unknown'
    assert {x.channel: x.state for x in assessment.channels}['capa'] == 'not-run'


def test_the_end_to_end_verdict_is_strictly_pending_until_the_engine_exists():
    assert_strictly_pending(test_pilot_sample_project_end_to_end)
