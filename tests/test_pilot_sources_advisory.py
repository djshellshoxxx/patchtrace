"""PIL-A2 advisory-side adapters: `pilot/sources/{advisory,identity,kev,window,snapshot}.py`
(docs/specs/program-e/PIL-integration-plan.md s4, s7, s9 "PIL-A2").

SYNTHETIC data only: the K fixtures under tests/fixtures/csaf (CVE-2099-*), the trimmed provider responses of
tests/fixtures/cve and fakes for the KEV and KB tracks, which are not built yet. Nothing here is live evidence.

Mandatory gates of PIL-A2: `test_cve_gate_table`, `test_kev_absence_is_unknown_context`,
`test_unified_beats_secondary_for_identity`, `test_confounding_counts_cves_fixed_on_newer`, and every `detail`
passing `sanitize_text`.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import itertools
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import get_args

import pytest

import patchtrace.pilot.sources as sources_package
from patchtrace.enrichment import cve as b3
from patchtrace.enrichment.contracts import AttributedText, AttributedValue, CveSnapshot
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence import contracts as intel
from patchtrace.intelligence.csaf import normalize as norm
from patchtrace.intelligence.csaf.applicability import supersession
from patchtrace.intelligence.csaf.identity import project_identities, record_only
from patchtrace.intelligence.csaf.validate import load_document
from patchtrace.intelligence.explain import build_report
from patchtrace.intelligence.hypotheses import hypotheses_for
from patchtrace.intelligence.lexicon import classify
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.pilot import contracts, keys, origins, ports
from patchtrace.pilot.limits import PilotError
from patchtrace.pilot.sources import advisory, snapshot, window
from patchtrace.pilot.sources import identity as pairing
from patchtrace.pilot.sources import kev as kev_port
from patchtrace.sample import synthetic_pe
from patchtrace.secondary.evidence import Verdict
from patchtrace.secondary.evidence_view import sanitize_text
from patchtrace.service import ProjectService
from patchtrace.unified.contracts import Decision

ROOT = Path(__file__).resolve().parents[1]
CSAF = ROOT / 'tests' / 'fixtures' / 'csaf'
PROVIDER = ROOT / 'tests' / 'fixtures' / 'cve'
PACKAGE = Path(sources_package.__file__).parent  # the package under test, wherever it is imported from
REV1 = (CSAF / 'synthetic-advisory-rev1.json').read_bytes()
REV2 = (CSAF / 'synthetic-advisory-rev2.json').read_bytes()
VEX = (CSAF / 'synthetic-vex.json').read_bytes()
HOSTILE = (CSAF / 'injection' / 'hostile-advisory.json').read_bytes()
CVE1, CVE2 = 'CVE-2099-10001', 'CVE-2099-10002'
REV1_SHA = hashlib.sha256(REV1).hexdigest()
OLDER = intel.ArtifactIdentity(side='older', sha256=hashlib.sha256(synthetic_pe(0)).hexdigest(),
                               facts_state='verified-bytes')
NEWER = intel.ArtifactIdentity(side='newer', sha256=hashlib.sha256(synthetic_pe(1)).hexdigest(),
                               facts_state='verified-bytes')
UNMAPPED = (record_only('older', 'e' * 64, 'unit test'), record_only('newer', 'f' * 64, 'unit test'))
H = {name: hashlib.sha256(name.encode()).hexdigest() for name in ('snapshot', 'kb', 'other')}
NO_COUNTS = contracts.LeadCounts(fit=0, review=0, partial=0, code=0, queue=0)
UNKNOWN_WINDOW = contracts.Confounding(state='unknown')
BANNED = ('probab', 'likelihood', 'confidence', 'percent', 'vulnerab', 'exploit', 'proven', 'certain', 'verified',
          'safe', 'secure')
V, C, U = 'verified', 'candidate', 'unknown'


# --- helpers ------------------------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Stored:
    """What `intelligence.explain.AdvisoryLike` reads of a stored advisory."""
    source: intel.AdvisorySource
    facts: intel.AdvisoryFacts
    superseded: bool


def stored(*documents: bytes) -> list[Stored]:
    """The K pipeline (validate, normalize, supersession) over fixture bytes, without a project store."""
    parsed = []
    for day, raw in enumerate(documents, start=1):
        doc, report = load_document(raw)
        sha = hashlib.sha256(raw).hexdigest()
        source = norm.make_source(doc, raw, origin='local-import', uri=None, file_name='advisory.json',
                                  retrieved_at=f'2099-03-0{day}T00:00:00Z')
        parsed.append((source, norm.normalize(doc, report, sha)))
    flags = supersession([facts for _, facts in parsed])
    return [Stored(source, facts, flags[facts.facts_id]) for source, facts in parsed]


def reports(*documents: bytes, pair=(OLDER, NEWER)) -> dict[str, intel.IntelligenceReport]:
    advisories = stored(*documents)
    return {cve: build_report(cve, advisories, *pair)
            for cve in sorted({c for a in advisories for c in a.facts.cves()})}


def edited(raw: bytes, change) -> bytes:
    doc = json.loads(raw)
    change(doc)
    return json.dumps(doc).encode()


def withdraw_second_cve(doc: dict) -> None:
    del doc['vulnerabilities'][1]


def other_cves(doc: dict) -> None:
    for index, item in enumerate(doc['vulnerabilities']):
        item['cve'] = f'CVE-2099-3000{index}'


def sums(**fields) -> contracts.ApplicabilitySummary:
    base = dict(older='affected', newer='fixed', older_mapping=V, newer_mapping=V, contradictions=0)
    return contracts.ApplicabilitySummary(**{**base, **fields})


def classification(cwe: str, confidence: str = 'phrase-match') -> intel.CweClassification:
    return intel.CweClassification(cwe_id=cwe, family='input', basis='curated-vocabulary', confidence=confidence,
                                   assessment='rule-hypothesis')


def profile(status: str, *classifications: intel.CweClassification) -> intel.CweProfile:
    return intel.CweProfile(cve=CVE1, lexicon_version='x', lexicon_digest=H['other'], status=status,
                            classifications=tuple(classifications))


def with_profile(report: intel.IntelligenceReport, cwe_profile: intel.CweProfile) -> intel.IntelligenceReport:
    return report.model_copy(update={'cwe_profile': cwe_profile, 'hypotheses': hypotheses_for(cwe_profile)})


def with_resolutions(report: intel.IntelligenceReport, older: str, newer: str) -> intel.IntelligenceReport:
    """A real report whose two sides were re-resolved to the given resolutions."""
    sides = {side: getattr(report.applicability, side).model_copy(update={'resolution': value})
             for side, value in (('older', older), ('newer', newer))}
    return report.model_copy(update={'applicability': report.applicability.model_copy(update=sides)})


def snap(cwes=(), descriptions=(('nvd', 'en', 'A flaw in a network stack.'),), conflicts=(),
         cve_id='CVE-2099-40001') -> CveSnapshot:
    """A synthetic provider snapshot (the strict B3 record built directly)."""
    return CveSnapshot(
        snapshot_id=H['snapshot'], cve_id=cve_id, normalization_version=1, response_digests={'nvd': H['other']},
        retrieved_at='2099-03-01T00:00:00Z',
        descriptions=tuple(AttributedText(source=s, lang=lang, text=t) for s, lang, t in descriptions),
        cwes=tuple(AttributedValue(source=s, value=v) for s, v in cwes), conflicts=tuple(conflicts))


def details(*contexts: advisory.AdvisoryContext) -> list[str]:
    return [o.detail for ctx in contexts for o in ctx.observations]


@pytest.fixture(scope='module')
def single():
    return reports(REV1)


@pytest.fixture(scope='module')
def conflicted():
    return reports(REV1, REV2, VEX)


@pytest.fixture(scope='module')
def hostile():
    return reports(HOSTILE)


@pytest.fixture(scope='module')
def provider_snapshot() -> CveSnapshot:
    responses = {'nvd': (PROVIDER / 'nvd_CVE-2024-38063.json').read_bytes(),
                 'msrc': (PROVIDER / 'msrc_CVE-2024-38063.json').read_bytes()}
    return b3.normalize('CVE-2024-38063', responses, '2026-10-12T00:00:00Z')


# --- the CVE gate (s7 "CVE gate"): test_cve_gate_table ------------------------------------------------------------

GATE_ROWS = [
    # id, older, newer, older mapping, newer mapping, contradictions, assumed, gate
    ('applies', 'affected', 'fixed', V, V, 0, False, 'applies'),
    ('applies-newer-not-affected', 'affected', 'not_affected', V, V, 0, False, 'applies'),
    ('applies-candidates', 'affected', 'fixed', C, C, 0, False, 'applies'),
    ('applies-mixed', 'affected', 'fixed', V, C, 0, False, 'applies'),
    ('older-unmapped', U, 'fixed', U, V, 0, False, 'unverified'),
    ('newer-unmapped', 'affected', U, V, U, 0, False, 'unverified'),
    ('both-unmapped', U, U, U, U, 0, False, 'unverified'),
    ('older-without-status', U, 'fixed', V, V, 0, False, 'unverified'),
    ('older-ambiguous', 'ambiguous', 'fixed', V, V, 0, False, 'unverified'),
    ('newer-ambiguous', 'affected', 'ambiguous', V, V, 0, False, 'unverified'),
    ('older-under-investigation', 'under_investigation', 'fixed', V, V, 0, False, 'unverified'),
    ('newer-under-investigation', 'affected', 'under_investigation', V, V, 0, False, 'unverified'),
    ('older-fixed-newer-unknown', 'fixed', U, V, V, 0, False, 'unverified'),
    ('both-fixed', 'fixed', 'fixed', V, V, 0, False, 'not-applicable'),
    ('both-not-affected', 'not_affected', 'not_affected', V, V, 0, False, 'not-applicable'),
    ('fixed-then-not-affected', 'fixed', 'not_affected', V, V, 0, False, 'not-applicable'),
    ('older-not-affected', 'not_affected', 'fixed', V, V, 0, False, 'not-applicable'),
    ('older-not-affected-newer-unknown', 'not_affected', U, V, U, 0, False, 'not-applicable'),
    ('older-not-affected-newer-ambiguous', 'not_affected', 'ambiguous', V, V, 0, False, 'not-applicable'),
    ('newer-still-affected', 'affected', 'affected', V, V, 0, False, 'not-applicable'),
    ('older-unmapped-newer-affected', U, 'affected', U, V, 0, False, 'not-applicable'),
    ('older-investigated-newer-affected', 'under_investigation', 'affected', V, V, 0, False, 'not-applicable'),
    ('newer-contradictory', 'affected', 'contradictory', V, V, 0, False, 'conflict'),
    ('older-contradictory', 'contradictory', 'fixed', V, V, 0, False, 'conflict'),
    ('contradiction-elsewhere', 'affected', 'fixed', V, V, 1, False, 'conflict'),
    ('orientation-contradiction', 'fixed', 'affected', V, V, 1, False, 'conflict'),
    ('both-fixed-contradiction', 'fixed', 'fixed', V, V, 2, False, 'conflict'),
    ('unmapped-contradiction', U, U, U, U, 1, False, 'conflict'),
    ('assume-unmapped', U, U, U, U, 0, True, 'asserted'),
    ('assume-without-status', U, 'fixed', V, V, 0, True, 'asserted'),
    ('assume-ambiguous', 'affected', 'ambiguous', V, V, 0, True, 'asserted'),
    ('assume-already-applies', 'affected', 'fixed', V, V, 0, True, 'applies'),
    ('assume-keeps-conflict', 'affected', 'fixed', V, V, 1, True, 'conflict'),
    ('assume-keeps-not-applicable', 'affected', 'affected', V, V, 0, True, 'not-applicable'),
    ('assume-keeps-older-not-affected', 'not_affected', U, V, U, 0, True, 'not-applicable'),
]


@pytest.mark.parametrize('older, newer, om, nm, contradictions, assumed, gate',
                         [row[1:] for row in GATE_ROWS], ids=[row[0] for row in GATE_ROWS])
def test_cve_gate_table(older, newer, om, nm, contradictions, assumed, gate):
    summary = sums(older=older, newer=newer, older_mapping=om, newer_mapping=nm, contradictions=contradictions)
    assert advisory.cve_gate(summary, assumed=assumed) == gate


FIXED_LIKE = {'fixed', 'not_affected'}


def gate_oracle(older: str, newer: str, contradictions: int, assumed: bool) -> str:
    """The s7 table as a decision list, written independently of the implementation."""
    if contradictions or 'contradictory' in (older, newer):
        base = 'conflict'
    elif older == 'not_affected' or newer == 'affected' or (older in FIXED_LIKE and newer in FIXED_LIKE):
        base = 'not-applicable'
    elif {older, newer} & {'unknown', 'ambiguous', 'under_investigation'}:
        base = 'unverified'
    else:
        assert older == 'affected' and newer in FIXED_LIKE
        base = 'applies'
    return 'asserted' if assumed and base == 'unverified' else base


def mapping_options(resolution: str) -> tuple[str, ...]:
    return (U, V, C) if resolution == 'unknown' else (V, C)  # an unmapped side always abstains


def test_cve_gate_agrees_with_the_table_for_every_combination():
    count = 0
    for older, newer in itertools.product(get_args(contracts.Resolution), repeat=2):
        for om, nm in itertools.product(mapping_options(older), mapping_options(newer)):
            for contradictions, assumed in itertools.product((0, 1, 3), (False, True)):
                summary = sums(older=older, newer=newer, older_mapping=om, newer_mapping=nm,
                               contradictions=contradictions)
                expected = gate_oracle(older, newer, contradictions, assumed)
                assert advisory.cve_gate(summary, assumed=assumed) == expected, summary
                count += 1
    assert count == (3 + 6 * 2) ** 2 * 3 * 2  # (mapping options per resolution)^2 x contradictions x assumed


def test_an_assumption_only_fills_a_gap_it_never_overrides_the_advisory():
    seen = set()
    for older, newer in itertools.product(get_args(contracts.Resolution), repeat=2):
        om, nm = (U if older == 'unknown' else V), (U if newer == 'unknown' else V)
        for contradictions in (0, 1):
            summary = sums(older=older, newer=newer, older_mapping=om, newer_mapping=nm, contradictions=contradictions)
            plain, assumed = advisory.cve_gate(summary), advisory.cve_gate(summary, assumed=True)
            assert assumed == ('asserted' if plain == 'unverified' else plain)
            seen.add((plain, assumed))
    assert seen == {('applies', 'applies'), ('conflict', 'conflict'), ('not-applicable', 'not-applicable'),
                    ('unverified', 'asserted')}


def test_the_gate_of_a_record_with_an_advisory_is_never_none():
    gates = {advisory.cve_gate(sums(older=o, newer=n, older_mapping=U if o == 'unknown' else V,
                                    newer_mapping=U if n == 'unknown' else V), assumed=a)
             for o, n in itertools.product(get_args(contracts.Resolution), repeat=2) for a in (False, True)}
    assert gates == set(get_args(contracts.ContextGate)) and 'none' not in gates


def test_real_reports_get_the_gates_the_advisory_supports(single, conflicted):
    def gate(report, **kw):
        return advisory.cve_gate(advisory.applicability_summary(report.applicability), **kw)
    assert gate(single[CVE1]) == 'applies'  # older affected, newer fixed, mapped through verified file hashes
    assert gate(single[CVE2]) == 'unverified'  # mapped, but the advisory has no status for this CVE
    assert gate(single[CVE2], assumed=True) == 'asserted'
    # a revision flip and a VEX contradiction on products of the other architecture are still contradictions
    assert gate(conflicted[CVE1]) == 'conflict' and gate(conflicted[CVE1], assumed=True) == 'conflict'
    unmapped = reports(REV1, pair=UNMAPPED)
    assert gate(unmapped[CVE1]) == 'unverified' and gate(unmapped[CVE1], assumed=True) == 'asserted'


def test_applicability_summary_restates_the_k_report(single, conflicted):
    assert advisory.applicability_summary(single[CVE1].applicability) == contracts.ApplicabilitySummary(
        older='affected', newer='fixed', older_mapping='candidate', newer_mapping='candidate', contradictions=0)
    assert advisory.applicability_summary(single[CVE2].applicability) == contracts.ApplicabilitySummary(
        older='unknown', newer='unknown', older_mapping='verified', newer_mapping='verified', contradictions=0)
    assert advisory.applicability_summary(conflicted[CVE1].applicability).contradictions == 2


# --- the CWE summary ----------------------------------------------------------------------------------------------

def test_cwe_summary_lists_the_usable_ids(single):
    assert advisory.cwe_summary(single[CVE1].cwe_profile) == contracts.CweSummary(
        status='explicit', ids=('CWE-122', 'CWE-191'))
    assert advisory.cwe_summary(single[CVE2].cwe_profile) == contracts.CweSummary(status='derived', ids=('CWE-416',))


def test_cwe_summary_weak_vague_and_none():
    weak = profile('weak', classification('CWE-20', 'weak'))
    assert advisory.cwe_summary(weak) == contracts.CweSummary(status='weak', ids=('CWE-20',))
    mixed = profile('derived', classification('CWE-787'), classification('CWE-20', 'weak'))
    assert advisory.cwe_summary(mixed).ids == ('CWE-787',)  # a weak match beside a usable one is noise
    for status in ('vague', 'none'):
        assert advisory.cwe_summary(profile(status)) == contracts.CweSummary(status=status, ids=())
    vague = profile('vague', classification('CWE-20', 'weak'))  # vague text lists nothing, even a weak match
    assert advisory.cwe_summary(vague) == contracts.CweSummary(status='vague', ids=())


def test_cwe_summary_keeps_the_first_sixteen_in_k_order():
    many = profile('derived', *(classification(f'CWE-{n}') for n in range(1, 21)))
    summary = advisory.cwe_summary(many)
    assert len(summary.ids) == 16 and list(summary.ids) == sorted(summary.ids)
    assert summary.ids == tuple(sorted(c.cwe_id for c in many.classifications[:16]))


# --- the advisory context from a K report -------------------------------------------------------------------------

def test_context_from_report_restates_the_k_report(single):
    report = single[CVE1]
    ctx = advisory.context_from_report(report)
    assert (ctx.cve, ctx.gate) == (CVE1, 'applies')
    assert ctx.applicability == advisory.applicability_summary(report.applicability)
    assert ctx.cwe == contracts.CweSummary(status='explicit', ids=('CWE-122', 'CWE-191'))
    assert ctx.source_ids == (REV1_SHA,) and ctx.facts_ids == (report.sources[0].facts_id,)
    assert ctx.hypotheses == report.hypotheses.hypotheses
    assert [h.rule_id for h in ctx.hypotheses] == ['R-INTEGER', 'R-MEMORY-WRITE']
    assert ctx.anchors == report.anchors.anchors
    assert ('advisory authenticity is unverified: a local file was imported and signatures are not checked'
            in ctx.limitations)
    assert report.limitations[0] in ctx.limitations
    assert any('differ' in line for line in ctx.limitations)  # explicit CWE-191 and the wording-derived CWE-122


def test_the_advisory_ledger_has_one_entry_per_usable_cwe(single):
    ctx = advisory.context_from_report(single[CVE1])
    derived, stated = sorted(ctx.observations, key=lambda o: o.kind)
    assert (stated.kind, stated.verification, stated.role, stated.channel) == (
        'adv:cwe-stated', 'advisory-claim', 'context', 'advisory')
    assert stated.detail == 'CWE-191 as stated by the advisory'
    assert stated.ref == contracts.ObsRef(kind='csaf-fact', id=CVE1, pointer='/vulnerabilities/0/cwe', sha256=REV1_SHA)
    assert stated.anchor_ids == ('cwe:CWE-191',) and stated.evidence_class == 'E-TEXT'
    assert stated.origins == ('D_vendor_text',) and stated.nav is None and stated.obligations == ()
    assert (derived.kind, derived.verification) == ('adv:cwe-derived', 'rule-hypothesis')
    assert derived.detail == 'CWE-122 inferred from the advisory wording (memory-write)'
    assert derived.ref.pointer == '/vulnerabilities/0/notes/0' and derived.ref.sha256 == REV1_SHA
    assert [o.obs_id for o in ctx.observations] == sorted(o.obs_id for o in ctx.observations)
    assert all(keys.observation_id(o) == o.obs_id for o in ctx.observations)


def test_advisory_statements_count_once_and_never_raise_a_tier(single):
    ctx = advisory.context_from_report(single[CVE1])
    assert len(origins.components([o.origins for o in ctx.observations])) == 1  # one origin, however many statements
    assert {o.role for o in ctx.observations} == {'context'}


def test_a_cve_without_a_usable_cwe_has_no_observations_and_no_hypotheses(single):
    ctx = advisory.context_from_report(with_profile(single[CVE1], profile('weak', classification('CWE-20', 'weak'))))
    assert ctx.observations == () and ctx.hypotheses == () and ctx.cwe.status == 'weak'


def test_provenance_names_the_one_current_document_that_holds_a_pointer():
    ctx = advisory.context_from_report(reports(REV1, VEX)[CVE1])
    by_kind = {o.kind: o for o in ctx.observations}
    # only the advisory has a cwe field; both documents have a description at notes/0, so no digest is guessed
    assert by_kind['adv:cwe-stated'].ref.sha256 == REV1_SHA
    assert by_kind['adv:cwe-derived'].ref.pointer == '/vulnerabilities/0/notes/0'
    assert by_kind['adv:cwe-derived'].ref.sha256 is None


def test_provenance_of_two_identical_documents_is_left_out_not_guessed():
    twin = edited(REV1, lambda d: d['document']['tracking'].update(id='PT-SYNTH_CVE-2099-10001-TWIN'))
    ctx = advisory.context_from_report(reports(REV1, twin)[CVE1])
    assert ctx.observations and all(o.ref.sha256 is None for o in ctx.observations)
    assert len(ctx.source_ids) == 2


def test_superseded_documents_do_not_own_a_pointer(conflicted):
    ctx = advisory.context_from_report(conflicted[CVE1])
    superseded = {s.source.source_id for s in conflicted[CVE1].sources if s.superseded}
    assert superseded == {REV1_SHA}
    # the cwe field exists in the superseded revision 1 and in the current revision 2: only the current one owns it
    stated = next(o for o in ctx.observations if o.kind == 'adv:cwe-stated')
    assert stated.ref.sha256 == hashlib.sha256(REV2).hexdigest()
    assert all(o.ref.sha256 not in superseded for o in ctx.observations)


def test_context_sources_and_facts_cover_every_document_of_the_report(conflicted):
    ctx = advisory.context_from_report(conflicted[CVE1])
    summaries = conflicted[CVE1].sources
    assert ctx.source_ids == tuple(sorted(s.source.source_id for s in summaries))
    assert ctx.facts_ids == tuple(sorted(s.facts_id for s in summaries)) and len(ctx.facts_ids) == 3


def test_an_assumption_is_labelled_and_never_silently_dropped(single, conflicted):
    unmapped = reports(REV1, pair=UNMAPPED)[CVE1]
    asserted = advisory.context_from_report(unmapped, assume_applies=True)
    assert asserted.gate == 'asserted' and advisory.ASSUMED in asserted.limitations
    assert advisory.context_from_report(unmapped).gate == 'unverified'
    assert advisory.ASSUMED not in advisory.context_from_report(unmapped).limitations
    needless = advisory.context_from_report(single[CVE1], assume_applies=True)
    assert needless.gate == 'applies' and advisory.ASSUMPTION_NOT_NEEDED in needless.limitations
    ignored = advisory.context_from_report(conflicted[CVE1], assume_applies=True)
    assert ignored.gate == 'conflict' and advisory.ASSUMPTION_IGNORED in ignored.limitations


def test_context_is_deterministic(single):
    assert advisory.context_from_report(single[CVE1]) == advisory.context_from_report(reports(REV1)[CVE1])
    assert advisory.context_from_report(single[CVE1]) != advisory.context_from_report(single[CVE2])


def test_origin_tags_come_from_the_given_registry(single, provider_snapshot):
    registry = origins.DefaultOriginRegistry({**origins.SOURCE_TAGS, 'advisory-text': ('D_elsewhere',)})
    for ctx in (advisory.context_from_report(single[CVE1], registry=registry),
                advisory.context_from_fact(snapshot.fact_from_snapshot(provider_snapshot), registry=registry)):
        assert ctx.observations and {o.origins for o in ctx.observations} == {('D_elsewhere',)}
    assert {o.origins for o in advisory.context_from_report(single[CVE1]).observations} == {('D_vendor_text',)}


def test_cve_context_assembles_the_persisted_record(single):
    ctx = advisory.context_from_report(single[CVE1])
    kev = contracts.Kev(state='listed', date_added='2099-02-10', snapshot_id=H['kb'])
    in_window = contracts.Confounding(state='yes', cves=(CVE1, CVE2))
    counts = contracts.LeadCounts(fit=1, review=0, partial=2, code=0, queue=5)
    record = advisory.cve_context(ctx, kev=kev, confounding=in_window, counts=counts)
    assert (record.cve, record.gate, record.kev, record.confounding) == (CVE1, 'applies', kev, in_window)
    assert (record.applicability, record.cwe, record.source_ids) == (ctx.applicability, ctx.cwe, ctx.source_ids)
    assert record.limitations == ctx.limitations and record.counts == counts
    assert contracts.CveContext.model_validate_json(record.model_dump_json()) == record


def test_a_not_applicable_context_cannot_claim_leads(single):
    ctx = advisory.context_from_report(with_resolutions(single[CVE1], 'fixed', 'fixed'))
    assert ctx.gate == 'not-applicable'
    unknown = contracts.Kev(state='unknown')
    advisory.cve_context(ctx, kev=unknown, confounding=UNKNOWN_WINDOW, counts=NO_COUNTS)
    with pytest.raises(ValueError, match='no leads'):
        advisory.cve_context(ctx, kev=unknown, confounding=UNKNOWN_WINDOW,
                             counts=contracts.LeadCounts(fit=0, review=0, partial=1, code=0, queue=0))


# --- plain text: every detail passes sanitize_text, hostile input never reaches a record ---------------------------

def test_all_details_pass_sanitize_text(single, conflicted, hostile, provider_snapshot):
    contexts = [advisory.context_from_report(r) for group in (single, conflicted, hostile) for r in group.values()]
    contexts.append(advisory.context_from_fact(snapshot.fact_from_snapshot(provider_snapshot)))
    found = details(*contexts)
    assert len(found) >= 8
    for detail in found:
        assert sanitize_text(detail) == detail and '\n' not in detail and '\t' not in detail
        assert contracts.plain_line(detail) == detail and 0 < len(detail) <= 200
        assert not any(word in detail.lower() for word in BANNED), detail


def test_limitations_are_plain_bounded_lines_even_for_hostile_advisories(single, hostile):
    nasty = '\x00x\u202eevil\u2029 <script>alert(1)</script>\r\n\tz\ud800' + 'A' * 600
    report = single[CVE1].model_copy(update={'unknowns': (nasty, *single[CVE1].unknowns),
                                             'limitations': (nasty, *single[CVE1].limitations)})
    contexts = [advisory.context_from_report(report), *(advisory.context_from_report(r) for r in hostile.values())]
    for ctx in contexts:
        assert ctx.limitations and len(ctx.limitations) <= contracts.MAX_NOTES
        for line in ctx.limitations:
            assert contracts.plain_line(line) == line and sanitize_text(line, 300) == line and len(line) <= 300
    cleaned = contexts[0].limitations
    assert sum(line.startswith('xevil <script>alert(1)</script>') and line.endswith('...') for line in cleaned) == 1


def test_the_limit_of_notes_is_visible_not_silent(single):
    many = tuple(f'note {n:03d}' for n in range(100))
    report = single[CVE1].model_copy(update={'unknowns': many, 'limitations': ('only limitation',)})
    ctx = advisory.context_from_report(report)
    total = len({*many, 'only limitation', *report.cwe_profile.disagreements})
    assert len(ctx.limitations) == contracts.MAX_NOTES
    assert ctx.limitations[:contracts.MAX_NOTES - 1] == many[:contracts.MAX_NOTES - 1]
    assert ctx.limitations[-1] == advisory.notes_left_out(total - (contracts.MAX_NOTES - 1))


def test_more_sources_than_the_record_holds_are_cut_and_said(single):
    first = single[CVE1].sources[0]
    crowd = tuple(first.model_copy(update={'source': first.source.model_copy(
        update={'source_id': f'{n:064x}', 'sha256': f'{n:064x}'})}) for n in range(1, 66))
    ctx = advisory.context_from_report(single[CVE1].model_copy(update={'sources': crowd}))
    assert len(ctx.source_ids) == contracts.MAX_SOURCES and list(ctx.source_ids) == sorted(ctx.source_ids)
    assert ctx.source_ids[0] == f'{1:064x}' and ctx.source_ids[-1] == f'{64:064x}'
    assert advisory.sources_left_out(1) in ctx.limitations


# --- the record path: B3 snapshot or CVE-record excerpt -> CVEFact -> context -----------------------------------

def test_snapshot_with_agreeing_providers_gives_an_explicit_cwe(provider_snapshot):
    fact = snapshot.fact_from_snapshot(provider_snapshot)
    assert (fact.cve, fact.source_id, fact.pointer, fact.title) == (
        'CVE-2024-38063', provider_snapshot.snapshot_id, '', None)
    assert fact.cwe is not None and (fact.cwe.id, fact.cwe.pointer) == ('CWE-191', '/cwes/0')
    assert [(n.category, n.pointer, n.title) for n in fact.notes] == [('description', '/descriptions/0', 'msrc'),
                                                                      ('description', '/descriptions/1', 'nvd')]
    assert not fact.product_status and fact.assessment == 'advisory-claim'  # nothing about products is invented
    assert intel.CVEFact.model_validate_json(fact.model_dump_json()) == fact
    assert classify(fact).status == 'explicit'


def test_snapshot_text_in_other_languages_is_left_out(provider_snapshot):
    assert provider_snapshot.descriptions[-1].lang == 'es'
    texts = [n.text for n in snapshot.fact_from_snapshot(provider_snapshot).notes]
    assert provider_snapshot.descriptions[-1].text not in texts and len(texts) == 2


def test_providers_that_disagree_keep_both_cwes_as_claims_in_the_text():
    disagreeing = snap(cwes=(('msrc', 'CWE-125'), ('nvd', 'CWE-787')), conflicts=('cwe: msrc=CWE-125; nvd=CWE-787',))
    fact = snapshot.fact_from_snapshot(disagreeing)
    assert fact.cwe is None  # no provider's CWE is promoted to the explicit field
    found = classify(fact)
    assert found.status == 'derived' and {c.cwe_id for c in found.classifications} == {'CWE-125', 'CWE-787'}
    assert {c.basis for c in found.classifications} == {'cwe-id-in-text'}
    assert all(c.assessment == 'advisory-claim' for c in found.classifications)
    limitations = snapshot.snapshot_limitations(disagreeing)
    assert any('differ' in line and 'CWE-125' in line and 'CWE-787' in line for line in limitations)
    ctx = advisory.context_from_fact(fact, limitations=limitations)
    assert ctx.cwe.ids == ('CWE-125', 'CWE-787') and {h.cwe_id for h in ctx.hypotheses} == {'CWE-125', 'CWE-787'}
    assert any('differ' in line for line in ctx.limitations)


def test_one_provider_naming_two_cwes_is_not_a_disagreement():
    both = snap(cwes=(('nvd', 'CWE-20'), ('nvd', 'CWE-787')))
    fact = snapshot.fact_from_snapshot(both)
    assert fact.cwe is None and {c.cwe_id for c in classify(fact).classifications} == {'CWE-20', 'CWE-787'}
    assert not any('differ' in line for line in snapshot.snapshot_limitations(both))


def test_a_snapshot_without_cwe_or_text_is_a_valid_empty_record():
    fact = snapshot.fact_from_snapshot(snap(descriptions=()))
    assert fact.cwe is None and fact.notes == ()
    ctx = advisory.context_from_fact(fact)
    assert ctx.cwe == contracts.CweSummary(status='none', ids=()) and ctx.observations == ()
    assert ctx.hypotheses == () and ctx.gate == 'unverified'


def test_a_record_carries_no_applicability_so_its_gate_is_a_gap(provider_snapshot):
    fact = snapshot.fact_from_snapshot(provider_snapshot)
    plain = advisory.context_from_fact(fact)
    assert plain.gate == 'unverified' and plain.applicability == contracts.ApplicabilitySummary(
        older='unknown', newer='unknown', older_mapping='unknown', newer_mapping='unknown', contradictions=0)
    assert advisory.NO_APPLICABILITY in plain.limitations
    asserted = advisory.context_from_fact(fact, assume_applies=True)
    assert asserted.gate == 'asserted' and advisory.ASSUMED in asserted.limitations
    assert plain.source_ids == plain.facts_ids == (provider_snapshot.snapshot_id,) and plain.anchors == ()


def test_record_observations_name_the_record_not_a_csaf_document(provider_snapshot):
    ctx = advisory.context_from_fact(snapshot.fact_from_snapshot(provider_snapshot))
    (stated,) = ctx.observations
    assert stated.kind == 'adv:cwe-stated' and stated.detail == 'CWE-191 as stated by the CVE record'
    assert stated.ref == contracts.ObsRef(kind='cve-record', id='CVE-2024-38063', pointer='/cwes/0',
                                          sha256=provider_snapshot.snapshot_id)
    assert [h.rule_id for h in ctx.hypotheses] == ['R-INTEGER'] and ctx.cwe.ids == ('CWE-191',)


def test_a_cwe_derived_from_record_wording_is_a_hypothesis_not_a_claim():
    record = snap(descriptions=(('nvd', 'en', 'Heap-based buffer overflow in a network stack.'),))
    ctx = advisory.context_from_fact(snapshot.fact_from_snapshot(record))
    derived = [o for o in ctx.observations if o.kind == 'adv:cwe-derived']
    assert derived and all(o.verification == 'rule-hypothesis' for o in derived)
    assert all(o.ref.kind == 'cve-record' and o.ref.pointer == '/descriptions/0' for o in derived)
    assert ctx.cwe.status == 'derived'


def test_hostile_record_text_stays_in_the_fact_and_out_of_every_detail():
    text = ('Heap-based buffer overflow <img src=x onerror=alert(1)> \u202eevil\u202c\x00 [click](javascript:alert(1))'
            ' | a | b |\n# heading')
    fact = snapshot.fact_from_snapshot(snap(descriptions=(('nvd', 'en', text),)))
    assert fact.notes[0].text == text  # verbatim data, escaped only where it is exported
    ctx = advisory.context_from_fact(fact)
    assert ctx.observations
    for detail in details(ctx):
        assert 'img' not in detail and 'alert' not in detail and sanitize_text(detail) == detail


EXCERPT = {'cve': 'CVE-2099-40002', 'cwe': 'CWE-125', 'description': 'Out-of-bounds read in a parser.'}


def test_excerpt_gives_a_fact_the_30d_path_can_classify():
    fact = snapshot.fact_from_excerpt(EXCERPT)
    assert (fact.cve, fact.cwe.id, fact.cwe.pointer) == ('CVE-2099-40002', 'CWE-125', '/cwe')
    assert fact.notes[0].text == EXCERPT['description'] and fact.notes[0].pointer == '/description'
    assert fact.source_id == snapshot.fact_from_excerpt(dict(reversed(list(EXCERPT.items())))).source_id
    assert fact.source_id != snapshot.fact_from_excerpt({**EXCERPT, 'description': 'Another text.'}).source_id
    ctx = advisory.context_from_fact(fact, assume_applies=True)  # a corpus case: the analyst states applicability
    assert ctx.gate == 'asserted' and ctx.cwe.status == 'explicit' and 'CWE-125' in ctx.cwe.ids
    assert 'R-MEMORY-READ' in [h.rule_id for h in ctx.hypotheses]


@pytest.mark.parametrize('excerpt', [
    {**EXCERPT, 'cwe': ['CWE-125', 'CWE-787']}, {**EXCERPT, 'cwe': None}, {**EXCERPT, 'title': 'Parser flaw'},
    {k: v for k, v in EXCERPT.items() if k != 'cwe'}], ids=['two-cwes', 'null-cwe', 'title', 'no-cwe-key'])
def test_excerpt_variants_are_accepted(excerpt):
    fact = snapshot.fact_from_excerpt(excerpt)
    assert fact.cve == 'CVE-2099-40002' and fact.title == excerpt.get('title')
    assert (fact.cwe is not None) == (excerpt.get('cwe') == 'CWE-125')
    assert intel.CVEFact.model_validate_json(fact.model_dump_json()) == fact


BAD_EXCERPTS = {  # id: (excerpt, the reason slug that names the refused part)
    'not-a-mapping': (['CVE-2099-40002'], 'excerpt-shape'),
    'missing-cve': ({'description': 'x'}, 'excerpt-cve'),
    'bad-cve': ({**EXCERPT, 'cve': 'cve-2099-40002'}, 'excerpt-cve'),
    'fullwidth-cve': ({**EXCERPT, 'cve': 'CVE-2099-' + '\uff14' * 5}, 'excerpt-cve'),
    'missing-description': ({'cve': 'CVE-2099-40002'}, 'excerpt-description'),
    'empty-description': ({**EXCERPT, 'description': ''}, 'excerpt-description'),
    'long-description': ({**EXCERPT, 'description': 'a' * 20_001}, 'excerpt-description'),
    'number-description': ({**EXCERPT, 'description': 5}, 'excerpt-description'),
    'lone-surrogate': ({**EXCERPT, 'description': 'bad \ud800 text'}, 'excerpt-description'),
    'long-title': ({**EXCERPT, 'title': 't' * 1001}, 'excerpt-title'),
    'bad-cwe': ({**EXCERPT, 'cwe': 'CWE-0'}, 'excerpt-cwe'),
    'cwe-with-name': ({**EXCERPT, 'cwe': 'CWE-125: Out-of-bounds Read'}, 'excerpt-cwe'),
    'cwe-not-text': ({**EXCERPT, 'cwe': 125}, 'excerpt-cwe'),
    'too-many-cwes': ({**EXCERPT, 'cwe': [f'CWE-{n}' for n in range(1, 18)]}, 'excerpt-cwe'),
    'unknown-key': ({**EXCERPT, 'severity': 'high'}, 'excerpt-keys'),
}


@pytest.mark.parametrize('excerpt, reason', list(BAD_EXCERPTS.values()), ids=list(BAD_EXCERPTS))
def test_malformed_excerpts_fail_with_a_typed_error(excerpt, reason):
    with pytest.raises(PilotError) as info:
        snapshot.fact_from_excerpt(excerpt)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', reason)


def test_an_excerpt_cwe_list_of_one_points_into_the_list():
    fact = snapshot.fact_from_excerpt({**EXCERPT, 'cwe': ['CWE-125']})
    assert (fact.cwe.id, fact.cwe.pointer) == ('CWE-125', '/cwe/0')
    assert fact.source_id == snapshot.fact_from_excerpt(EXCERPT).source_id  # the same content, however it is written


def test_the_pointer_of_an_explicit_cwe_follows_its_position_in_the_snapshot():
    fact = snapshot.fact_from_snapshot(snap(cwes=(('msrc', 'NVD-CWE-Other'), ('nvd', 'CWE-787'))))
    assert (fact.cwe.id, fact.cwe.pointer) == ('CWE-787', '/cwes/1')


def test_values_that_are_not_cwe_ids_are_ignored_and_said():
    odd = snap(cwes=(('msrc', 'NVD-CWE-Other'), ('nvd', 'CWE-787 <b>'), ('nvd', 'CWE-787')))
    assert snapshot.fact_from_snapshot(odd).cwe.id == 'CWE-787'
    assert snapshot.snapshot_limitations(odd) == ('2 CWE value(s) in the record are not CWE ids and were ignored.',)
    assert snapshot.snapshot_limitations(snap(cwes=(('nvd', 'CWE-787'),))) == ()


def test_a_snapshot_with_a_non_ascii_cve_id_is_refused():
    # B3's model pattern uses \d, which also matches other Unicode digits; K's CveId does not
    with pytest.raises(PilotError) as info:
        snapshot.fact_from_snapshot(snap(cve_id='CVE-2099-' + '\uff14' * 5))
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', 'snapshot-record')


def test_provider_names_are_untrusted_labels():
    nasty = '\u202eevil<b>' + 'x' * 20  # a provider label holds at most 32 characters
    record = snap(cwes=((nasty, 'CWE-125'), ('nvd', 'CWE-787')), descriptions=((nasty, 'en', 'A flaw.'),),
                  conflicts=('cwe: odd',))
    fact = snapshot.fact_from_snapshot(record)
    assert fact.notes[0].title == 'evil<b>' + 'x' * 20
    synthesized = next(n for n in fact.notes if n.category == 'general')  # the note the adapter writes itself
    assert synthesized.text == 'evil<b>' + 'x' * 20 + ': CWE-125; nvd: CWE-787'
    (line,) = snapshot.snapshot_limitations(record)
    assert contracts.plain_line(line) == line and '\u202e' not in line and 'evil<b>' in line


# --- stored advisories as the AdvisorySource port ------------------------------------------------------------------

def test_stored_source_is_an_advisory_source_over_k_reports(single):
    advisories = stored(REV1)
    source = advisory.StoredAdvisorySource(advisories, OLDER, NEWER)
    assert isinstance(source, ports.AdvisorySource)
    assert source.cves() == (CVE1, CVE2)
    assert source.report(CVE1) == single[CVE1] and source.report(CVE2) == single[CVE2]
    assert source.report('CVE-2099-99999') is None and source.report('not a cve') is None
    assert source.report(CVE1) is source.report(CVE1)  # built once per CVE
    assert source.facts_ids() == tuple(sorted(a.facts.facts_id for a in advisories))


def test_stored_source_is_independent_of_the_order_of_the_stored_advisories():
    advisories = stored(REV1, REV2, VEX)
    forward = advisory.StoredAdvisorySource(advisories, OLDER, NEWER)
    backward = advisory.StoredAdvisorySource(list(reversed(advisories)), OLDER, NEWER)
    assert forward.cves() == backward.cves() and forward.facts_ids() == backward.facts_ids()
    assert all(forward.report(c) == backward.report(c) for c in forward.cves())


def test_the_universe_can_be_narrowed_to_the_cves_of_a_run():
    narrowed = advisory.StoredAdvisorySource(stored(REV1, VEX), OLDER, NEWER, cves=[CVE2, 'CVE-2099-99999'])
    assert narrowed.cves() == (CVE2,) and narrowed.report(CVE1) is None and narrowed.report(CVE2) is not None


def test_facts_ids_include_a_revision_that_withdrew_a_cve_and_exclude_unrelated_documents():
    advisories = stored(REV1, edited(REV2, withdraw_second_cve), edited(VEX, other_cves))
    rev1, rev2, unrelated = (a.facts.facts_id for a in advisories)
    only_second = advisory.StoredAdvisorySource(advisories, OLDER, NEWER, cves=[CVE2])
    # rev2 no longer lists CVE-2099-10002, yet it supersedes rev1, which changes what the report says about it
    assert only_second.facts_ids() == tuple(sorted((rev1, rev2)))
    assert only_second.report(CVE2).sources[0].superseded is True
    assert only_second.report(CVE2) != advisory.StoredAdvisorySource(stored(REV1), OLDER, NEWER).report(CVE2)
    everything = advisory.StoredAdvisorySource(advisories, OLDER, NEWER)
    assert everything.facts_ids() == tuple(sorted((rev1, rev2, unrelated)))


def test_stored_source_refuses_swapped_orientation():
    with pytest.raises(PilotError) as info:
        advisory.StoredAdvisorySource(stored(REV1), NEWER, OLDER)
    assert info.value.code == 'PT-PILOT-ORIENTATION'


def test_stored_source_translates_k_failures_into_typed_errors(monkeypatch):
    cancel = threading.Event()
    source = advisory.StoredAdvisorySource(stored(REV1), OLDER, NEWER, cancel=cancel)
    cancel.set()
    with pytest.raises(PilotError) as info:
        source.report(CVE1)
    assert info.value.code == 'PT-PILOT-CANCEL' and info.value.exit_code == 5

    def refuse(*args, **kwargs):
        raise intel.IntelError('PT-INTEL-LIMIT', 'a message that may quote advisory text')
    monkeypatch.setattr(advisory, 'build_report', refuse)
    with pytest.raises(PilotError) as info:
        advisory.StoredAdvisorySource(stored(REV1), OLDER, NEWER).report(CVE1)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', 'pt-intel-limit')
    assert 'advisory text' not in info.value.message  # the K message is not repeated


def test_a_record_without_a_cve_id_is_refused():
    fact = intel.CVEFact(source_id=H['snapshot'], pointer='')
    with pytest.raises(PilotError) as info:
        advisory.context_from_fact(fact)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', 'record-cve')


UNUSABLE = ('advisory source row x failed its integrity hash; skipped',)


@pytest.mark.parametrize('documents, warnings, state', [
    ((), (), 'not-run'), ((), UNUSABLE, 'failed'), ((REV1,), UNUSABLE, 'partial'), ((REV1,), (), 'available')],
    ids=['empty', 'unusable', 'some-unusable', 'ok'])
def test_the_advisory_channel_says_what_was_available(documents, warnings, state):
    status = advisory.StoredAdvisorySource(stored(*documents), OLDER, NEWER, warnings=warnings).status()
    assert (status.channel, status.state) == ('advisory', state)
    assert (status.reason is None) == (state == 'available') and sanitize_text(status.reason) == (status.reason or '')


def test_stored_source_over_a_real_project_store(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        store = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                              service.project.revision)
        store.add(REV1, origin='local-import', uri=None, file_name='rev1.json', retrieved_at='2099-03-01T00:00:00Z')
        advisories, warnings = store.advisories()
        older, newer = project_identities(service.project.artifacts, service.root)
    source = advisory.StoredAdvisorySource(advisories, older, newer, warnings=warnings)
    report = source.report(CVE1)
    assert report is not None and source.status().state == 'available'
    ctx = advisory.context_from_report(report)
    assert ctx.gate == 'applies' and ctx.applicability.older == 'affected'


# --- KEV: context for ordering CVEs, absence is not a vote ----------------------------------------------------------

LISTED, ABSENT, ELSEWHERE = 'CVE-2099-20001', 'CVE-2099-20002', 'CVE-2099-20003'


class FakeKev:
    """A KEV source as the KEV track will provide it (not built yet)."""

    def __init__(self, answer, snapshot_id: str | None):
        self.answer, self._snapshot = answer, snapshot_id

    def lookup(self, cve: str):
        return self.answer

    def snapshot_id(self) -> str | None:
        return self._snapshot


def test_kev_absence_is_unknown_context():
    catalog = kev_port.CatalogKev(H['kb'], {LISTED: '2099-02-10'})
    listed = kev_port.kev_context(catalog, LISTED)
    absent = kev_port.kev_context(catalog, ABSENT)
    nothing = kev_port.kev_context(None, ABSENT)
    assert listed == contracts.Kev(state='listed', date_added='2099-02-10', snapshot_id=H['kb'])
    assert absent == contracts.Kev(state='not-in-snapshot', snapshot_id=H['kb'])  # context of one snapshot, no date
    assert nothing == contracts.Kev(state='unknown') and nothing.snapshot_id is None
    # absence neither promotes nor demotes: it ranks exactly like having no catalog at all, below a listing
    assert kev_port.kev_rank(absent) == kev_port.kev_rank(nothing) > kev_port.kev_rank(listed)
    ranked = kev_port.order_cves({ABSENT: absent, ELSEWHERE: nothing, LISTED: listed, 'CVE-2099-20000': absent})
    assert ranked == (LISTED, 'CVE-2099-20000', ABSENT, ELSEWHERE)  # KEV first, then CVE id: nothing else
    # the record has no field that could read as "not exploited" or "safe"
    assert set(contracts.Kev.model_fields) == {'state', 'date_added', 'snapshot_id'}
    assert catalog.snapshot_id() == H['kb'] and kev_port.CatalogKev(H['kb'], {}).lookup(LISTED) == absent


def test_kev_ordering_depends_on_the_state_only():
    listed = {c: kev_port.kev_context(kev_port.CatalogKev(H['kb'], {c: d}), c)
              for c, d in (('CVE-2099-20005', '2099-01-01'), ('CVE-2099-20004', '2099-12-31'))}
    assert kev_port.order_cves(listed) == ('CVE-2099-20004', 'CVE-2099-20005')  # not by date, not by anything else
    assert kev_port.order_cves({}) == ()


@pytest.mark.parametrize('bad', ['CVE-2099-' + '\uff12' * 5, 'cve-2099-20001', '', 'CVE-2099-20001 ', 'x' * 1000, None, 7],
                         ids=['fullwidth', 'lower-case', 'empty', 'trailing-space', 'long', 'none', 'int'])
def test_kev_malformed_ids_are_unknown_never_not_in_the_snapshot(bad):
    catalog = kev_port.CatalogKev(H['kb'], {LISTED: '2099-02-10'})
    assert catalog.lookup(bad) == contracts.Kev(state='unknown')


@pytest.mark.parametrize('snapshot_id, listed', [
    (H['kb'][:-1], {}), ('Z' * 64, {}), (H['kb'].upper(), {}), (None, {}), (H['kb'], {'CVE-2099-1': '2099-01-01'}),
    (H['kb'], {LISTED: '2099-02-30'}), (H['kb'], {LISTED: 'yesterday'}), (H['kb'], {LISTED: None}),
    (H['kb'], {'CVE-2099-' + '\uff12' * 5: '2099-01-01'}), (H['kb'], [LISTED])],
    ids=['short-id', 'not-hex', 'upper-case-id', 'no-id', 'bad-cve', 'no-such-day', 'not-a-date', 'null-date',
         'fullwidth-cve', 'not-a-mapping'])
def test_a_catalog_is_validated_when_it_is_built(snapshot_id, listed):
    with pytest.raises(PilotError) as info:
        kev_port.CatalogKev(snapshot_id, listed)
    assert info.value.code == 'PT-PILOT-INPUT'


def test_a_catalog_is_a_kev_source_and_its_snapshot_is_part_of_every_answer():
    catalog = kev_port.CatalogKev(H['kb'], {LISTED: '2099-02-10'})
    assert isinstance(catalog, ports.KevSource)
    other = kev_port.CatalogKev(H['other'], {LISTED: '2099-02-10'})
    assert other.lookup(LISTED).snapshot_id == other.lookup(ABSENT).snapshot_id == H['other']


def test_kev_context_refuses_an_answer_from_another_snapshot():
    answer = contracts.Kev(state='not-in-snapshot', snapshot_id=H['other'])
    with pytest.raises(PilotError) as info:
        kev_port.kev_context(FakeKev(answer, H['kb']), ABSENT)
    assert info.value.code == 'PT-PILOT-MISMATCH'
    unknown = contracts.Kev(state='unknown')
    assert kev_port.kev_context(FakeKev(unknown, H['kb']), ABSENT) == unknown  # it consulted no snapshot to compare
    with pytest.raises(PilotError):
        kev_port.kev_context(FakeKev(contracts.Kev(state='not-in-snapshot', snapshot_id=H['kb']), None), ABSENT)


def test_kev_context_refuses_a_foreign_answer_type():
    with pytest.raises(PilotError) as info:
        kev_port.kev_context(FakeKev({'state': 'listed'}, H['kb']), LISTED)
    assert info.value.code == 'PT-PILOT-INPUT'


def test_kev_never_produces_evidence_about_a_function():
    names = {n for n in dir(kev_port) if not n.startswith('_')}
    assert 'Observation' not in names and 'make_observation' not in names  # context only, by construction


# --- the confounded window -----------------------------------------------------------------------------------------

WA, WB, WC, WD, WE = (f'CVE-2099-3000{n}' for n in range(1, 6))
GATES = {WA: 'applies', WB: 'asserted', WC: 'not-applicable', WD: 'unverified', WE: 'conflict'}


@dataclasses.dataclass
class FakeKb:
    """A KB window source as the KB track will provide it (not built yet)."""
    value: window.KbWindow | None

    def window(self) -> window.KbWindow | None:
        return self.value


def kb(cves=(), complete=False) -> FakeKb:
    return FakeKb(window.KbWindow(cves=tuple(cves), complete=complete, link_digest=H['kb']))


def test_confounding_counts_cves_fixed_on_newer():
    # applies and asserted CVEs are fixed on the newer build; fixed earlier (not-applicable), still unknown
    # (unverified) and contradictory ones are not counted
    assert window.confounding(GATES) == contracts.Confounding(state='yes', cves=(WA, WB))
    assert window.confounding({WA: 'applies', WB: 'applies', WC: 'applies'}).cves == (WA, WB, WC)
    assert window.confounding({WA: 'applies', WB: 'not-applicable'}).state != 'yes'
    assert window.confounding({WA: 'unverified', WB: 'unverified', WC: 'conflict'}).state != 'yes'


def test_one_fixed_cve_does_not_show_that_the_window_is_clean():
    for gates in ({WA: 'applies'}, {WA: 'applies', WC: 'not-applicable'}, {}, {WA: 'applies', WD: 'unverified'}):
        assert window.confounding(gates) == UNKNOWN_WINDOW  # the imported documents are a partial list


def test_the_threshold_follows_the_configuration():
    assert window.confounding(GATES, min_cves=3) == UNKNOWN_WINDOW
    assert window.confounding({WA: 'applies', WB: 'applies', WC: 'asserted'}, min_cves=3).state == 'yes'
    assert contracts.PilotConfig(limits_digest=H['other']).confounded_min_cves == 2  # the default the adapter uses


def test_confounding_does_not_depend_on_the_order_of_the_gates():
    assert window.confounding(dict(reversed(list(GATES.items())))) == window.confounding(GATES)


def test_the_kb_window_adds_cves_and_only_a_complete_one_can_close_the_window():
    assert window.confounding({WA: 'applies'}, kb=kb((WB,))) == contracts.Confounding(state='yes', cves=(WA, WB))
    assert window.confounding({WA: 'applies'}, kb=kb((WA, WB))).cves == (WA, WB)  # the same CVE is counted once
    assert window.confounding({}, kb=kb((WA, WB, WC))).state == 'yes'
    assert window.confounding({}, kb=kb((WA, WB), complete=True)) == contracts.Confounding(state='yes', cves=(WA, WB))
    assert window.confounding({WA: 'applies'}, kb=kb((), complete=False)) == UNKNOWN_WINDOW
    assert window.confounding({WA: 'applies'}, kb=kb((), complete=True)) == contracts.Confounding(state='no',
                                                                                                  cves=(WA,))
    assert window.confounding({}, kb=kb((), complete=True)) == contracts.Confounding(state='no')
    assert window.confounding(GATES, kb=kb((), complete=True)).state == 'yes'  # more than the threshold: yes wins
    assert window.confounding({WA: 'applies'}, kb=FakeKb(None)) == UNKNOWN_WINDOW  # no link: the CSAF count alone


def test_a_kb_source_is_a_port():
    assert isinstance(kb(), window.KbWindowSource)


def test_window_inputs_are_validated():
    for key in ('cve-2099-30001', 'CVE-2099-' + '\uff13' * 5, 'CVE-2099-3'):
        with pytest.raises(PilotError) as info:
            window.confounding({key: 'applies'})
        assert info.value.code == 'PT-PILOT-INPUT'
    for gate in ('none', 'fixed', None, 'APPLIES'):
        with pytest.raises(PilotError):
            window.confounding({WA: gate})
    for threshold in (1, 0, -3, True, 2.0):
        with pytest.raises(PilotError):
            window.confounding(GATES, min_cves=threshold)


@pytest.mark.parametrize('fields', [
    dict(cves=(WB, WA), complete=True, link_digest=H['kb']), dict(cves=(WA, WA), complete=True, link_digest=H['kb']),
    dict(cves=('CVE-1',), complete=True, link_digest=H['kb']), dict(cves=(WA,), complete=1, link_digest=H['kb']),
    dict(cves=(WA,), complete=True, link_digest='short'), dict(cves=[WA], complete=True, link_digest=H['kb'])],
    ids=['unsorted', 'duplicate', 'bad-cve', 'complete-not-bool', 'bad-digest', 'list-not-tuple'])
def test_a_kb_window_must_be_canonical(fields):
    with pytest.raises(PilotError) as info:
        window.KbWindow(**fields)
    assert info.value.code == 'PT-PILOT-INPUT'


def test_a_window_larger_than_the_record_is_refused_not_cut():
    crowd = tuple(f'CVE-2099-{n:05d}' for n in range(1, contracts.MAX_WINDOW_CVES + 2))
    with pytest.raises(PilotError) as info:
        window.confounding({}, kb=kb(crowd))
    assert info.value.code == 'PT-PILOT-LIMIT' and info.value.reason == 'window-cves'


# --- the pairing verdict map (s7 "Identity map") -------------------------------------------------------------------

UNIFIED_ROWS = [('matched', 'corroborated'), ('tentative', 'unassessed'), ('candidate', 'unassessed'),
                ('older-only', 'unassessed'), ('newer-only', 'unassessed'), ('unknown', 'unassessed'),
                ('contested', 'contested'), ('ambiguous', 'contested')]
SECONDARY_ROWS = [('corroborated', 'corroborated'), ('single-engine', 'unassessed'), ('insufficient', 'unassessed'),
                  ('contested', 'contested')]


@pytest.mark.parametrize('decision, expected', UNIFIED_ROWS, ids=[r[0] for r in UNIFIED_ROWS])
def test_unified_decisions_map_to_identity(decision, expected):
    assert pairing.identity_from_unified(decision) == expected


@pytest.mark.parametrize('verdict, expected', SECONDARY_ROWS, ids=[r[0] for r in SECONDARY_ROWS])
def test_secondary_verdicts_map_to_identity(verdict, expected):
    assert pairing.identity_from_secondary(verdict) == expected


def test_nothing_is_unassessed_not_a_negative_vote():
    assert pairing.identity_from_unified(None) == 'unassessed' == pairing.identity_from_secondary(None)
    assert pairing.pairing_identity(unified=None, secondary=None, unified_current=False) == 'unassessed'


def test_identity_tables_cover_exactly_the_engine_vocabularies():
    assert set(pairing.UNIFIED_IDENTITY) == set(get_args(Decision))
    assert set(pairing.SECONDARY_IDENTITY) == set(get_args(Verdict))
    assert set(pairing.UNIFIED_IDENTITY.values()) | set(pairing.SECONDARY_IDENTITY.values()) == set(
        get_args(contracts.Identity))
    assert dict(pairing.UNIFIED_IDENTITY) == dict(UNIFIED_ROWS)
    assert dict(pairing.SECONDARY_IDENTITY) == dict(SECONDARY_ROWS)


def test_unified_beats_secondary_for_identity():
    # a current unified result speaks alone: a secondary verdict (same Ghidriff origin) can neither upgrade nor
    # downgrade it
    assert pairing.pairing_identity(unified='tentative', secondary='corroborated', unified_current=True) == 'unassessed'
    assert pairing.pairing_identity(unified='matched', secondary='contested', unified_current=True) == 'corroborated'
    assert pairing.pairing_identity(unified='contested', secondary='corroborated', unified_current=True) == 'contested'
    # a candidate that the current unified result does not hold is unassessed, whatever the secondary engines say
    assert pairing.pairing_identity(unified=None, secondary='corroborated', unified_current=True) == 'unassessed'
    # without a current unified result (absent or stale) the secondary adjudication speaks
    assert pairing.pairing_identity(unified=None, secondary='corroborated', unified_current=False) == 'corroborated'
    assert pairing.pairing_identity(unified=None, secondary='contested', unified_current=False) == 'contested'
    assert pairing.pairing_identity(unified='matched', secondary='contested', unified_current=False) == 'contested'
    for unified, secondary in itertools.product((*pairing.UNIFIED_IDENTITY, None), (*pairing.SECONDARY_IDENTITY, None)):
        assert pairing.pairing_identity(unified=unified, secondary=secondary, unified_current=True) == \
            pairing.identity_from_unified(unified)
        assert pairing.pairing_identity(unified=unified, secondary=secondary, unified_current=False) == \
            pairing.identity_from_secondary(secondary)


def test_only_the_source_that_speaks_is_read():
    assert pairing.pairing_identity(unified='nope', secondary='contested', unified_current=False) == 'contested'
    assert pairing.pairing_identity(unified='matched', secondary='nope', unified_current=True) == 'corroborated'


@pytest.mark.parametrize('call', [
    lambda: pairing.identity_from_unified('matched-ish'), lambda: pairing.identity_from_unified('MATCHED'),
    lambda: pairing.identity_from_unified(7), lambda: pairing.identity_from_secondary('agree'),
    lambda: pairing.identity_from_secondary(''), lambda: pairing.identity_from_secondary(['contested']),
    lambda: pairing.pairing_identity(unified='nope', secondary=None, unified_current=True),
    lambda: pairing.pairing_identity(unified=None, secondary='nope', unified_current=False)],
    ids=['unified-unknown', 'unified-case', 'unified-int', 'secondary-ui-word', 'secondary-empty', 'secondary-list',
         'pairing-unified', 'pairing-secondary'])
def test_an_unknown_pairing_state_fails_closed(call):
    with pytest.raises(PilotError) as info:
        call()
    assert info.value.code == 'PT-PILOT-INPUT' and info.value.reason == 'unknown-pairing-state'


# --- purity: no Qt, sqlite, network, process or other feature's internals ------------------------------------------

MODULES = ('advisory', 'identity', 'kev', 'snapshot', 'window')
STDLIB = {'__future__', 'collections', 'collections.abc', 'dataclasses', 'hashlib', 'itertools', 'json', 're',
          'threading', 'types', 'typing', 'unicodedata'}
RUNTIME_ALLOWED = {
    'advisory': {'patchtrace.intelligence.contracts', 'patchtrace.intelligence.explain',
                 'patchtrace.intelligence.hypotheses', 'patchtrace.intelligence.lexicon', 'patchtrace.pilot.contracts',
                 'patchtrace.pilot.keys', 'patchtrace.pilot.limits', 'patchtrace.pilot.origins'},
    'identity': {'patchtrace.pilot.contracts', 'patchtrace.pilot.limits'},
    'kev': {'patchtrace.pilot.contracts', 'patchtrace.pilot.limits'},
    'snapshot': {'patchtrace.enrichment.contracts', 'patchtrace.enrichment.identity',
                 'patchtrace.intelligence.contracts', 'patchtrace.intelligence.lexicon', 'patchtrace.pilot.contracts',
                 'patchtrace.pilot.limits'},
    'window': {'patchtrace.pilot.contracts', 'patchtrace.pilot.limits'}}
TYPING_ALLOWED = {'advisory': {'patchtrace.pilot.ports'}, 'kev': {'patchtrace.pilot.ports'},
                  'window': set(), 'identity': set(), 'snapshot': set()}


def imports_of(path: Path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    guarded = set()
    for node in ast.walk(tree):  # imports under `if TYPE_CHECKING:` are annotations only
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING':
            guarded |= {id(n) for n in ast.walk(node)}
    runtime, typing_only = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ''
            if node.level:
                parent = ['patchtrace.pilot.sources', 'patchtrace.pilot', 'patchtrace'][node.level - 1]
                base = f'{parent}.{base}' if base else parent
            names = {base} if node.module else {f'{base}.{a.name}' for a in node.names}
        else:
            continue
        (typing_only if id(node) in guarded else runtime).update(names)
    return runtime, typing_only


@pytest.mark.parametrize('module', MODULES, ids=MODULES)
def test_sources_modules_respect_the_import_rules(module):
    runtime, typing_only = imports_of(PACKAGE / f'{module}.py')
    assert runtime - STDLIB <= RUNTIME_ALLOWED[module], runtime
    assert typing_only <= TYPING_ALLOWED[module], typing_only


def test_sources_init_is_documentation_only():
    tree = ast.parse((PACKAGE / '__init__.py').read_text(encoding='utf-8'))
    assert all(isinstance(n, ast.Expr) for n in tree.body)


def test_sources_import_no_qt_sqlite_network_process_or_other_feature():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.pilot.sources.advisory, patchtrace.pilot.sources.identity\n'
            'import patchtrace.pilot.sources.kev, patchtrace.pilot.sources.snapshot, patchtrace.pilot.sources.window\n'
            'bad = [m for m in ("PySide6", "sqlite3", "subprocess", "ssl", "urllib.request", "http.client",\n'
            '                   "patchtrace.unified", "patchtrace.secondary", "patchtrace.enrichment.storage",\n'
            '                   "patchtrace.intelligence.storage", "patchtrace.persistence") if m in sys.modules]\n'
            'print(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
