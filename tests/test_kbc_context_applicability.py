"""CSAF applicability on KB context cards (KBF-03 s5.2, ``build_bundle`` over ``report_for``). SYNTHETIC, hermetic.

The CSAF facts come from the production port's ``parse_csaf`` over the committed synthetic revisions, with the
synthetic update token renamed to a KB so the KB index ties the document to a lead; nothing is fetched and no target
file is executed. A card restates what CSAF claims for the two files; unknown stays unknown, a bundle without a CSAF
claim keeps its bytes and key, and nothing ties a function to a CVE.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock, write_pair
from kbc_k4a_golden import banned_in

from patchtrace.intelligence.contracts import CweProfile, HypothesisSet
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import APPLICABILITY, build_bundle
from patchtrace.kbcorrelation.contracts import Lead
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.leads import _chip
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.sample import synthetic_pe

pytestmark = pytest.mark.usefixtures('no_sockets')
FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
NOW = '2099-02-15T00:00:00Z'
INV = '00000000-0000-4000-8000-0000000000d1'
CVE = 'CVE-2099-10001'
KB = 'KB5041585'
OLD_SHA = 'dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215'  # PT-800 file hash in rev1/rev2
NEW_SHA = '4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168'  # PT-900 file hash in rev1/rev2
TRACKING = 'PT-SYNTH_CVE-2099-10001'
PORT = wiring.IntelligenceAdvisory()
RULES = wiring.IntelligenceRules()
# The CVRF-only bundle of ``cvrf_only`` as built BEFORE build_bundle read CSAF applicability (base 9451d7e).
PINNED_KEY = '9df959f74598a6ff4f05df78f587601d3ed293795b9f9076e75ba70335bba183'
PINNED_DUMP_SHA256 = '5b1f9deeb44c54f727b1b925d0151715a449745828712affcf49554a731896db'
CLAIM = ('advisory-claim: older file affected, newer file fixed; any file-hash mapping is a candidate, not verified; '
         f'restated from CSAF {TRACKING} revision 1')
QUALIFIER = 'any file-hash mapping is a candidate, not verified'
LONG_CVE = 'CVE-2099-1234567890123456789'  # kb-syntax/1 (4-19 digits) but longer than the 24-character card CveId
WITHDRAWN = (f'{CVE} (CSAF): a current CSAF revision no longer lists {CVE}; the earlier statements are superseded '
             'and nothing replaces them')


class FixedRules:
    """A ``RulesPort`` with fixed digests that interprets nothing, so the pinned bytes depend on kbcorrelation only."""
    rules_digest = '1' * 64
    lexicon_digest = '2' * 64

    def interpret(self, card, facts):
        return (CweProfile(cve=card.cve, lexicon_version='pinned', lexicon_digest=self.lexicon_digest, status='none'),
                HypothesisSet(cve=card.cve, rules_version='pinned', rules_digest=self.rules_digest,
                              unknowns=('The pinned test rules make no interpretation.',)))


def csaf(name: str = 'rev1', *, drop_cve: bool = False, shas: tuple[str, str] = (OLD_SHA, NEW_SHA)) -> bytes:
    """A synthetic CSAF revision whose update token is a KB; ``drop_cve`` withdraws the CVE, ``shas`` re-hash files."""
    doc = json.loads((FIXTURES / f'synthetic-advisory-{name}.json').read_text(encoding='utf-8'))
    if drop_cve:
        doc['vulnerabilities'] = [v for v in doc['vulnerabilities'] if v['cve'] != CVE]
    text = json.dumps(doc, indent=2).replace('PT5041585', KB)
    for fixture_sha, sha in zip((OLD_SHA, NEW_SHA), shas, strict=True):
        text = text.replace(fixture_sha, sha)
    return (text + '\n').encode('utf-8')


def facts(raw: bytes) -> dict:
    return dict(PORT.parse_csaf(raw, source_sha256=hashlib.sha256(raw).hexdigest()))


def index_of(*raws: bytes) -> ReverseIndex:
    index = ReverseIndex()
    for raw in raws:
        index.add(import_bytes(raw, now=NOW, advisory=PORT))
    return index


def bundle(index, *, older=OLD_SHA, newer=NEW_SHA, rules=RULES, cves=(CVE,), lead=KB, coverage=None, **extra):
    return build_bundle(investigation_id=INV, base_revision=3, lead=Lead(kind='kb', value=lead, raw=lead), cves=cves,
                        index=index, rules=rules, now=NOW,
                        coverage=(index.coverage(now=NOW),) if coverage is None else coverage, scope_id=None,
                        pair_id='c' * 64, older_sha=older, newer_sha=newer, **extra)


def reports(documents, *, older=OLD_SHA, newer=NEW_SHA, cves=(CVE,)) -> dict:
    return {cve: PORT.report_for(cve, documents, older, newer) for cve in cves}


def cvrf_only(**extra):
    index = ReverseIndex()
    index.add(import_fixture('cvrf-2099-Feb.json'))
    return bundle(index, rules=FixedRules(), cves=(h.CVE_A,), lead=h.KB_CLIENT, coverage=(), **extra)


REV1 = csaf('rev1')
GONE = csaf('rev2', drop_cve=True)


def test_hash_tied_files_restate_the_csaf_claim_as_a_candidate_mapping():
    plain = bundle(index_of(REV1))
    claimed = bundle(index_of(REV1), applicability=reports([facts(REV1)]))
    card, = claimed.context.cards
    assert card.applicability == CLAIM
    assert plain.context.cards[0].applicability == APPLICABILITY
    assert claimed.context_key != plain.context_key  # the claim is an input of the context identity
    assert claimed.context.unknowns == plain.context.unknowns  # both sides resolved: the report adds no unknown


def test_a_revision_that_drops_the_cve_is_unknown_and_says_so_never_affected():
    claimed = bundle(index_of(REV1), applicability=reports([facts(REV1), facts(GONE)]))
    text = claimed.context.cards[0].applicability
    assert text == ('unknown: older file unknown, newer file unknown; any file-hash mapping is a candidate, not '
                    f'verified; restated from CSAF {TRACKING} revision 1 (superseded), {TRACKING} revision 2')
    assert 'affected' not in text and 'fixed' not in text
    unknowns = claimed.context.unknowns
    assert unknowns.count(WITHDRAWN) == 1
    assert f'{CVE} (CSAF): older file: applicability is unknown' in unknowns
    assert not any('affected' in u for u in unknowns)


@pytest.mark.parametrize('missing', ['older', 'newer'], ids=['old', 'new'])
def test_a_missing_sha256_keeps_the_fixed_unknown_text_and_the_bytes(missing):
    older, newer = (None, NEW_SHA) if missing == 'older' else (OLD_SHA, None)
    plain = bundle(index_of(REV1), older=older, newer=newer)
    given = bundle(index_of(REV1), older=older, newer=newer,
                   applicability=reports([facts(REV1)], older=older, newer=newer))
    assert given.context.cards[0].applicability == APPLICABILITY
    assert (given.context_key, given.model_dump_json()) == (plain.context_key, plain.model_dump_json())


@pytest.mark.parametrize('variant', ['absent', 'empty', 'unlisted', 'no-sha'], ids=['absent', 'empty', 'unl', 'nosha'])
def test_a_bundle_without_a_csaf_claim_is_byte_identical_to_the_pinned_bundle(variant):
    extra = {'absent': {}, 'empty': {'applicability': {}},
             'unlisted': {'applicability': reports([facts(REV1)], cves=(h.CVE_A,))},
             'no-sha': {'applicability': reports([facts(REV1)], newer=None)}}[variant]
    built = cvrf_only(**extra)
    assert built.context.cards[0].applicability == APPLICABILITY
    assert built.context_key == PINNED_KEY
    assert hashlib.sha256(built.model_dump_json().encode()).hexdigest() == PINNED_DUMP_SHA256


def test_document_order_repetition_and_unused_reports_do_not_change_the_bundle():
    index = index_of(REV1, csaf('rev2'))
    expected = bundle(index, applicability=reports([facts(REV1), facts(csaf('rev2'))]))
    again = reports([facts(csaf('rev2')), copy.deepcopy(facts(REV1)), facts(REV1)])
    unused = {'CVE-2099-10002': PORT.report_for('CVE-2099-10002', [facts(REV1)], OLD_SHA, NEW_SHA), **again}
    for given in (again, unused):
        built = bundle(index, applicability=given)
        assert (built.context_key, built.model_dump_json()) == (expected.context_key, expected.model_dump_json())
    assert 'revision 1 (superseded)' in expected.context.cards[0].applicability


def test_the_card_text_names_no_function_or_address_and_no_banned_word():
    for documents in ([facts(REV1)], [facts(REV1), facts(GONE)]):
        built = bundle(index_of(REV1), applicability=reports(documents))
        texts = [built.context.cards[0].applicability, *built.context.unknowns]
        assert banned_in(texts) == []
        assert not any(re.search(r'function|\brva\b|0x[0-9a-f]+', t, re.IGNORECASE) for t in texts)


def test_hostile_report_text_is_cleaned_and_bounded():
    hostile = 'T‮\n\x07' + 'x' * 2000
    report = {'cve': CVE, 'assessment': 'advisory-claim', 'unknowns': [hostile],
              'applicability': {'older': {'resolution': 'affected'}, 'newer': {'resolution': 'fixed'}},
              'sources': [{'tracking_id': hostile, 'revision': '1', 'superseded': False}]}
    built = bundle(index_of(REV1), applicability={CVE: report})
    for text in (built.context.cards[0].applicability, *built.context.unknowns):
        assert len(text) <= 1000 and not re.search('[‮\n\x07]', text)
    assert built.context.cards[0].applicability.startswith('advisory-claim: older file affected, newer file fixed')


@pytest.mark.parametrize('kind', ['many', 'long'], ids=['many', 'long'])
def test_the_leads_chip_keeps_the_candidate_qualifier_whatever_the_source_list(kind):
    """The Leads applicability chip cuts the card text to 500 characters; the fixed qualifier must survive it."""
    sources = ([{'tracking_id': f'VENDOR-SA-2099-00{n:02d}', 'revision': f'1.0.{n}', 'superseded': False}
                for n in range(16)] if kind == 'many' else
               [{'tracking_id': 'T' * 1000, 'revision': '1' * 40, 'superseded': True}])
    hostile = 'x' * (0 if kind == 'many' else 2000)
    report = {'cve': CVE, 'assessment': 'advisory-claim' + hostile, 'unknowns': [],
              'applicability': {'older': {'resolution': 'affected' + hostile},
                                'newer': {'resolution': 'fixed' + hostile}}, 'sources': sources}
    text = bundle(index_of(REV1), applicability={CVE: report}).context.cards[0].applicability
    assert len(text) <= 1000 and QUALIFIER in text
    chip = _chip('applicability', 'unknown', text)
    assert chip.state == 'unknown' and QUALIFIER in chip.text
    assert chip.text.startswith('advisory-claim')


def _workspace(tmp_path, fault=None):
    """A KB workspace holding the KB variant of rev1 whose file hashes are the two synthetic PE files."""
    shas = tuple(hashlib.sha256(synthetic_pe(variant)).hexdigest() for variant in (0, 1))
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock(), fault=fault)
    raw = csaf('rev1', shas=shas)
    with WorkspaceStore(service.root) as ws:
        assert ws.add_document(import_bytes(raw, now=NOW, advisory=PORT), raw)
    older, newer = write_pair(tmp_path)
    return service, service.search(KB).result['investigation_id'], str(older), str(newer)


class _StopBeforeRow:
    """Crash-point seam: the attach stops before its first project row, so the context stays pending."""

    def __call__(self, point: str) -> None:
        if point == 'attach_before_row':
            raise RuntimeError('interrupted by the test')


def test_attach_and_kb_explain_show_the_csaf_claim(tmp_path):
    service, inv, older, newer = _workspace(tmp_path)
    project = tmp_path / 'P'
    assert service.import_pair(inv, older, newer, str(project)).exit == 0
    explained = wiring.build_service(service.root, clock=FixedClock()).explain(str(project), CVE)
    assert explained.exit == 0 and explained.result['cves'][0]['card']['applicability'] == CLAIM
    assert f'  Applicability: {CLAIM}; ' in explained.text


def test_a_repaired_context_carries_the_same_csaf_claim(tmp_path):
    service, inv, older, newer = _workspace(tmp_path, fault=_StopBeforeRow())
    project = tmp_path / 'P'
    assert service.import_pair(inv, older, newer, str(project)).exit == 3
    fresh = wiring.build_service(service.root, clock=FixedClock())
    assert fresh.attach(str(project), inv, repair_it=True).exit == 0
    explained = fresh.explain(str(project), CVE)
    assert explained.result['cves'][0]['card']['applicability'] == CLAIM
    assert f'  Applicability: {CLAIM}; ' in explained.text


@pytest.mark.parametrize('repair', [False, True], ids=['attach', 'repair'])
def test_a_cve_lead_longer_than_a_card_cve_still_attaches_with_csaf_loaded(tmp_path, repair):
    """A kb-syntax/1 CVE that cannot be a card CVE gets no CSAF report: the attach completes as before."""
    service, _, older, newer = _workspace(tmp_path, fault=_StopBeforeRow() if repair else None)
    inv = service.search(LONG_CVE).result['investigation_id']
    project = tmp_path / 'P'
    attached = service.import_pair(inv, older, newer, str(project))
    if repair:
        assert attached.exit == 3
        service = wiring.build_service(service.root, clock=FixedClock())
        attached = service.attach(str(project), inv, repair_it=True)
    assert attached.exit == 0
    built = service._project_bundles(str(project))[-1]
    assert built.context.cards == ()
    assert f'{LONG_CVE} has no advisory text in the loaded documents; no interpretation was made.' \
        in built.context.unknowns
