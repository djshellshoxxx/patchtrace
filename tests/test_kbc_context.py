"""K3: documentary context and export (KB-integration-plan 7.2 `ContextReport`, 7.4 keys, 10.1 step 4/6). Synthetic;
offline. The rules are the real reused `intelligence` lexicon and hypotheses, bound as `wiring` binds them."""
from __future__ import annotations

import json

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, import_doc, import_fixture, no_sockets  # noqa: F401

from patchtrace.kbcorrelation import export
from patchtrace.kbcorrelation.context import ContextBundle, build_bundle, vulnerability_pointer
from patchtrace.kbcorrelation.contracts import Lead
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.wiring import IntelligenceRules, escape_markdown

pytestmark = pytest.mark.usefixtures('no_sockets')
INV = '00000000-0000-4000-8000-0000000000c3'
CVE = h.CVE_A


@pytest.fixture(scope='module')
def rules():
    return IntelligenceRules()


def index_of(*names):
    index = ReverseIndex()
    for name in names:
        index.add(import_fixture(name))
    return index


def bundle(index, rules, *, cves=(CVE,), base=3, scope_id=None, mention=(), older='1' * 64, newer='2' * 64):
    return build_bundle(investigation_id=INV, base_revision=base, lead=Lead(kind='kb', value=h.KB_CLIENT, raw='kb'),
                        cves=cves, index=index, rules=rules, now=NOW, coverage=(index.coverage(now=NOW),),
                        scope_id=scope_id, pair_id='c' * 64, older_sha=older, newer_sha=newer, mention_only=mention)


def test_stated_cwe_gives_the_curated_hypothesis_and_says_who_stated_it(rules):
    b = bundle(index_of('cvrf-2099-Feb.json'), rules)
    card = b.context.cards[0]
    assert (card.cve, card.stated_cwe, card.source_kind, card.kev) == (CVE, 'CWE-125', 'cvrf', 'not-loaded')
    assert b.cwe_profiles[0].status == 'explicit'
    assert [x.rule_id for x in b.hypotheses[0].hypotheses] == ['R-MEMORY-READ']
    assert b.hypotheses[0].hypotheses[0].assessment == 'rule-hypothesis'


def test_unknowns_and_limits_are_explicit(rules):
    b = bundle(index_of('cvrf-2099-Feb.json'), rules, mention=(h.CVE_MENTION,))
    unknowns = ' | '.join(b.context.unknowns)
    assert 'KEV listing was not loaded' in unknowns and h.CVE_MENTION in unknowns and 'unverified' in unknowns
    assert b.context.cards[0].applicability.startswith('unknown')
    assert 'does not show that any changed function addresses a vulnerability' in b.context.limitations[0]
    assert b.context.coverage and b.context.hooks == tuple(sorted(b.context.hooks))


def test_a_chosen_product_is_still_not_verified(rules):
    index = index_of('cvrf-2099-Feb.json')
    scope = next(s.scope_id for s in index.scopes() if s.architecture == 'amd64' and 'Server' not in s.display_name)
    b = bundle(index, rules, scope_id=scope)
    assert 'no document verifies that these two files belong to it' in ' '.join(b.context.unknowns)


def test_a_cve_without_advisory_text_is_an_unknown_not_a_card(rules):
    b = bundle(index_of('cvrf-2099-Feb.json'), rules, cves=('CVE-2099-29999',))
    assert b.context.cards == () and 'CVE-2099-29999 has no advisory text' in ' '.join(b.context.unknowns)


def test_the_key_is_deterministic_and_follows_its_inputs(rules):
    index = index_of('cvrf-2099-Feb.json')
    key = bundle(index, rules).context_key
    assert key == bundle(index, rules).context_key
    assert key != bundle(index, rules, base=4).context_key
    assert key != bundle(index, rules, newer='3' * 64).context_key
    march = h.baseline_cvrf()
    march['document'].update(release_id='2099-Mar', tracking_id='PT-CVRF-2099-Mar')
    march['vulnerabilities'].append(h.vulnerability('CVE-2099-20009', 'Another flaw'))
    wider = index_of('cvrf-2099-Feb.json')
    wider.add(import_doc(march))
    assert key != bundle(wider, rules).context_key


def test_the_bundle_round_trips_through_json_and_rejects_a_mismatched_profile_list(rules):
    b = bundle(index_of('cvrf-2099-Feb.json'), rules)
    assert ContextBundle.model_validate_json(b.model_dump_json()) == b
    broken = json.loads(b.model_dump_json())
    broken['hypotheses'] = []
    with pytest.raises(ValueError):
        ContextBundle.model_validate_json(json.dumps(broken))


def test_vulnerability_pointer_keeps_the_item_not_the_remediation():
    assert vulnerability_pointer('/vulnerabilities/12/remediations/0') == '/vulnerabilities/12'
    assert vulnerability_pointer('/x') == '/'


def test_json_export_is_sorted_lf_and_has_no_local_path(rules, tmp_path):
    b = bundle(index_of('cvrf-2099-Feb.json'), rules)
    data = export.to_json(b)
    assert data.endswith(b'\n') and b'\r' not in data and json.loads(data)['context_key'] == b.context_key
    assert str(tmp_path).encode() not in data


def test_markdown_export_escapes_hostile_advisory_text(rules):
    doc = h.baseline_cvrf()
    doc['vulnerabilities'][0]['title'] = '[click](https://evil.example.invalid/x) <script>alert(1)</script>'
    index = ReverseIndex()
    index.add(import_doc(doc))
    text = export.to_markdown(bundle(index, rules), escape_markdown)
    assert '<script>' not in text and '](https://' not in text and '\\[click\\]' in text
    assert text.endswith('\n') and 'Hypothesis R\\-MEMORY\\-READ' in text
