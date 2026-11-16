"""K1: product scopes and the versioned alias catalog (KB-integration-plan 7.2 `ProductScope`). SYNTHETIC/mocked names."""
from __future__ import annotations

import contextlib
import unicodedata
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, json_bytes, no_sockets  # noqa: F401

from patchtrace.kbcorrelation import alias_catalog, products
from patchtrace.kbcorrelation.contracts import ProductScope, domain_id
from patchtrace.kbcorrelation.sources import csaf_bridge, cvrf, cvrf_msrc
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
D1, D2 = '1' * 64, '2' * 64


@pytest.mark.parametrize('name,family,release,arch,key', [
    ('Windows 11 Version 24H2 for x64-based Systems', 'windows-client', '24H2', 'amd64', '11-24H2'),
    ('Windows 11 Version 24H2 for ARM64-based Systems', 'windows-client', '24H2', 'arm64', '11-24H2'),
    ('Windows 10 Version 22H2 for 32-bit Systems', 'windows-client', '22H2', 'x86', '10-22H2'),
    ('Windows 10 Version 1809 for x64-based Systems', 'windows-client', '1809', 'amd64', '10-1809'),
    ('Windows Server 2022 (Server Core installation)', 'windows-server', '2022', 'unknown', None),
    ('Windows Server 2012 R2', 'windows-server', '2012 R2', 'unknown', None),
    ('Microsoft Office 2019 for 32-bit editions', 'other', None, 'x86', None),
    ('Something Else Entirely', 'unknown', None, 'unknown', None),
])
def test_derive_from_names(name, family, release, arch, key):
    facts = products.derive(name)
    assert (facts.family, facts.release, facts.architecture, facts.winbindex_key) == (family, release, arch, key)


@pytest.mark.parametrize('name,release,arch,key', [
    ('Windows 10 for x64-based Systems', '1507', 'amd64', '10-1507'),
    ('Windows 10 for 32-bit Systems', '1507', 'x86', '10-1507'),
    ('Windows 10 Version 2004 for x64-based Systems', '2004', 'amd64', '10-2004'),
    ('Windows 10 Version 2004 for 32-bit Systems', '2004', 'x86', '10-2004'),
    ('Windows 10 Version 2004 for ARM64-based Systems', '2004', 'arm64', '10-2004'),
    ('Windows 11 for x64-based Systems', '21H2', 'amd64', '11-21H2'),
    ('Windows 11 for ARM64-based Systems', '21H2', 'arm64', '11-21H2'),
    ('  WINDOWS 10   for X64-based systems ', '1507', 'amd64', '10-1507'),
], ids=['10-rtm-x64', '10-rtm-x86', '2004-x64', '2004-x86', '2004-arm64', '11-rtm-x64', '11-rtm-arm64', 'wording'])
def test_kba08_client_names_without_a_release_token_get_the_first_release(name, release, arch, key):
    """Audit KBA-08, alias catalog 2 (spec 31-C C1). SYNTHETIC inputs: the Windows 10 form occurs in the committed
    MSRC projection; MSRC use of the Version 2004 and release-less Windows 11 forms is unverified offline."""
    facts = products.derive(name)
    assert (facts.family, facts.release, facts.architecture, facts.winbindex_key) == (
        'windows-client', release, arch, key)
    assert facts.mapping == 'candidate' and not facts.conflicts


@pytest.mark.parametrize('name', [
    'Windows 10 Enterprise LTSC 2019 for x64-based Systems',
    'Windows 10 Enterprise 2015 LTSB for x64-based Systems',
    'Windows 10 LTSC for x64-based Systems',
    'Windows 10 IoT Enterprise for x64-based Systems',
    'Windows 11 SE for x64-based Systems',
    'Windows 10 for x64-based Systems Preview',
    'Windows 10 for x64-based Systems and Windows 11 for x64-based Systems',
    'Windows 10 x64',
    'Windows 10 Version 2104 for x64-based Systems',
    'Windows 10 2004 for x64-based Systems',
], ids=['ltsc-2019', 'ltsb-2015', 'ltsc-bare', 'iot', 'se', 'trailing-word', 'two-products', 'short', 'not-a-release',
        'no-version-word'])
def test_kba08_any_other_name_without_a_release_token_stays_unkeyed(name):
    facts = products.derive(name)
    assert (facts.family, facts.release, facts.winbindex_key) == ('windows-client', None, None)
    scope = products.scope_for(D1, 'P', name)
    assert scope.scope_id == domain_id('kbc.scope', 1, {
        'family': 'windows-client', 'release': None, 'architecture': facts.architecture, 'channel': facts.channel,
        'edition': facts.edition, 'build': None, 'name': facts.name_key})


def test_kba08_an_implied_release_needs_the_client_family():
    clash = products.derive('Windows 10 for x64-based Systems', family_hint='windows-server')
    assert (clash.family, clash.release, clash.winbindex_key, clash.mapping) == ('unknown', None, None, 'conflicted')
    agreed = products.derive('Windows 10 for x64-based Systems', family_hint='windows-client', arch_hint='amd64')
    assert (agreed.release, agreed.winbindex_key, agreed.mapping) == ('1507', '10-1507', 'candidate')
    hinted = products.derive('Example OS for x64-based Systems', family_hint='windows-client')
    assert (hinted.family, hinted.release, hinted.winbindex_key) == ('windows-client', None, None)


def test_kba08_server_version_2004_gains_its_release_and_no_key():
    """``Version 2004`` is a release token like 1903 and 1909, so the server name is attribute-keyed like they are."""
    old, new = (products.derive(f'Windows Server, version {r} (Server Core installation)') for r in ('1909', '2004'))
    assert (old.family, old.release, old.winbindex_key) == ('windows-server', '1909', None)
    assert (new.family, new.release, new.winbindex_key, new.edition) == ('windows-server', '2004', None, 'core')


def test_kba08_alias_catalog_version_is_two():
    assert alias_catalog.ALIAS_CATALOG_VERSION == 2
    assert products.scope_for(D1, 'P', 'Windows 10 for x64-based Systems').alias_catalog_version == 2


def test_server_core_edition_and_channel_tokens():
    assert products.derive('Windows Server 2022 (Server Core installation)').edition == 'core'
    assert products.derive('Windows 10 Version 21H2 LTSC x64').channel == 'ltsc'


def test_string_derived_scopes_are_never_verified():
    for name in ('Windows 11 Version 24H2 for x64-based Systems', 'Windows Server 2022', 'Example OS', 'Office'):
        scope = products.scope_for(D1, 'P', name)
        assert scope.mapping in ('candidate', 'unknown') and scope.mapping != 'verified'
        assert scope.alias_catalog_version == alias_catalog.ALIAS_CATALOG_VERSION
    assert products.scope_for(D1, 'P', 'Windows 11 24H2 x64').mapping == 'candidate'
    assert products.scope_for(D1, 'P', 'Office 2019').mapping == 'unknown'


def test_hints_fill_gaps_but_contradictions_are_conflicts():
    filled = products.scope_for(D1, 'P', 'Example OS 24H2 x64', family_hint='windows-client', arch_hint='amd64')
    assert (filled.family, filled.architecture, filled.mapping) == ('windows-client', 'amd64', 'candidate')
    clash = products.scope_for(D1, 'P', 'Windows Server 2022 x64', family_hint='windows-client', arch_hint='arm64')
    assert (clash.family, clash.architecture, clash.mapping) == ('unknown', 'unknown', 'conflicted')
    assert products.scope_for(D1, 'P', 'x86 and x64 build', arch_hint='x86').architecture == 'x86'
    bogus = products.scope_for(D1, 'P', 'Example OS', family_hint='nonsense', arch_hint='mips')
    assert (bogus.family, bogus.architecture) == ('unknown', 'unknown')


def test_scope_id_ignores_document_and_wording_but_not_architecture():
    a = products.scope_for(D1, 'A', 'Windows 11 Version 24H2 for x64-based Systems')
    b = products.scope_for(D2, 'B', 'WINDOWS 11  version 24h2 for   x64-based systems')
    c = products.scope_for(D1, 'C', 'Windows 11 Version 24H2 for ARM64-based Systems')
    assert a.scope_id == b.scope_id != c.scope_id


@pytest.mark.parametrize('release', ['21H2', '22H2'])
def test_client_generations_with_the_same_release_never_merge(release):
    ten = products.scope_for(D1, 'TEN', f'Windows 10 Version {release} for x64-based Systems')
    eleven = products.scope_for(D1, 'ELEVEN', f'Windows 11 Version {release} for x64-based Systems')
    assert ten.scope_id != eleven.scope_id
    assert products.merge_scopes((ten, eleven)) == products.merge_scopes((eleven, ten))
    merged = products.merge_scopes((ten, eleven))
    assert len(merged) == 2
    assert {(s.winbindex_key, tuple(r.product_id for r in s.source_product_ids)) for s in merged} == {
        (f'10-{release}', ('TEN',)), (f'11-{release}', ('ELEVEN',))}


@pytest.mark.parametrize('name', ['Windows Server 2022 x64', 'Example OS 24H2 x64', 'Office 2019'])
def test_non_client_scope_identity_keeps_the_legacy_formula(name):
    facts = products.derive(name)
    informative = facts.family != 'unknown' and facts.release is not None and not facts.conflicts
    legacy_key = {'family': facts.family, 'release': facts.release, 'architecture': facts.architecture,
                  'channel': facts.channel, 'edition': facts.edition, 'build': None,
                  'name': None if informative else facts.name_key}
    assert products.scope_for(D1, 'P', name).scope_id == domain_id('kbc.scope', 1, legacy_key)


def test_uninformative_names_do_not_merge():
    a = products.scope_for(D1, 'A', 'Example Server 2099 x64', family_hint='windows-server')
    b = products.scope_for(D1, 'B', 'Example Server 2099 Core x64', family_hint='windows-server')
    assert a.scope_id != b.scope_id


def test_merge_scopes_unions_product_ids_and_is_sorted():
    a = products.scope_for(D1, 'A', 'Windows 11 24H2 x64')
    b = products.scope_for(D2, 'B', 'Windows 11 24H2 x64 ')
    other = products.scope_for(D1, 'Z', 'Windows 10 22H2 x64')
    merged = products.merge_scopes([b, other, a])
    assert [s.scope_id for s in merged] == sorted(s.scope_id for s in merged)
    both = next(s for s in merged if s.scope_id == a.scope_id)
    assert [(r.doc_id, r.product_id) for r in both.source_product_ids] == [(D1, 'A'), (D2, 'B')]
    assert isinstance(both, ProductScope)


def test_find_scopes_never_picks_for_the_caller():
    scopes = products.merge_scopes([products.scope_for(D1, 'PT-C', 'Windows 11 24H2 x64'),
                                    products.scope_for(D1, 'PT-A', 'Windows 11 24H2 ARM64')])
    assert len(products.find_scopes(scopes, '24h2')) == 2
    assert [s.source_product_ids[0].product_id for s in products.find_scopes(scopes, 'PT-C')] == ['PT-C']
    assert [s.display_name for s in products.find_scopes(scopes, scopes[0].scope_id[:10])] == [scopes[0].display_name]
    assert products.find_scopes(scopes, '') == () and products.find_scopes(scopes, 'zzz') == ()


def test_catalog_digest_is_stable_and_sensitive(monkeypatch):
    before = products.catalog_digest()
    assert before == products.catalog_digest() and len(before) == 64
    monkeypatch.setattr(alias_catalog, 'CHANNEL_PATTERNS', (('ltsc', r'\bltsx\b'),))
    assert products.catalog_digest() != before


def test_display_name_is_clean_plain_text():
    scope = products.scope_for(D1, 'P', 'Win‮dows\x00 11 <b>x64</b>')
    assert scope.display_name == 'Windows 11 <b>x64</b>'
    assert products.scope_for(D1, 'PID', '\x00‮').display_name == 'PID'


# --- SEC-B (2026-11-11): `clean_text` applies the one hostile-character rule; it runs again at every read ----------

LS, PS = '\N{LINE SEPARATOR}', '\N{PARAGRAPH SEPARATOR}'


def clean_text_before_the_shared_rule(value: object, limit: int = 1000) -> str:
    """`products.clean_text` as it was when existing workspaces were written (it kept U+2028 and U+2029), frozen here
    so that a test can write a store the old way. Not a reference for anything else."""
    if not isinstance(value, str):
        return ''
    out = []
    for ch in value:
        code = ord(ch)
        if ch in '\n\r\t':
            out.append(' ')
        elif code < 0x20 or 0x7f <= code < 0xa0 or unicodedata.category(ch) == 'Cf':
            continue
        elif 0xd800 <= code <= 0xdfff:
            out.append('\N{REPLACEMENT CHARACTER}')
        else:
            out.append(ch)
    return ''.join(out)[:limit]


@pytest.fixture
def the_rule_before(monkeypatch):
    """A context manager inside which every parser cleans text the old way."""
    @contextlib.contextmanager
    def active():
        with monkeypatch.context() as patch:
            for module in (products, cvrf, cvrf_msrc, csaf_bridge):
                patch.setattr(module, 'clean_text', clean_text_before_the_shared_rule)
            yield
    return active


def separator_month() -> bytes:
    """The synthetic month with U+2028 and U+2029 in every text `clean_text` gates: a product name that joins the
    scope key (no hints, unknown family), a title, a remediation subtype and a status name."""
    doc = h.baseline_cvrf()
    doc['product_tree'].append({'product_id': 'PT-ODD', 'name': f'Example{LS}Suite{PS}Pro{LS}'})
    first = doc['vulnerabilities'][0]
    first['title'] = f'Out-of-bounds{LS}read{PS}in the item reader'
    first['remediations'].append({'type': 2, 'description': h.KB_CLIENT[2:], 'product_ids': ['PT-ODD'],
                                  'sub_type': f'Security{LS}Update'})
    first['product_statuses'][f'Known{LS}Not{PS}Affected'] = ['PT-ODD']
    return json_bytes(doc)


def shown_texts(doc) -> list[str]:
    return [*(s.display_name for s in doc.scopes), *(c.title or '' for c in doc.cards),
            *(e.sub_type or '' for e in doc.edges), *(s.value for s in doc.statuses)]


def test_a_workspace_written_before_the_shared_rule_still_opens_and_verifies(tmp_path, the_rule_before):
    """`WorkspaceStore.load_index` parses every stored object again and refuses a document that no longer yields its
    recorded rows (PT-KBC-VERIFY). The rule change must move no identity and no count: only shown text differs."""
    raw = separator_month()
    with the_rule_before(), WorkspaceStore(tmp_path / 'kb') as store:
        old = import_bytes(raw, now=NOW)
        assert store.add_document(old, raw)
    assert sum(LS in text or PS in text for text in shown_texts(old)) >= 4  # written the old way, separators kept

    with WorkspaceStore(tmp_path / 'kb', create=False) as store:
        index = store.load_index()
        new = index.get(old.doc_id)
        stored_rows = store.edges_for_kb(h.KB_CLIENT)
        assert store.sources() == (old.source,)
    assert new is not None and new.source == old.source
    assert [e.edge_id for e in new.edges] == [e.edge_id for e in old.edges] and len(old.edges) >= 4
    assert [(e.scope_id, e.relation, e.fixed_build) for e in new.edges] == [
        (e.scope_id, e.relation, e.fixed_build) for e in old.edges]
    assert [s.scope_id for s in new.scopes] == [s.scope_id for s in old.scopes]
    assert [(s.cve, s.scope_id, s.klass, s.pointer) for s in new.statuses] == [
        (s.cve, s.scope_id, s.klass, s.pointer) for s in old.statuses]
    assert 'not_affected' in {s.klass for s in new.statuses}  # the separated status name classified, both ways
    assert [c.cve for c in new.cards] == [c.cve for c in old.cards] and new.problems == old.problems
    assert {row['scope_id'] for row in stored_rows} <= {s.scope_id for s in new.scopes}
    assert {row['doc_id'] for row in stored_rows} == {old.doc_id}
    assert not any(LS in text or PS in text for text in shown_texts(new))
    assert 'Example Suite Pro' in {s.display_name for s in new.scopes}


@pytest.mark.parametrize('name', [
    f'Example{LS}Suite', f'{PS}Example Suite{LS}', f'Example {LS}{PS}\t Suite', f'Windows 11{LS}Version 24H2 x64',
    f'Windows{PS}Server 2022', 'x' * 998 + f'{LS}{PS}yz', LS, f'A{LS}B\x00\N{SOFT HYPHEN}C\N{RIGHT-TO-LEFT OVERRIDE}'],
    ids=['inner', 'edges', 'run', 'client', 'server', 'at-the-limit', 'only-a-separator', 'mixed'])
def test_the_shared_rule_moves_no_scope_identity(name, the_rule_before):
    """The scope key reads a name through `normal_name`, which collapses whitespace (U+2028 and U+2029 included), so
    turning a separator into a space changes neither the name key nor the scope id of any stored product."""
    now = products.scope_for(D1, 'P', name)
    now_key = products.derive(name).name_key
    with the_rule_before():
        before = products.scope_for(D1, 'P', name)
        before_key = products.derive(name).name_key
    assert (now.scope_id, now_key) == (before.scope_id, before_key)
    assert now.model_dump(exclude={'display_name'}) == before.model_dump(exclude={'display_name'})
    assert LS not in now.display_name and PS not in now.display_name
    assert len(now.display_name) == len(before.display_name)
# --- audit KBA-08: scope identity of the committed fixtures across the alias catalog 1 -> 2 change -------------

MSRC_FACTS = Path(__file__).parent / 'fixtures' / 'kbcve' / 'msrc' / '2024-Aug-CVE-2024-38193.facts.json'
# Scope id by source product id as origin/main 882d1ca0 (alias catalog 1) derived it for every product of the
# committed advisory fixtures: the MSRC factual projection (real product names) and the synthetic baseline month.
MAIN_SCOPE_IDS = {
    'msrc-2024-Aug': {
        '9312': '5c51ed33eed4b54212d7d1ef2b699fabd23adad331af0d66975a9a01b1e5fa26',
        '9318': 'fb8aebbd9672f1f4d72ea00d84de6f99914fe8623a7bf3f525cc0c802e8766b5',
        '9344': '06be8f7126bf2d5370a956b86d21f40bf171d3d89982fc38459dc34ed777e1fa',
        '10049': 'ffbcb29b2c660d7f255ed58f6e6ba4c15d9c2b7934f05158c606cc54e49dbfc4',
        '10051': '3dc5324947d282ddc0034930149623d4dc4162782b561f462b8d330d793762a9',
        '10287': '28947d7c9fbc88c1c7bae555555ebf6c7a0df603a87d316469c103e8402b219c',
        '10378': '98fe56a45628880439802c03b59fd94a101bb90196e4e530739183c5cf2f60a7',
        '10379': '9417aa0851bbba3d1a80678e73136047c4e3b1038dc25a0ddad98a6e5f98bc53',
        '10483': '12089bd27e0fc4ac2d7e8e54f8b90b1063edb1773ef3615c30c52978ed3ed603',
        '10543': 'fb345be564cc394e32f8dbeb040fc51b50524df0fe2ea9350524b8a55bc49ecb',
        '10729': 'd815e06a7b1c78e399105184e1ced94359cfbe045ca9c50b09818e0dc4c1c2ad',
        '10735': '7e6607cf3e2b0f5589edb1f90b1c4404bcc9ffc276974f557571dec6fdb389a3',
        '10816': '9fbbad2ef30be25bb6775e837b5143b1c6deebd928b6cbf13dba888f28548fbd',
        '10852': '17f5269e70f46dd3454306e832f9066cc692032b5887a5607ae4ea942e18cde0',
        '10853': '0cc47a6dbcb3451e3b69f6a6f46a2a42a48a832d32c915f360c7bf05ec2fb614',
        '10855': '32e1fe8d62b9181e896e2ad58e1e990077f93dcefcd87fd1fb946d0148484000',
        '11568': 'b979e425149ae47c094d9eae8f969f6ac973f07203542fa60fe6b9fa0c054129',
        '11569': '8255a7ee59f45a84fd6622e3676e8e583f9c2df74bd5dafafd96beeb1d5905f3',
        '11571': 'daf72d2698911cc5f6f8a3609101623a55056eb0ba0d0298a639396f5fb0d906',
        '11572': '994bb1bb7c53580e23a2e6b96d9147a54dc57bd6f75ca64bc4855ecbe469bf61',
        '11923': '69764c202840de4de63b57f1a66536c89bb58f0742eaa70352c488529ce1d718',
        '11924': '99cd9a8b45d59b234ed7da0dbd7434daf03caf321beae98e77ca188d6a7ff659',
        '11926': '8daf292f85050186fe4b53ca7b30d1fd15234de0d0298b6fae6ece008f9b7803',
        '11927': '19f65f8739df52d460d5f2b33b01b44c49c1f5dd7fdd6236cd8eadf8828c332a',
        '11929': '3223cc3007526eacd2410e5cb4d8deecb9e3dd6c9210d274a35f5132a2dfae50',
        '11930': '84262fd7648cbad967c3ec5e057993820e5ba432d5cc37d812837bd7c3219a14',
        '11931': '6e9631327cabcc73548ad983779b0809fd727a160c58449a87cd7ffe6208a73c',
        '12085': '5faed23c33a1b665aad4338474f099c1981be48d755d3c919e9b0801f62b9ae1',
        '12086': '3a76723cb0321a83a27d5b9128e3c052581d1eb2c6579678d69b4fd36a66cbb8',
        '12097': '95c963d263a53c3f835c093e5235205834168731bca0092d7eb7102ac51c8065',
        '12098': 'edd4d3b99c9be9824f4b59d5e3647d6e96df140fe0df79406aaacf55eba6b3aa',
        '12099': '3927d787b8bb9a8e4dcfe8f7ade6fb98be21a7be53bc842aa1f05a6a2a860570',
        '12242': '9e318d567d4190fd47a7a44816484b47e174ad3a87fd244b2cbf2df8f56a761f',
        '12243': '3de04516a20713d959763f370d8dd2583180f02512ef26d3d750e96e01646224',
        '12244': 'c55931175766e38606157e9797aab47a539ba7681b1c4bf734c488150919878b',
        '12389': '90a950ad88a83629f10f907a5079f114a6f2fc5131fa9d3bbfca41c2992dab36',
        '12390': '409eaa28d0c56c30a2f58baab6fb82ae5fd3656677a8cd9bf486dffc10d8c9e5',
    },
    'cvrf-2099-Feb': {
        'PT-CLIENT': '04abf8961c1ac9579b78bdcec8d6b877ec8fa3031d36f25685412e1045b1d68c',
        'PT-CLIENT-ARM': '55968283d67d166932325db01731ea67b6eee4cae6c0f3837f428fefae608777',
        'PT-SERVER': '92187cb5c082549bf0acc9d15d1520e2939e7bbdb42a4bee3091e388cea46644',
        'PT-SERVER-CORE': '8aaac463211f1e3cd9b436bb10f65b4bdd932ce46e425ced5a5aac9203519a39',
    },
}
# The only fixture products whose identity changes: the Windows 10 names without a release token. Each joins the
# scope an explicit ``Version 1507`` name of the same architecture has.
REKEYED = {'10729': 'Windows 10 Version 1507 for 32-bit Systems', '10735': 'Windows 10 Version 1507 for x64-based Systems'}


def fixture_scopes() -> dict[str, dict[str, ProductScope]]:
    raw = {'msrc-2024-Aug': MSRC_FACTS.read_bytes(), 'cvrf-2099-Feb': h.read_fixture_bytes('cvrf-2099-Feb.json')}
    return {label: {ref.product_id: scope for scope in import_bytes(data, now='2099-03-01T00:00:00Z').scopes
                    for ref in scope.source_product_ids} for label, data in raw.items()}


def test_kba08_scope_ids_of_the_committed_fixtures_change_only_for_the_rekeyed_names():
    got = fixture_scopes()
    assert {label: sorted(scopes) for label, scopes in got.items()} == {
        label: sorted(ids) for label, ids in MAIN_SCOPE_IDS.items()}
    for label, ids in MAIN_SCOPE_IDS.items():
        kept = {pid: scope_id for pid, scope_id in ids.items() if pid not in REKEYED}
        assert {pid: got[label][pid].scope_id for pid in kept} == kept, label
    for pid, explicit in REKEYED.items():
        scope = got['msrc-2024-Aug'][pid]
        assert (scope.release, scope.winbindex_key) == ('1507', '10-1507')
        assert scope.scope_id != MAIN_SCOPE_IDS['msrc-2024-Aug'][pid]
        assert scope.scope_id == products.scope_for(D1, 'P', explicit).scope_id


def test_kba08_release_less_windows_11_name_is_the_21h2_scope():
    """The earlier vendor spelling joins the scope the later version 21H2 spelling already had on main."""
    main = MAIN_SCOPE_IDS['msrc-2024-Aug']
    assert products.scope_for(D1, 'P', 'Windows 11 for x64-based Systems').scope_id == main['11926']
    assert products.scope_for(D1, 'P', 'Windows 11 for ARM64-based Systems').scope_id == main['11927']
    merged = products.merge_scopes([products.scope_for(D1, 'OLD', 'Windows 11 for x64-based Systems'),
                                    products.scope_for(D1, 'NEW', 'Windows 11 version 21H2 for x64-based Systems')])
    assert [[r.product_id for r in s.source_product_ids] for s in merged] == [['NEW', 'OLD']]
