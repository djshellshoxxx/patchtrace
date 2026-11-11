"""K1: product scopes and the versioned alias catalog (KB-integration-plan 7.2 `ProductScope`). SYNTHETIC/mocked names."""
from __future__ import annotations

import contextlib
import unicodedata

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
