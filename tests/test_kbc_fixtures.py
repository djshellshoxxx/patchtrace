"""K0f: committed KB-CVE fixtures match MANIFEST.json and their builders; helpers import; data is synthetic.

Offline by construction: an autouse fixture refuses every socket operation.
"""
from __future__ import annotations

import json
import re
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

import kbc_helpers as h
import pytest

from patchtrace.kbcorrelation import ids
from patchtrace.kbcorrelation.ids import KbSyntaxError
from patchtrace.sample import synthetic_pe

MANIFEST = json.loads((h.FIXTURE_DIR / h.MANIFEST_NAME).read_text(encoding='utf-8'))
LISTED = MANIFEST['files']
REQUIRED_KEYS = {'path', 'sha256', 'bytes', 'created', 'origin', 'licence', 'used_by'}
CREATED_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
FORBIDDEN_HOSTS = (
    'msrc.microsoft.com', 'support.microsoft.com', 'download.microsoft.com',
    'catalog.update.microsoft.com', 'learn.microsoft.com',
)
MATRIX = h.identifier_matrix()


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('KB fixture tests must not open sockets')

    monkeypatch.setattr(socket, 'socket', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(socket, 'getaddrinfo', refuse)


def fixture_text_files() -> list[Path]:
    return sorted(p for p in h.FIXTURE_DIR.iterdir()
                  if p.is_file() and p.name not in (h.MANIFEST_NAME,))


# --- manifest ---


def test_manifest_lists_every_fixture_and_nothing_else():
    on_disk = {p.name for p in h.FIXTURE_DIR.iterdir() if p.is_file()} - {h.MANIFEST_NAME, h.README_NAME}
    assert set(LISTED) == on_disk


@pytest.mark.parametrize('name', sorted(LISTED))
def test_manifest_row_matches_the_committed_bytes(name):
    row = LISTED[name]
    assert REQUIRED_KEYS <= row.keys(), f'{name} lacks {REQUIRED_KEYS - row.keys()}'
    assert row['path'] == name
    data = h.read_fixture_bytes(name)
    assert h.sha256_hex(data) == row['sha256'], f'{name}: hash differs from MANIFEST.json'
    assert len(data) == row['bytes']
    assert b'\r' not in data, f'{name} must use LF line endings'


@pytest.mark.parametrize('name', sorted(LISTED))
def test_every_row_is_declared_synthetic_with_a_licence_and_a_consumer(name):
    row = LISTED[name]
    assert 'synthetic' in row['origin'].lower()
    assert 'not microsoft-derived' in row['origin'].lower()
    assert row['licence'].strip()
    assert row['used_by'] and all(isinstance(entry, str) and entry for entry in row['used_by'])
    assert CREATED_RE.match(row['created']), row['created']


def test_builder_made_files_are_listed_with_their_generator():
    for name in h.generated_files():
        assert LISTED[name].get('generator'), f'{name} is builder-made but MANIFEST names no generator'


def test_manifest_contract_marks_the_whole_set_synthetic():
    assert MANIFEST['synthetic'] is True
    assert MANIFEST['contract'] == 'kbcorrelation-fixtures/1'


# --- builders reproduce the committed bytes ---


@pytest.mark.parametrize('name', sorted(h.generated_files()))
def test_builder_reproduces_the_committed_bytes(name):
    assert h.generated_files()[name] == h.read_fixture_bytes(name), (
        f'{name} is stale: regenerate from tests/kbc_helpers.py and recompute MANIFEST.json')


# --- strict and lenient JSON (NEG-07) ---


def test_duplicate_key_source_is_refused_by_the_strict_loader():
    with pytest.raises(h.FixtureError, match='duplicate key'):
        h.load_fixture_json('cvrf-2099-Feb-duplicate-key.json', strict=True)


def test_duplicate_key_source_is_silently_last_wins_when_parsed_leniently():
    lenient = h.load_fixture_json('cvrf-2099-Feb-duplicate-key.json')
    assert lenient['document']['release_id'] == '2099-Mar'


# --- XML encodings ---


def test_empty_month_is_well_formed_and_has_no_vulnerabilities():
    root = ET.fromstring(h.read_fixture_bytes('cvrf-2099-Feb-empty.xml'))
    assert root.tag.endswith('}CvrfDoc')
    vulnerabilities = root.find('{https://example.invalid/synthetic-cvrf/1}Vulnerabilities')
    assert vulnerabilities is not None and len(vulnerabilities) == 0


def test_dialect_unknown_root_is_well_formed_and_is_not_a_known_dialect():
    root = ET.fromstring(h.read_fixture_bytes('cvrf-2099-Feb-dialect-unknown.xml'))
    assert root.tag == 'SyntheticFutureCvrf'
    assert root.find('.//Fixes') is not None


# --- content shape ---


def remediation_fixes(vuln: dict) -> dict[str, str]:
    return {pid: item['description'] for item in vuln['remediations'] if item['type'] == 2
            for pid in item['product_ids']}


def test_baseline_month_matches_the_plan_s5_shape():
    doc = h.load_fixture_json('cvrf-2099-Feb.json')
    assert doc['dialect'] == h.DIALECT and doc['synthetic'] is True
    vulns = {v['cve']: v for v in doc['vulnerabilities']}
    assert set(vulns) == {h.CVE_A, h.CVE_B, h.CVE_MENTION}
    assert remediation_fixes(vulns[h.CVE_A]) == {
        h.PRODUCT_CLIENT: '5099001', h.PRODUCT_ARM: '5099001', h.PRODUCT_SERVER: '5099002'}
    assert remediation_fixes(vulns[h.CVE_B]) == {h.PRODUCT_SERVER: '5099002'}
    assert {item['type'] for item in vulns[h.CVE_MENTION]['remediations']} == {5}
    assert vulns[h.CVE_A]['cwe']['id'] == 'CWE-125'
    assert vulns[h.CVE_B]['cwe']['id'] == 'CWE-190'


def test_reordered_month_has_the_same_content_as_the_baseline():
    base = h.load_fixture_json('cvrf-2099-Feb.json')
    shuffled = h.load_fixture_json('cvrf-2099-Feb-reordered.json')

    def canonical(doc):
        return json.dumps(doc, sort_keys=True)

    def sort_all(doc):
        doc = json.loads(canonical(doc))
        doc['vulnerabilities'].sort(key=lambda v: v['cve'])
        for v in doc['vulnerabilities']:
            v['remediations'].sort(key=lambda r: (r['type'], r['description']))
            for r in v['remediations']:
                r['product_ids'].sort()
            for k in v['product_statuses']:
                v['product_statuses'][k].sort()
        doc['product_tree'].sort(key=lambda p: p['product_id'])
        return doc

    assert sort_all(base) == sort_all(shuffled)
    assert canonical(base) != canonical(shuffled)


def test_neg_month_uses_only_defined_products_except_the_declared_unknown_one():
    doc = h.load_fixture_json('cvrf-2099-Feb-neg.json')
    defined = {p['product_id'] for p in doc['product_tree']}
    used = {pid for v in doc['vulnerabilities'] for item in v['remediations'] for pid in item['product_ids']}
    assert used - defined == {h.PRODUCT_UNKNOWN}


def test_csaf_fixture_expands_groups_and_has_no_kb_for_the_fixless_cve():
    doc = h.load_fixture_json('csaf-kb.json')
    groups = {g['group_id']: set(g['product_ids']) for g in doc['product_tree']['product_groups']}
    assert groups['PT-GRP-CLIENT'] == {h.PRODUCT_CLIENT, h.PRODUCT_ARM}
    vulns = {v['cve']: v for v in doc['vulnerabilities']}
    assert 'KB' not in json.dumps(vulns[h.CVE_B]['remediations'])
    assert h.PRODUCT_SERVER_LEGACY in vulns[h.CVE_B]['product_status']['known_not_affected']
    assert h.PRODUCT_SERVER_LEGACY not in vulns[h.CVE_B]['product_status'].get('known_affected', [])


def test_kev_snapshot_lists_only_the_first_cve():
    doc = h.load_fixture_json('kev-synthetic.json')
    assert [v['cveID'] for v in doc['vulnerabilities']] == [h.CVE_A]


# --- synthetic-only sweep ---


@pytest.mark.parametrize('path', fixture_text_files(), ids=lambda p: p.name)
def test_every_cve_is_in_the_impossible_year_2099(path):
    text = path.read_text(encoding='utf-8')
    years = set(re.findall(r'CVE-(\d{4})-\d', text))
    assert years <= {'2099'}, f'{path.name} uses real-looking CVE years {years - {"2099"}}'


@pytest.mark.parametrize('path', fixture_text_files(), ids=lambda p: p.name)
def test_no_vendor_host_appears_in_any_fixture(path):
    text = path.read_text(encoding='utf-8').lower()
    for host in FORBIDDEN_HOSTS:
        assert host not in text, f'{path.name} names {host}'


# --- helpers ---


def test_helpers_import_and_expose_the_documented_api():
    assert callable(h.two_cve_project)
    assert callable(h.generated_files)
    assert callable(h.identifier_matrix)
    assert h.FIXTURE_DIR.is_dir()


def test_two_cve_project_writes_the_old_and_new_pe_as_exampledrv(tmp_path):
    project = h.two_cve_project(tmp_path)
    assert project.older_path == tmp_path / 'old' / 'exampledrv.sys'
    assert project.newer_path == tmp_path / 'new' / 'exampledrv.sys'
    assert project.older_path.read_bytes() == synthetic_pe(0)
    assert project.newer_path.read_bytes() == synthetic_pe(1)
    assert project.older_sha256 == h.sha256_hex(synthetic_pe(0))
    assert project.newer_sha256 == h.sha256_hex(synthetic_pe(1))
    assert project.older_sha256 != project.newer_sha256


def test_two_cve_project_baseline_identifiers_and_sources(tmp_path):
    project = h.two_cve_project(tmp_path)
    assert (project.kb_client, project.kb_server) == ('KB5099001', 'KB5099002')
    assert (project.cve_first, project.cve_second, project.cve_mention) == (
        'CVE-2099-20001', 'CVE-2099-20002', 'CVE-2099-20003')
    assert project.products == ('PT-CLIENT', 'PT-CLIENT-ARM', 'PT-SERVER')
    for path in (project.cvrf_path, project.csaf_path, project.kev_path):
        assert path.is_file()


def test_two_cve_project_is_repeatable(tmp_path):
    first = h.two_cve_project(tmp_path / 'a')
    second = h.two_cve_project(tmp_path / 'b')
    assert (first.older_sha256, first.newer_sha256) == (second.older_sha256, second.newer_sha256)


@pytest.mark.parametrize('bad', ['../cvrf-2099-Feb.json', 'sub/x.json', '.hidden', 'MANIFEST.json', ''])
def test_fixture_path_refuses_traversal_and_metadata_names(bad):
    with pytest.raises(h.FixtureError):
        h.fixture_path(bad)


# --- identifier matrix against the K0 rules ---


def test_matrix_covers_every_rule_family_and_has_unique_ids():
    assert {row['op'] for row in MATRIX} == {'canonical_kb', 'edge_kb', 'edge_cve', 'kb_tokens'}
    assert len({row['id'] for row in MATRIX}) == len(MATRIX)


@pytest.mark.parametrize('row', MATRIX, ids=[row['id'] for row in MATRIX])
def test_identifier_row_agrees_with_kbcorrelation_ids(row):
    op, raw, expect = row['op'], row['input'], row['expect']
    if op == 'canonical_kb':
        if expect == 'ok':
            assert ids.is_canonical_kb(raw)
            assert ids.canonical_kb(raw) == row['output']
        else:
            assert not ids.is_canonical_kb(raw)
            with pytest.raises(KbSyntaxError):
                ids.canonical_kb(raw)
    elif op == 'edge_kb':
        if expect == 'ok':
            assert ids.normalise_kb_edge(raw) == row['output']
        else:
            with pytest.raises(KbSyntaxError):
                ids.normalise_kb_edge(raw)
    elif op == 'edge_cve':
        if expect == 'ok':
            assert ids.normalise_cve(raw) == row['output']
        else:
            with pytest.raises(KbSyntaxError):
                ids.normalise_cve(raw)
    else:
        assert list(ids.find_kb_tokens(raw)) == row['output']


def test_identifiers_file_is_the_matrix_it_was_built_from():
    stored = h.load_fixture_json('identifiers.json')
    assert stored['synthetic'] is True
    assert stored['rows'] == MATRIX
