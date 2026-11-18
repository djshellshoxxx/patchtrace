"""Selected superseded-source explanations; authored offline data, never native acceptance."""
from __future__ import annotations

import copy
import json
import os
import ssl  # noqa: F401  # Load SSLSocket before no_sockets replaces socket.socket.
import subprocess
import sys
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from pydantic import ValidationError

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.contracts import SearchScope
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources import scope as scopes
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
NOW = '2099-03-01T00:00:00Z'
CVE = 'CVE-2099-0001'
OLD_KB, NEW_KB = 'KB1111', 'KB2222'
PRODUCTS = [{'product_id': 'P1', 'name': 'Windows 11 Version 24H2 for x64-based Systems'},
            {'product_id': 'P2', 'name': 'Windows Server 2025 for x64-based Systems'}]
PREFIX = 'NAMED_SUPERSEDED:'
ROOT = Path(__file__).resolve().parents[1]


class Clock:
    def now_utc(self):
        return NOW


def revision(day, kb=OLD_KB, *, products=('P1',), repeats=1, release='2099-Feb', cve=CVE):
    return json.dumps({
        'dialect': 'cvrf-json/0',
        'document': {'release_id': release, 'current_release_date': f'2099-02-{day:02d}T00:00:00Z'},
        'product_tree': PRODUCTS,
        'vulnerabilities': [{'cve': cve, 'remediations': [
            {'type': 2, 'description': kb, 'product_ids': products} for _ in range(repeats)]}],
    }).encode()


def loaded(*raws):
    index = ReverseIndex()
    docs = [import_bytes(raw, now=NOW) for raw in raws or (revision(1), revision(20, NEW_KB))]
    for doc in docs:
        index.add(doc)
    return index, docs


def named(result):
    return [warning for warning in result.warnings if warning.startswith(PREFIX)]


def seeded_service(tmp_path, *raws):
    raws = raws or (revision(1), revision(20, NEW_KB))
    service = wiring.build_service(tmp_path / 'workspace', clock=Clock())
    docs = [import_bytes(raw, now=NOW) for raw in raws]
    with WorkspaceStore(service.root, clock=Clock()) as store:
        for raw, doc in zip(raws, docs, strict=True):
            store.add_document(doc, raw)
    return service, docs


def scope_file(tmp_path, *doc_ids, months=()):
    path = tmp_path / 'scope.json'
    path.write_text(json.dumps({'doc_ids': doc_ids, 'months': months}), encoding='utf-8')
    return path


@pytest.mark.parametrize('query_kind,query', [('kb', OLD_KB), ('cve', CVE)])
@pytest.mark.parametrize('kind', ['provided_files', 'mixed'])
def test_named_old_hit_stays_withheld_and_names_the_exact_selected_source(query_kind, query, kind):
    index, (older, newer) = loaded()
    scope = scopes.files_scope([older.doc_id]) if kind == 'provided_files' else SearchScope(
        kind='mixed', doc_ids=(older.doc_id,), months=('2099-Feb',), corpus_digest=index.corpus_digest())
    got = getattr(index, f'lookup_{query_kind}')(query, scope=scope, now=NOW)
    assert index.active_ids() == {newer.doc_id}
    assert len(got.superseded) == 1 and got.superseded[0].ref.doc_id == older.doc_id
    if kind == 'provided_files' or query_kind == 'kb':
        assert (got.status, got.exit_code, got.edges, got.groups, got.cards) == ('not_observed', 4, (), (), ())
    else:
        assert got.status == 'found' and [edge.kb for edge in got.edges] == [NEW_KB]
    assert len(named(got)) == 1 and older.doc_id in named(got)[0]
    assert newer.doc_id not in named(got)[0] and len(named(got)[0]) <= 500
    assert 'loaded index' in named(got)[0] and 'active results' in named(got)[0]


@pytest.mark.parametrize('scope_kind', ['active', 'cached', 'cached_with_ids', 'months', 'missing'])
def test_only_an_explicit_named_old_hit_adds_the_explanation(scope_kind):
    index, (older, newer) = loaded()
    scope = {'active': scopes.files_scope([newer.doc_id]), 'cached': None,
             'cached_with_ids': scopes.corpus_scope([older.doc_id]),
             'months': scopes.months_scope(['2099-Feb']), 'missing': scopes.files_scope(['f' * 64])}[scope_kind]
    got = index.lookup_kb(NEW_KB if scope_kind == 'active' else OLD_KB, scope=scope, now=NOW)
    assert named(got) == []
    if scope_kind == 'active':
        assert got.status == 'found' and len(got.edges) == 1
    elif scope_kind != 'missing':
        assert not got.edges and got.superseded and got.status == 'not_observed'
    else:
        assert not got.edges and not got.superseded and got.status == 'not_searched'


def test_mixed_scope_does_not_name_an_unselected_or_unrelated_old_hit():
    index, (older, _newer, unrelated, _replacement) = loaded(
        revision(1), revision(20, NEW_KB),
        revision(1, NEW_KB, release='2099-Jan'), revision(20, NEW_KB, release='2099-Jan'))
    scope = SearchScope(kind='mixed', months=('2099-Feb',), doc_ids=(unrelated.doc_id,),
                        corpus_digest=index.corpus_digest())
    got = index.lookup_kb(OLD_KB, scope=scope, now=NOW)
    assert [edge.ref.doc_id for edge in got.superseded] == [older.doc_id]
    assert named(got) == [] and not got.edges


def test_duplicate_rows_name_the_source_once():
    index, (older, _newer) = loaded(revision(1, repeats=3), revision(20, NEW_KB))
    got = index.lookup_kb(OLD_KB, scope=scopes.files_scope([older.doc_id]), now=NOW)
    assert len(got.superseded) == 3 and not got.edges
    assert len(named(got)) == 1 and named(got)[0].count(older.doc_id) == 1


@pytest.mark.parametrize('count', [5, 7, 12])
def test_source_list_is_deterministic_bounded_and_counts_unique_omitted_ids(count):
    raws = [revision(day) for day in range(1, count + 1)] + [revision(20, NEW_KB)]
    index, docs = loaded(*raws)
    ids = sorted(doc.doc_id for doc in docs[:-1])
    scope = scopes.files_scope(ids)
    first = index.lookup_kb(OLD_KB, scope=scope, now=NOW)
    reordered, _ = loaded(*reversed(raws))
    second = reordered.lookup_kb(OLD_KB, scope=scope, now=NOW)
    assert len(first.superseded) == count and first.status == 'not_observed'
    assert len(named(first)) == 1 and named(first) == named(second)
    warning = named(first)[0]
    assert len(warning) <= 500 and '\n' not in warning
    assert all(source in warning for source in ids[:5]) and not any(source in warning for source in ids[5:])
    assert [warning.index(source) for source in ids[:5]] == sorted(warning.index(source) for source in ids[:5])
    assert (f'and {count - 5} more' in warning) if count > 5 else ' more' not in warning


@pytest.mark.parametrize('bad', ['a' * 65, 'a' * 64 + '\n', '<b>' + 'a' * 64, 'Ａ' * 64])
def test_explicit_source_identifiers_keep_the_existing_fixed_digest_contract(bad):
    with pytest.raises(ValidationError):
        scopes.files_scope([bad])


def test_product_filter_explains_only_superseded_rows_for_that_product():
    index, (older, newer) = loaded(revision(1), revision(20, OLD_KB, products=('P2',)))
    selected = scopes.files_scope([older.doc_id, newer.doc_id])
    old_product = older.edges[0].scope_id
    active_product = newer.edges[0].scope_id
    old = index.lookup_kb(OLD_KB, scope=selected, scope_id=old_product, now=NOW)
    active = index.lookup_kb(OLD_KB, scope=selected, scope_id=active_product, now=NOW)
    assert old.status == 'not_observed' and not old.edges and len(old.superseded) == 1
    assert active.status == 'found' and len(active.edges) == 1 and not active.superseded
    assert len(named(old)) == 1 and older.doc_id in named(old)[0] and named(active) == []


@pytest.mark.parametrize('zoned', [False, True])
def test_ambiguous_native_revisions_are_not_declared_superseded(zoned):
    # Modified factual projection is an authored ambiguity control, not a new vendor statement.
    path = ROOT / 'tests/fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json'
    older = json.loads(path.read_bytes())
    newer = copy.deepcopy(older)
    date = '2026-10-28T01:48:49' + ('Z' if zoned else '')
    older['DocumentTracking']['CurrentReleaseDate'] = date
    newer['DocumentTracking']['CurrentReleaseDate'] = date
    newer['Vulnerability'][0]['Remediations'][0]['Description']['Value'] = '5999999'
    index, docs = loaded(*(json.dumps(value).encode() for value in (older, newer)))
    got = index.lookup_cve('CVE-2024-38193', scope=scopes.files_scope(d.doc_id for d in docs), now=NOW)
    assert index.active_ids() == {doc.doc_id for doc in docs} and not got.superseded
    assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in got.warnings)
    assert any(w.startswith('REVISION_EDGE_CONFLICT:') for w in got.warnings)
    assert got.disputed and named(got) == []


@pytest.mark.parametrize('lead', [OLD_KB, CVE])
def test_service_explains_selected_old_hit_without_a_false_document_negative(tmp_path, lead):
    service, (older, _newer) = seeded_service(tmp_path)
    out = service.search(lead, scope_file=scope_file(tmp_path, older.doc_id))
    assert (out.exit, out.status, out.result['state']) == (4, 'unavailable', 'NOT_OBSERVED')
    assert out.result['edges'] == out.result['cards'] == []
    assert len(named(out)) == 1 and named(out)[0] in out.text
    assert out.result['warnings'] == out.warnings and older.doc_id in out.text
    assert 'these documents do not list it' not in out.text
    with WorkspaceStore(service.root, clock=Clock()) as store:
        saved = store.current_revision(out.result['investigation_id'])
        assert any(w == named(out)[0] for w in saved.warnings)


def test_service_product_filter_does_not_reuse_another_products_named_warning(tmp_path):
    service, (older, newer) = seeded_service(tmp_path, revision(1), revision(20, OLD_KB, products=('P2',)))
    path = scope_file(tmp_path, older.doc_id, newer.doc_id)
    active = service.search(OLD_KB, scope_file=path, product=newer.edges[0].scope_id)
    old = service.search(OLD_KB, scope_file=path, product=older.edges[0].scope_id)
    # Existing service status is the full search's state; this warning-only repair must not change it.
    assert (active.exit, active.status, old.exit, old.status) == (0, 'complete', 0, 'complete')
    assert len(active.result['edges']) == 1 and not old.result['edges']
    assert named(active) == [] and PREFIX not in active.text
    assert len(named(old)) == 1 and named(old)[0] in old.text
    assert active.result['warnings'] == active.warnings and old.result['warnings'] == old.warnings


def test_partial_named_scope_explains_the_old_hit_without_hiding_missing_sources(tmp_path):
    service, (older, _newer) = seeded_service(tmp_path)
    out = service.search(OLD_KB, scope_file=scope_file(tmp_path, older.doc_id, 'f' * 64))
    assert (out.exit, out.status, out.result['coverage']['state']) == (3, 'partial', 'partial_in_scope')
    assert not out.result['edges'] and any(w.startswith('PARTIAL:') for w in out.warnings)
    assert len(named(out)) == 1 and named(out)[0] in out.text


def test_ordinary_active_and_absent_service_results_keep_their_presentation(tmp_path):
    service, (_older, newer) = seeded_service(tmp_path)
    active = service.search(NEW_KB, scope_file=scope_file(tmp_path, newer.doc_id))
    absent = service.search('KB9999')
    assert (active.exit, active.status, len(active.result['edges'])) == (0, 'complete', 1)
    assert (absent.exit, absent.status, absent.result['edges']) == (4, 'unavailable', [])
    assert named(active) == named(absent) == []
    assert 'these documents do not list it' in absent.text and PREFIX not in active.text + absent.text


@pytest.mark.parametrize('lead', [OLD_KB, CVE])
@pytest.mark.parametrize('as_json', [False, True])
def test_actual_headless_cli_keeps_exit_and_evidence_while_explaining_named_source(tmp_path, lead, as_json):
    service, (older, _newer) = seeded_service(tmp_path)
    path = scope_file(tmp_path, older.doc_id)
    guard = ('import socket,sys; '
             'socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(AssertionError("network")); '
             'from patchtrace.cli import main; code=main(sys.argv[1:]); '
             'assert not any(n.startswith("PySide6") for n in sys.modules); sys.exit(code)')
    command = [sys.executable, '-c', guard, 'kb', 'search', lead, '--offline', '--workspace', str(service.root),
               '--scope-file', str(path), *(['--json'] if as_json else [])]
    proc = subprocess.run(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 4 and proc.stderr == '', proc.stderr
    if as_json:
        value = json.loads(proc.stdout)
        assert value['status'] == 'unavailable' and value['result']['edges'] == value['result']['cards'] == []
        assert len([w for w in value['warnings'] if w.startswith(PREFIX)]) == 1
        assert value['warnings'] == value['result']['warnings']
    else:
        assert PREFIX in proc.stdout and older.doc_id in proc.stdout
        assert 'these documents do not list it' not in proc.stdout
