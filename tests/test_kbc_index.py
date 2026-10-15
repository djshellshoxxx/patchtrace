"""K1: local reverse index lookups, coverage statuses and the `kb index` import/status/verify verbs (KB-integration-plan
6, 8.1, 10.1 step 1; SPEC-37 32A S01-S10, S15-S18, NEG-02/03/04/05). SYNTHETIC/mocked; offline (sockets denied)."""
from __future__ import annotations

import gzip
import json

import kbc_helpers as h
import pytest
from kbc_k1_support import (
    CSAF_VALID,
    NOW,
    IntelligenceAdvisoryPort,
    import_doc,
    import_fixture,
    json_bytes,
    no_sockets,  # noqa: F401
)

from patchtrace.kbcorrelation import cli_index
from patchtrace.kbcorrelation.index import ReverseIndex, distinct_groups
from patchtrace.kbcorrelation.sources import scope as sc

pytestmark = pytest.mark.usefixtures('no_sockets')


def loaded(*names):
    index = ReverseIndex()
    for name in names:
        assert index.add(import_fixture(name))
    return index


def scope_ids(index):
    return {s.display_name: s.scope_id for s in index.scopes()}


def test_s01_kb_lookup_is_product_scoped():
    """S01: KB5099001 -> CVE-2099-20001 for the client scopes; the server scope and CVE B are not in the answer."""
    index = loaded('cvrf-2099-Feb.json')
    result = index.lookup_kb('KB5099001', now=NOW)
    assert result.status == 'found' and result.exit_code == 0
    assert {(g.cve, next(s.display_name for s in result.scopes if s.scope_id == g.scope_id)) for g in result.groups} == {
        (h.CVE_A, 'Example OS 24H2 x64'), (h.CVE_A, 'Example OS 24H2 ARM64')}
    assert [e.cve for e in result.mention_only] == [h.CVE_MENTION] and result.disputed == ()
    client = scope_ids(index)['Example OS 24H2 x64']
    narrowed = index.lookup_kb('KB5099001', scope_id=client, now=NOW)
    assert len(narrowed.groups) == 1 and narrowed.excluded == ((scope_ids(index)['Example OS 24H2 ARM64'], 1),)


def test_s02_cve_lookup_has_no_cross_join_of_kbs_between_scopes():
    index = loaded('cvrf-2099-Feb.json')
    result = index.lookup_cve(h.CVE_A, now=NOW)
    pairs = {(next(s.display_name for s in result.scopes if s.scope_id == g.scope_id), g.kb) for g in result.groups}
    assert pairs == {('Example OS 24H2 x64', 'KB5099001'), ('Example OS 24H2 ARM64', 'KB5099001'),
                     ('Example Server 2099 x64', 'KB5099002')}
    assert [(c.source_kind, c.stated_cwe) for c in result.cards] == [('cvrf', 'CWE-125')]
    server = index.lookup_cve(h.CVE_A, scope_id=scope_ids(index)['Example Server 2099 x64'], now=NOW)
    assert [g.kb for g in server.groups] == ['KB5099002'] and len(server.excluded) == 2


def test_s03_unrelated_cve_is_excluded():
    result = loaded('cvrf-2099-Feb.json').lookup_kb('KB5099002', now=NOW)
    assert {g.cve for g in result.groups} == {h.CVE_A, h.CVE_B}
    assert h.CVE_MENTION not in {e.cve for e in result.edges}


def test_s05_duplicates_display_once_but_keep_both_pointers():
    index = loaded('cvrf-2099-Feb-neg.json')
    result = index.lookup_kb('KB5099003', now=NOW)
    assert len(result.edges) == 2 and len(result.groups) == 1
    assert [r.pointer for r in result.groups[0].refs] == ['/vulnerabilities/0/remediations/0',
                                                          '/vulnerabilities/0/remediations/1']
    assert distinct_groups(result.edges) == result.groups


def test_s07_type5_only_kb_is_not_observed_and_empty_documents_are_not_zero_cves():
    """S07: a KB named only in known-issue text is not a remediation; an empty month is not '0 CVEs'."""
    result = loaded('cvrf-2099-Feb-neg.json').lookup_kb('KB5099006', now=NOW)
    assert result.status == 'not_observed' and result.exit_code == 4 and result.edges == ()
    assert len(result.mention_only) == 1 and any(w.startswith('MENTION_ONLY') for w in result.warnings)
    empty = loaded('cvrf-2099-Feb-empty.xml').lookup_kb('KB5099001', now=NOW)
    assert empty.status == 'not_observed' and any(w.startswith('EMPTY_DOCUMENTS') for w in empty.warnings)
    assert 'no CVEs' not in empty.text


def test_s08_disputed_rows_are_listed_apart_and_never_count_as_edges():
    result = loaded('cvrf-2099-Feb-neg.json').lookup_kb('KB5099008', now=NOW)
    assert result.edges == () and len(result.disputed) == 1 and result.status == 'not_observed'
    assert any(w.startswith('DISPUTED') for w in result.warnings)


def test_neg02_absent_kb_in_a_complete_scope_is_not_observed_with_coverage():
    result = loaded('cvrf-2099-Feb.json').lookup_kb('KB5099777', now=NOW)
    assert (result.status, result.exit_code, result.coverage.state) == ('not_observed', 4, 'complete_in_scope')
    assert 'Checked 1 of 1 documents' in result.text and 'nothing else was checked' in result.text


def test_s10_neg03_a_missing_document_makes_the_answer_partial_never_zero():
    """S10/NEG-03: a scope naming a document that is not loaded is partial (exit 3), whether or not edges were found."""
    index = loaded('cvrf-2099-Feb.json')
    scope = sc.months_scope(['2099-Jan', '2099-Feb'])
    absent = index.lookup_kb('KB5099777', scope=scope, now=NOW)
    assert (absent.status, absent.exit_code, absent.coverage.state) == ('partial', 3, 'partial_in_scope')
    assert any(w.startswith('PARTIAL') for w in absent.warnings) and '1 requested document not loaded' in absent.text
    found = index.lookup_kb('KB5099001', scope=scope, now=NOW)
    assert found.status == 'partial' and len(found.edges) == 2
    only_missing = index.lookup_kb('KB5099001', scope=sc.months_scope(['2099-Jan']), now=NOW)
    assert (only_missing.status, only_missing.exit_code, only_missing.coverage.state) == ('partial', 3, 'not_searched') \
        or only_missing.exit_code == 3


def test_partial_never_zero_cves():
    index = loaded('cvrf-2099-Feb.json')
    scope = sc.parse_scope_file(f'2099-Feb\n{"f" * 64}')
    result = index.lookup_kb('KB5099777', scope=scope, now=NOW)
    assert result.status == 'partial' and result.exit_code == 3 and result.coverage.requested_ids != result.coverage.inspected_ids


def test_empty_index_is_not_searched_exit_3():
    result = ReverseIndex().lookup_kb('KB5099001', now=NOW)
    assert (result.status, result.exit_code, result.coverage.state) == ('not_searched', 3, 'not_searched')
    assert any(w.startswith('NOT_SEARCHED') for w in result.warnings)


def test_neg04_neg05_other_kb_and_unselected_product_give_no_false_association():
    index = loaded('cvrf-2099-Feb.json')
    assert index.lookup_kb('KB5099002', scope_id=scope_ids(index)['Example OS 24H2 x64'], now=NOW).edges == ()


def test_canonical_inputs_only():
    index = loaded('cvrf-2099-Feb.json')
    with pytest.raises(Exception, match='canonical KB'):
        index.lookup_kb('kb5099001', now=NOW)
    with pytest.raises(ValueError):
        index.lookup_cve('cve-2099-20001', now=NOW)


def revised(release, current, kb):
    return import_doc(h.cvrf_document(
        [h.vulnerability(h.CVE_A, 'rev', remediations=[h.remediation(2, kb[2:], [h.PRODUCT_CLIENT])])],
        release_id=release) | {'document': {**h.baseline_cvrf()['document'], 'release_id': release,
                                            'current_release_date': current}})


def test_s15_revisions_are_both_retained_the_newest_is_active_and_a_timeline_exists():
    """S15/B4: two snapshots of one month stay in the index; lookups use the newest and list the older as superseded."""
    index = ReverseIndex()
    old, new = revised('2099-Feb', '2099-02-13', 'KB5099601'), revised('2099-Feb', '2099-03-05', 'KB5099602')
    assert old.doc_id != new.doc_id and index.add(old) and index.add(new)
    assert index.active_ids() == {new.doc_id}
    got = index.lookup_cve(h.CVE_A, now=NOW)
    assert [g.kb for g in got.groups] == ['KB5099602'] and [e.kb for e in got.superseded] == ['KB5099601']
    assert any(w.startswith('SUPERSEDED') for w in got.warnings) and got.coverage.state == 'complete_in_scope'
    scope_id = got.groups[0].scope_id
    line = index.timeline(h.CVE_A, scope_id)
    assert [(t.doc_id, t.active, t.kbs) for t in line] == [(old.doc_id, False, ('KB5099601',)),
                                                          (new.doc_id, True, ('KB5099602',))]
    assert index.lookup_kb('KB5099601', now=NOW).edges == ()
    assert len(index.lookup_kb('KB5099601', now=NOW).superseded) == 1


def test_adding_the_same_document_twice_changes_nothing():
    index = loaded('cvrf-2099-Feb.json')
    digest = index.corpus_digest()
    assert index.add(import_fixture('cvrf-2099-Feb.json')) is False
    assert index.corpus_digest() == digest and len(index.documents) == 1


def test_cached_corpus_goes_stale_after_the_policy_or_when_the_corpus_changes():
    index = loaded('cvrf-2099-Feb.json')
    pinned = index.cached_scope()
    late = index.lookup_kb('KB5099001', now='2099-05-15T00:00:00Z')
    assert late.coverage.state == 'stale_cache' and any(w.startswith('STALE_CACHE') for w in late.warnings)
    assert late.status == 'found'
    index.add(revised('2099-Mar', '2099-03-12', 'KB5099701'))
    assert index.lookup_kb('KB5099001', scope=pinned, now=NOW).coverage.state == 'stale_cache'
    assert index.lookup_kb('KB5099001', now=NOW).coverage.state == 'complete_in_scope'


def test_csaf_documents_join_the_same_index_as_associations():
    index = loaded('cvrf-2099-Feb.json', CSAF_VALID)
    result = index.lookup_kb('KB5099001', now=NOW)
    assert {g.relation for g in result.groups} == {'vendor-remediation', 'vendor-association'}
    csaf_only = index.lookup_kb('KB5099001', scope=sc.files_scope([import_fixture(CSAF_VALID).doc_id]), now=NOW)
    assert csaf_only.coverage.source_kind == 'csaf' and {g.relation for g in csaf_only.groups} == {'vendor-association'}


def test_edge_set_digest_follows_active_edges():
    a = loaded('cvrf-2099-Feb.json').edge_set_digest()
    b = loaded('cvrf-2099-Feb-reordered.json').edge_set_digest()
    assert a != b and a == loaded('cvrf-2099-Feb.json').edge_set_digest()


# --------------------------------------------------------------------------------------------- CLI


class Clock:
    def now_utc(self):
        return NOW


class Run:
    def __init__(self, tmp_path, capsys):
        self.ws, self.capsys = tmp_path / 'ws', capsys
        self.ports = cli_index.IndexPorts(advisory=IntelligenceAdvisoryPort(), clock=Clock())

    def __call__(self, *argv, ports=None):
        code = cli_index.main([*argv, '--workspace', str(self.ws), '--json'], ports=ports or self.ports)
        out = self.capsys.readouterr()
        return code, (json.loads(out.out) if out.out.strip() else None), out.err


@pytest.fixture
def run(tmp_path, capsys):
    return Run(tmp_path, capsys)


def fx(name):
    return str(h.fixture_path(name))


def test_e0_step1_import_baseline_reports_four_edges_one_mention_only(run):
    """Plan 10.1 step 1 (reconciled): 1 document, 4 edges, 1 mention-only (5 rows), coverage complete_in_scope."""
    code, doc, _ = run('import', fx('cvrf-2099-Feb.json'))
    result = doc['result']
    assert code == 0 and doc['status'] == 'complete' and doc['command'] == 'kb index import'
    assert (len(result['documents']), result['totals']['edges'], result['totals']['mention_only'],
            result['totals']['edge_rows']) == (1, 4, 1, 5)
    assert result['coverage']['state'] == 'complete_in_scope' and result['index_changed'] is True
    assert result['documents'][0]['authenticity'] == 'unverified-local-file'
    assert str(run.ws) not in json.dumps(doc)  # no absolute paths in the output


def test_import_is_idempotent_and_status_lists_it(run):
    run('import', fx('cvrf-2099-Feb.json'))
    code, doc, _ = run('import', fx('cvrf-2099-Feb.json'))
    assert code == 0 and doc['result']['index_changed'] is False and doc['result']['documents'][0]['already_present']
    code, doc, _ = run('status')
    assert code == 0 and doc['result']['state'] == 'ready' and doc['result']['documents'][0]['active'] is True
    assert doc['result']['coverage']['text'].startswith('Checked 1 of 1 documents')


@pytest.mark.parametrize('bad', ['cvrf-2099-Feb-duplicate-key.json', 'cvrf-2099-Feb-dialect-unknown.xml'])
def test_malformed_file_is_exit_2_and_the_index_is_unchanged(run, bad):
    """Plan 10.1 step 1: a malformed file -> 2 and the index (and object store) is unchanged, even in a batch."""
    run('import', fx('cvrf-2099-Feb.json'))
    before = sorted(p.name for p in run.ws.rglob('*') if p.is_file())
    ids = [d['doc_id'] for d in run('status')[1]['result']['documents']]
    code, doc, err = run('import', fx('cvrf-2099-Feb-empty.xml'), fx(bad))
    assert code == 2 and doc['status'] == 'failed' and doc['result']['index_changed'] is False
    assert doc['result']['rejected'][0]['file'] == bad and err.startswith('error:')
    assert sorted(p.name for p in run.ws.rglob('*') if p.is_file()) == before
    assert [d['doc_id'] for d in run('status')[1]['result']['documents']] == ids


def test_missing_file_and_oversize_file_are_exit_2(run, tmp_path):
    code, doc, _ = run('import', str(tmp_path / 'nope.json'))
    assert code == 2 and doc['result']['rejected'][0]['code'] == 'PT-KBC-INPUT'
    big = tmp_path / 'big.json'
    big.write_bytes(b'{' + b' ' * (32 * 1024 * 1024))
    code, doc, _ = run('import', str(big))
    assert code == 2 and doc['result']['rejected'][0]['code'] == 'PT-KBC-LIMIT'


def test_csaf_needs_the_advisory_port_and_works_with_it(run):
    unbound = cli_index.IndexPorts(clock=Clock())
    code, doc, _ = run('import', fx(CSAF_VALID), ports=unbound)
    assert code == 2 and doc['result']['rejected'][0]['code'] == 'PT-KBC-UNSUPPORTED'
    code, doc, _ = run('import', fx(CSAF_VALID))
    assert code == 0 and doc['result']['documents'][0]['kind'] == 'csaf'
    code, doc, _ = run('status', ports=unbound)  # stored CSAF but no parser bound: reported, exit 3
    assert code == 3 and doc['status'] == 'partial' and doc['result']['unreadable'][0]['reason']


def test_gzip_import_stores_plain_bytes_hash(run, tmp_path):
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json')
    packed = tmp_path / 'm.json.gz'
    packed.write_bytes(gzip.compress(raw))
    code, doc, _ = run('import', str(packed))
    assert code == 0 and doc['result']['documents'][0]['sha256'] == h.sha256_hex(raw)
    stored = next(run.ws.glob('objects/*/*.gz'))
    assert stored.stem == h.sha256_hex(raw) and gzip.decompress(stored.read_bytes()) == raw


def test_verify_detects_tampering_and_missing_objects(run):
    run('import', fx('cvrf-2099-Feb.json'), fx('cvrf-2099-Feb-neg.json'))
    code, doc, _ = run('verify')
    assert code == 0 and doc['result']['state'] == 'ok' and len(doc['result']['checked']) == 2
    objects = sorted(run.ws.glob('objects/*/*.gz'))
    objects[0].write_bytes(gzip.compress(b'{"tampered": true}'))
    objects[1].unlink()
    code, doc, _ = run('verify')
    assert code == 3 and doc['status'] == 'failed' and len(doc['result']['problems']) == 2
    code, doc, _ = run('status')
    assert code == 3 and len(doc['result']['unreadable']) == 2


def test_empty_workspace_is_exit_4_for_status_and_verify(run):
    for verb in ('status', 'verify'):
        code, doc, _ = run(verb)
        assert code == 4 and doc['status'] == 'unavailable'


def test_damaged_database_is_a_runtime_error(run):
    run('import', fx('cvrf-2099-Feb.json'))
    (run.ws / 'kbc.sqlite3').write_bytes(b'not a database' * 100)
    code, doc, _ = run('status')
    assert code == 3 and 'PT-KBC-STORAGE' in doc['error']


def test_arguments_and_help(run, capsys):
    assert cli_index.main(['import'], ports=run.ports) == 2
    assert cli_index.main(['bogus', '--json'], ports=run.ports) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'
    assert cli_index.main(['--help'], ports=run.ports) == 0


def test_default_workspace_resolution(tmp_path):
    assert cli_index.default_workspace({'LOCALAPPDATA': str(tmp_path)}) == tmp_path / 'PatchTrace' / 'kb'
    assert cli_index.default_workspace({'XDG_DATA_HOME': str(tmp_path)}) == tmp_path / 'PatchTrace' / 'kb'
    assert cli_index.default_workspace({}).parts[-3:] == ('share', 'PatchTrace', 'kb')


def test_hostile_advisory_text_plain_in_cli_output(run, tmp_path):
    doc = h.baseline_cvrf()
    doc['vulnerabilities'][0]['remediations'][0]['description'] = '<script>alert(1)</script>‮'
    path = tmp_path / 'hostile.json'
    path.write_bytes(json_bytes(doc))
    code, out, _ = run('import', str(path))
    assert code == 0
    blob = json.dumps(out)
    assert '<script>' not in blob and '\\u202e' not in blob
