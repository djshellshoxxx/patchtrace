from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from search_builders import RUN, SECRET_STRING, make_service

from patchtrace.search.build import build_request
from patchtrace.search.errors import SearchError
from patchtrace.search.segment import Flag
from patchtrace.search.sources.base import selected_run
from patchtrace.search.sources.functions import function_spec
from patchtrace.search.sources.notes import annotation_spec, finding_spec
from patchtrace.search.sources.pe import PeLoader, pe_spec
from patchtrace.search.sources.raw import raw_spec


@pytest.fixture
def service(tmp_path):
    return make_service(tmp_path)


def spec(service, group: str):
    return next(s for s in build_request(service).specs if s.group == group)


def docs(service, group: str):
    return list(spec(service, group).documents())


def by_subject(items, subject: str, kind: str):
    return next(d for d in items if d.subject == subject and d.kind == kind)


def test_functions_emit_name_and_code_documents(service):
    items = docs(service, 'fn')
    fmt = by_subject(items, 'f-new-fmt', 'function')
    assert (fmt.side, fmt.name_raw, fmt.extra) == ('newer', 'formatline', 'int FormatLine(int v)')
    assert 'format' in fmt.name_words.split() and 'line' in fmt.name_words.split()
    code = by_subject(items, 'f-new-fmt', 'code')
    assert code.ref == fmt.ref and 'CheckLength(v)' in code.code_body
    assert {'check', 'length', 'probe', 'read'} <= set(code.code_idents.split())
    assert not any(d.kind == 'code' for d in items if d.subject == 'f-old-helper')


def test_function_flags_and_rva(service):
    items = docs(service, 'fn')
    assert by_subject(items, 'f-new-auto', 'function').flags & Flag.AUTO
    assert by_subject(items, 'f-new-same', 'function').flags & Flag.UNCHANGED
    assert not by_subject(items, 'f-new-chk', 'function').flags
    # the synthetic PE image base is 0x140000000, read from the verified artifact copy
    assert by_subject(items, 'f-new-chk', 'function').rva == 0x1F00
    assert by_subject(items, 'f-old-fmt', 'code').rva == 0x1600


def test_function_upstream_name_words_are_searchable_but_derived(service):
    old = by_subject(docs(service, 'fn'), 'f-old-fmt', 'function')
    assert old.name_raw == 'formatline' and 'fun' in old.name_words.split()


@pytest.mark.parametrize('seed', [1, 2, 3], ids=['s1', 's2', 's3'])
def test_functions_are_independent_of_source_order(tmp_path, service, seed):
    other = make_service(tmp_path / 'other', seed=seed)
    assert spec(other, 'fn').digest16 == spec(service, 'fn').digest16
    assert docs(other, 'fn') == docs(service, 'fn')
    assert docs(other, 'ann') == docs(service, 'ann')


def test_function_digest_follows_code_edits_of_equal_length(tmp_path, service):
    other = make_service(tmp_path / 'other')
    other.project.matches[0].newer[0].code = other.project.matches[0].newer[0].code.replace('v)', 'w)', 1)
    assert spec(other, 'fn').digest16 != spec(service, 'fn').digest16


def test_no_completed_run_means_not_applicable(tmp_path):
    empty = make_service(tmp_path, completed=False)
    for group in ('fn', 'raw'):
        s = spec(empty, group)
        assert (s.status, s.digest16, list(s.documents())) == ('not-applicable', None, [])
        assert 'No completed analysis run' in s.reason
    assert selected_run(empty.project, None) is None


def test_pe_groups_cover_imports_exports_and_build_facts(service):
    older, newer = docs(service, 'pe:older'), docs(service, 'pe:newer')
    labels = lambda items, kind: {d.display for d in items if d.kind == kind}  # noqa: E731
    assert labels(newer, 'import') == {'KERNEL32.dll!CreateFileW', 'KERNEL32.dll!ReadFile', 'KERNEL32.dll!WriteFile'}
    assert 'KERNEL32.dll!WriteFile' not in labels(older, 'import')
    assert labels(newer, 'export') == {'ExportedApi', 'NewExport'}
    build = labels(older, 'build')
    assert {'Section: .text', 'PDB: synthetic.pdb'} <= build and any(b.startswith('COFF timestamp (untrusted)') for b in build)
    assert all(d.side == 'older' for d in older) and [d.ref for d in older] == list(range(len(older)))
    write = by_subject(newer, 'KERNEL32.dll', 'import')
    assert 'create' in write.name_words.split() or 'file' in write.name_words.split()


def test_pe_group_with_a_damaged_artifact_fails_with_a_source_error(tmp_path):
    service = make_service(tmp_path)
    (tmp_path / service.project.artifacts[0].relative_path).write_bytes(b'tampered')
    with pytest.raises(SearchError) as caught:
        list(pe_spec('older', service.project.artifacts[0], PeLoader(tmp_path, {
            a.side: a for a in service.project.artifacts})).documents())
    assert caught.value.code == 'PT-SEARCH-SOURCE'


def test_notes_skip_validation_json_and_keep_stale_marker(service):
    items = docs(service, 'ann')
    assert sorted(d.text_body for d in items) == ['Looks like a bounds check', 'Revisit CheckLength callers']
    assert {d.text_title for d in items} == {'note', 'bookmark'}
    service.project.annotations[0].stale = True
    assert [d.extra for d in annotation_spec(service.project).documents() if d.subject == 'm-mod'] == ['stale']


def test_findings_keep_model_and_analyst_origin_apart(service):
    items = docs(service, 'fnd')
    assert [d.extra for d in items] == ['model', 'analyst']
    assert 'CWE-787' in items[0].text_body and 'Confirmed' not in items[0].text_body
    assert items[1].text_body.startswith('Confirmed')
    assert finding_spec(service.project).digest16 == spec(service, 'fnd').digest16


def test_raw_strings_map_added_to_newer_and_dedupe(service):
    items = docs(service, 'raw')
    strings = [(d.side, d.display) for d in items if d.kind == 'string']
    assert ('newer', 'Contoso\\Config') in strings and ('older', 'Legacy path') in strings
    assert sorted(strings).count(('older', 'CheckLength failed')) == 1 and ('newer', 'CheckLength failed') in strings
    symbols = {(d.side, d.display): d for d in items if d.kind == 'function'}
    assert symbols[('newer', 'CheckLength')].flags & Flag.SYMBOL and ('older', 'OldHelper') in symbols
    assert spec(service, 'raw').reason == 'unchanged functions: not indexed'


def test_raw_secrets_are_redacted_but_hashed(service):
    items = docs(service, 'raw')
    secret = next(d for d in items if d.flags & Flag.SECRET)
    assert secret.display == '[redacted: credential-assignment]' and secret.text_title == secret.display
    assert secret.value_sha == hashlib.sha256(SECRET_STRING.encode()).hexdigest()
    assert 'hunter2' not in repr(items)


@pytest.mark.parametrize('document', [{'functions': {}}, {'strings': ['a']}, {'strings': {'added': 'x'}},
                                      {'symbols': {'sideways': []}}],
                         ids=['no-section', 'list-section', 'bad-list', 'bad-key'])
def test_raw_with_an_unrecognised_shape_fails_closed(tmp_path, document):
    service = make_service(tmp_path, raw=document)
    with pytest.raises(SearchError) as caught:
        list(spec(service, 'raw').documents())
    assert caught.value.code == 'PT-SEARCH-SOURCE'


def test_raw_with_a_changed_file_fails_the_hash_check(service):
    path = service.root / service.project.runs[0].raw_path
    path.write_bytes(path.read_bytes().replace(b'Legacy', b'Altered'))
    with pytest.raises(SearchError) as caught:
        list(spec(service, 'raw').documents())
    assert 'hash' in caught.value.message


def test_raw_run_without_a_saved_file_is_unavailable(service):
    service.project.runs[0].raw_path = None
    s = raw_spec(service.project, Path(service.root), None)
    assert (s.status, s.digest16) == ('unavailable', None)


def test_raw_and_function_specs_use_the_same_run(service):
    assert RUN == selected_run(service.project, None).id
    assert function_spec(service.project, 'nope', PeLoader(service.root, {})).status == 'not-applicable'
