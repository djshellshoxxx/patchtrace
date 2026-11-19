"""Authored native reports: observable identity conflicts must never receive name-only credit."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import scorerun, scoring  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402
from tools.research_qualification.adapters import _common, rizin  # noqa: E402


def row(old=256, new=512, name='sym.fix', *, new_name=None, similarity=0.25, kind='PARTIAL'):
    return {'similarity': similarity, 'type': kind,
            'original': None if old is None else {'addr': old, 'name': name, 'size': 16},
            'modified': None if new is None else
            {'addr': new, 'name': name if new_name is None else new_name, 'size': 16}}


def text(*rows):
    return json.dumps(rows)


def duplicate_name_rows(*, unchanged=False):
    # Truth: 256->512 is the intended function and is unchanged; 768->1024 is unrelated.
    return [row(similarity=1.0), row(768, 1024, similarity=1.0 if unchanged else 0.25)]


def test_unchanged_expected_function_cannot_borrow_another_address_change():
    case = {'id': 'authored', 'expected': {'function': 'fix', 'accept': ['sym.fix']}}
    with pytest.raises(ValueError):
        scoring.score_case(case, rizin.parse(text(*duplicate_name_rows())))


@pytest.mark.parametrize('rows', [
    [row(name='_fix@8'), row(768, 1024, name='@fix@12')],
    [row(), row(name='sym.alias')],
    [row(), row(new_name='sym.alias')],
    [row(), row(new=1024, new_name='sym.other')],
    [row(), row(old=768, name='sym.other', new_name='sym.fix')],
    [row(similarity=1.0), row(similarity=0.25)],
    [row(), row(kind='COMPLETE')],
    [row(name='_fix@8'), row(name='@fix@12')],
    [row(), row(new=None, kind='UNLIKE')],
    [row(), row(old=None, kind='UNLIKE')],
    [row(name='sym.old', new_name='sym.fix', similarity=1.0),
     row(768, 1024, name='sym.fix', new_name='sym.unrelated')],
    [row(name='sym.old', new_name='_fix@8'), row(768, 1024, name='@fix@12')],
], ids=['decorated-name-collision', 'old-name-conflict', 'new-name-conflict', 'one-to-many', 'many-to-one',
        'similarity-conflict', 'type-conflict', 'raw-name-conflict', 'matched-and-removed', 'matched-and-added',
        'cross-side-rename-collision', 'cross-side-normalization-collision'])
def test_conflicts_are_refused_in_both_orders(rows):
    for ordered in (rows, list(reversed(rows))):
        with pytest.raises(ValueError):
            rizin.parse(text(*ordered))


@pytest.mark.parametrize('side', ['original', 'modified'])
def test_repeated_address_with_conflicting_size_is_refused(side):
    other = row()
    other[side]['size'] = 17
    with pytest.raises(ValueError):
        rizin.parse(text(row(), other))


@pytest.mark.parametrize('side', ['original', 'modified'])
@pytest.mark.parametrize(('field', 'bad'), [
    ('addr', None), ('addr', True), ('addr', -1), ('addr', 2**64), ('addr', 1.0), ('addr', '256'),
    ('name', None), ('name', 1), ('name', ''), ('name', ' \t '), ('name', '\ud800'),
    ('size', None), ('size', True), ('size', -1), ('size', 1.0),
])
def test_invalid_unchanged_side_is_not_skipped(side, field, bad):
    bad_row = row(similarity=1.0)
    bad_row[side][field] = bad
    with pytest.raises(ValueError):
        rizin.parse(text(bad_row))


@pytest.mark.parametrize('side', ['original', 'modified'])
@pytest.mark.parametrize('field', ['addr', 'name', 'size'])
def test_missing_identity_fields_are_refused(side, field):
    bad_row = row(similarity=1.0)
    del bad_row[side][field]
    with pytest.raises(ValueError):
        rizin.parse(text(bad_row))


@pytest.mark.parametrize('side', ['original', 'modified'])
@pytest.mark.parametrize('bad', [1, [], 'side'])
def test_nonobject_side_is_refused(side, bad):
    bad_row = row(similarity=1.0)
    bad_row[side] = bad
    with pytest.raises(ValueError):
        rizin.parse(text(bad_row))


@pytest.mark.parametrize('field', ['original', 'modified', 'similarity', 'type'])
def test_missing_native_row_field_is_refused(field):
    bad_row = row()
    del bad_row[field]
    with pytest.raises(ValueError):
        rizin.parse(text(bad_row))


@pytest.mark.parametrize('change', ['row-extra', 'side-extra', 'both-null'])
def test_native_row_shape_is_closed(change):
    bad_row = row()
    if change == 'row-extra':
        bad_row['name'] = 'legacy'
    elif change == 'side-extra':
        bad_row['original']['alias'] = 'different'
    else:
        bad_row['original'] = bad_row['modified'] = None
    with pytest.raises(ValueError):
        rizin.parse(text(bad_row))


@pytest.mark.parametrize('bad', [None, True, -0.1, 1.1, '0.5'])
def test_one_sided_similarity_is_still_validated(bad):
    with pytest.raises(ValueError):
        rizin.parse(text(row(new=None, similarity=bad, kind='UNLIKE')))


@pytest.mark.parametrize('bad', [None, True, 'NEW', 'complete'])
def test_native_match_type_is_validated(bad):
    with pytest.raises(ValueError):
        rizin.parse(text(row(similarity=1.0, kind=bad)))


@pytest.mark.parametrize(('old', 'new'), [
    ('"addr": 256', '"addr": 768, "addr": 256'),
    ('"name": "sym.fix"', '"name": "other", "name": "sym.fix"'),
    ('"similarity": 0.25', '"similarity": 1.0, "similarity": 0.25'),
    ('"size": 16', '"size": 17, "size": 16'),
    ('"original":', '"original": null, "original":'),
])
def test_duplicate_native_json_keys_are_rejected(old, new):
    with pytest.raises(ValueError, match='duplicate'):
        rizin.parse(text(row()).replace(old, new, 1))


def test_duplicate_legacy_json_keys_are_rejected():
    with pytest.raises(ValueError, match='duplicate'):
        rizin.parse('[{"name":"other","name":"fix","similarity":0.25}]')


@pytest.mark.parametrize('doc', [
    {'rows': [row()]},
    {'selected': [row()], 'ignored': [row(768, 1024)]},
    {'ignored': [row(768, 1024)], 'selected': [row()]},
    {'selected': [], 'ignored': [row()]},
    {'selected': [{'name': 'legacy', 'similarity': 0.25}], 'ignored': [row()]},
    {'selected': [{'name': 'legacy', 'similarity': 0.25}], 'metadata': {'nested': [row()]}},
])
def test_native_wrapper_cannot_hide_records(doc):
    with pytest.raises(ValueError):
        rizin.parse(json.dumps(doc))


@pytest.mark.parametrize('other', [{'name': 'legacy', 'similarity': 0.25}, {}, 1])
def test_mixed_native_and_legacy_layouts_are_refused(other):
    for doc in ([row(), other], [other, row()]):
        with pytest.raises(ValueError):
            rizin.parse(json.dumps(doc))


@pytest.mark.parametrize('repeated', [False, True])
def test_native_raw_row_cap_counts_unchanged_and_duplicates(monkeypatch, repeated):
    monkeypatch.setattr(_common, 'MAX_FUNCTIONS', 2)
    doc = [row(similarity=1.0)] * 3 if repeated else [
        row(i, i + 100, name=f'sym.f{i}', similarity=1.0) for i in range(3)]
    with pytest.raises(ValueError, match='more than'):
        rizin.parse(json.dumps(doc))


def test_exact_repeats_deduplicate_and_keep_existing_order():
    a, b = row(name='sym.b'), row(768, 1024, name='sym.a')
    repeated = copy.deepcopy(a)
    want = ['sym.a', 'sym.b']
    assert rizin.parse(text(a, b)) == want
    assert rizin.parse(text(a, b, repeated)) == want
    assert rizin.parse(text(repeated, b, a)) == want
    assert rizin.parse(text(row(similarity=1), row(similarity=1.0))) == []


def test_valid_ranking_and_one_sided_rows_are_preserved():
    doc = [row(name='sym.b'), row(768, 1024, name='sym.a'),
           row(1280, 1536, name='sym.same', similarity=1.0),
           row(1792, None, name='sym.zz', kind='UNLIKE'),
           row(None, 2048, name='sym.aa', kind='UNLIKE')]
    assert rizin.parse(text(*doc)) == ['sym.a', 'sym.b', 'sym.aa', 'sym.zz']
    assert rizin.parse(text(row(name='sym.old', new_name='sym.new'))) == ['sym.old']


def test_literal_prefix_unicode_and_address_bounds_are_preserved():
    doc = [row(0, 0, name='sym.fix'), row(1, 1, name='fix'),
           row(2, 3, name='sym.caf\u00e9'), row(3, 2, name='sym.cafe\u0301'),
           row(2**64 - 1, 2**64 - 1, name='_decorated@8')]
    assert rizin.parse(text(*doc)) == sorted(['sym.fix', 'fix', 'sym.caf\u00e9', 'sym.cafe\u0301', 'decorated'])


def test_valid_native_fixture_remains_unchanged():
    fixture = Path('tests/fixtures/secondary/rzdiff-functions.json')
    before = fixture.read_bytes()
    assert rizin.parse(before) == ['fcn.140001008', 'fcn.140002000', 'fcn.140003000']
    assert fixture.read_bytes() == before


def test_valid_legacy_flat_wrappers_and_text_remain_unchanged():
    flat = [{'name': 'sym.same', 'similarity': 1.0}, {'name': 'sym.fix', 'similarity': 0.25},
            {'name': 'sym.added', 'type': 'new'}]
    assert rizin.parse(json.dumps(flat)) == ['sym.fix', 'sym.added']
    assert rizin.parse(json.dumps({'rows': flat})) == ['sym.fix', 'sym.added']
    fixture = Path('tests/fixtures/research_adapters/radiff2_C.txt')
    assert rizin.parse(fixture.read_bytes()) == ['sym.parse_header', 'sym.alpha', 'sym.checksum', 'sym.new_func']


def test_cli_identity_refusal_is_clean_error(tmp_path, capsys):
    report = tmp_path / 'native.json'
    report.write_text(text(*duplicate_name_rows()))
    assert main(['adapters', 'rizin', str(report), '--case', 'authored']) == 2
    output = capsys.readouterr()
    assert output.out == ''
    assert 'error:' in output.err and 'Traceback' not in output.err


@pytest.mark.parametrize('no_change', [False, True])
def test_scorerun_ambiguous_report_is_blocked_not_scored(tmp_path, no_change):
    case = {'id': 'authored', 'layer': 'L3', 'project': 'authored', 'stratum': 'synthetic',
            'holdout': False, 'facts': 'verified',
            'older': {'sha256': 'a' * 64}, 'newer': {'sha256': 'b' * 64},
            'expected': {'no_change': True} if no_change else {'function': 'sym.fix'}}
    pair = {'id': 'authored', 'status': 'found',
            'older': {'path': 'authored/older/a.sys', 'sha256': 'a' * 64},
            'newer': {'path': 'authored/newer/a.sys', 'sha256': 'b' * 64}}
    report_dir = tmp_path / 'authored'
    report_dir.mkdir()
    # Exercise the existing report locator and engine dispatch; no native execution is implied.
    (report_dir / 'native.ghidriff.json').write_text(text(*duplicate_name_rows(unchanged=no_change)))
    result = scorerun.score_all({'authored': pair}, {'cases': [case], 'schema': 'rq-case-manifest/1'},
                               tmp_path, 5, 'rizin')
    assert result['rows'][0]['verdict'] == 'BLOCKED'
    assert result['rows'][0]['reason'] == 'unparseable_report'
    assert result['development']['scored'] == result['development']['pass'] == result['development']['fail'] == 0
    assert result['development']['blocked'] == 1
    assert scorerun.exit_for(result) == 2


@pytest.mark.parametrize('kind', ['COMPLETE', 'PARTIAL', 'UNLIKE'])
def test_orphan_native_type_requires_both_side_keys(kind):
    with pytest.raises(ValueError):
        rizin.parse(json.dumps([{'type': kind, 'similarity': 1.0}]))


def test_orphan_native_cli_is_clean_error(tmp_path, capsys):
    report = tmp_path / 'orphan.json'
    report.write_text('[{"similarity":1.0,"type":"COMPLETE"}]')
    assert main(['adapters', 'rizin', str(report)]) == 2
    output = capsys.readouterr()
    assert output.out == ''
    assert 'error:' in output.err and 'Traceback' not in output.err


def test_orphan_native_scorerun_cannot_credit_no_change(tmp_path):
    case = {'id': 'orphan', 'layer': 'L3', 'project': 'authored', 'stratum': 'synthetic',
            'holdout': False, 'facts': 'verified', 'older': {'sha256': 'a' * 64},
            'newer': {'sha256': 'b' * 64}, 'expected': {'no_change': True}}
    pair = {'id': 'orphan', 'status': 'found',
            'older': {'path': 'orphan/older/a.sys', 'sha256': 'a' * 64},
            'newer': {'path': 'orphan/newer/a.sys', 'sha256': 'b' * 64}}
    report_dir = tmp_path / 'orphan'
    report_dir.mkdir()
    (report_dir / 'orphan.ghidriff.json').write_text('[{"similarity":1.0,"type":"COMPLETE"}]')
    result = scorerun.score_all({'orphan': pair}, {'cases': [case], 'schema': 'rq-case-manifest/1'},
                               tmp_path, 5, 'rizin')
    assert result['rows'][0]['verdict'] == 'BLOCKED'
    assert result['rows'][0]['reason'] == 'unparseable_report'
    assert result['development']['scored'] == 0
    assert scorerun.exit_for(result) == 2


@pytest.mark.parametrize('kind', ['COMPLETE', 'PARTIAL', 'UNLIKE'])
def test_orphan_recognizer_preserves_named_flat_legacy(kind):
    assert rizin.parse(json.dumps([{'type': kind, 'similarity': 0.25, 'name': 'legacy'}])) == ['legacy']
    assert rizin.parse(json.dumps([{'type': kind, 'similarity': 0.25, 'name2': 'legacy'}])) == ['legacy']


def test_orphan_recognizer_does_not_promote_legacy_unnamed_rows():
    # Compatibility only: these legacy shapes have no verified native identity and cannot bypass the
    # production strict normalizer in a verified pilot.
    assert rizin.parse('[{}]') == []
    assert rizin.parse('[{"name":"","similarity":1.0,"type":"COMPLETE"}]') == []
