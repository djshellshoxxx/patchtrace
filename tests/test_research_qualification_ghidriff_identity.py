"""Authored Ghidriff report ambiguity controls; no native engine or accuracy claim."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import scorerun  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402
from tools.research_qualification.adapters import _common, ghidriff  # noqa: E402


def row(name='Target', *, old='1000', new='2000', new_name=None, changed=True):
    return {'old': {'name': name, 'fullname': name, 'address': old},
            'new': {'name': new_name or name, 'fullname': new_name or name, 'address': new},
            'diff_type': ['code'] if changed else ['address'], 'ratio': 0.25 if changed else 1.0,
            'b_ratio': 0.5 if changed else 1.0, 'm_ratio': 0.75 if changed else 1.0}


def document(*rows, added=(), deleted=()):
    return {'functions': {'modified': list(rows), 'added': list(added), 'deleted': list(deleted)}}


def text(*rows, **kwargs):
    return json.dumps(document(*rows, **kwargs))


@pytest.mark.parametrize('first_changed', [False, True])
def test_same_label_on_distinct_endpoints_is_refused_before_unchanged_filter(first_changed):
    rows = [row(changed=first_changed), row(old='3000', new='4000')]
    for ordered in (rows, rows[::-1]):
        with pytest.raises(ValueError, match='ambiguous|conflict'):
            ghidriff.parse(text(*ordered))


@pytest.mark.parametrize('side', ['old', 'new'])
def test_same_address_with_other_label_is_refused(side):
    other = row('Other', old='3000', new='4000')
    other[side]['address'] = row()[side]['address']
    with pytest.raises(ValueError, match='ambiguous|conflict'):
        ghidriff.parse(text(row(changed=False), other))


@pytest.mark.parametrize('side', ['old', 'new'])
def test_counterpart_conflicts_are_refused(side):
    other = row()
    other[side]['address'] = '3000'
    with pytest.raises(ValueError, match='ambiguous|conflict'):
        ghidriff.parse(text(row(), other))


def test_renamed_new_label_cannot_identify_another_pair():
    with pytest.raises(ValueError, match='ambiguous|conflict'):
        ghidriff.parse(text(row('Before', new_name='After', changed=False),
                            row('After', old='3000', new='4000')))


def test_name_normalization_cannot_merge_different_functions():
    with pytest.raises(ValueError, match='ambiguous|conflict'):
        ghidriff.parse(text(row('_Target@8', changed=False), row('Target', old='3000', new='4000')))


@pytest.mark.parametrize('key', ['added', 'deleted'])
def test_one_sided_record_conflicts_with_a_paired_name(key):
    extra = {'name': 'Target', 'fullname': 'Target', 'address': '3000'}
    with pytest.raises(ValueError, match='ambiguous|conflict'):
        ghidriff.parse(text(row(changed=False), **{key: [extra]}))


@pytest.mark.parametrize(('original', 'replacement'), [
    ('"functions":', '"functions": {}, "functions":'),
    ('"modified":', '"modified": [], "modified":'),
    ('"old":', '"old": {}, "old":'),
    ('"name": "Target"', '"name": "Other", "name": "Target"'),
    ('"ratio": 0.25', '"ratio": 1.0, "ratio": 0.25'),
])
def test_duplicate_json_keys_are_refused(original, replacement):
    with pytest.raises(ValueError, match='duplicate'):
        ghidriff.parse(text(row()).replace(original, replacement, 1))


@pytest.mark.parametrize('side', ['old', 'new'])
@pytest.mark.parametrize(('field', 'value'), [
    ('name', 1), ('name', '\ud800'), ('name', 'n' * 513),
    ('fullname', 1), ('fullname', 'bad\nname'), ('fullname', '\ud800'),
    ('address', True), ('address', 3), ('address', -1), ('address', 'not-address'),
    ('address', '10000000000000000'),
])
def test_invalid_unchanged_side_is_not_silently_skipped(side, field, value):
    bad = row(changed=False)
    bad[side][field] = value
    with pytest.raises(ValueError):
        ghidriff.parse(text(bad))


@pytest.mark.parametrize('side', ['old', 'new'])
@pytest.mark.parametrize('value', [None, [], 4, 'side'])
def test_present_side_must_be_an_object(side, value):
    bad = row(changed=False)
    bad[side] = value
    with pytest.raises(ValueError):
        ghidriff.parse(text(bad))


@pytest.mark.parametrize('side', ['old', 'new'])
def test_blank_side_cannot_become_no_change_credit(side):
    bad = row(changed=False)
    bad[side]['name'] = bad[side]['fullname'] = ''
    with pytest.raises(ValueError):
        ghidriff.parse(text(bad))


@pytest.mark.parametrize(('field', 'value'), [
    ('diff_type', [None]), ('diff_type', ['name', 3]), ('b_ratio', True), ('m_ratio', 2),
])
def test_unused_change_fields_still_validate(field, value):
    bad = row(changed=False)
    bad[field] = value
    with pytest.raises(ValueError):
        ghidriff.parse(text(bad))


def test_unknown_function_collection_cannot_hide_ambiguity():
    doc = document(row())
    doc['functions']['unchanged'] = [row(old='3000', new='4000', changed=False)]
    with pytest.raises(ValueError):
        ghidriff.parse(json.dumps(doc))


@pytest.mark.parametrize('repeated', [False, True])
def test_raw_record_cap_includes_unchanged_and_repeated_rows(monkeypatch, repeated):
    monkeypatch.setattr(_common, 'MAX_FUNCTIONS', 2)
    rows = [row(changed=False)] * 3 if repeated else [
        row(f'f{i}', old=f'{i:x}', new=f'{i + 10:x}', changed=False) for i in range(3)]
    with pytest.raises(ValueError, match='more than'):
        ghidriff.parse(text(*rows))


def test_exact_json_repeats_deduplicate_without_changing_ranking():
    first, second = row('b'), row('a', old='3000', new='4000')
    assert ghidriff.parse(text(first, second, copy.deepcopy(first))) == ['a', 'b']
    assert ghidriff.parse(text(row(changed=False), row(changed=False))) == []


def test_name_only_legacy_rows_and_valid_native_addresses_remain_supported():
    legacy = {'old': {'fullname': 'legacy'}, 'diff_type': ['code'], 'ratio': 0.75}
    assert ghidriff.parse(text(legacy)) == ['legacy']
    assert ghidriff.parse(text(row('Target', old='0', new='FFFFFFFFFFFFFFFF'))) == ['Target']
    assert ghidriff.parse(text(row('Target', old=None, new=''))) == ['Target']
    assert ghidriff.parse(text(row('Before', new_name='After'))) == ['Before']


@pytest.mark.parametrize('section', ['Modified', 'Modified (No Code Changes)', 'Added', 'Deleted'])
def test_markdown_duplicate_labels_are_refused_across_all_sections(section):
    report = ('# Modified\n## Target\n### Target Diff\n```diff\n-old\n+new\n```\n'
              f'# {section}\n## Target\n')
    with pytest.raises(ValueError, match='ambiguous|conflict'):
        ghidriff.parse(report)


def test_markdown_unchanged_function_still_has_a_valid_name():
    with pytest.raises(ValueError):
        ghidriff.parse('# Modified (No Code Changes)\n## bad\u202ename\n')


@pytest.mark.parametrize('reported', ['_Target@8', '@Target@12'])
def test_markdown_diff_block_matches_the_reported_heading_before_normalization(reported):
    report = f'# Modified\n## {reported}\n### {reported} Diff\n```diff\n-old\n+new\n```\n'
    assert ghidriff.parse(report) == ['Target']


def test_markdown_record_cap_includes_unchanged_headings(monkeypatch):
    monkeypatch.setattr(_common, 'MAX_FUNCTIONS', 2)
    with pytest.raises(ValueError, match='more than'):
        ghidriff.parse('# Modified (No Code Changes)\n## one\n## two\n## three\n')


def test_unknown_markdown_section_is_not_a_no_change_report():
    with pytest.raises(ValueError):
        ghidriff.parse('# Modified (Unrecognized)\n## Target\n')


def test_existing_fixture_bytes_and_rankings_are_unchanged():
    root = Path('tests/fixtures/research_adapters')
    fixtures = {name: (root / name).read_bytes() for name in ('ghidriff_report.json', 'ghidriff_report.md')}
    assert ghidriff.parse(fixtures['ghidriff_report.json']) == [
        'Parser::parse_header', 'alpha', 'checksum', 'Util::old_helper', 'new_helper']
    assert ghidriff.parse(fixtures['ghidriff_report.md']) == [
        'Parser::parse_header', 'small_fix', 'Util::old_helper', 'new_helper']
    assert fixtures == {name: (root / name).read_bytes() for name in fixtures}


def test_cli_ambiguity_refusal_has_no_partial_stdout(tmp_path, capsys):
    report = tmp_path / 'authored.json'
    report.write_text(text(row(changed=False), row(old='3000', new='4000')), encoding='utf-8')
    assert main(['adapters', 'ghidriff', str(report), '--case', 'authored']) == 2
    output = capsys.readouterr()
    assert output.out == '' and 'error:' in output.err and 'Traceback' not in output.err


@pytest.mark.parametrize('no_change', [False, True])
def test_scorerun_refuses_ambiguous_report_without_scoring(tmp_path, no_change):
    case = {'id': 'authored', 'layer': 'L3', 'project': 'authored', 'stratum': 'authored',
            'holdout': False, 'facts': 'verified', 'older': {'sha256': 'a' * 64},
            'newer': {'sha256': 'b' * 64},
            'expected': {'no_change': True} if no_change else {'function': 'Target'}}
    pair = {'id': 'authored', 'status': 'found',
            'older': {'path': 'authored/older/a.sys', 'sha256': 'a' * 64},
            'newer': {'path': 'authored/newer/a.sys', 'sha256': 'b' * 64}}
    folder = tmp_path / 'authored'
    folder.mkdir()
    (folder / 'result.ghidriff.json').write_text(
        text(row(changed=False), row(old='3000', new='4000', changed=not no_change)), encoding='utf-8')
    result = scorerun.score_all({'authored': pair}, {'cases': [case], 'schema': 'rq-case-manifest/1'},
                               tmp_path, 5, 'ghidriff')
    assert result['rows'][0]['verdict'] == 'BLOCKED'
    assert result['rows'][0]['reason'] == 'unparseable_report'
    assert result['development']['scored'] == 0 and result['development']['blocked'] == 1
    assert scorerun.exit_for(result) == 2
