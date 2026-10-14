"""K5: additive ``winbindex.parse_rows`` (KB2 s2.D, RK2 s1.5). Synthetic records only; ``parse`` is unchanged."""
from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest

from patchtrace.acquisition import winbindex as wb
from patchtrace.acquisition.contracts import AcquisitionError

FIXTURES = Path(__file__).parent / 'fixtures' / 'kbcorrelation' / 'winbindex'
A, X, Y, Z, V = ('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64, 'f' * 64)


def drv() -> dict:
    return json.loads((FIXTURES / 'exampledrv.sys.json').read_text(encoding='utf-8'))


def rows(doc: dict | None = None):
    body = json.dumps(drv() if doc is None else doc).encode('utf-8')
    return wb.parse_rows(body, 'exampledrv.sys', '2099-02-12', compressed=False)


def by(result, kb: str, key: str):
    return next(r for r in result.rows if r.kb == kb and r.version_key == key)


def test_md5_only_rows_kept():
    result = rows()
    z = by(result, 'KB5099001', '11-24H2')
    assert z.sha256 == Z and z.variant == 'delta' and z.download == 'candidates'
    assert z.virtual_size is None and z.last_section_va == 0x1f000
    # the legacy parser still drops it, which is exactly the defect parse_rows exists to avoid
    assert Z not in {c.sha256 for c in wb.parse(json.dumps(drv()).encode(), 'exampledrv.sys', '2099-02-12',
                                                 compressed=False).candidates}


def test_version_to_kb_pairing_and_shared_versions_are_kept():
    result = rows()
    assert {(r.version_key, r.kb) for r in result.rows if r.sha256 == Y} == {('11-24H2', 'KB5097000'),
                                                                            ('11-24H2', 'KB5098000')}
    z = by(result, 'KB5099001', '11-24H2')
    assert z.other_versions == ('11-25H2',) and z.release_version == '26200.120'
    assert 'OS Builds 26200.120 and 26100.120' in z.heading


@pytest.mark.parametrize('kb, expected', [('KB5096000', 'standard'), ('KB5098000', 'preview')],
                         ids=['standard', 'preview'])
def test_heading_class(kb, expected):
    assert by(rows(), kb, '11-24H2').heading_class == expected


@pytest.mark.parametrize('heading, expected', [
    ('x (OS Build 1.1) Preview', 'preview'), ('x Out-of-band', 'out-of-band'), ('x out of band', 'out-of-band'),
    ('EXPIRED x', 'expired'), (None, 'none'), ('plain', 'standard')],
    ids=['preview', 'oob', 'oob-spaced', 'expired', 'missing', 'plain'])
def test_heading_class_table(heading, expected):
    assert wb.heading_class(heading) == expected


def test_base_is_a_dated_row_without_a_kb():
    base = by(rows(), None, '11-24H2')
    assert base.sha256 == A and base.release_date == '2098-10-01' and base.heading_class == 'none'
    assert base.release_version is None


def test_unreadable_entries_and_bodies_are_counted_not_dropped_silently():
    result = rows()
    assert result.skipped == 2 and result.skipped_bodies == 1
    assert '2 index rows skipped (newest builds may be missing)' in result.warnings[0]
    assert len({r.sha256 for r in result.rows}) == 5


def test_conflicting_file_info_sha_is_skipped():
    doc = drv()
    doc[X]['fileInfo']['sha256'] = Y
    result = rows(doc)
    assert X not in {r.sha256 for r in result.rows} and result.skipped == 3


@pytest.mark.parametrize('mutate', [lambda d: d.__setitem__(Z, []), lambda d: d[Z].__setitem__('fileInfo', 5)],
                         ids=['entry-list', 'info-int'])
def test_malformed_entry_is_skipped(mutate):
    doc = drv()
    mutate(doc)
    assert Z not in {r.sha256 for r in rows(doc).rows}


def test_rows_are_deterministic_and_variants_are_labelled():
    first, second = rows(), rows(dict(reversed(list(drv().items()))))
    assert first.rows == second.rows
    assert by(first, 'KB5096000', '11-24H2').variant == 'full'
    assert by(first, 'KB5096000', '11-24H2').download == 'direct'


def test_record_digest_changes_with_the_entry():
    doc = drv()
    before = by(rows(doc), 'KB5096000', '11-24H2').record_sha256
    doc[X]['fileInfo']['size'] += 1
    assert by(rows(doc), 'KB5096000', '11-24H2').record_sha256 != before


def test_hostile_heading_is_bounded_and_control_free():
    doc = drv()
    doc[X]['windowsVersions']['11-24H2']['KB5096000']['updateInfo']['heading'] = '‮EVIL\x00' + 'x' * 5000
    heading = by(rows(doc), 'KB5096000', '11-24H2').heading
    assert len(heading) <= wb.HEADING_MAX and '‮' not in heading and '\x00' not in heading


def test_as_mapping_is_plain_json_data():
    mapping = by(rows(), 'KB5099001', '11-24H2').as_mapping()
    assert json.loads(json.dumps(mapping)) == mapping and mapping['other_versions'] == ['11-25H2']


def test_parse_rows_reads_gzip_and_rejects_bad_dates():
    body = gzip.compress(json.dumps(copy.deepcopy(drv())).encode('utf-8'), mtime=0)
    assert wb.parse_rows(body, 'exampledrv.sys', '2099-02-12').rows
    with pytest.raises(AcquisitionError):
        wb.parse_rows(body, 'exampledrv.sys', 'yesterday')
