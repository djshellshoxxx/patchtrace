"""SPEC-08 §6 pure acceptance: Winbindex parsing, URL formatting, candidate arithmetic."""
from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest

from patchtrace.acquisition import winbindex as wb
from patchtrace.acquisition.contracts import (
    AcquisitionError,
    AcquisitionQuery,
    BuildCandidate,
    acquisition_id,
    symbol_server_url,
    validate_file_name,
)

FIXTURE = Path(__file__).parent / 'fixtures' / 'winbindex' / 'afd.sys.json'
DIRECT = '7f145acc6cd255c5b21b64c6e0f84c487738bacbc7a8e5f812bc40368e6d70eb'
DELTA_ONLY = 'a151f2258bf5d5748f1cd25b536dc5412e72a5418b319bfd01bc033c5225236a'


def record() -> dict:
    return json.loads(FIXTURE.read_text(encoding='utf-8'))


def gz(doc) -> bytes:
    return gzip.compress(json.dumps(doc).encode(), mtime=0)


def parse(doc, name='afd.sys'):
    return wb.parse(gz(doc), name, '2026-10-12')


def by_sha(result):
    return {c.sha256: c for c in result.candidates}


def test_real_afd_fixture_parses_and_classifies():
    result = parse(record())
    assert result.skipped == 0 and result.warnings == ()
    cands = by_sha(result)
    assert len(cands) == 4
    direct = cands[DIRECT]
    assert direct.download == 'direct' and direct.virtual_size == 729088 and direct.timestamp == 3547891873
    assert direct.size == 744832 and direct.x64 and direct.version.startswith('10.0.28000.3086')
    assert direct.windows_versions == ('11-26H1',) and direct.kbs[0].kb == 'KB5124006'
    assert direct.kbs[0].release_date == '2026-09-22' and direct.source == 'winbindex@2026-10-12'
    delta = cands[DELTA_ONLY]
    assert delta.download == 'candidates' and delta.virtual_size is None
    assert (delta.last_section_va, delta.last_section_raw) == (704512, 700416)
    assert all(c.download == 'direct' for s, c in cands.items() if s != DELTA_ONLY)


def test_direct_url_matches_verified_live_probe():
    # docs/research/phase3/acquisition.md: this exact URL returned 302 and the matching bytes.
    assert wb.direct_url(by_sha(parse(record()))[DIRECT]) == \
        'https://msdl.microsoft.com/download/symbols/afd.sys/D37888A1b2000/afd.sys'


def test_url_format_is_padded_upper_timestamp_and_lower_unpadded_size():
    assert symbol_server_url('x.dll', 0x1, 0xABC000) == \
        'https://msdl.microsoft.com/download/symbols/x.dll/00000001abc000/x.dll'
    with pytest.raises(AcquisitionError):
        symbol_server_url('x.dll', 2**32, 0x1000)
    with pytest.raises(AcquisitionError):
        symbol_server_url('x.dll', 1, 0)


def test_metadata_url_is_lowercase_only():
    assert wb.metadata_url('afd.sys') == \
        'https://winbindex.m417z.com/data/by_filename_compressed/afd.sys.json.gz'
    for bad in ('AFD.SYS', 'afd.txt', '../afd.sys', 'a/b.sys', 'afd.sys\n', '', 'sys', 'x' * 130 + '.sys', 7):
        with pytest.raises(AcquisitionError):
            wb.metadata_url(bad)
    assert validate_file_name('clfs.sys') == 'clfs.sys'
    with pytest.raises(ValueError):
        AcquisitionQuery(file_name='Clfs.sys')
    assert AcquisitionQuery(file_name='clfs.sys').dataset == 'x64'


def test_candidate_enumeration_arithmetic():
    cand = by_sha(parse(record()))[DELTA_ONLY]
    # end = 704512 + (734744 - 700416) = 738840 -> round up to 0xB5000; stop at 0xAC000 + 0x1000.
    sizes = wb.candidate_sizes(cand)
    assert sizes[0] == 0xB5000 and sizes[-1] == 0xAD000 and len(sizes) == 9
    assert all(a - b == 0x1000 for a, b in zip(sizes, sizes[1:], strict=False))
    urls = wb.candidate_urls(cand)
    assert urls[0].endswith('/B1F54133b5000/afd.sys')
    with pytest.raises(AcquisitionError):
        wb.direct_url(cand)
    with pytest.raises(AcquisitionError):
        wb.candidate_sizes(by_sha(parse(record()))[DIRECT])


def test_candidate_enumeration_exact_page_and_probe_cap():
    doc = {DELTA_ONLY: {'fileInfo': {'sha256': DELTA_ONLY, 'size': 0x3000, 'machineType': 34404,
                                     'timestamp': 1, 'lastSectionVirtualAddress': 0x1000,
                                     'lastSectionPointerToRawData': 0x1000}}}
    # end = 0x1000 + 0x2000 = 0x3000 (already aligned) -> 0x3000, 0x2000.
    assert wb.candidate_sizes(parse(doc).candidates[0]) == (0x3000, 0x2000)
    doc[DELTA_ONLY]['fileInfo']['size'] = 0x1000 + 300 * 0x1000
    with pytest.raises(AcquisitionError) as err:
        wb.candidate_sizes(parse(doc).candidates[0])
    assert err.value.code == 'PT-ACQ-LIMIT'
    doc[DELTA_ONLY]['fileInfo']['size'] = 0x10
    assert wb.candidate_sizes(parse(doc).candidates[0]) == ()


def test_missing_required_fields_are_skipped_and_counted():
    doc = record()
    for field in ('sha256', 'size', 'machineType', 'timestamp'):
        broken = copy.deepcopy(doc[DIRECT])
        del broken['fileInfo'][field]
        key = f'{field[:1]}' * 64 if field != 'sha256' else 'e' * 64
        if field != 'sha256':
            key = 'f' * 63 + str(len(field) % 10)
            broken['fileInfo']['sha256'] = key
        doc[key] = broken
    doc['0' * 64] = {'fileInfo': {'sha256': '1' * 64, 'size': 1, 'machineType': 34404, 'timestamp': 1}}
    doc['2' * 64] = {'fileInfo': {'sha256': '2' * 64, 'size': True, 'machineType': 34404, 'timestamp': 1}}
    doc['3' * 64] = 'not an object'
    result = parse(doc)
    assert len(result.candidates) == 4 and result.skipped == 7
    assert '7 Winbindex entries skipped' in result.warnings[0]


def test_missing_virtual_size_and_last_section_is_unavailable_and_non_x64_kept_ineligible():
    entry = record()[DIRECT]
    info = {k: entry['fileInfo'][k] for k in ('sha256', 'size', 'machineType', 'timestamp')}
    unavailable = parse({DIRECT: {'fileInfo': info}}).candidates[0]
    assert unavailable.download == 'unavailable' and unavailable.kbs == ()
    arm = dict(entry['fileInfo'], machineType=43620)
    cand = parse({DIRECT: {'fileInfo': arm}}).candidates[0]
    assert not cand.x64 and cand.machine_type == 43620


def test_strict_json_and_caps():
    with pytest.raises(AcquisitionError):
        wb.parse(gzip.compress(b'{"a": 1, "a": 2}'), 'afd.sys', '2026-10-12')
    with pytest.raises(AcquisitionError):
        wb.parse(gzip.compress(b'{"a": NaN}'), 'afd.sys', '2026-10-12')
    with pytest.raises(AcquisitionError):
        wb.parse(gzip.compress(b'[]'), 'afd.sys', '2026-10-12')
    with pytest.raises(AcquisitionError):
        wb.parse(b'not gzip', 'afd.sys', '2026-10-12')
    with pytest.raises(AcquisitionError):
        wb.parse(gzip.compress(b'{}')[:-4], 'afd.sys', '2026-10-12')
    with pytest.raises(AcquisitionError):
        wb.parse(gzip.compress(b'{}'), 'afd.sys', 'yesterday')


@pytest.mark.parametrize('text', ['\ud800', 'a\udfffb'], ids=['high', 'low-inside'])
def test_unpaired_surrogate_escape_is_a_typed_provider_error(text):
    doc = record()
    next(iter(doc.values()))['fileInfo']['version'] = text
    with pytest.raises(AcquisitionError) as err:
        parse(doc)
    assert err.value.code == 'PT-ACQ-PROVIDER'


def test_paired_surrogate_escape_still_parses():
    doc = record()
    next(iter(doc.values()))['fileInfo']['version'] = '\U0001f600'  # json.dumps escapes it as a pair
    assert len(parse(doc).candidates) == 4


def test_decompression_bomb_is_capped(monkeypatch):
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', 1000)
    with pytest.raises(AcquisitionError) as err:
        wb.decompress(gzip.compress(b'{' + b' ' * 5000 + b'}'))
    assert err.value.code == 'PT-ACQ-LIMIT'
    monkeypatch.setattr(wb, 'MAX_COMPRESSED', 10)
    with pytest.raises(AcquisitionError):
        wb.decompress(gzip.compress(b'{}' * 100))


def test_record_digest_and_identity_are_stable():
    a, b = parse(record()), parse(dict(reversed(list(record().items()))))
    assert [c.record_sha256 for c in a.candidates] == [c.record_sha256 for c in b.candidates]
    assert acquisition_id('afd.sys', DIRECT) == acquisition_id('afd.sys', DIRECT) != acquisition_id('afd.sys', DELTA_ONLY)


def test_candidate_record_rejects_inconsistent_classification():
    good = by_sha(parse(record()))[DIRECT]
    with pytest.raises(ValueError):
        BuildCandidate.model_validate(good.model_dump() | {'download': 'unavailable'})
    with pytest.raises(ValueError):
        BuildCandidate.model_validate(good.model_dump() | {'windows_versions': ('b', 'a')})
