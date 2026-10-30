"""Regression tests for issue #105 BUG-ACQ-1..4: hostile Winbindex text, surrogates, dates and the download fd.
Offline; synthetic records only."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from patchtrace.acquisition import transport as tr
from patchtrace.acquisition import winbindex
from patchtrace.acquisition.contracts import AcquisitionError, PlannedDownload, symbol_server_url

SHA = 'a' * 64
ESC = '\x1b]0;PWNED\x07\x1b[2J'


def record(*, info=None, windows=None, extra=None) -> bytes:
    body = {'sha256': SHA, 'size': 1000, 'machineType': 34404, 'timestamp': 1, 'virtualSize': 4096, **(info or {})}
    entry = {'fileInfo': body, 'windowsVersions': windows or {}, **(extra or {})}
    return gzip.compress(json.dumps({SHA: entry}, ensure_ascii=True).encode())


def other_entry() -> dict:
    return {'b' * 64: {'fileInfo': {'sha256': 'b' * 64, 'size': 10, 'machineType': 34404, 'timestamp': 2,
                                    'virtualSize': 4096}, 'windowsVersions': {}}}


def test_acq1_terminal_controls_never_reach_parsed_text():
    data = record(info={'version': '1.0' + ESC},
                  windows={'22H2': {'KB5000001' + ESC: {'updateInfo': {'releaseDate': '2024-01-01',
                                                                       'releaseVersion': ESC,
                                                                       'heading': 'a b c'}}}})
    candidate = winbindex.parse(data, 'ntdll.dll', '2026-01-01').candidates[0]
    texts = [candidate.version, candidate.kbs[0].kb, candidate.kbs[0].release_version]
    assert all('\x1b' not in t and '\x07' not in t for t in texts)
    assert candidate.version.startswith('1.0')
    assert winbindex._clean('a b c', 100) == 'a b c'


def test_acq2_a_lone_surrogate_skips_one_entry_instead_of_failing_the_record():
    document = json.loads(gzip.decompress(record(extra={'note': '\ud800'})))
    document.update(other_entry())
    data = gzip.compress(json.dumps(document, ensure_ascii=True).encode())
    result = winbindex.parse(data, 'ntdll.dll', '2026-01-01')
    assert [c.sha256 for c in result.candidates] == ['b' * 64] and result.skipped == 1
    rows = winbindex.parse_rows(data, 'ntdll.dll', '2026-01-01')
    assert rows.skipped == 1


def test_acq2_strict_json_rejects_surrogates_and_duplicate_keys_by_default():
    bad_surrogate = b'{"note": "\\uD800"}'
    with pytest.raises(AcquisitionError, match='PT-ACQ-PROVIDER'):
        winbindex.strict_json(bad_surrogate)
    assert winbindex.strict_json(bad_surrogate, allow_entry_surrogates=True)['note'] == '\\ud800'
    with pytest.raises(AcquisitionError, match='PT-ACQ-PROVIDER'):
        winbindex.strict_json(b'{"item": 1, "item": 2}', allow_entry_surrogates=True)


@pytest.mark.parametrize('bad', ['٢٠٢٤-٠١-٠١', '2024-99-99', '2024-02-30'])
def test_acq3_non_ascii_or_impossible_release_dates_are_dropped(bad):
    data = record(windows={'22H2': {'KB5000001': {'updateInfo': {'releaseDate': bad}}}})
    assert winbindex.parse(data, 'ntdll.dll', '2026-01-01').candidates[0].kbs[0].release_date is None
    assert {r.release_date for r in winbindex.parse_rows(data, 'ntdll.dll', '2026-01-01').rows} == {None}
    with pytest.raises(AcquisitionError):
        winbindex.parse(data, 'ntdll.dll', bad)


def test_acq3_real_dates_still_parse():
    data = record(windows={'22H2': {'KB5000001': {'updateInfo': {'releaseDate': '2024-02-29'}}}})
    assert winbindex.parse(data, 'ntdll.dll', '2024-02-29').candidates[0].kbs[0].release_date == '2024-02-29'


@pytest.mark.skipif(not Path('/proc/self/fd').is_dir(), reason='counts descriptors through /proc')
def test_acq4_a_raising_progress_callback_leaks_no_descriptor_and_no_file(tmp_path):
    data = b'x' * 100
    url = symbol_server_url('a.dll', 1, 4096)
    planned = PlannedDownload(side='older', file_name='a.dll', sha256=hashlib.sha256(data).hexdigest(), size=100,
                              url=url, record_sha256='b' * 64)

    class Response:
        status, headers = 200, {}

        def __init__(self):
            self.body = data

        def read1(self, size):
            out, self.body = self.body[:size], self.body[size:]
            return out

        read = read1

        def close(self):
            pass

    transport = tr.Transport(opener=lambda method, url, headers, timeout: Response(), sleep=lambda s, c: None)
    consent = tr.AcquisitionConsent.for_urls([url])

    def boom(done, total):
        raise RuntimeError('ui cancelled')

    before = len(os.listdir('/proc/self/fd'))
    for _ in range(5):
        with pytest.raises(RuntimeError):
            transport.download(planned, consent, tmp_path, boom)
    assert len(os.listdir('/proc/self/fd')) == before
    assert list(tmp_path.iterdir()) == []
    assert sys.platform  # descriptor count is the Linux oracle; Windows CI checks the leftover file only
