"""SPEC-31 S3b: the strict reader of `decomp.jsonl` (extract/decomp.py): the file is the output of an external
process, so every line is validated and nothing is repaired."""
from __future__ import annotations

import dataclasses
import json
import os

import pytest

from patchtrace.unified.extract.decomp import DecompRecord, read_decomp
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError

OK = {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': 'int f(void)\n{\n\treturn 1;\n}'}


def write(tmp_path, *documents, raw: bytes | None = None):
    path = tmp_path / 'decomp.jsonl'
    path.write_bytes(raw if raw is not None else
                     b''.join(json.dumps(d, separators=(',', ':')).encode('utf-8') + b'\n' for d in documents))
    return path


def reason(tmp_path, *documents, rvas=(0x1000,), side='older', raw=None, limits=DEFAULT_LIMITS):
    with pytest.raises(UnifiedError) as caught:
        read_decomp(write(tmp_path, *documents, raw=raw), side, rvas, limits)
    assert caught.value.code == 'PT-UNIFIED-EXTRACT'
    return caught.value.reason


def test_a_valid_file_is_read_by_rva_in_ascending_order(tmp_path):
    rows = [dict(OK, rva=0x1200), dict(OK, rva=0x1000), {'side': 'older', 'rva': 0x1100, 'status': 'timeout', 'code': None},
            {'side': 'older', 'rva': 0x1300, 'status': 'failed', 'code': None}]
    records = read_decomp(write(tmp_path, *rows), 'older', [0x1000, 0x1100, 0x1200, 0x1300])
    assert list(records) == [0x1000, 0x1100, 0x1200, 0x1300]
    assert records[0x1000] == DecompRecord('older', 0x1000, 'ok', OK['code'])
    assert records[0x1100] == DecompRecord('older', 0x1100, 'timeout', None) and records[0x1300].status == 'failed'


def test_blank_lines_are_ignored_and_a_missing_or_symlinked_file_is_no_output(tmp_path):
    path = write(tmp_path, raw=b'\n' + json.dumps(OK).encode() + b'\n\n')
    assert read_decomp(path, 'older', [0x1000])[0x1000].status == 'ok'
    with pytest.raises(UnifiedError) as caught:
        read_decomp(tmp_path / 'absent.jsonl', 'older', [0x1000])
    assert caught.value.reason == 'no-decomp'
    link = tmp_path / 'link.jsonl'
    try:
        os.symlink(path, link)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are not available here')
    with pytest.raises(UnifiedError) as caught:
        read_decomp(link, 'older', [0x1000])
    assert caught.value.reason == 'no-decomp'


def test_only_the_requested_rvas_may_appear_each_once_and_all_of_them(tmp_path):
    assert reason(tmp_path, OK, dict(OK, rva=0x1100)) == 'bad-decomp-rva'                  # not requested
    assert reason(tmp_path, OK, OK) == 'bad-decomp-rva'                                    # repeated
    assert reason(tmp_path, OK, rvas=(0x1000, 0x1100)) == 'bad-decomp-missing'             # a requested one is absent
    assert reason(tmp_path, rvas=(0x1000,), raw=b'') == 'bad-decomp-missing'
    for bad in (4096.0, True, '4096', None, -1):
        assert reason(tmp_path, dict(OK, rva=bad)) in ('bad-decomp-rva', 'bad-decomp-json')


def test_side_keys_and_status_are_closed(tmp_path):
    assert reason(tmp_path, dict(OK, side='newer')) == 'bad-decomp-keys'
    assert reason(tmp_path, dict(OK, extra=1)) == 'bad-decomp-keys'
    assert reason(tmp_path, {k: v for k, v in OK.items() if k != 'code'}) == 'bad-decomp-keys'
    assert reason(tmp_path, dict(OK, status='done')) == 'bad-decomp-status'
    assert reason(tmp_path, dict(OK, status=None)) == 'bad-decomp-status'


def test_code_belongs_to_ok_and_to_nothing_else(tmp_path):
    assert reason(tmp_path, dict(OK, code=None)) == 'bad-decomp-code'
    assert reason(tmp_path, dict(OK, status='timeout')) == 'bad-decomp-code'
    assert reason(tmp_path, dict(OK, status='failed')) == 'bad-decomp-code'
    assert reason(tmp_path, dict(OK, code='')) == 'bad-decomp-code'
    assert reason(tmp_path, dict(OK, code=7)) == 'bad-decomp-code'


@pytest.mark.parametrize('text', [b'{"side":"older","rva":NaN,"status":"failed","code":null}',
                                  b'{"side":"older","rva":4096,"status":"failed","code":null,"code":null}',
                                  b'{"side":"older","rva":4096.5,"status":"failed","code":null}',
                                  b'[1,2,3]', b'not json', b'{"side":"older","rva":4096,"status":"failed","code":null} x',
                                  b'\xff\xfe{}', b'{"side":"older","rva":Infinity,"status":"failed","code":null}'],
                         ids=['nan', 'duplicate', 'float', 'array', 'text', 'trailing', 'bytes', 'infinity'])
def test_malformed_json_is_rejected(tmp_path, text):
    assert reason(tmp_path, raw=text + b'\n') in ('bad-decomp-json', 'bad-decomp-rva')


def test_a_lone_surrogate_in_the_text_is_rejected(tmp_path):
    assert reason(tmp_path, raw=b'{"side":"older","rva":4096,"status":"ok","code":"a\\ud800b"}\n') == 'bad-decomp-code'


def test_text_limits_and_controls(tmp_path):
    tight = dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_chars=20, l29_pseudo_lines=3)
    assert reason(tmp_path, dict(OK, code='x' * 21), limits=tight) == 'bad-decomp-code-cap'
    assert reason(tmp_path, dict(OK, code='a\nb\nc\nd'), limits=tight) == 'bad-decomp-code-cap'
    assert read_decomp(write(tmp_path, dict(OK, code='a\nb\nc')), 'older', [0x1000], tight)[0x1000].code == 'a\nb\nc'
    cleaned = read_decomp(write(tmp_path, dict(OK, code='a\x1b[0m‮\tb\x00\nc')), 'older', [0x1000])[0x1000].code
    assert cleaned == 'a?[0m?\tb?\nc'                               # controls and bidi replaced, TAB and LF kept


def test_a_line_over_the_json_budget_is_rejected_without_reading_it_all(tmp_path):
    tight = dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_chars=10)
    huge = b'{"side":"older","rva":4096,"status":"ok","code":"' + b'x' * 200_000 + b'"}\n'
    assert reason(tmp_path, raw=huge, limits=tight) == 'bad-decomp-line'
