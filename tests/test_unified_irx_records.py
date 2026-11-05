"""irx audit: strictness of the extractor records and the script's helpers (U7-09, hostile JSONL, hostile PE)."""
from __future__ import annotations

import copy
import importlib.util
import re
import struct
from pathlib import Path

import pytest
from unified_extract_builder import function

from patchtrace.unified import extract
from patchtrace.unified.contracts import _STDERR_UNSAFE, _UNSAFE_TEXT
from patchtrace.unified.ir import records
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError

SIZE = 0x5000
GOOD = function(0x1000, [('lea', 0x2040), ('call', 0x1100), ('cmp', 7), ('mov',), ('ret',)], name='caller',
                calls=[(0x1007, 0x1100, None, 'call')], strings=[(0x1000, 'ab' * 32, 4, 'text')],
                blocks=[(0, [1], ['fall']), (3, [], [])])
SCRIPT = Path(extract.__file__).parent / extract.SCRIPT_NAME


def load_script():
    spec = importlib.util.spec_from_file_location('pt_ir_extract_irx', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = load_script()
ALL = ''.join(chr(c) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF)


def matched(pattern: re.Pattern) -> str:
    return ''.join(pattern.findall(ALL))


def parse(document):
    return records.parse_fn(document, SIZE, DEFAULT_LIMITS)


def set_call_key(document):
    document['calls'][0][2] = 'k.dll!f\n'
    document['calls'][0][1] = None


@pytest.mark.parametrize('mutate', [
    lambda d: d['insns'][0].__setitem__(2, 'LEA\n'),                       # `$` matches before a trailing newline
    lambda d: d['insns'][0].__setitem__(5, d['insns'][0][5] + '\n'),
    lambda d: d['strings'][0].__setitem__(1, 'ab' * 32 + '\n'),
    set_call_key,
    lambda d: d.__setitem__('raw', d['raw'] + '\n'),
])
def test_a_trailing_newline_never_passes_a_shape_check(mutate):
    document = copy.deepcopy(GOOD)
    mutate(document)
    with pytest.raises(UnifiedError) as caught:
        parse(document)
    assert caught.value.code == 'PT-UNIFIED-IR'


def test_reference_text_with_a_trailing_newline_is_rejected():
    document = copy.deepcopy(GOOD)
    document['insns'][0][4][0][3] = [['DATA', 'rva:12\n']]
    with pytest.raises(UnifiedError):
        parse(document)


def test_import_keys_with_bidi_or_invisible_characters_are_rejected():
    for bad in ('k.dll!f\u202e', 'k​.dll!f', 'k.dll!­f'):
        document = copy.deepcopy(GOOD)
        document['calls'] = [[0x1007, None, bad, 'call']]
        with pytest.raises(UnifiedError):
            parse(document)


def test_import_stub_dll_and_name_are_sanitised_like_every_other_text():
    document = copy.deepcopy(GOOD)
    document['import'] = {'dll': 'K\u202eX.dll', 'name': 'f​n', 'ordinal': None}
    record = parse(document)
    assert record.imp == {'dll': 'K?X.dll', 'name': 'f?n', 'ordinal': None} and record.sanitized == 2


def test_block_extent_must_lie_inside_the_image():
    document = copy.deepcopy(GOOD)
    document['blocks'][1][1] = SIZE
    with pytest.raises(UnifiedError):
        parse(document)


# --- U7-09: the control-character copies equal the shared definition -----------------------------------------------

def test_scripts_control_ranges_equal_contracts():
    assert matched(script._CONTROL) == matched(_UNSAFE_TEXT)
    assert matched(script._CODE_CONTROL) == matched(_STDERR_UNSAFE)


def test_records_sanitiser_equals_contracts():
    sample = ''.join(c for c in ALL if records.strip_unsafe(c, replacement='?') != c)
    assert sample == matched(_UNSAFE_TEXT)
    counter = [0]
    assert records._text('a­b\u202ec', 'name', 16, counter=counter) == 'a?b?c' and counter == [1]


def test_script_clean_text_scrubs_what_contracts_scrubs():
    assert script.clean_text('x­​\u202e﻿y', 64) == 'x????y'
    assert script.clean_code('a\tb\nc​d') == 'a\tb\nc?d'


# --- import keys the ingest accepts ------------------------------------------------------------------------------------

@pytest.mark.parametrize('library', ['a b.dll', 'a!b.dll', 'İ' * 100, ' x.dll ', 'KERNEL32.dll'])
def test_the_scripts_import_keys_always_pass_the_ingest_shape(library):
    key = script.import_key(library, 'Func Name', None)
    assert records._import_key_ok(key), key
    assert script.import_parts(key)['dll'] == key.partition('!')[0]


# --- hostile PE header --------------------------------------------------------------------------------------------------

def test_parse_pe_header_does_not_read_the_file_up_to_a_hostile_e_lfanew(tmp_path):
    path = tmp_path / 'big.bin'
    head = bytearray(b'MZ' + bytes(0x3E))
    struct.pack_into('<I', head, 0x3C, 3_000_000)
    optional = bytearray(112)
    struct.pack_into('<H', optional, 0, 0x20B)
    struct.pack_into('<Q', optional, 24, 0x140000000)
    struct.pack_into('<I', optional, 56, 0x9000)
    path.write_bytes(bytes(head) + bytes(3_000_000 - len(head)) + b'PE\0\0' + bytes(20) + bytes(optional) + bytes(64))
    reads = []
    real_open = open

    class Counting:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *exc):
            return self.handle.__exit__(*exc)

        def read(self, n=-1):
            data = self.handle.read(n)
            reads.append(len(data))
            return data

        def __getattr__(self, name):
            return getattr(self.handle, name)

    script.open = lambda *a, **k: Counting(real_open(*a, **k))
    try:
        result = script.parse_pe_header(str(path))
    finally:
        del script.open
    assert result == {'image_base': 0x140000000, 'size_of_image': 0x9000}
    assert max(reads) < 4096 + 200


def test_truncated_with_raw_bytes_is_rejected():
    document = copy.deepcopy(GOOD)
    document['truncated'] = True
    with pytest.raises(UnifiedError) as caught:
        parse(document)
    assert caught.value.reason == 'bad-record-truncated'


def test_an_addr_object_outside_the_image_is_rejected():
    document = copy.deepcopy(GOOD)
    for insn in document['insns']:
        for op in insn[4]:
            for obj in op[2]:
                if obj[0] == 'addr':
                    obj[1] = SIZE
                    with pytest.raises(UnifiedError):
                        parse(document)
                    return
    raise AssertionError('the sample holds no addr object')
