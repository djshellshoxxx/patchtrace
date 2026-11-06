"""Bounded DER reader: structure, decoders, hostile shapes (indefinite length, giant lengths, depth, node and byte
caps) and the rule that only `DerError` ever escapes."""
from __future__ import annotations

import random

import pytest
from pe_meta_builder import gen_time, integer, length, null, octets, oid, seq, set_, tlv, utc_time, utf8

from patchtrace.pe_overview.der import (
    DerError,
    DerLimits,
    decode_int,
    decode_oid,
    decode_text,
    decode_time,
    parse,
)


def test_sequence_children_and_offsets():
    data = seq(oid('1.2.840.113549.1.7.2'), integer(300), octets(b'abc'))
    node = parse(data)
    assert (node.tag, node.constructed, node.cls) == (0x10, True, 0)
    assert [c.tag for c in node.children] == [6, 2, 4]
    assert node.start == 0 and node.end == len(data)
    assert node.children[2].content == b'abc'
    assert node.raw == data


@pytest.mark.parametrize('dotted', ['1.2.840.113549.1.7.2', '2.5.4.3', '1.3.6.1.4.1.311.2.1.4', '2.16.840.1.101.3.4.2.1',
                                    '1.3.14.3.2.26', '2.999.3'],
                         ids=['pkcs7', 'cn', 'spc', 'sha256', 'sha1', 'big-second-arc'])
def test_oid_round_trip(dotted):
    assert decode_oid(parse(oid(dotted))) == dotted


@pytest.mark.parametrize('value', [0, 1, 127, 128, 255, 256, 2**64 + 5, -1, -129],
                         ids=['0', '1', '127', '128', '255', '256', 'big', 'neg1', 'neg129'])
def test_integer_round_trip(value):
    assert decode_int(parse(integer(value))) == value


@pytest.mark.parametrize('encoded,expected', [
    (utc_time('20240229123045'), '2024-02-29T12:30:45Z'),
    (utc_time('20491231235959'), '2049-12-31T23:59:59Z'),
    (utc_time('20500101000000'), '2050-01-01T00:00:00Z'),
    (gen_time('19990101000000'), '1999-01-01T00:00:00Z'),
    (tlv(0x17, b'990101000000Z'), '1999-01-01T00:00:00Z'),
], ids=['utc', 'utc-2049', 'gen-2050', 'gen-1999', 'utc-two-digit-1999'])
def test_time_decodes_to_iso(encoded, expected):
    assert decode_time(parse(encoded)) == expected


@pytest.mark.parametrize('encoded', [tlv(0x17, b'2402301230Z'), tlv(0x17, b'240230123045Z'), tlv(0x18, b'abcdefghijklmnopZ'),
                                     tlv(0x17, b'240229123045+0100'), octets(b'x')],
                         ids=['short', 'feb30', 'letters', 'offset', 'not-time'])
def test_time_refuses_non_times(encoded):
    assert decode_time(parse(encoded)) is None


def test_text_is_cleaned_of_hostile_characters():
    node = parse(utf8('Acme\u202e evil\x00\x07'))
    assert decode_text(node) == 'Acme? evil??'


def test_text_bad_utf8_is_replaced_not_raised():
    assert decode_text(parse(tlv(0x0C, b'ok\xff\xfe'))) == 'ok��'


def test_long_form_length():
    body = b'x' * 70000
    node = parse(octets(body), DerLimits(max_bytes=80000))
    assert node.content == body


def test_high_tag_number():
    node = parse(bytes([0x5F, 0x81, 0x01]) + length(1) + b'z')
    assert (node.cls, node.tag) == (1, 129)


@pytest.mark.parametrize('data,code', [
    (b'', 'signature_der_invalid'),
    (b'\x30', 'signature_der_invalid'),
    (b'\x30\x80\x00\x00', 'signature_der_invalid'),            # indefinite length
    (b'\x30\x05\x02\x01', 'signature_der_invalid'),             # content shorter than declared
    (b'\x04\x84\xff\xff\xff\xff', 'signature_der_invalid'),     # 4 GiB length
    (b'\x04\x85\x01\x00\x00\x00\x00', 'signature_der_invalid'),  # length of length over 4
    (b'\x30\x03\x02\x05\x01', 'signature_der_invalid'),         # child overruns parent
    (b'\x30\x04\x02\x01\x01\x05', 'signature_der_invalid'),     # truncated trailing child
    (b'\x1f', 'signature_der_invalid'),                         # tag continues past the end
    (b'\x5f\xff\xff\xff\xff\xff\x01\x00', 'signature_der_invalid'),  # tag number too big
], ids=['empty', 'tag-only', 'indefinite', 'short', 'huge', 'len-of-len', 'overrun', 'trailing', 'tag-eof', 'tag-huge'])
def test_hostile_encodings_raise_typed_invalid(data, code):
    with pytest.raises(DerError) as caught:
        parse(data)
    assert caught.value.code == code


def _nested(depth: int) -> bytes:
    data = null()
    for _ in range(depth):
        data = seq(data)
    return data


def test_depth_cap_is_exact():
    parse(_nested(31))   # 31 sequences + a leaf: depth 32
    with pytest.raises(DerError) as caught:
        parse(_nested(32))
    assert caught.value.code == 'signature_der_over_cap'


def test_node_cap():
    data = seq(*[null()] * 100)
    parse(data, DerLimits(max_nodes=101))
    with pytest.raises(DerError) as caught:
        parse(data, DerLimits(max_nodes=100))
    assert caught.value.code == 'signature_der_over_cap'


def test_node_cap_default_is_20000():
    with pytest.raises(DerError) as caught:
        parse(seq(*[null()] * 20000))
    assert caught.value.code == 'signature_der_over_cap'


def test_byte_cap():
    parse(octets(b'a' * 100), DerLimits(max_bytes=110))
    with pytest.raises(DerError) as caught:
        parse(octets(b'a' * 100), DerLimits(max_bytes=50))
    assert caught.value.code == 'signature_der_over_cap'


def test_trailing_bytes_are_not_consumed():
    node = parse(seq(null()) + b'\0\0\0')
    assert node.end == 4


def test_set_children_keep_file_order():
    assert [decode_int(c) for c in parse(set_(integer(9), integer(1))).children] == [9, 1]


def test_mutated_input_only_raises_der_error():
    rng = random.Random(51)
    base = seq(oid('1.2.3'), set_(integer(5), seq(utf8('x'), utc_time('20240101000000'))), octets(b'0123456789'))
    for _ in range(3000):
        data = bytearray(base)
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            del data[rng.randrange(len(data)):]
        try:
            node = parse(bytes(data))
        except DerError:
            continue
        assert node.end <= len(data)

def test_oversized_oid_arc_is_rejected_before_decimal_conversion():
    # About 5,270 decimal digits: Python's int-to-decimal guard must not escape parsing.
    huge_arc = b'\x81' * 2500 + b'\x00'
    assert decode_oid(parse(tlv(0x06, huge_arc))) is None
    assert decode_oid(parse(oid('2.999.3'))) == '2.999.3'
