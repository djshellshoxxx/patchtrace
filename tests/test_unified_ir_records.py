"""SPEC-31 S1: strict validation of the untrusted extractor records (ir/records.py), field by field."""
from __future__ import annotations

import copy

import pytest
from unified_extract_builder import SHA, document_set, function, header

from patchtrace.unified.ir import records
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError

SIZE = 0x5000
STRAIGHT = [('lea', 0x2040), ('call', 0x1100), ('cmp', 7), ('mov',), ('ret',)]
GOOD = function(0x1000, STRAIGHT, name='caller', calls=[(0x1007, 0x1100, None, 'call')],
                strings=[(0x1000, 'ab' * 32, 4, 'text')], aliases=['alias_one'],
                blocks=[(0, [1], ['fall']), (3, [], [])])


def fresh():
    return copy.deepcopy(GOOD)


def parse(document, limits=DEFAULT_LIMITS):
    return records.parse_fn(document, SIZE, limits)


def reason_of(document, limits=DEFAULT_LIMITS):
    with pytest.raises(UnifiedError) as caught:
        parse(document, limits)
    assert caught.value.code == 'PT-UNIFIED-IR'
    return caught.value.reason


def test_a_well_formed_record_parses_into_a_typed_record():
    record = parse(fresh())
    assert record.rva == 0x1000 and record.name == 'caller' and record.aliases == ['alias_one']
    assert [i.mnem for i in record.insns] == ['LEA', 'CALL', 'CMP', 'MOV', 'RET']
    assert record.blocks[0].succ == (record.blocks[1].rva,) and record.calls == [(0x1007, 0x1100, None, 'call')]
    assert record.sanitized == 0 and records.check_instruction_layout(record)[0] == 0x1000


def set_key(key, value):
    def mutate(d):
        d[key] = value
    return mutate


def set_path(*path, value):
    def mutate(d):
        target = d
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = value
    return mutate


def drop_key(key):
    def mutate(d):
        del d[key]
    return mutate


def add_key(d):
    d['surprise'] = 1


MUTATIONS = {
    # id: (mutation, expected field)
    'extra': (add_key, 'keys'), 'missing': (drop_key('calls'), 'keys'), 'type': (set_key('type', 'footer'), 'keys'),
    'rva-int': (set_key('rva', '4096'), 'rva'), 'rva-neg': (set_key('rva', -1), 'rva'),
    'rva-big': (set_key('rva', SIZE), 'rva'), 'rva-bool': (set_key('rva', True), 'rva'),
    'rva-outside': (set_key('ranges', [[0x2000, 24]]), 'rva'),
    'ranges-type': (set_key('ranges', 'x'), 'ranges'), 'ranges-empty': (set_key('ranges', []), 'ranges'),
    'ranges-item': (set_key('ranges', [[0x1000]]), 'ranges'), 'ranges-zero': (set_key('ranges', [[0x1000, 0]]), 'ranges'),
    'ranges-over': (set_key('ranges', [[0x1000, 8], [0x1004, 8]]), 'ranges'),
    'ranges-end': (set_key('ranges', [[0x4ffc, 100]]), 'ranges'),
    'ranges-many': (set_key('ranges', [[0x1000 + 16 * i, 4] for i in range(65)]), 'ranges'),
    'src': (set_key('name_src', 'GUESS'), 'kind'), 'kind': (set_key('kind', 'import'), 'kind'),
    'name-type': (set_key('name', 5), 'name'), 'name-long': (set_key('name', 'x' * 513), 'name'),
    'name-surrogate': (set_key('name', 'a\ud800b'), 'name'),
    'alias-many': (set_key('aliases', [f'a{i}' for i in range(17)]), 'aliases'),
    'alias-type': (set_key('aliases', [1]), 'aliases'),
    'thunk': (set_key('thunk_target', SIZE + 5), 'thunk-target'),
    'import-type': (set_key('import', 'x'), 'import'),
    'import-keys': (set_key('import', {'dll': 'a.dll', 'name': 'f'}), 'import'),
    'import-both': (set_key('import', {'dll': 'a.dll', 'name': 'f', 'ordinal': 3}), 'import'),
    'import-none': (set_key('import', {'dll': 'a.dll', 'name': None, 'ordinal': None}), 'import'),
    'import-dll': (set_key('import', {'dll': '', 'name': 'f', 'ordinal': None}), 'import'),
    'import-ord': (set_key('import', {'dll': 'a.dll', 'name': None, 'ordinal': 70000}), 'import'),
    'import-name': (set_key('import', {'dll': 'a.dll', 'name': 'n' * 300, 'ordinal': None}), 'import'),
    'lib': (set_key('lib', 1), 'flags'), 'truncated': (set_key('truncated', 'no'), 'flags'),
    'raw-odd': (set_key('raw', 'abc'), 'raw'), 'raw-upper': (set_key('raw', 'AB' * 24), 'raw'),
    'raw-short': (set_key('raw', 'ab' * 5), 'raw'), 'raw-type': (set_key('raw', 5), 'raw'),
    'raw-none': (set_key('raw', None), 'raw'),
    'insns-type': (set_key('insns', 'x'), 'insns'), 'insn-arity': (set_path('insns', 0, value=[0, 1]), 'insns'),
    'insn-off': (set_path('insns', 0, 0, value=-1), 'insns'), 'insn-len0': (set_path('insns', 0, 1, value=0), 'insns'),
    'insn-len16': (set_path('insns', 0, 1, value=16), 'insns'),
    'insn-mnem': (set_path('insns', 0, 2, value='mo v'), 'insns'), 'insn-flow': (set_path('insns', 0, 5, value='fall'), 'insns'),
    'insn-mask': (set_path('insns', 0, 3, value='ff'), 'insns'),
    'insn-beyond': (set_path('insns', 4, 0, value=0x7000), 'insns'),
    'insn-end': (set_path('insns', 4, 0, value=23), 'insns'),
    'ops-arity': (set_path('insns', 0, 4, 0, value=[1, 2]), 'ops'),
    'ops-type': (set_path('insns', 0, 4, 0, 0, value=-1), 'ops'),
    'ops-mask': (set_path('insns', 0, 4, 0, 1, value='ff'), 'ops'),
    'ops-many': (set_path('insns', 0, 4, value=[[0, None, [], []]] * 7), 'ops'),
    'obj-arity': (set_path('insns', 0, 4, 0, 2, value=[['reg']]), 'objs'),
    'obj-kind': (set_path('insns', 0, 4, 0, 2, value=[['mem', 1]]), 'objs'),
    'obj-reg': (set_path('insns', 0, 4, 0, 2, value=[['reg', 'not a register']]), 'objs'),
    'obj-scalar': (set_path('insns', 0, 4, 0, 2, value=[['scalar', 1.5]]), 'objs'),
    'obj-addr': (set_path('insns', 0, 4, 0, 2, value=[['addr', 2 ** 40]]), 'objs'),
    'obj-many': (set_path('insns', 0, 4, 0, 2, value=[['scalar', 1]] * 9), 'objs'),
    'ref-arity': (set_path('insns', 0, 4, 1, 3, value=[['DATA']]), 'refs'),
    'ref-type': (set_path('insns', 0, 4, 1, 3, value=[['data', 'rva:5']]), 'refs'),
    'ref-text': (set_path('insns', 0, 4, 1, 3, value=[['DATA', 'rva:05']]), 'refs'),
    'ref-ext': (set_path('insns', 0, 4, 1, 3, value=[['DATA', 'ext:nobang']]), 'refs'),
    'ref-kind': (set_path('insns', 0, 4, 1, 3, value=[['DATA', 7]]), 'refs'),
    'blocks-arity': (set_key('blocks', [[0x1000, 4]]), 'blocks'),
    'blocks-mismatch': (set_path('blocks', 0, 4, value=[]), 'blocks'),
    'blocks-kind': (set_path('blocks', 0, 4, value=['maybe']), 'blocks'),
    'blocks-order': (set_path('blocks', 1, 0, value=0x1000), 'blocks'),
    'blocks-target': (set_path('blocks', 0, 3, value=[0x1003]), 'blocks'),
    'blocks-len': (set_path('blocks', 0, 1, value=0), 'blocks'),
    'calls-arity': (set_key('calls', [[1, 2]]), 'calls'), 'calls-kind': (set_path('calls', 0, 3, value='jmp'), 'calls'),
    'calls-both': (set_path('calls', 0, 2, value='a.dll!f'), 'calls'),
    'calls-key': (set_key('calls', [[0x1007, None, 'bad', 'call']]), 'calls'),
    'strings-arity': (set_key('strings', [[1, 2]]), 'strings'), 'strings-sha': (set_path('strings', 0, 1, value='zz'), 'strings'),
    'strings-len': (set_path('strings', 0, 2, value=-1), 'strings'),
    'strings-prefix': (set_path('strings', 0, 3, value='p' * 65), 'strings'),
    'text-count': (set_key('text', ['x']), 'text'), 'text-type': (set_path('text', 0, value=5), 'text'),
    'text-long': (set_path('text', 0, value='t' * 257), 'text'),
    'raw-needed': (lambda d: d.update(raw=None), 'raw'),
}


@pytest.mark.parametrize('name', sorted(MUTATIONS))
def test_every_malformed_field_is_rejected_with_its_slug(name):
    mutate, field = MUTATIONS[name]
    document = fresh()
    mutate(document)
    assert reason_of(document) == f'bad-record-{field}'


def test_raw_none_with_no_content_is_a_valid_header_only_record():
    document = fresh()
    document.update(raw=None, insns=[], text=[], blocks=[], calls=[], strings=[])
    record = parse(document)
    assert record.raw is None and record.insns == [] and record.blocks == []


def test_control_characters_are_sanitised_and_counted_not_rejected():
    document = fresh()
    document['name'] = 'bad\x00name‮'
    document['text'][0] = 'lea \x1b[31m'
    document['strings'][0][3] = 'p\x07'
    record = parse(document)
    assert record.name == 'bad?name?' and record.texts[0] == 'lea ?[31m' and record.sanitized == 3


def test_instruction_and_function_limits_follow_the_limits_object():
    tight = DEFAULT_LIMITS.__class__(l06_fn_instructions=3)
    assert reason_of(fresh(), tight) == 'bad-record-insns'
    small = DEFAULT_LIMITS.__class__(l06_fn_raw_bytes=10)
    document = fresh()
    assert reason_of(document, small) == 'bad-record-raw'


def test_layout_check_rejects_overlap_and_instructions_spanning_a_gap():
    record = parse(fresh())
    record.insns[1] = record.insns[1]._replace(off=0)                      # overlaps the first instruction
    with pytest.raises(UnifiedError) as caught:
        records.check_instruction_layout(record)
    assert caught.value.reason == 'bad-record-insns'
    two = function(0x1000, [('mov',), ('mov',), ('ret',)], ranges=[[0x1000, 2], [0x2000, 3]])
    parsed = parse(copy.deepcopy(two))
    assert records.check_instruction_layout(parsed)[0] == 0x1000
    parsed.insns[0] = parsed.insns[0]._replace(off=1, length=2)            # crosses from range 0 into range 1
    with pytest.raises(UnifiedError):
        records.check_instruction_layout(parsed)


# --- JSON lines -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('line', [b'[]', b'"x"', b'1', b'null', b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": Infinity}',
                                  b'{"a": 1.5}', b'{"a": 1e3}', b'\xff\xfe{}', b'{', b'', b'{"a": ' + b'[' * 5000 + b'}'],
                         ids=['list', 'str', 'int', 'null', 'dupkey', 'nan', 'inf', 'float', 'exp', 'utf8', 'open',
                              'empty', 'deep'])
def test_json_lines_must_be_strict_objects(line):
    with pytest.raises(UnifiedError) as caught:
        records.parse_json_line(line)
    assert caught.value.reason == 'bad-record-json'


def test_json_lines_accept_big_integers_and_unicode():
    assert records.parse_json_line('{"a": 12345678901234567890, "b": "é"}') == {'a': 12345678901234567890,
                                                                                    'b': 'é'}
    assert records.parse_json_line(b'{"a": [1, {"b": null}]}') == {'a': [1, {'b': None}]}


# --- header and footer ---------------------------------------------------------------------------------------------------------

def test_header_checks_identity_orientation_and_language():
    good = header()
    parsed = records.parse_header(good, SHA)
    assert parsed.producer.ghidra == '12.0.4'
    with pytest.raises(UnifiedError) as caught:
        records.parse_header(header(sha='cc' * 32), SHA)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-PAIR', 'artifact-hash')
    with pytest.raises(UnifiedError) as caught:
        records.parse_header(header(sha='cc' * 32), SHA, other_sha256='cc' * 32)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-ORIENTATION', 'reversed-side')
    mixed = dict(good, program_sha256='dd' * 32)
    with pytest.raises(UnifiedError) as caught:
        records.parse_header(mixed, SHA)
    assert caught.value.reason == 'artifact-hash'
    with pytest.raises(UnifiedError) as caught:
        records.parse_header(header(language='x86:LE:32:default'), SHA)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-UNSUPPORTED', 'unsupported-language')


@pytest.mark.parametrize('change', [{'contract': 'ir-extract/2'}, {'image_base': -1}, {'size_of_image': 0},
                                    {'surprise': 1}, {'producer': {}}, {'artifact_sha256': 'XYZ'}, {'language': 5}],
                         ids=['contract', 'base', 'size', 'extra', 'producer', 'sha', 'language'])
def test_malformed_headers_are_rejected(change):
    with pytest.raises(UnifiedError) as caught:
        records.parse_header(dict(header(), **change), SHA)
    assert caught.value.reason == 'bad-record-header'


def test_footer_is_validated_by_the_contract_model():
    footer = document_set(function(0x1000, [('ret',)]))[-1]
    assert records.parse_footer(footer).functions == 1
    for change in ({'status': 'done'}, {'functions': -1}, {'surprise': 1}, {'warnings': 'x'}):
        with pytest.raises(UnifiedError) as caught:
            records.parse_footer(dict(footer, **change))
        assert caught.value.reason == 'bad-record-footer'


def test_structural_failures_carry_the_spec_slugs():
    for reason in ('no-output', 'no-footer', 'truncated', 'trailing-data'):
        error = records.fail(reason)
        assert (error.code, error.reason) == ('PT-UNIFIED-IR', reason)
