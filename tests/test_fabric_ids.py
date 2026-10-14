"""FAB-0 identities, key grammars and the semantic checks (docs/specs/program-e/FAB-integration-plan.md s4, s7).

Covers: `anchor_id`, `witness_id` and `anchors_digest` against an independent oracle of the domain-id formula (and
pinned goldens), `pair_key` parity with `unified.keys.row_id` and `pilot.keys.candidate_key`, the value-to-key
constructors, `make_witness`/`make_anchor`, the `check_anchor` matrix with its typed errors, `verify_anchor` tamper
detection and the orientation check. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata

import fabric_support as fs
import pytest

from patchtrace.fabric import contracts, ids
from patchtrace.fabric.limits import FabricError
from patchtrace.pilot import keys as pilot_keys
from patchtrace.unified import keys as unified_keys


def oracle(domain: str, payload) -> str:
    """The SPEC-07 domain-id formula written out independently of `enrichment.identity`."""
    head = b'patchtrace\x00' + domain.encode('ascii') + b'\x00' + b'1' + b'\x00'
    body = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(head + body).hexdigest()


def raised(call, *args, **kwargs) -> FabricError:
    with pytest.raises(FabricError) as info:
        call(*args, **kwargs)
    return info.value


# --- identities ---------------------------------------------------------------------------------------------------

def test_anchor_id_follows_the_planned_formula():
    a = fs.cve_anchor('CVE-2099-0001')
    payload = {'kind': 'cve', 'key': 'CVE-2099-0001', 'side': 'none', 'role': 'stated', 'subject': None}
    assert a.anchor_id == oracle('fabric-anchor', payload) == ids.anchor_id('cve', 'CVE-2099-0001', 'none', 'stated', None)


def test_anchor_id_depends_on_exactly_kind_key_side_role_subject():
    base = ('import', 'createfile', 'newer', 'observed', fs.pair_key())
    seen = {ids.anchor_id(*base)}
    for index, other in enumerate(('string', 'createfilex', 'older', 'hint', None)):
        changed = list(base)
        changed[index] = other
        seen.add(ids.anchor_id(*changed))
    assert len(seen) == 6


def test_anchors_that_differ_only_in_witnesses_share_one_identity():
    one = fs.import_anchor('CreateFileW', producer='cap', source='capa', label='capa saw it')
    two = fs.import_anchor('CreateFileA', producer='ue', source='call-label', batch='other', label='ghidra saw it',
                           facets=(('name', 'CreateFileA'),), tool='ghidra', tool_version='11.1')
    assert one.anchor_id == two.anchor_id and one.witnesses != two.witnesses


def test_witness_id_covers_every_other_field_and_nothing_else():
    ref = contracts.Ref(kind='advisory-facts', id='f1', pointer='/a', sha256='c' * 64)
    base = dict(producer='kb', batch='b1', source='advisory-text', origins=('D_vendor_text',), label='text',
                facets=(('a', 'x'),), tool='t', tool_version='1', input_sha256='d' * 64, ref=ref)
    first = ids.make_witness(**base)
    payload = {k: v for k, v in first.model_dump(mode='json').items() if k != 'witness_id' and v is not None}
    assert first.witness_id == oracle('fabric-witness', payload)
    changes = dict(producer='cap', batch='b2', source='pairing', origins=('D_bytes',), label='other',
                   facets=(('a', 'y'),), tool='u', tool_version='2', input_sha256='e' * 64,
                   ref=contracts.Ref(kind='advisory-facts', id='f2'))
    for name, value in changes.items():
        assert ids.make_witness(**{**base, name: value}).witness_id != first.witness_id, name
    assert len({ids.make_witness(**{**base, n: v}).witness_id for n, v in changes.items()}) == len(changes)


def test_witness_id_ignores_optional_fields_that_are_none():
    plain = ids.make_witness(producer='kb', batch='b1', source='advisory-text', origins=('D_vendor_text',), label='x')
    payload = {'producer': 'kb', 'batch': 'b1', 'source': 'advisory-text', 'origins': ['D_vendor_text'],
               'label': 'x', 'facets': []}
    assert plain.witness_id == oracle('fabric-witness', payload)


def test_goldens_pin_the_identity_formulas():
    """Literal values: a change to a formula, a domain name or a payload field must be deliberate (plan s7)."""
    cve = fs.cve_anchor('CVE-2099-0001')
    assert ids.string_key('hello') == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    assert ids.string_key('Café') == hashlib.sha256('café'.encode()).hexdigest()
    assert ids.string_key('Café') == '850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e'
    assert fs.pair_key() == 'pair:105837206ad87418126b223eceee6eccab87d9d036e2c4aef7f6bc17a0194f28'
    assert cve.anchor_id == '3375f5fdd28d3168250ce4302e2c45cadb96c7a77bbeaf62bdbf2be26e6e16c3'
    assert cve.witnesses[0].witness_id == '01d58693c857a684c05f32dff8e7d4b422233b6c5c98600728fc72cdd5d5530c'
    assert ids.anchors_digest([]) == '45572e8aefe3d52a884a365618fc95b68bb4ea371e5fd513e96035f5bf1ce84a'
    assert ids.anchors_digest([cve]) == 'f8176dca883f8a13a8b273b86411de70801107c7cfe83ed82982d6ab19193b23'


def test_anchors_digest_is_order_independent_and_sensitive_to_witnesses():
    a, b = fs.cve_anchor('CVE-2099-0001'), fs.cwe_anchor(190)
    assert ids.anchors_digest([a, b]) == ids.anchors_digest([b, a]) == ids.anchors_digest(iter((b, a)))
    wider = ids.make_anchor(kind='cve', key=a.key, side='none', role='stated',
                            witnesses=(*a.witnesses, fs.wit('kev', 'kev-cwe', batch='k1')))
    assert ids.anchors_digest([wider, b]) != ids.anchors_digest([a, b])
    assert ids.anchors_digest([a]) != ids.anchors_digest([a, b])
    expected = oracle('fabric-anchors', sorted([[x.anchor_id, [w.witness_id for w in x.witnesses]] for x in (a, b)]))
    assert ids.anchors_digest([a, b]) == expected
    assert ids.anchors_digest([]) == oracle('fabric-anchors', [])


# --- keys ---------------------------------------------------------------------------------------------------------

def test_pair_key_equals_the_unified_row_id_and_the_pilot_candidate_key():
    older, newer = [0x1010, 0x1000], [0x2000]
    expected = unified_keys.row_id(fs.OLDER, fs.NEWER, older, newer)
    assert ids.pair_key(fs.OLDER, fs.NEWER, older, newer) == 'pair:' + expected
    assert expected == pilot_keys.candidate_key(fs.OLDER, fs.NEWER, older, newer)
    assert ids.pair_key(fs.OLDER, fs.NEWER, [0x1000, 0x1010], newer) == 'pair:' + expected


def test_pair_key_is_orientation_sensitive_and_allows_a_one_sided_function():
    forward = ids.pair_key(fs.OLDER, fs.NEWER, [0x10], [0x20])
    assert forward != ids.pair_key(fs.NEWER, fs.OLDER, [0x10], [0x20])
    assert forward != ids.pair_key(fs.OLDER, fs.NEWER, [0x20], [0x10])
    assert ids.pair_key(fs.OLDER, fs.NEWER, [], [0x20]).startswith('pair:')


@pytest.mark.parametrize('args', [
    (fs.OLDER, fs.NEWER, [], []), (fs.OLDER, fs.NEWER, [1, 1], []), (fs.OLDER, fs.NEWER, [-1], []),
    (fs.OLDER, fs.NEWER, [2 ** 32], []), (fs.OLDER, fs.NEWER, [True], []), (fs.OLDER, fs.NEWER, ['1'], []),
    ('abc', fs.NEWER, [1], []), (fs.OLDER, fs.NEWER.upper(), [1], [])],
    ids=['empty', 'duplicate', 'negative', 'too-big', 'bool', 'text', 'short-sha', 'upper-sha'])
def test_pair_key_refuses_malformed_input(args):
    err = raised(ids.pair_key, *args)
    assert err.code == 'PT-FAB-KEY'


def test_image_key_and_pair_members_use_the_rva_function_id_form():
    assert ids.image_key(fs.OLDER, 0x1000) == f'image:{fs.OLDER}:rva:0x1000'
    pair = fs.pair_ref(older=(0x1010, 0x1000), newer=(0x2000,))
    assert ids.pair_members(pair) == (f'image:{fs.OLDER}:rva:0x1000', f'image:{fs.OLDER}:rva:0x1010',
                                      f'image:{fs.NEWER}:rva:0x2000')
    for bad in (-1, 2 ** 64, True, '4096'):
        assert raised(ids.image_key, fs.OLDER, bad).code == 'PT-FAB-KEY'
    assert raised(ids.image_key, 'xyz', 1).code == 'PT-FAB-KEY'


def test_string_key_is_the_sha256_of_nfc_text_with_ascii_letters_lower_cased():
    assert ids.string_key('hello') == hashlib.sha256(b'hello').hexdigest()
    assert ids.string_key('Hello') == ids.string_key('hELLO') == ids.string_key('hello')
    nfc = 'caf\xe9'
    assert ids.string_key(nfc) == ids.string_key(unicodedata.normalize('NFD', nfc))
    assert ids.string_key('É') != ids.string_key('é')  # Unicode case is not folded: stable across Pythons
    assert ids.string_key('ß') != ids.string_key('ss')
    assert ids.string_key('a b') != ids.string_key('ab')


@pytest.mark.parametrize('value', ['', 'a\ud800', None, b'x', 7], ids=['empty', 'surrogate', 'none', 'bytes', 'int'])
def test_string_key_refuses_empty_unencodable_and_non_text(value):
    assert raised(ids.string_key, value).code == 'PT-FAB-KEY'


API_KEYS = [('CreateFileW', 'createfile'), ('CreateFileA', 'createfile'), ('kernel32.dll!CreateFileW', 'createfile'),
            ('KERNEL32!CreateFileA', 'createfile'), ('kernel32.CreateFileW', 'createfile'),
            ('RtlULongAdd', 'rtlulongadd'), ('ntdll!NtClose', 'ntclose'), ('  MessageBoxW  ', 'messagebox'),
            ('GetW', 'getw'), ('abcdW', 'abcd'), ('abcW', 'abcw'), ('??0Foo@@QEAA@XZ', '??0foo@@qeaa@xz')]


@pytest.mark.parametrize('name,key', API_KEYS, ids=[f'api{i}' for i in range(len(API_KEYS))])
def test_api_key_follows_the_cap_rule(name, key):
    assert ids.api_key(name) == key


@pytest.mark.parametrize('name', ['', '   ', 'a b', 'café', 'ws2_32.dll!#115', '#115', 'x' * 201, 'dll!', None],
                         ids=['empty', 'blank', 'space', 'non-ascii', 'ordinal', 'bare-ordinal', 'long', 'no-name',
                              'none'])
def test_api_key_refuses_what_is_not_a_named_import(name):
    assert raised(ids.api_key, name).code == 'PT-FAB-KEY'


def test_ordinal_key_keeps_the_module_because_ordinals_are_per_dll():
    assert ids.ordinal_key('WS2_32.dll', 115) == 'ws2_32!#115' == ids.ordinal_key('ws2_32', 115)
    assert ids.ordinal_key('ws2_32', 0) == 'ws2_32!#0' and ids.ordinal_key('ws2_32', 65535) == 'ws2_32!#65535'
    for dll, number in (('ws2_32', -1), ('ws2_32', 65536), ('ws2_32', True), ('ws2_32', '1'), ('', 1), ('a b', 1),
                        ('a!b', 1), ('café', 1), ('x' * 65, 1)):
        assert raised(ids.ordinal_key, dll, number).code == 'PT-FAB-KEY'


@pytest.mark.parametrize('call,value,key', [
    (ids.cve_key, ' cve-2024-1234 ', 'CVE-2024-1234'), (ids.cve_key, 'CVE-2099-0000001', 'CVE-2099-0000001'),
    (ids.cwe_key, '79', 'CWE-79'), (ids.cwe_key, 'cwe-79', 'CWE-79'), (ids.cwe_key, 'CWE79', 'CWE-79'),
    (ids.kb_key, '5034441', 'KB5034441'), (ids.kb_key, ' kb5034441', 'KB5034441')],
    ids=['cve', 'cve-long', 'cwe-digits', 'cwe-lower', 'cwe-nodash', 'kb-digits', 'kb-lower'])
def test_identifier_constructors_normalise(call, value, key):
    assert call(value) == key


@pytest.mark.parametrize('call,value', [
    (ids.cve_key, 'CVE-24-1'), (ids.cve_key, 'CVE-2024-123'), (ids.cve_key, 'banana'), (ids.cve_key, 'CVE-２024-1234'),
    (ids.cve_key, None), (ids.cwe_key, '0'), (ids.cwe_key, 'CWE-0'), (ids.cwe_key, 'CWE-1234567'), (ids.cwe_key, 'CWE-'),
    (ids.cwe_key, '٣'), (ids.kb_key, 'KB1234'), (ids.kb_key, '1234567890'), (ids.kb_key, 'KB'), (ids.kb_key, 5034441)],
    ids=[f'bad{i}' for i in range(14)])
def test_identifier_constructors_refuse(call, value):
    assert raised(call, value).code == 'PT-FAB-KEY'


def test_key_for_value_maps_a_display_value_to_the_kind_key():
    ordinal, pair_key = 'ws2_32.dll!#115', fs.pair_key()
    image, rule = f'image:{fs.OLDER}:rva:0x10', 'yara:0123456789ab.v2'
    cases = [('string', 'Hello', ids.string_key('hello')),
             ('advisory_phrase', 'Some Phrase', ids.string_key('some phrase')),
             ('import', 'kernel32!CreateFileW', 'createfile'), ('import', ordinal, 'ws2_32!#115'),
             ('cve', 'cve-2099-0001', 'CVE-2099-0001'), ('cwe', '79', 'CWE-79'), ('kb', '5034441', 'KB5034441'),
             ('capability', 'create process', 'create process'), ('rule', rule, rule),
             ('build_fact', 'linker=14.38', 'linker=14.38'), ('function', pair_key, pair_key),
             ('function', image, image), ('function', 'sub_1000', None)]
    for kind, value, key in cases:
        assert ids.key_for_value(kind, value) == key, (kind, value)
    assert raised(ids.key_for_value, 'banana', 'x').code == 'PT-FAB-KIND'
    assert raised(ids.key_for_value, 'cve', 'banana').code == 'PT-FAB-KEY'


# --- builders -----------------------------------------------------------------------------------------------------

def test_make_witness_sanitises_text_sorts_and_accepts_mappings():
    w = ids.make_witness(producer='kb', batch='b1', source='advisory-text', origins=['D_vendor_text', 'D_vendor_text'],
                         label='bad' + chr(0x202E) + 'text', facets={'b': 'x\x00y', 'a': 'z'}, tool='csaf\n')
    assert w.label == 'badtext' and w.facets == (('a', 'z'), ('b', 'xy')) and w.tool == 'csaf '
    assert w.origins == ('D_vendor_text',)


@pytest.mark.parametrize('change,reason', [
    ({'producer': 'gui'}, 'witness-producer'), ({'batch': 'Bad Batch'}, 'witness-batch'),
    ({'label': chr(0x202E)}, 'witness-label'), ({'origins': []}, 'witness-origins'),
    ({'input_sha256': 'xyz'}, 'witness-input-sha256')], ids=['producer', 'batch', 'label', 'origins', 'sha'])
def test_make_witness_wraps_shape_errors_in_a_typed_error(change, reason):
    fields = dict(producer='kb', batch='b1', source='advisory-text', origins=['D_vendor_text'], label='x')
    err = raised(ids.make_witness, **{**fields, **change})
    assert (err.code, err.reason) == ('PT-FAB-INPUT', reason)


def test_make_anchor_sorts_dedupes_and_derives_the_ids():
    w1, w2 = fs.wit('kb', 'advisory-text', batch='b1'), fs.wit('kev', 'kev-cwe', batch='b2')
    anchor = ids.make_anchor(kind='cwe', key='CWE-190', side='none', role='stated', witnesses=(w2, w1, w2))
    assert [w.witness_id for w in anchor.witnesses] == sorted({w1.witness_id, w2.witness_id})
    assert anchor.anchor_id == ids.anchor_id('cwe', 'CWE-190', 'none', 'stated', None)
    ids.verify_anchor(anchor)


def test_make_anchor_derives_the_pair_key_from_the_pair():
    pair = fs.pair_ref(older=(0x1010, 0x1000), newer=(0x2000,))
    anchor = fs.anchor('function', None, 'both', 'observed', pair=pair, producer='ue', source='pairing')
    assert anchor.key == ids.pair_key(fs.OLDER, fs.NEWER, [0x1000, 0x1010], [0x2000]) and anchor.pair == pair


def test_make_anchor_needs_a_key_unless_a_pair_gives_it():
    witnesses = (fs.wit('kb', 'advisory-text'),)
    err = raised(ids.make_anchor, kind='cve', key=None, side='none', role='stated', witnesses=witnesses)
    assert (err.code, err.reason) == ('PT-FAB-KEY', 'key-missing')
    err = raised(ids.make_anchor, kind='cve', key='CVE-2099-0001', side='none', role='stated', witnesses=())
    assert (err.code, err.reason) == ('PT-FAB-INPUT', 'anchor-witnesses')


# --- the semantic matrix ------------------------------------------------------------------------------------------

HEX = 'c' * 64
NFD_CAFE = unicodedata.normalize('NFD', 'caf\xe9')
PAIR = fs.pair_ref()
MATRIX = {
    'key-cve': (dict(kind='cve', key='CVE-1', side='none', role='stated'), 'PT-FAB-KEY', 'key-grammar'),
    'key-string': (dict(kind='string', key='abc', side='newer', role='observed', input=fs.NEWER),
                   'PT-FAB-KEY', 'key-grammar'),
    'key-import-upper': (dict(kind='import', key='CreateFile', side='newer', role='observed', input=fs.NEWER),
                         'PT-FAB-KEY', 'key-grammar'),
    'key-import-module': (dict(kind='import', key='kernel32!createfile', side='newer', role='observed', input=fs.NEWER),
                          'PT-FAB-KEY', 'key-grammar'),
    'key-import-bare-ordinal': (dict(kind='import', key='#115', side='newer', role='observed', input=fs.NEWER),
                                'PT-FAB-KEY', 'key-grammar'),
    'key-capability-nfd': (dict(kind='capability', key=NFD_CAFE, side='newer', role='observed', input=fs.NEWER),
                           'PT-FAB-KEY', 'key-grammar'),
    'key-rule': (dict(kind='rule', key='sigma:abc', side='none', role='stated'), 'PT-FAB-KEY', 'key-grammar'),
    'key-build-fact': (dict(kind='build_fact', key='linker', side='newer', role='observed', input=fs.NEWER),
                       'PT-FAB-KEY', 'key-grammar'),
    'key-advisory': (dict(kind='advisory_phrase', key='not-hex', side='none', role='stated'), 'PT-FAB-KEY', 'key-grammar'),
    'key-kb': (dict(kind='kb', key='KB12', side='none', role='stated'), 'PT-FAB-KEY', 'key-grammar'),
    'key-cwe': (dict(kind='cwe', key='CWE-0', side='none', role='stated'), 'PT-FAB-KEY', 'key-grammar'),
    'key-function': (dict(kind='function', key='foo', side='both', role='observed'), 'PT-FAB-KEY', 'key-grammar'),
    'role-cve-observed': (dict(kind='cve', key='CVE-2099-0001', side='newer', role='observed', input=fs.NEWER),
                          'PT-FAB-INPUT', 'role-not-allowed'),
    'role-function-hint': (dict(kind='function', key='pair:' + HEX, side='none', role='hint', pair=PAIR),
                           'PT-FAB-INPUT', 'role-not-allowed'),
    'role-string-stated': (dict(kind='string', key=HEX, side='none', role='stated'), 'PT-FAB-INPUT', 'role-not-allowed'),
    'side-observed-none': (dict(kind='string', key=HEX, side='none', role='observed'), 'PT-FAB-ORIENTATION',
                           'observed-needs-side'),
    'side-hint-newer': (dict(kind='string', key=HEX, side='newer', role='hint'), 'PT-FAB-ORIENTATION', 'hint-has-no-side'),
    'side-pair-newer': (dict(kind='function', key='pair:' + HEX, side='newer', role='observed', pair=PAIR, input=fs.NEWER),
                        'PT-FAB-ORIENTATION', 'function-side'),
    'side-image-both': (dict(kind='function', key=f'image:{fs.OLDER}:rva:0x10', side='both', role='observed'),
                        'PT-FAB-ORIENTATION', 'function-side'),
    'input-missing': (dict(kind='string', key=HEX, side='newer', role='observed', input=None), 'PT-FAB-ORIENTATION',
                      'input-sha-missing'),
    'subject-on-function': (dict(kind='function', key=f'image:{fs.NEWER}:rva:0x10', side='newer', role='observed',
                                 input=fs.NEWER, subject='pair:' + HEX), 'PT-FAB-INPUT', 'function-has-no-subject'),
    'subject-grammar': (dict(kind='import', key='createfile', side='newer', role='observed', input=fs.NEWER,
                             subject='sub_1000'), 'PT-FAB-KEY', 'subject-grammar'),
    'pair-required': (dict(kind='function', key='pair:' + HEX, side='both', role='observed'), 'PT-FAB-KEY',
                      'pair-required'),
    'pair-unexpected': (dict(kind='string', key=HEX, side='newer', role='observed', input=fs.NEWER, pair=PAIR),
                        'PT-FAB-KEY', 'pair-unexpected'),
    'pair-key-mismatch': (dict(kind='function', key='pair:' + HEX, side='both', role='observed', pair=PAIR),
                          'PT-FAB-KEY', 'pair-key-mismatch'),
}


@pytest.mark.parametrize('name', sorted(MATRIX), ids=sorted(MATRIX))
def test_make_anchor_enforces_the_semantic_matrix_with_typed_errors(name):
    fields, code, reason = MATRIX[name]
    fields = dict(fields)
    witness = fs.wit(input_sha=fields.pop('input', None))
    err = raised(ids.make_anchor, witnesses=(witness,), **fields)
    assert (err.code, err.reason) == (code, reason)
    assert 'CVE' not in err.message and HEX not in err.message  # fixed templates, never the offending value


@pytest.mark.parametrize('kind,key,side,role', [
    ('function', 'pair:' + ids.pair_key(fs.OLDER, fs.NEWER, [0x10], [0x20])[5:], 'both', 'observed'),
    ('function', f'image:{fs.OLDER}:rva:0xabcdef', 'older', 'observed'),
    ('string', ids.string_key('x'), 'both', 'observed'), ('string', ids.string_key('x'), 'none', 'hint'),
    ('import', 'rtlulongadd', 'newer', 'observed'), ('import', 'ws2_32!#115', 'older', 'observed'),
    ('import', 'rtlulongadd', 'none', 'hint'), ('capability', 'create process on Windows', 'newer', 'observed'),
    ('rule', 'patch:R-MEMORY-WRITE@patch-rules/1', 'none', 'stated'),
    ('rule', 'yara:0123456789ab.v12', 'older', 'observed'),
    ('build_fact', 'linker=14.38.33135', 'older', 'observed'),
    ('build_fact', 'kb=KB5034441 (stated)', 'newer', 'stated'),
    ('advisory_phrase', ids.string_key('tcpip.sys'), 'none', 'stated'),
    ('advisory_phrase', ids.string_key('x'), 'none', 'hint'),
    ('cve', 'CVE-2099-0001', 'newer', 'stated'), ('kb', 'KB5034441', 'newer', 'stated'),
    ('cwe', 'CWE-190', 'none', 'stated'), ('cwe', 'CWE-190', 'none', 'hint')],
    ids=[f'ok{i}' for i in range(18)])
def test_the_grammar_accepts_a_valid_key_of_every_kind(kind, key, side, role):
    pair = None
    if key.startswith('pair:'):
        pair = fs.pair_ref(older=(0x10,), newer=(0x20,))
    input_sha = fs.side_sha(side) if role == 'observed' else None
    anchor = ids.make_anchor(kind=kind, key=key, side=side, role=role, pair=pair,
                             witnesses=(fs.wit(input_sha=input_sha),))
    ids.verify_anchor(anchor)


def test_subject_forms_pair_and_image_are_accepted():
    for subject in (fs.pair_key(), f'image:{fs.NEWER}:rva:0x1040'):
        anchor = fs.import_anchor('RtlULongAdd', subject=subject)
        assert anchor.subject == subject


# --- verification -------------------------------------------------------------------------------------------------

def _tampered(anchor, **change):
    return anchor.model_copy(update=change)


@pytest.mark.parametrize('reason', ['anchor-id', 'witness-id', 'pair-key'])
def test_verify_anchor_names_each_kind_of_tampering(reason):
    anchor = fs.pair_anchor()
    ids.verify_anchor(anchor)
    bad = {
        'anchor-id': _tampered(anchor, anchor_id='0' * 64),
        'witness-id': _tampered(anchor, witnesses=(anchor.witnesses[0].model_copy(update={'label': 'changed'}),)),
        'pair-key': _tampered(anchor, pair=fs.pair_ref(older=(0x1001,))),
    }[reason]
    err = raised(ids.verify_anchor, bad)
    assert (err.code, err.reason) == ('PT-FAB-INTEGRITY', reason)


def test_verify_anchor_also_applies_the_semantic_checks():
    good = fs.cve_anchor()
    bad = _tampered(good, role='observed', side='newer')
    bad = _tampered(bad, anchor_id=ids.anchor_id(bad.kind, bad.key, bad.side, bad.role, bad.subject))
    assert raised(ids.verify_anchor, bad).code == 'PT-FAB-INPUT'


# --- orientation --------------------------------------------------------------------------------------------------

ORIENTATION = {
    'pair-ok': (lambda: fs.pair_anchor(), None),
    'pair-swapped': (lambda: fs.anchor('function', None, 'both', 'observed',
                                       pair=fs.pair_ref(older_sha=fs.NEWER, newer_sha=fs.OLDER),
                                       producer='ue', source='pairing'), 'orientation-swapped'),
    'pair-foreign': (lambda: fs.anchor('function', None, 'both', 'observed',
                                       pair=fs.pair_ref(older_sha='c' * 64), producer='ue', source='pairing'),
                     'pair-mismatch'),
    'input-ok': (lambda: fs.import_anchor('Foo', 'older'), None),
    'input-swapped': (lambda: fs.import_anchor('Foo', 'older', input_sha=fs.NEWER), 'orientation-swapped'),
    'input-foreign': (lambda: fs.import_anchor('Foo', 'newer', input_sha='c' * 64), 'input-sha-mismatch'),
    'both-foreign': (lambda: fs.anchor('string', ids.string_key('x'), 'both', 'observed', input_sha='c' * 64),
                     'input-sha-mismatch'),
    'image-key-swapped': (lambda: fs.anchor('function', ids.image_key(fs.NEWER, 0x10), 'older', 'observed',
                                            producer='ue', source='pairing'), 'orientation-swapped'),
    'subject-ok': (lambda: fs.import_anchor('Foo', 'newer', subject=f'image:{fs.NEWER}:rva:0x10'), None),
    'subject-other-side': (lambda: fs.import_anchor('Foo', 'newer', subject=f'image:{fs.OLDER}:rva:0x10'),
                           'subject-side-mismatch'),
    'subject-foreign': (lambda: fs.import_anchor('Foo', 'newer', subject=f'image:{"c" * 64}:rva:0x10'),
                        'subject-sha-mismatch'),
}


@pytest.mark.parametrize('name', sorted(ORIENTATION), ids=sorted(ORIENTATION))
def test_check_orientation_against_the_bound_pair(name):
    build, reason = ORIENTATION[name]
    anchor = build()
    if reason is None:
        ids.check_orientation(anchor, fs.OLDER, fs.NEWER)
        return
    err = raised(ids.check_orientation, anchor, fs.OLDER, fs.NEWER)
    assert (err.code, err.reason) == ('PT-FAB-ORIENTATION', reason)
