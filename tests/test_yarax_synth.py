"""R1: closed-grammar rule synthesis. Goldens, Formatter fixed point, engine semantics, hostile-input sweeps.

The engine (`yara_x`) is a test-time oracle only; `patchtrace.yarax.synth` never imports it.
"""
from __future__ import annotations

import hashlib
import io
import re
import sys
import unicodedata
from functools import partial
from pathlib import Path

import pytest
import yara_x
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from patchtrace.yarax import contracts as c
from patchtrace.yarax import synth
from patchtrace.yarax.errors import RulesError
from patchtrace.yarax.limits import LIMITS

GOLDEN = Path(__file__).resolve().parent / 'fixtures' / 'yarax' / 'golden'
OLDER_SHA, NEWER_SHA, LINEAGE = 'a1' * 32, 'b2' * 32, '0123456789abcdef' * 4
PIN_WINDOW = 'C3 48 83 EC 28 48 8D 0D 70 10 00 00 FF 15 ?? ?? ?? ?? 48 89 C1 48 8D 15'
SLOW = settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow])


# ---- builders -----------------------------------------------------------------------------------------------------

def pair(category: str = 'modified', project: str = 'proj-1', older_name: str = '', newer_name: str = '',
         cwe: tuple[str, ...] = ()) -> c.PairSource:
    older = None if category == 'added' else c.FunctionRef(name=older_name, rva=0x104D, size=64, extent='pdata')
    newer = None if category == 'removed' else c.FunctionRef(name=newer_name, rva=0x108D, size=64, extent='pdata')
    return c.PairSource(project_id=project, revision=1, run_id='run-1', older_sha256=OLDER_SHA, newer_sha256=NEWER_SHA,
                        match_id='m1', category=category, materiality='material', cwe=cwe, older=older, newer=newer)


def bytes_feature(pattern: str = PIN_WINDOW, side: str = 'older', pins: tuple[c.CallPin, ...] = (),
                  included: bool = True) -> c.BytesFeature:
    tokens = pattern.split(' ')
    runs = [len(run) for run in re.findall(r'(?:[0-9A-F]{2} ?)+', pattern.replace('??', ' '))]
    return c.BytesFeature(side=side, window_rva=0x1040, length=len(tokens), pattern=pattern,
                          literal=sum(t != '??' for t in tokens), longest_run=max(r // 3 + 1 for r in runs),
                          mask_source='iced-x86', pins=pins, source_hits=1, other_hits=0, separation='older-only',
                          included=included)


def pin(dll: str = 'KERNEL32.dll', name: str = 'GetModuleHandleA', disp: int = 14, end: int = 18) -> c.CallPin:
    return c.CallPin(disp_offset=disp, end_offset=end, dll=dll, name=name)


def escape(raw: bytes) -> str:
    """Test-side escaper, independent of the module under test."""
    return ''.join(chr(b) if chr(b).isalnum() and b < 128 else f'\\x{b:02x}' for b in raw)


def string_feature(raw: bytes = b'Beep', encoding: str = 'ascii', side: str = 'older', text: str | None = None,
                   length: int | None = None) -> c.StringFeature:
    feature = c.StringFeature(side=side, value_sha256=hashlib.sha256(raw).hexdigest(), length=len(raw),
                              text=escape(raw), encoding=encoding, offset=0, evidence_run_id='run-1',
                              linked_by='file-level', separation='older-only', included=True)
    if text is None and length is None:
        return feature
    # model_copy skips validation: forged text and lengths must be survivable
    return feature.model_copy(update={'text': feature.text if text is None else text,
                                      'length': feature.length if length is None else length})


def imported(dll: str = 'KERNEL32.dll', name: str | None = 'TerminateProcess', ordinal: int | None = None,
             delay: bool = False) -> c.ImportFeature:
    return c.ImportFeature(dll=dll, name=name, ordinal=ordinal, delay=delay, origin='pe-imports',
                           separation='older-only', included=True)


def capability(rule_id: str = 'terminate process', gates: tuple[str, ...] = ()) -> c.CapabilityFeature:
    return c.CapabilityFeature(rule_id=rule_id, namespace='host-interaction/process/terminate', api_gates=gates,
                               separation='older-only', included=True)


def spec(features, direction: str = 'older', **kw) -> synth.RuleSpec:
    source = kw.pop('source', None) or pair()
    return synth.RuleSpec(source=source, direction=direction, lineage_id=LINEAGE, version=kw.pop('version', 1),
                          features=tuple(features), **kw)


GOLDEN_SPECS = {
    'bytes_pin': lambda: spec([bytes_feature(pins=(pin(),))]),
    'text_newer': lambda: spec([string_feature(b'Beep\x00\xff"\\', 'ascii-wide', 'newer'),
                                string_feature(b'kernel32.dll', 'wide', 'newer'), imported(name='WriteFile')],
                               'newer', source=pair('added')),
    'imports': lambda: spec([imported(), imported('ntdll.dll', None, 7), imported('ADVAPI32.dll', 'RegOpenKeyExW', None, True),
                             imported('SHELL32.dll', None, 12, True)]),
    'full': lambda: spec([bytes_feature(pins=(pin(), pin('ntdll.dll', 'NtClose', 14, 18))), string_feature(b'PATCHTRACE'),
                          imported(), capability('terminate process', ('TerminateProcess', 'ExitProcess'))],
                         source=pair('removed', 'proj "x"', 'FuncA', cwe=('CWE-787',)), include_names=True, unvetted=True,
                         analyst_label='Older build only', cve=('CVE-2024-0001',), kb=('KB5000001',), cwe=('CWE-20',),
                         version=3),
}


def compile_rules(text: str):
    compiler = yara_x.Compiler(error_on_slow_pattern=True, includes_enabled=False)
    compiler.allowed_rule_name(r'^PT_[0-9a-f]{12}_(older|newer)$', error=True)
    compiler.allowed_tags(['patchtrace', 'older_side', 'newer_side'], error=True)
    compiler.allowed_metadata('patchtrace_rule_id', yara_x.MetaType.STRING, required=True, regexp=None, error=True)
    compiler.allowed_metadata('patchtrace_version', yara_x.MetaType.INTEGER, required=True, regexp=None, error=True)
    compiler.add_source(text)
    warnings = [w['code'] for w in compiler.warnings()]  # before build(): build() resets them
    return compiler.build(), warnings


def formatted(text: str) -> str:
    out = io.StringIO()
    yara_x.Formatter().format(io.StringIO(text), out)
    return out.getvalue()


def assert_engine_clean(text: str) -> None:
    rules, warnings = compile_rules(text)
    assert set(warnings) <= {'text_as_hex'}
    assert rules.imports() == ['pe']
    assert formatted(text) == text


_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')


def skeleton(text: str) -> str:
    return _LITERAL.sub('""', text)


def sanitised(value: str) -> str:
    return ''.join(ch if ' ' <= ch <= '~' else '?' for ch in value)


def meta_of(text: str) -> dict:
    return dict(synth.parse_rule(text).meta)


def code_of(call) -> str:
    with pytest.raises(RulesError) as caught:
        call()
    return caught.value.code


# ---- goldens and the engine ---------------------------------------------------------------------------------------

@pytest.mark.parametrize('name', sorted(GOLDEN_SPECS), ids=sorted(GOLDEN_SPECS))
def test_golden_rule_text(name):
    expected = (GOLDEN / f'{name}.yar').read_bytes()
    assert synth.synthesize(GOLDEN_SPECS[name]()).encode('ascii') == expected
    assert b'\r' not in expected and expected.endswith(b'}\n')


@pytest.mark.parametrize('name', sorted(GOLDEN_SPECS), ids=sorted(GOLDEN_SPECS))
def test_synth_is_formatter_fixed_point_and_compiles_clean(name):
    assert_engine_clean(synth.synthesize(GOLDEN_SPECS[name]()))


@pytest.mark.parametrize('name', sorted(GOLDEN_SPECS), ids=sorted(GOLDEN_SPECS))
def test_goldens_are_ascii_and_use_the_copy_rules(name):
    text = synth.synthesize(GOLDEN_SPECS[name]()).lower()
    assert text.isascii()
    for banned in ('vulnerab', 'exploit', 'safe', 'secure', 'fixed', 'verified', 'proven', 'probab'):
        assert banned not in text


def test_names_are_off_by_default_and_opt_in():
    features = [bytes_feature()]
    quiet = synth.synthesize(spec(features, source=pair(older_name='SecretName')))
    assert 'SecretName' not in quiet and 'function_older ' in quiet
    named = synth.synthesize(spec(features, source=pair(older_name='SecretName'), include_names=True))
    assert meta_of(named)['function_older_name'] == 'SecretName'


def test_unincluded_and_capability_only_sets():
    off = bytes_feature(included=False)
    assert code_of(lambda: synth.synthesize(spec([off]))) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([capability()]))) == 'PT-RULE-INPUT'
    text = synth.synthesize(spec([bytes_feature(), off.model_copy(update={'pattern': '90 ' * 15 + '91'})]))
    assert text.count('$b') == 2  # one definition and one use; the unticked feature never appears
    assert '90 90' not in text


def test_pin_matches_only_the_named_iat_slot_in_a_real_image():
    from test_intel_tools_pe import capa_api_pair
    older, _ = capa_api_pair()

    def hits(feature_pin, image=older):
        text = synth.synthesize(spec([bytes_feature(pins=(feature_pin,))]))
        rules, _ = compile_rules(text)
        return len(yara_x.Scanner(rules).scan(image).matching_rules)

    assert hits(pin()) == 1
    assert hits(pin(dll='kernel32.DLL')) == 1  # DLL names compare case-insensitively
    assert hits(pin(name='TerminateProcess')) == 0
    assert hits(pin(name='GetProcAddress')) == 0


def test_import_gate_is_positive_evidence_in_a_real_image():
    from test_intel_tools_pe import capa_api_pair
    older, newer = capa_api_pair()
    rules, _ = compile_rules(synth.synthesize(spec([imported('kernel32.dll', 'TerminateProcess')])))
    assert len(yara_x.Scanner(rules).scan(older).matching_rules) == 1
    assert len(yara_x.Scanner(rules).scan(newer).matching_rules) == 0
    rules, _ = compile_rules(synth.synthesize(spec([imported('kernel32.dll', 'WriteFile'),
                                                    capability('x', ('GetProcAddress',))])))
    assert len(yara_x.Scanner(rules).scan(older).matching_rules) == 0
    assert len(yara_x.Scanner(rules).scan(newer).matching_rules) == 1


# ---- escaping against the real engine -----------------------------------------------------------------------------

def scan_hits(source: str, data: bytes):
    compiler = yara_x.Compiler()
    compiler.add_source(source)
    result = yara_x.Scanner(compiler.build()).scan(data)
    return [(m.offset, m.length) for rule in result.matching_rules for p in rule.patterns for m in p.matches]


@pytest.mark.parametrize('value', range(256), ids=[f'b{v:02x}' for v in range(256)])
def test_every_byte_value_is_a_single_engine_byte(value):
    source = f'rule t {{ strings: $a = {synth._text_literal(bytes([value]))} condition: $a }}'
    pad = bytes([(value + 1) % 256]) * 2
    assert scan_hits(source, pad + bytes([value]) + pad) == [(2, 1)]


@pytest.mark.parametrize('raw', [b'a"b', b'a\\b', b'\\"', b'\\\\x41', b'"\\"', b'*/ /* //', b'}\n{', b'\x00\x00\x01',
                                 b'\xe2\x80\xae', b'$a #a @a', b'/a.*b/', b'{ 90 90 }', b'[1-2]', b'a|b'],
                         ids=[f'r{i:02d}' for i in range(14)])
def test_text_literal_round_trips_through_the_engine(raw):
    source = f'rule t {{ strings: $a = {synth._text_literal(raw)} condition: $a }}'
    assert scan_hits(source, b'..' + raw + b'..') == [(2, len(raw))]
    wide = f'rule t {{ strings: $a = {synth._text_literal(raw)} wide condition: $a }}'
    assert scan_hits(wide, b'..' + raw.decode('latin-1').encode('utf-16-le') + b'..')


@pytest.mark.parametrize('value', ['a"b', 'a\\b', '\\"', '"\\', 'a\\\\"b', '*/ /* //', '}{', 'x y', '/a.*b/', '$b #b'],
                         ids=[f'm{i:02d}' for i in range(10)])
def test_meta_literal_round_trips_through_the_engine(value):
    compiler = yara_x.Compiler()
    compiler.add_source(f'rule t {{ meta: k = {synth._string_literal(value)} condition: true }}')
    rule = list(yara_x.Scanner(compiler.build()).scan(b'').matching_rules)[0]
    found = dict(rule.metadata)['k']
    assert (found.encode() if isinstance(found, str) else found) == value.encode()


# ---- hostile input ------------------------------------------------------------------------------------------------

HOSTILE = [
    '"', '\\', '\n', '\r', '\r\n', '*/', '/*', '//', '}', '{', '\x00', '\u202e', '\u2066', '\u2028', '\u2029', '\x85',
    '\x1b[31m', '"; condition: true } rule evil { condition: true } //', '" and true or "', 'a" and pe.is_pe or "b',
    '\\"', '\\\\"', '\\x41', '$b', '#b', '@b[1]', ' } rule x { condition: true', '/.*/', '/a/ nocase', '{ 90 90 }',
    '[0-9]', '(a|b)', '~', '\ufeff', '\U0001f600', '\ud800', '\udc80', '\t', '\x7f', '\xa0', '\u00e9', '\uff45',
]
HOSTILE_IDS = [f'h{i:02d}' for i in range(len(HOSTILE))]


def _category_samples() -> dict[str, str]:
    samples: dict[str, str] = {'Cs': '\ud800', 'Cn': '\u0378'}
    for code in range(0x30000):
        samples.setdefault(unicodedata.category(chr(code)), chr(code))
    return samples


CATEGORIES = _category_samples()


def free_text_spec(value: str) -> synth.RuleSpec:
    # model_copy skips validation: lone surrogates and oversize values must be survivable even if a model is forged
    source = pair(older_name='f', newer_name='n').model_copy(update={'project_id': f'p{value}'[:128]})
    source = source.model_copy(update={'older': source.older.model_copy(update={'name': f'f{value}'[:200]})})
    cap = capability().model_copy(update={'rule_id': f'cap{value}'[:200]})
    return spec([bytes_feature(), cap], include_names=True, analyst_label=f'L{value}'[:120], source=source)


BASELINE = synth.synthesize(free_text_spec('x'))


def check_free_text(value: str) -> None:
    text = synth.synthesize(free_text_spec(value))
    assert text.isascii() and '\r' not in text and text.count('\n') == BASELINE.count('\n')
    assert skeleton(text) == skeleton(BASELINE)
    assert_engine_clean(text)
    meta = meta_of(text)
    assert meta['patchtrace_project_id'] == sanitised(f'p{value}'[:128])
    assert meta['analyst_label'] == sanitised(f'L{value}'[:120])
    assert meta['function_older_name'] == sanitised(f'f{value}'[:200])
    assert meta['capability'] == sanitised(f'cap{value}'[:200])


@pytest.mark.parametrize('value', HOSTILE, ids=HOSTILE_IDS)
def test_hostile_free_text_never_changes_structure(value):
    check_free_text(value)


@pytest.mark.parametrize('category', sorted(CATEGORIES), ids=sorted(CATEGORIES))
def test_every_unicode_category_in_free_text(category):
    check_free_text(f'a{CATEGORIES[category]}b')


@SLOW
@given(st.text(max_size=80))
def test_any_free_text_never_changes_structure(value):
    check_free_text(value)


@SLOW
@given(st.text(alphabet=st.sampled_from('"\\\n\r/*{}$#@\x00\u202e\u2066 abc;(|)[]'), max_size=80))
def test_structural_alphabet_in_free_text(value):
    check_free_text(value)


def test_free_text_over_the_meta_cap_is_a_limit_not_a_truncation():
    long = pair(project='p').model_copy(update={'project_id': 'p' * (LIMITS.meta_string_chars + 1)})
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], source=long))) == 'PT-RULE-LIMIT'


ALLOWED = {'dll': synth._DLL, 'name': synth._SYMBOL, 'ordinal-dll': synth._DLL, 'pin-dll': synth._DLL,
           'pin-name': synth._SYMBOL, 'api-gate': synth._SYMBOL, 'cve': synth._ANCHORS['cve'], 'kb': synth._ANCHORS['kb'],
           'cwe': synth._ANCHORS['cwe']}


def whitelisted_spec(field: str, value: str, ok: bool = False) -> synth.RuleSpec:
    """A valid spec with exactly one field forged to `value` (model_copy skips validation)."""
    bytes_f, imp, cap = bytes_feature(pins=(pin(),)), imported(), capability('x', ('Gate',))
    extra = {}
    if field == 'dll':
        imp = imp.model_copy(update={'dll': value})
    elif field == 'name':
        imp = imp.model_copy(update={'name': value})
    elif field == 'ordinal-dll':
        imp = imp.model_copy(update={'dll': value, 'name': None, 'ordinal': 3})
    elif field == 'pin-dll':
        bytes_f = bytes_f.model_copy(update={'pins': (pin().model_copy(update={'dll': value}),)})
    elif field == 'pin-name':
        bytes_f = bytes_f.model_copy(update={'pins': (pin().model_copy(update={'name': value}),)})
    elif field == 'api-gate':
        cap = cap.model_copy(update={'api_gates': (value,)})
    else:
        extra[field] = (value,)
    return spec([bytes_f, imp, cap], **extra)


@pytest.mark.parametrize('value', HOSTILE, ids=HOSTILE_IDS)
@pytest.mark.parametrize('field', sorted(ALLOWED), ids=sorted(ALLOWED))
def test_whitelisted_fields_reject_or_pass_inertly(field, value):
    baseline = synth.synthesize(whitelisted_spec(field, {'cve': 'CVE-2024-0001', 'kb': 'KB5000001', 'cwe': 'CWE-1'}.get(
        field, 'a.b')))
    if ALLOWED[field].fullmatch(value):  # a legitimate value that merely looks odd: structure must still not move
        text = synth.synthesize(whitelisted_spec(field, value))
        assert skeleton(text) == skeleton(baseline) and text.isascii()
        assert_engine_clean(text)
    else:
        assert code_of(lambda: synth.synthesize(whitelisted_spec(field, value))) == 'PT-RULE-INPUT'


@pytest.mark.parametrize('char', [' ', '"', '\\', "'", '\n', '/', '*', '{', '}', ';', '(', ')', ',', '='],
                         ids=['sp', 'dq', 'bs', 'sq', 'nl', 'sl', 'st', 'lb', 'rb', 'sc', 'lp', 'rp', 'cm', 'eq'])
@pytest.mark.parametrize('field', ['dll', 'name', 'ordinal-dll', 'pin-dll', 'pin-name', 'api-gate'])
def test_whitelists_are_tight_not_merely_escaped(field, char):
    assert code_of(partial(synth.synthesize, whitelisted_spec(field, f'a{char}b'))) == 'PT-RULE-INPUT'


@pytest.mark.parametrize('value', ['kernel32.dll', 'api-ms-win-core-file-l1-1-0.dll', 'A_b+c~d.sys'], ids=['k', 'api', 'sym'])
def test_ordinary_dll_names_pass(value):
    assert_engine_clean(synth.synthesize(spec([imported(value, 'CreateFileW')])))


@pytest.mark.parametrize('name', ['CreateFileW', '?Foo@@YAXXZ', '_imp_x', 'a.b', 'Nt$x'], ids=['w', 'mangled', 'imp', 'dot', 'dollar'])
def test_ordinary_symbol_names_pass(name):
    text = synth.synthesize(spec([imported('a.dll', name)]))
    assert_engine_clean(text)
    assert synth.parse_rule(text).imports[0].name == name


@pytest.mark.parametrize('pattern', [
    '48 8B\n', '48 8B\n90', '48  8B', ' 48 8B', '48 8B ', '48 8b', '4', '48 8B 9', '48 [1-2] 8B', '( 48 | 49 ) 8B',
    '~48 8B', '48 8B ?', '48 8B ???', '\uff14\uff18 8B', '48\t8B', '', '48 8B }', '{ 48 8B', '48 8B /* x */', '48 ?1 8B', '??? 48',
    '48 8B\r', '48 8B\x00',
], ids=[f'x{i:02d}' for i in range(23)])
def test_malformed_hex_patterns_are_rejected_even_when_validation_is_bypassed(pattern):
    forged = bytes_feature().model_construct(**{**bytes_feature().__dict__, 'pattern': pattern})
    assert code_of(lambda: synth.synthesize(spec([forged]))) == 'PT-RULE-INPUT'
    with pytest.raises(ValidationError):  # the strict model refuses the same value on its own
        bytes_feature().model_validate({**bytes_feature().model_dump(), 'pattern': pattern})


def test_hex_pattern_limits():
    tokens = ' '.join(['90'] * (LIMITS.hex_pattern_bytes + 1))
    forged = bytes_feature().model_copy(update={'pattern': tokens, 'length': LIMITS.hex_pattern_bytes + 1})
    assert code_of(lambda: synth.synthesize(spec([forged]))) == 'PT-RULE-LIMIT'
    assert code_of(lambda: synth.synthesize(spec([bytes_feature(), bytes_feature('90 ' * 15 + '91')]))) == 'PT-RULE-LIMIT'


@pytest.mark.parametrize('raw', [h.encode('utf-8', 'surrogatepass')[:LIMITS.text_pattern_bytes] for h in HOSTILE if h],
                         ids=HOSTILE_IDS[:len([h for h in HOSTILE if h])])
@pytest.mark.parametrize('encoding', ['ascii', 'wide', 'ascii-wide'])
def test_hostile_bytes_become_inert_text_patterns(raw, encoding):
    # padded: the engine rejects one-byte patterns as slow, which is a gate of the compose step, not of synthesis
    raw = b'Be' + raw + b'ep'
    base = synth.synthesize(spec([string_feature(b'Beep', encoding)]))
    text = synth.synthesize(spec([string_feature(raw, encoding)]))
    assert text.isascii()
    assert skeleton(text) == skeleton(base)
    assert synth.parse_rule(text).texts[0].value == raw
    assert_engine_clean(text)


def reference_decode(escaped: str) -> bytes | None:
    """Independent reading of the accepted escape grammar."""
    out, index = bytearray(), 0
    simple = {'\\': 92, '"': 34, 'n': 10, 'r': 13, 't': 9, '0': 0}
    while index < len(escaped):
        ch = escaped[index]
        if ch != '\\':
            if not 32 <= ord(ch) <= 126:
                return None
            out.append(ord(ch))
            index += 1
        elif escaped[index + 1:index + 2] in simple and escaped[index + 1:index + 2]:
            out.append(simple[escaped[index + 1]])
            index += 2
        elif escaped[index + 1:index + 2] == 'x' and re.fullmatch(r'[0-9a-fA-F]{2}', escaped[index + 2:index + 4]):
            out.append(int(escaped[index + 2:index + 4], 16))
            index += 4
        else:
            return None
    return bytes(out)


@pytest.mark.parametrize('escaped', [h for h in HOSTILE if h], ids=HOSTILE_IDS[:len([h for h in HOSTILE if h])])
def test_raw_hostile_text_either_decodes_inertly_or_is_rejected(escaped):
    escaped = 'Be' + escaped + 'ep'
    base = synth.synthesize(spec([string_feature(b'Beep')]))
    expected = reference_decode(escaped)
    if expected is None:
        error = code_of(lambda: synth.synthesize(spec([string_feature(text=escaped, length=len(escaped))])))
        assert error == 'PT-RULE-INPUT'
        return
    text = synth.synthesize(spec([string_feature(text=escaped, length=len(expected))]))
    assert skeleton(text) == skeleton(base) and text.isascii()
    assert synth.parse_rule(text).texts[0].value == expected
    assert_engine_clean(text)


@pytest.mark.parametrize('escaped', ['\\q', '\\x4', '\\x', 'abc\\', '\\x4g', '\u00e9', '\n', 'a\nb', '\\u0041', '\\101', '\x00',
                                     '\\X41', 'a\x7f', '\u202e'], ids=[f'e{i:02d}' for i in range(14)])
def test_bad_escapes_are_rejected(escaped):
    assert code_of(lambda: synth.synthesize(spec([string_feature(text=escaped, length=3)]))) == 'PT-RULE-INPUT'


def test_text_length_must_match_the_decoded_bytes():
    assert code_of(lambda: synth.synthesize(spec([string_feature(b'Beep', length=5)]))) == 'PT-RULE-INPUT'
    assert synth.synthesize(spec([string_feature(text='B\\x65ep', length=4)])) == synth.synthesize(spec([string_feature(b'Beep')]))


def test_pattern_count_caps():
    many = [string_feature(bytes([65 + i]) * 3 + b'z') for i in range(LIMITS.text_patterns_v1 + 1)]
    assert code_of(lambda: synth.synthesize(spec(many))) == 'PT-RULE-LIMIT'
    assert len(synth.parse_rule(synth.synthesize(spec(many[:-1]))).texts) == LIMITS.text_patterns_v1


def test_pin_offsets_must_lie_on_masked_bytes():
    for bad in (pin(disp=13, end=18), pin(disp=15, end=18), pin(disp=14, end=17), pin(disp=22, end=24)):
        assert code_of(partial(synth.synthesize, spec([bytes_feature(pins=(bad,))]))) == 'PT-RULE-INPUT'
    forged = bytes_feature().model_copy(update={'pins': (pin(),) * (LIMITS.call_pins + 1)})
    assert code_of(lambda: synth.synthesize(spec([forged]))) == 'PT-RULE-LIMIT'


def test_features_of_the_other_side_are_rejected():
    assert code_of(lambda: synth.synthesize(spec([bytes_feature(side='newer')]))) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([string_feature(side='newer')]))) == 'PT-RULE-INPUT'


class _EvilStr(str):
    def replace(self, *args):
        return '" and true or "'

    def __iter__(self):
        return iter('"')


def test_str_subclasses_and_non_exact_numbers_are_rejected():
    evil_import = imported().model_copy(update={'dll': _EvilStr('a.dll')})
    assert code_of(lambda: synth.synthesize(spec([evil_import]))) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], version=True))) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], version=0))) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], version=LIMITS.versions_per_lineage + 1))) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], direction='older; evil'))) == 'PT-RULE-INPUT'
    forged = synth.RuleSpec(pair(), 'older', LINEAGE.upper(), 1, (bytes_feature(),))
    assert code_of(lambda: synth.synthesize(forged)) == 'PT-RULE-INPUT'
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], analyst_label=_EvilStr('x')))) == 'PT-RULE-INPUT'
    project = pair().model_copy(update={'project_id': _EvilStr('x')})
    assert code_of(lambda: synth.synthesize(spec([bytes_feature()], source=project))) == 'PT-RULE-INPUT'


def test_error_messages_never_echo_the_input():
    secret = 'SECRET-DLL"; evil'
    with pytest.raises(RulesError) as caught:
        synth.synthesize(spec([imported(secret, 'X')]))
    assert 'SECRET' not in str(caught.value)


# ---- strict parser ------------------------------------------------------------------------------------------------

FULL = synth.synthesize(GOLDEN_SPECS['full']())
MUTATIONS = {
    'crlf': lambda t: t.replace('\n', '\r\n'),
    'no-final-newline': lambda t: t[:-1],
    'blank-at-end': lambda t: t + '\n',
    'header-comment': lambda t: '// x\n' + t,
    'extra-clause': lambda t: t.replace('    pe.is_pe and\n', '    pe.is_pe and\n    true and\n'),
    'or-clause': lambda t: t.replace('pe.is_pe and', 'pe.is_pe or'),
    'tail-or': lambda t: t.replace('}\n', '').rstrip('\n') + ' or true\n}\n',
    'second-rule': lambda t: t + '\nrule x {\n  condition:\n    true\n}\n',
    'unknown-meta': lambda t: t.replace('    statement', '    zzz       = "x"\n    statement', 1),
    'tab': lambda t: t.replace('    $b', '\t$b', 1),
    'lower-hex': lambda t: t.replace('FF 15', 'ff 15'),
    'jump': lambda t: t.replace(' ?? ', ' [1-4] ', 1),
    'text-id': lambda t: t.replace('$t0', '$t1', 1),
    'side-tag': lambda t: t.replace('older_side', 'newer_side'),
    'import-math': lambda t: t.replace('import "pe"', 'import "math"'),
    'quote-break': lambda t: t.replace('"Older build only"', '"Older" build only"'),
    'nul': lambda t: t.replace('Older build', 'Older\x00build'),
    'non-ascii': lambda t: t.replace('Older build', 'Older \u202e build'),
    'int-as-string': lambda t: re.sub(r'(patchtrace_version +)= 3', r'\1= "3"', t),
    'dll-space': lambda t: t.replace('"ntdll.dll"', '"nt dll.dll"'),
    'no-condition': lambda t: t[:t.index('  condition:')] + '}\n',
    'garbage': lambda t: 'rule x { condition: true }\n',
    'empty': lambda t: '',
    'not-str': lambda t: t.encode(),
}


@pytest.mark.parametrize('name', sorted(MUTATIONS), ids=sorted(MUTATIONS))
def test_parser_rejects_anything_outside_the_grammar(name):
    mutated = MUTATIONS[name](FULL)
    assert mutated != FULL
    assert code_of(lambda: synth.parse_rule(mutated)) == 'PT-RULE-INPUT'


def test_parser_round_trips_every_golden():
    for make in GOLDEN_SPECS.values():
        text = synth.synthesize(make())
        parsed = synth.parse_rule(text)
        assert synth.render_rule(parsed) == text
        assert parsed == synth.build_rule(make())


def test_parser_applies_the_whitelists_to_grammar_shaped_text():
    forged = FULL.replace('"ntdll.dll"', '"nt dll"')
    assert code_of(lambda: synth.parse_rule(forged)) == 'PT-RULE-INPUT'


# ---- determinism and properties -----------------------------------------------------------------------------------

def test_feature_order_does_not_change_the_rule():
    features = list(GOLDEN_SPECS['full']().features)
    reference = synth.synthesize(GOLDEN_SPECS['full']())
    for rotation in range(len(features)):
        rotated = features[rotation:] + features[:rotation]
        assert synth.synthesize(synth.RuleSpec(**{**GOLDEN_SPECS['full']().__dict__, 'features': tuple(rotated)})) == reference
    assert synth.synthesize(synth.RuleSpec(**{**GOLDEN_SPECS['full']().__dict__, 'features': tuple(reversed(features))})) == reference


def test_synthesis_is_deterministic_and_lf_only():
    assert synth.synthesize(GOLDEN_SPECS['full']()) == FULL
    assert '\r' not in FULL and not re.search(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', FULL)  # no timestamps in the hashed body


def test_the_synth_module_is_pure():
    result = __import__('subprocess').run(
        [sys.executable, '-c', 'import sys, patchtrace.yarax.synth; sys.exit(any(m.startswith(("yara_x", "PySide6")) '
                               'for m in sys.modules))'], check=False)
    assert result.returncode == 0


token = st.sampled_from(['00', '48', '8B', 'FF', '15', 'E8', 'C3', '90', 'CC'])
imports_strategy = st.builds(
    imported, st.sampled_from(['KERNEL32.dll', 'ntdll.dll', 'api-ms-win-core-x.dll']),
    st.sampled_from(['CreateFileW', 'Nt$X', '?f@@YAXXZ', 'a.b']), st.none(), st.booleans())


@st.composite
def hex_features(draw):
    head = draw(st.lists(st.sampled_from([f'{v:02X}' for v in range(0x20, 0xE0, 7)]), min_size=6, max_size=6))
    middle = draw(st.lists(st.one_of(token, st.just('??')), min_size=4, max_size=20))
    pins = ()
    if draw(st.booleans()):
        disp = len(head) + len(middle) + 2
        middle += ['FF', '15', '??', '??', '??', '??']
        pins = (pin(draw(st.sampled_from(['KERNEL32.dll', 'ntdll.dll'])), draw(st.sampled_from(['A1', 'B_2', 'Nt$'])),
                    disp, disp + 4),)
    tail = draw(st.lists(st.sampled_from([f'{v:02X}' for v in range(0x21, 0xE0, 11)]), min_size=6, max_size=6))
    return bytes_feature(' '.join(head + middle + tail), pins=pins)


texts = st.binary(min_size=4, max_size=40).filter(lambda raw: len(set(raw)) >= 3)


@SLOW
@given(hex_features(), st.lists(st.tuples(texts, st.sampled_from(['ascii', 'wide', 'ascii-wide'])), max_size=4, unique=True),
       st.lists(imports_strategy, max_size=4), st.permutations(range(10)), st.sampled_from(['older', 'newer']))
def test_any_feature_set_serialises_compiles_and_is_order_free(hexf, text_items, imports_, order, direction):
    side = direction
    features = [hexf.model_copy(update={'side': side})] + [string_feature(raw, enc, side) for raw, enc in text_items]
    features += imports_
    reference = synth.synthesize(spec(features, direction))
    assert_engine_clean(reference)
    shuffled = sorted(features, key=lambda feature: order[features.index(feature) % 10])
    assert synth.synthesize(spec(shuffled, direction)) == reference
    assert synth.render_rule(synth.parse_rule(reference)) == reference
