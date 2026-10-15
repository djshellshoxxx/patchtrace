"""R1 closed-grammar synthesis (docs/specs/program-e/YRX-integration-plan.md s6, s7, s9). Synthetic data only.

Gates of R1: hostile strings of every kind never leave the grammar (a lexical oracle that does not trust the engine, then
the real YARA-X as parser, linter, formatter and scanner), every shape compiles under R2's policy with no warning, the
text is a fixed point of `yara_x.Formatter`, and the goldens in tests/fixtures/rules/golden match byte for byte.

The pure tests run without the engine. The engine tests need the `rules` extra: locally a missing engine skips them with
a reason; in CI the extra is installed and test_rules_worker.py::test_engine_extra_is_installed_in_the_qa_matrix fails
instead, so a matrix cannot pass hollow. After an intended grammar change rewrite the goldens with
`PYTHONPATH=src python tests/test_rules_synth.py` and review the diff.
"""
from __future__ import annotations

import ast
import hashlib
import itertools
import re
import struct
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_builder import CODE, DATA, RDATA, PeSpec, SectionSpec, build_pe_ex
from pydantic import TypeAdapter

from patchtrace.rules import contracts as c
from patchtrace.rules import synth
from patchtrace.rules.errors import RuleError
from patchtrace.rules.limits import DEFAULT_LIMITS

try:
    import yara_x

    from patchtrace.rules import engine
except ImportError:
    yara_x = engine = None
needs_engine = pytest.mark.skipif(engine is None, reason='YARA-X (pip install "patchtrace[rules]") is not installed')

GOLDEN = Path(__file__).resolve().parent / 'fixtures' / 'rules' / 'golden'
FAST = dict(max_examples=200, deadline=None, database=None)
SLOW = dict(max_examples=100, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])

# --- synthetic inputs ---------------------------------------------------------------------------------------------------
SHA_A, SHA_B = 'a' * 64, 'b' * 64
LINEAGE = '0123456789ab' + 'c' * 52
# The plan's `term` function (24 bytes, one masked RIP displacement) and a 31-byte function with two masked calls.
TERM = '48 83 EC 28 31 C9 BA 01 00 00 00 90 48 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3'
TWO = '48 83 EC 28 31 C9 BA 01 00 00 00 48 FF 15 ?? ?? ?? ?? 90 48 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3'
PIN = c.CallPin(disp_offset=15, end_offset=19, dll='KERNEL32.dll', name='TerminateProcess')
PIN_A = c.CallPin(disp_offset=14, end_offset=18, dll='KERNEL32.dll', name='TerminateProcess')
PIN_B = c.CallPin(disp_offset=22, end_offset=26, dll='KERNEL32.dll', name='CloseHandle')


def pair(category: str = 'removed', **changes) -> c.PairSource:
    older = c.FunctionRef(rva=0x104d, size=24, extent='pdata')
    newer = c.FunctionRef(rva=0x108d, size=31, extent='pdata')
    parts = {'removed': (older, None), 'added': (None, newer), 'modified': (older, newer)}[category]
    fields = dict(project_id='project-1', revision=3, run_id='run-1', older_sha256=SHA_A, newer_sha256=SHA_B,
                  match_id='match-1', category=category, review='accepted', materiality='material',
                  analyst_confirmed_material=False, older=parts[0], newer=parts[1])
    return c.PairSource(**(fields | changes))


def window(pattern: str = TERM, side: str = 'older', pins: tuple = (PIN,), included: bool = True) -> c.BytesFeature:
    length, literal, longest = c.pattern_metrics(pattern)
    return c.BytesFeature(included=included, side=side, window_rva=0x104d, length=length, pattern=pattern,
                          literal=literal, longest_run=longest, mask=('rip-disp',), mask_source='iced-x86', pins=pins,
                          source_hits=1, other_hits=0, separation=f'{side}-only')


def text(data: bytes, encoding: str = 'ascii', side: str = 'older', included: bool = True) -> c.StringFeature:
    return c.StringFeature(included=included, side=side, value_sha256=hashlib.sha256(data).hexdigest(), length=len(data),
                           text=synth.escape_bytes(data), encoding=encoding, offset=0x2210, evidence_run_id='tool-run-1',
                           linked_by='file-level', separation=f'{side}-only')


def imported(dll: str = 'KERNEL32.dll', name: str | None = 'TerminateProcess', ordinal: int | None = None,
             delay: bool = False, side: str = 'older', included: bool = True) -> c.ImportFeature:
    return c.ImportFeature(included=included, dll=dll, name=None if ordinal else name, ordinal=ordinal, delay=delay,
                           origin='pe-imports', separation=f'{side}-only')


def capability(rule_id: str = 'terminate process', gates: tuple = (), side: str = 'older', included: bool = True):
    kind = 'removed-with-code' if side == 'older' else 'newly-introduced'
    return c.CapabilityFeature(included=included, rule_id=rule_id, classification=kind, separation=f'{side}-only',
                               api_gates=tuple(c.ApiRef(dll=d, name=n) for d, n in sorted(gates)))


def copy(model, **updates):
    """A copy that skips validation: how the tests stand in for a corrupted row or a contract that let a value through."""
    return model.model_copy(update=updates)


def render(*features, direction: str = 'older', category: str | None = None, version: int = 1, **kw) -> str:
    category = category or ('removed' if direction == 'older' else 'added')
    return synth.render_rule(kw.pop('source', None) or pair(category), lineage_id=LINEAGE, direction=direction,
                             version=version, features=features, **kw)


# --- lexical oracle (does not trust the engine) ---------------------------------------------------------------------------
LITERAL = re.compile(r'"(?:[ !#-\[\]-~]|\\(?:["\\nrt]|x[0-9a-f]{2}))*"')


def skeleton(rule_text: str) -> str:
    """The rule with every string literal blanked. A quote that does not open a closed-alphabet literal, a character outside
    printable ASCII and LF, or a literal that would run over a line end fails the test: whatever a value contains, the
    rest of the text is then the template."""
    out, i = [], 0
    while i < len(rule_text):
        char = rule_text[i]
        if char == '"':
            literal = LITERAL.match(rule_text, i)
            assert literal, f'a quote opens something that is not a closed literal at offset {i}'
            out.append('""')
            i = literal.end()
        else:
            assert char == '\n' or ' ' <= char <= '~', f'{char!r} is outside printable ASCII and LF'
            out.append(char)
            i += 1
    return ''.join(out)


def literal_bytes(literal: str) -> bytes:
    """Reference decoder of one closed literal (Python's own escape rules agree with YARA's on this alphabet)."""
    assert LITERAL.fullmatch(literal)
    return bytes(ord(char) for char in literal[1:-1].encode('ascii').decode('unicode_escape'))


def lossy(value: str) -> str:
    """What descriptive text becomes: a character outside ASCII is a question mark."""
    return ''.join(char if ord(char) < 128 else '?' for char in value)


BIDI = ''.join(map(chr, (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F)))
ATOMS = ('"', '\\', '\\"', '\\\\', '\x00', '\n', '\r', '\r\n', '\t', '\x0b\x0c\x1b', '\x7f', '\x80\x9f', '*/', '/*',
         '//', '}', '{', ' } rule evil { condition: true } ', 'condition:', 'meta:', 'strings:', 'import "pe"',
         'include "x"', 'rule ', '$b', '#b', '@b[1]', 'true', 'and', '\\x', '\\x4', '\\x41', '\\n', '?', "'", '`', '%',
         ';', ' ', 'caf' + chr(0xe9), chr(0x65e5) + chr(0x672c), BIDI, chr(0x200b) + chr(0xfeff), chr(0x2028) + chr(0x2029),
         chr(0x1f600), chr(0xd800), chr(0xdfff))
HOSTILE = st.lists(st.one_of(st.sampled_from(ATOMS), st.text(max_size=6)), max_size=12).map(''.join)
HOSTILE_ASCII = HOSTILE.map(lambda s: ''.join(ch for ch in s if ord(ch) < 128))
HOSTILE_BYTES = st.lists(st.one_of(st.sampled_from([a.encode('utf-8', 'surrogatepass') for a in ATOMS]),
                                   st.binary(max_size=6)), min_size=1, max_size=24).map(b''.join).filter(bool)


# =================================================================================================================
# String literals: the only door for text
# =================================================================================================================

@pytest.mark.parametrize('data,expected', [
    (b'plain text', 'plain text'), (b'"', '\\"'), (b'\\', '\\\\'), (b'\n', '\\n'), (b'\r', '\\r'), (b'\t', '\\t'),
    (b'\x00', '\\x00'), (b'\x7f', '\\x7f'), (b'\x80\xff', '\\x80\\xff'), (b' ~', ' ~'), (b'*/ // /* } {', '*/ // /* } {'),
    (b'\x1b[0m', '\\x1b[0m'), (b'a\\"b', 'a\\\\\\"b')],
    ids=['plain', 'quote', 'backslash', 'lf', 'cr', 'tab', 'nul', 'del', 'high', 'edges', 'comment-marks', 'escape-char',
         'mixed'])
def test_escape_bytes_spells_each_byte_one_way(data, expected):
    assert synth.escape_bytes(data) == expected
    assert synth.unescape(expected) == data


@given(st.binary(min_size=1, max_size=DEFAULT_LIMITS.text_pattern_bytes))
@settings(**FAST)
def test_any_bytes_escape_into_the_closed_alphabet_and_back(data):
    escaped = synth.escape_bytes(data)
    assert LITERAL.fullmatch(f'"{escaped}"')
    assert literal_bytes(f'"{escaped}"') == data and synth.unescape(escaped) == data
    assert TypeAdapter(c.EscapedText).validate_python(escaped) == escaped and c.unescaped_length(escaped) == len(data)


@pytest.mark.parametrize('data,code', [
    (b'', 'PT-RULE-LIMIT'), (b'x' * (DEFAULT_LIMITS.text_pattern_bytes + 1), 'PT-RULE-LIMIT'),
    ('text', 'PT-RULE-INPUT'), (bytearray(b'ab'), 'PT-RULE-INPUT'), (None, 'PT-RULE-INPUT')],
    ids=['empty', 'too-long', 'str', 'bytearray', 'none'])
def test_escape_bytes_refuses_what_is_not_a_bounded_byte_string(data, code):
    with pytest.raises(RuleError) as caught:
        synth.escape_bytes(data)
    assert caught.value.code == code


def test_escape_bytes_accepts_the_longest_text_pattern():
    assert len(synth.escape_bytes(b'\x00' * DEFAULT_LIMITS.text_pattern_bytes)) == 4 * DEFAULT_LIMITS.text_pattern_bytes


@pytest.mark.parametrize('escaped', ['say "hi"', 'back\\', 'x\\q', 'x\\x4', 'x\\xzz', 'x\\0', 'x\\u0041', 'new\nline',
                                     'cr\r', 'tab\t', 'nul\x00', 'del\x7f', 'caf' + chr(0xe9), '', '\\\\"', '"'],
                         ids=['quote', 'backslash-end', 'unknown-escape', 'short-hex', 'bad-hex', 'octal', 'unicode',
                              'lf', 'cr', 'tab', 'nul', 'del', 'non-ascii', 'empty', 'quote-after-escape', 'lone-quote'])
def test_unescape_refuses_everything_outside_the_alphabet(escaped):
    with pytest.raises(RuleError) as caught:
        synth.unescape(escaped)
    assert caught.value.code == 'PT-RULE-INPUT'


def test_unescape_reads_either_hex_case_but_only_the_lower_case_spelling_is_canonical():
    assert synth.unescape('\\x7F') == synth.unescape('\\x7f') == b'\x7f'
    assert synth.escape_bytes(b'\x7f') == '\\x7f'


@given(st.text(max_size=DEFAULT_LIMITS.meta_string_chars))
@settings(**FAST)
def test_quote_always_yields_one_closed_literal_and_loses_only_non_ascii(value):
    literal = synth.quote(value)
    assert LITERAL.fullmatch(literal)
    assert literal_bytes(literal).decode('latin-1') == lossy(value)


@given(HOSTILE)
@settings(**FAST)
def test_quote_of_hostile_atoms_is_closed(value):
    assert LITERAL.fullmatch(synth.quote(value))
    assert literal_bytes(synth.quote(value)).decode('latin-1') == lossy(value)


@given(st.text(min_size=1, max_size=DEFAULT_LIMITS.meta_string_chars) | HOSTILE_ASCII.filter(bool))
@settings(**FAST)
def test_quote_exact_keeps_ascii_exactly_and_refuses_the_rest(value):
    if value.isascii():
        assert literal_bytes(synth.quote_exact(value)).decode('ascii') == value
    else:
        with pytest.raises(RuleError) as caught:
            synth.quote_exact(value)
        assert caught.value.reason == 'non-ascii'


@pytest.mark.parametrize('call,value', [
    (synth.quote, 'x' * (DEFAULT_LIMITS.meta_string_chars + 1)), (synth.quote_exact, 'x' * 513),
    (synth.quote_exact, ''), (synth.quote, None), (synth.quote, b'bytes'), (synth.quote_exact, 12)],
    ids=['quote-long', 'exact-long', 'exact-empty', 'none', 'bytes', 'int'])
def test_literals_are_bounded_text(call, value):
    with pytest.raises(RuleError):
        call(value)


def test_the_longest_value_and_the_empty_description_are_accepted():
    assert synth.quote('x' * DEFAULT_LIMITS.meta_string_chars) and synth.quote('') == '""'


MARK = 'SECRET-MARK-7f3a'


@pytest.mark.parametrize('call', [
    lambda: synth.quote_exact(MARK + chr(0xe9)), lambda: synth.quote(MARK * 100), lambda: synth.unescape(MARK + '"'),
    lambda: synth.comment_line(MARK * 100), lambda: synth.with_header(MARK, ['x']),
    lambda: render(imported(MARK + '/' + chr(0xe9), 'x')), lambda: render(copy(window(), pattern=MARK)),
    lambda: synth.render_rule(pair(), lineage_id=MARK, direction='older', version=1, features=[window()]),
    lambda: synth.render_rule(pair(), lineage_id=LINEAGE, direction=MARK, version=1, features=[window()]),
    lambda: render(window(), label=MARK * 100)],
    ids=['exact', 'long', 'escape', 'comment', 'header', 'import', 'hex', 'lineage', 'direction', 'label'])
def test_a_refusal_never_echoes_the_value(call):
    with pytest.raises(RuleError) as caught:
        call()
    assert MARK not in str(caught.value) and MARK not in caught.value.message and caught.value.reason


# =================================================================================================================
# Comments: the export header
# =================================================================================================================

@given(st.text(max_size=DEFAULT_LIMITS.meta_string_chars) | HOSTILE)
@settings(**FAST)
def test_a_comment_line_is_one_printable_ascii_line_that_starts_with_slashes(value):
    line = synth.comment_line(value)
    assert line.startswith('//') and '\n' not in line and '\r' not in line
    assert all(' ' <= char <= '~' for char in line) and line == line.rstrip()
    assert line[3:] == lossy_comment(value).rstrip()


def lossy_comment(value: str) -> str:
    return ''.join(char if ' ' <= char <= '~' else '?' for char in value)


@pytest.mark.parametrize('value,expected', [
    ('', '//'), ('label "x" \\ y', '// label "x" \\ y'), ('a\nb', '// a?b'), ('a\r\nb', '// a??b'), ('end */', '// end */'),
    ('tab\there', '// tab?here'), ('trail   ', '// trail'), ('caf' + chr(0xe9), '// caf?'), ('rtl' + chr(0x202e), '// rtl?')],
    ids=['empty', 'quotes', 'lf', 'crlf', 'star-slash', 'tab', 'trailing', 'non-ascii', 'bidi'])
def test_comment_line_cases(value, expected):
    assert synth.comment_line(value) == expected


def test_comment_line_is_bounded():
    assert synth.comment_line('x' * DEFAULT_LIMITS.meta_string_chars)
    for bad, code in (('x' * (DEFAULT_LIMITS.meta_string_chars + 1), 'PT-RULE-LIMIT'), (None, 'PT-RULE-INPUT'),
                      (b'x', 'PT-RULE-INPUT')):
        with pytest.raises(RuleError) as caught:
            synth.comment_line(bad)
        assert caught.value.code == code


def test_with_header_puts_comment_lines_and_a_blank_line_above_the_rule():
    rule = render(window())
    out = synth.with_header(rule, ['one', 'two\nthree'])
    assert out == '// one\n// two?three\n\n' + rule
    assert synth.with_header(rule, []) == rule


@pytest.mark.parametrize('bad', ['rule x { condition: true }\n', '// header\nimport "pe"\n', '', None],
                         ids=['not-generated', 'already-headed', 'empty', 'none'])
def test_with_header_takes_only_generated_rules(bad):
    with pytest.raises(RuleError) as caught:
        synth.with_header(bad, ['x'])
    assert caught.value.reason == 'not-a-rule'


# =================================================================================================================
# The rule: layout, determinism, refusals
# =================================================================================================================

def everything() -> dict:
    """Every optional part at once: a modified pair seen from the newer build."""
    return dict(
        direction='newer', category='modified', version=2, label='Example label', cve=('CVE-2099-10002', 'CVE-2099-10001'),
        kb=('KB5099001',), cwe=('CWE-404',), include_names=True,
        features=(window(TWO, 'newer', (PIN_A, PIN_B)), text(b'Example one', 'ascii', 'newer'),
                  text(b'Ex\x00am\xffple', 'wide', 'newer'), imported(side='newer'),
                  imported(ordinal=12, side='newer'), imported('DELAY.dll', 'LoadIt', delay=True, side='newer'),
                  imported('DELAY.dll', ordinal=7, delay=True, side='newer'),
                  capability('write file', (('KERNEL32.dll', 'WriteFile'),), 'newer')))


def everything_source() -> c.PairSource:
    return pair('modified', older=c.FunctionRef(name='OldName', rva=0x104d, size=24, extent='pdata'),
                newer=c.FunctionRef(name='NewName', rva=0x108d, size=31, extent='pdata'))


def render_everything(**changes) -> str:
    spec = everything() | changes
    return synth.render_rule(everything_source(), lineage_id=LINEAGE, direction=spec['direction'],
                             version=spec['version'], features=spec['features'], label=spec['label'], cve=spec['cve'],
                             kb=spec['kb'], cwe=spec['cwe'], include_names=spec['include_names'])


@pytest.mark.parametrize('everything_rule', [False, True], ids=['plain', 'everything'])
def test_the_output_is_accepted_by_the_candidate_and_version_contracts(everything_rule):
    """R3 and R5 store this text in `RuleCandidate` and `RuleVersion`: their validators check name, hash and features."""
    spec = everything() if everything_rule else dict(direction='older', version=1, features=(window(), imported()))
    source = everything_source() if everything_rule else pair('removed')
    rule = render_everything() if everything_rule else render(*spec['features'])
    direction, stamp = spec['direction'], c.EngineStamp(version='1.21.0', version_source='pin')
    candidate = c.RuleCandidate(candidate_id='1' * 64, lineage_id=LINEAGE, direction=direction, source=source,
                                features=spec['features'], rule_name=c.rule_name_for(LINEAGE, direction), rule_text=rule,
                                rule_sha256=c.rule_text_sha256(rule), gates=(), engine=stamp, unvetted=False)
    version = c.RuleVersion(version_id='3' * 64, lineage_id=LINEAGE, version=spec['version'], candidate_id='1' * 64,
                            decision_id='2' * 64, rule_text=rule, rule_sha256=c.rule_text_sha256(rule), source=source,
                            engine=stamp, created_at='2099-03-01T00:00:00Z',
                            supersedes=None if spec['version'] == 1 else '4' * 64)
    assert candidate.rule_text == version.rule_text == rule


def test_rule_text_is_lf_printable_ascii_defines_its_rule_and_ends_with_a_newline():
    for rule in (render(window()), render(text(b'Example')), render(imported()), render_everything()):
        assert TypeAdapter(c.RuleText).validate_python(rule) == rule and rule.endswith('}\n')
        assert re.search(rf'(?m)^rule PT_{LINEAGE[:12]}_(older|newer): patchtrace (older|newer)_side \{{$', rule)


def test_direction_decides_name_tag_and_side():
    older, newer = render(window()), render_everything()
    assert 'rule PT_0123456789ab_older: patchtrace older_side {' in older and '"older"' in older
    assert 'rule PT_0123456789ab_newer: patchtrace newer_side {' in newer
    assert re.search(r'side\s+= "newer"', newer) and '"0123456789ab.v2"' in newer


def test_meta_keys_follow_the_plan_order_and_repeat_for_lists():
    rule = render_everything()
    keys = re.findall(r'(?m)^    (\w+) += ', rule.split('  strings:')[0])
    plan = ['patchtrace_rule_id', 'patchtrace_version', 'patchtrace_project_id', 'older_sha256', 'newer_sha256', 'side',
            'change', 'function_older', 'function_newer', 'cve', 'kb', 'cwe', 'capability', 'analyst_label', 'statement']
    assert [k for k, _ in itertools.groupby(keys)] == plan
    assert keys.count('cve') == 2 and keys.index('statement') == len(keys) - 1
    assert '"CVE-2099-10001"' in rule and rule.index('CVE-2099-10001') < rule.index('CVE-2099-10002')


def test_function_names_are_opt_in():
    quiet, named = render_everything(include_names=False), render_everything()
    assert 'OldName' not in quiet and 'NewName' not in quiet and '"0x104d"' in quiet and '"0x108d"' in quiet
    assert '"0x104d OldName"' in named and '"0x108d NewName"' in named
    spec = everything()   # names may come from symbol files: asking for nothing gives none
    default = synth.render_rule(everything_source(), lineage_id=LINEAGE, direction=spec['direction'], version=2,
                                features=spec['features'], label=spec['label'], cve=spec['cve'], kb=spec['kb'], cwe=spec['cwe'])
    assert default == quiet


def test_the_text_the_template_adds_carries_no_verdict_word():
    bare = render_everything(label=None).lower()
    for stem in ('vulnerab', 'exploit', 'safe', 'secure', 'fixed', 'verified', 'proven', 'probab'):
        assert stem not in bare


def test_the_executable_scope_the_pin_and_the_gates_appear_only_with_their_features():
    plain = render(imported())
    assert 'strings:' not in plain and '$b' not in plain and 'for any i' not in plain
    assert plain.count('pe.imports(') == 1 and 'pe.machine == pe.MACHINE_AMD64' in plain
    pinned = render(window())
    assert '$b in (s.raw_data_offset..' in pinned and pinned.count('for any i in (1..8): (') == 1
    unpinned = render(window(pins=()))
    assert '$b in (' in unpinned and 'for any i' not in unpinned and 'import_details' not in unpinned


def test_feature_order_and_duplicates_never_change_the_text():
    features = list(everything()['features'])
    base = render_everything()
    for order in itertools.islice(itertools.permutations(features), 0, None, 331):   # 122 of the 40,320 orders
        assert render_everything(features=order) == base
    twin = imported('kernel32.DLL', 'TerminateProcess', side='newer')   # the same gate, spelled differently
    assert render_everything(features=(*features, twin)) == base == render_everything(features=(twin, *features))
    assert render_everything(features=(*features, features[1], features[3])) == base


def test_only_included_features_shape_the_rule():
    kept = render(window(), imported())
    extra = (text(b'Other string', included=False), imported('USER32.dll', 'MessageBoxW', included=False),
             capability('unused', (('A.dll', 'F'),), included=False), window(TWO, pins=(), included=False))
    assert render(*extra, window(), imported()) == kept


def test_a_capability_adds_metadata_and_import_gates_never_a_condition_of_its_own():
    rule = render(window(), capability('terminate process', (('KERNEL32.dll', 'TerminateProcess'), ('A.dll', 'B'))))
    assert '"terminate process"' in rule and rule.count('pe.imports(') == 2
    assert render(window(), capability('terminate process')).count('pe.imports(') == 0


@pytest.mark.parametrize('features', [(), (capability(),), (capability('x', ()), text(b'Example', included=False)),
                                      (window(included=False),)],
                         ids=['none', 'capability-alone', 'nothing-included', 'only-excluded'])
def test_a_rule_needs_a_pattern_or_an_import_gate_besides_the_pe_gate(features):
    with pytest.raises(RuleError) as caught:
        render(*features)
    assert caught.value.reason == 'no-discriminator'


LONG = 'D' * 500


def raw(**kw):
    return dict(lineage_id=LINEAGE, direction='older', version=1, features=(window(),)) | kw


@pytest.mark.parametrize('reason,call', [
    ('wrong-side', lambda: render(copy(window(), side='newer', separation='newer-only'))),
    ('wrong-side', lambda: render(window(), imported(side='newer'))),
    ('wrong-side', lambda: render(copy(window(), other_hits=2, separation='both-sides'))),
    ('wrong-side', lambda: render(text(b'Other string', side='newer'))),
    ('wrong-side', lambda: render(window(), capability(side='newer'))),
    ('too-many-patterns', lambda: render(window(), copy(window(TWO, pins=()), window_rva=1))),
    ('too-many-patterns', lambda: render(*(text(b'string %d' % n) for n in range(5)))),
    ('too-many-features', lambda: render(*(text(b'string %d' % n, included=False) for n in range(65)))),
    ('bad-feature', lambda: render('text', window())),
    ('bad-feature', lambda: render(None)),
    ('bad-direction', lambda: synth.render_rule(pair(), **raw(direction='both'))),
    ('bad-direction', lambda: synth.render_rule(pair(), **raw(direction=['older']))),
    ('bad-direction', lambda: synth.render_rule(pair(), **raw(direction='OLDER'))),
    ('no-function', lambda: synth.render_rule(pair('added'), **raw())),
    ('no-function', lambda: synth.render_rule(pair('removed'), **raw(direction='newer'))),
    ('bad-lineage', lambda: synth.render_rule(pair(), **raw(lineage_id='g' * 64))),
    ('bad-lineage', lambda: synth.render_rule(pair(), **raw(lineage_id=LINEAGE.upper()))),
    ('bad-lineage', lambda: synth.render_rule(pair(), **raw(lineage_id=LINEAGE[:-1]))),
    ('bad-lineage', lambda: synth.render_rule(pair(), **raw(lineage_id=LINEAGE + '\n'))),
    ('bad-lineage', lambda: synth.render_rule(pair(), **raw(lineage_id='0123456789ab {} //' + 'c' * 46))),
    ('bad-lineage', lambda: synth.render_rule(pair(), **raw(lineage_id=None))),
    ('bad-number', lambda: synth.render_rule(pair(), **raw(version=0))),
    ('bad-number', lambda: synth.render_rule(pair(), **raw(version=DEFAULT_LIMITS.versions_per_lineage + 1))),
    ('bad-number', lambda: synth.render_rule(pair(), **raw(version=True))),
    ('bad-number', lambda: synth.render_rule(pair(), **raw(version=1.0))),
    ('bad-number', lambda: synth.render_rule(pair(), **raw(version='1'))),
    ('bad-label', lambda: render(window(), label='')),
    ('bad-label', lambda: render(window(), label='L' * (DEFAULT_LIMITS.label_chars + 1))),
    ('not-text', lambda: render(window(), label=b'bytes')),
    ('too-many-ids', lambda: render(window(), cve=[f'CVE-2099-{n:05d}' for n in range(17)])),
    ('too-many-ids', lambda: render(window(), kb=[f'KB{n:07d}' for n in range(17)])),
    ('not-a-list', lambda: render(window(), cve='CVE-2099-10001')),
    ('not-a-list', lambda: render(window(), cwe=b'CWE-404')),
    ('bad-hash', lambda: render(window(), source=copy(pair(), older_sha256='A' * 64))),
    ('bad-hash', lambda: render(window(), source=copy(pair(), newer_sha256='b' * 63 + '"'))),
    ('bad-change', lambda: render(window(), source=copy(pair(), category='deleted'))),
    ('bad-number', lambda: render(window(), source=copy(pair(), older=copy(pair().older, rva=2**32)))),
    ('bad-number', lambda: render(window(), source=copy(pair(), older=copy(pair().older, rva=-1)))),
    ('bad-hex', lambda: render(copy(window(), pattern=TERM.lower()))),
    ('bad-hex', lambda: render(copy(window(), pattern=TERM + ' [1-2] 48'))),
    ('bad-hex', lambda: render(copy(window(), pattern=TERM + '\n'))),
    ('bad-hex', lambda: render(copy(window(), pattern=TERM.replace('?? ', '4? ', 1)))),
    ('bad-hex', lambda: render(copy(window(), pattern=TERM + ' } rule evil { condition: true //'))),
    ('bad-hex', lambda: render(copy(window(), pattern=TERM.replace(' ', '  ', 1)))),
    ('bad-hex-length', lambda: render(copy(window(), pattern=' '.join(['48'] * 15), pins=()))),
    ('bad-hex-length', lambda: render(copy(window(), pattern=' '.join(['48'] * 513), pins=()))),
    ('text-not-canonical', lambda: render(copy(text(b'Example'), text='\\x45xample'))),
    ('text-not-canonical', lambda: render(copy(text(b'\x7f' * 4), text='\\x7F' * 4))),
    ('bad-escape', lambda: render(copy(text(b'Example'), text='say "x"'))),
    ('bad-escape', lambda: render(copy(text(b'Example'), text='trailing\\'))),
    ('bad-escape', lambda: render(copy(text(b'Example'), text='new\nline'))),
    ('bad-encoding', lambda: render(copy(text(b'Example'), encoding='utf8'))),
    ('bad-encoding', lambda: render(copy(text(b'Example'), encoding='ascii" wide nocase xor'))),
    ('bad-text-length', lambda: render(copy(text(b'Example'), text='x' * 257))),
    ('bad-import', lambda: render(copy(imported(), ordinal=3))),
    ('bad-import', lambda: render(copy(imported(), name=None))),
    ('bad-import', lambda: render(copy(imported(), delay=1))),
    ('bad-number', lambda: render(copy(imported(ordinal=5), ordinal=0))),
    ('bad-number', lambda: render(copy(imported(ordinal=5), ordinal=65536))),
    ('bad-number', lambda: render(copy(imported(ordinal=5), ordinal=True))),
    ('non-ascii', lambda: render(imported('KERNEL32' + chr(0xe9) + '.dll'))),
    ('non-ascii', lambda: render(copy(imported(), name='Terminate' + chr(0x202e)))),
    ('non-ascii', lambda: render(copy(window(), pins=(copy(PIN, name='Name' + chr(0x65e5)),)))),
    ('empty-value', lambda: render(copy(imported(), dll=''))),
    ('value-too-long', lambda: render(copy(imported(), name='N' * 513))),
    ('bad-number', lambda: render(copy(window(), pins=(copy(PIN, end_offset=25),)))),
    ('bad-number', lambda: render(copy(window(), pins=(copy(PIN, disp_offset=22, end_offset=26),)))),
    ('bad-number', lambda: render(copy(window(), pins=(copy(PIN, disp_offset=-1),)))),
    ('bad-number', lambda: render(copy(window(), pins=(copy(PIN, disp_offset=True),)))),
    ('too-many-pins', lambda: render(copy(window(), pins=(PIN,) * 5))),
    ('rule-too-long', lambda: render(*(copy(imported(), dll=f'{n}' + LONG, name=f'{n}' + LONG) for n in range(64)))),
    ('bad-text-length', lambda: synth.escape_bytes(b'')),
    ('bad-text-length', lambda: synth.unescape('a' * (4 * DEFAULT_LIMITS.text_pattern_bytes + 1))),
    ('bad-hex-length', lambda: render(copy(window(), pattern='zz'))),
    ('bad-hex-length', lambda: render(copy(window(), pattern='48 ' * 100_000))),
], ids=lambda value: value if isinstance(value, str) else '')
def test_refusals_name_their_reason(reason, call):
    with pytest.raises(RuleError) as caught:
        call()
    assert caught.value.reason == reason and caught.value.code in ('PT-RULE-INPUT', 'PT-RULE-LIMIT')


def test_synth_limits_stay_inside_the_contract_ceilings():
    assert synth.HEX_PATTERNS <= DEFAULT_LIMITS.hex_patterns_per_rule
    assert synth.TEXT_PATTERNS <= DEFAULT_LIMITS.text_patterns_per_rule
    assert synth.HEX_PATTERNS + synth.TEXT_PATTERNS <= DEFAULT_LIMITS.patterns_per_rule
    assert synth.ADVISORY_IDS == 16 and synth.CHECKED_MATCHES == 8


def test_the_statement_equals_the_one_the_contract_examples_use():
    import importlib.util
    spec = importlib.util.spec_from_file_location('generate_rules_schemas',
                                                  Path(__file__).resolve().parents[1] / 'tools' / 'generate_rules_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert synth.STATEMENT == module.STATEMENT


def test_synth_imports_only_the_standard_library_and_three_contract_modules():
    """Pure: no engine, decoder, Qt, network or file access, so the parent process and the GUI can build rule text."""
    tree = ast.parse(Path(synth.__file__).read_text(encoding='utf-8'))
    imported_names, called = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported_names.add(('.' * node.level) + (node.module or ''))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called.add(node.func.id)
    assert imported_names == {'__future__', 're', 'collections.abc', 'typing', '.contracts', '.errors', '.limits'}
    assert not called & {'open', 'eval', 'exec', 'compile', '__import__', 'input', 'print'}


# =================================================================================================================
# Golden shapes: also the shapes the engine tests compile
# =================================================================================================================

def populated(value: str, exact: str, blob: bytes) -> str:
    """A rule with every kind of value position filled: `value` where text is descriptive, `exact` (ASCII) where the engine
    compares names, `blob` as a text pattern. The shape never depends on the values."""
    base = pair('modified')
    source = copy(base, project_id=value, older=copy(base.older, name=value), newer=copy(base.newer, name=value))
    pins = (copy(PIN_A, dll=exact, name=exact), copy(PIN_B, dll=exact + '1', name=exact))
    features = (copy(window(TWO, 'newer', ()), pins=pins), text(blob, 'ascii-wide', 'newer'),
                copy(imported(side='newer'), dll=exact, name=exact), copy(imported(ordinal=12, side='newer'), dll=exact),
                copy(imported('D.dll', 'F', delay=True, side='newer'), dll=exact, name=exact),
                copy(imported('D.dll', ordinal=7, delay=True, side='newer'), dll=exact),
                copy(capability('c', (('D.dll', 'F'),), 'newer'), rule_id=value,
                     api_gates=(c.ApiRef.model_construct(dll=exact + 'z', name=exact),)))   # sorts after the others, always
    return synth.render_rule(source, lineage_id=LINEAGE, direction='newer', version=3, features=features,
                             label=value[:DEFAULT_LIMITS.label_chars] or 'x', cve=(value,), kb=(value,), cwe=(value,),
                             include_names=True)


HOSTILE_VALUE = 'a"b\\c\n}*/ import "x" condition: true // ' + chr(0x202e) + 'end\x00' + chr(0xe9)
BENIGN = ('Example value', 'Example', b'Example bytes')


def case_term_with_pin_and_import() -> str:
    """The plan's `term` rule: one masked call pinned to its import slot, and the import gate."""
    return render(window(), imported())


def case_two_pins_and_a_string() -> str:
    return synth.render_rule(pair('modified'), lineage_id=LINEAGE, direction='newer', version=2, label='Example label',
                             features=(window(TWO, 'newer', (PIN_A, PIN_B)), text(b'Example string', 'ascii', 'newer')),
                             cve=('CVE-2099-10001',), kb=('KB5099001',), cwe=('CWE-404',))


def case_strings_and_capabilities() -> str:
    return render(text(b'say "hello" \\ world', 'ascii'), text(b'Wide text', 'wide'),
                  text(b'Both \xe9\xff*/ }', 'ascii-wide'),
                  capability('terminate process', (('KERNEL32.dll', 'TerminateProcess'),)),
                  capability('create process', (('ADVAPI32.dll', 'CreateProcessAsUserW'), ('KERNEL32.dll', 'CreateProcessW'))))


def case_every_import_gate() -> str:
    added = c.FunctionRef(name='ExampleAdded', rva=0x108d, size=35, extent='pdata')
    return synth.render_rule(pair('added', newer=added), lineage_id=LINEAGE, direction='newer', version=1,
                             include_names=True,
                             features=(imported('KERNEL32.dll', 'WriteFile', side='newer'),
                                       imported('KERNEL32.dll', ordinal=12, side='newer'),
                                       imported('DELAY.dll', 'LoadIt', delay=True, side='newer'),
                                       imported('DELAY.dll', ordinal=7, delay=True, side='newer')))


def case_hostile_values() -> str:
    exact = ''.join(char for char in HOSTILE_VALUE if ord(char) < 128)
    return populated(HOSTILE_VALUE, exact, b'Hostile \x00"\\ bytes \xff')


def case_export_header() -> str:
    return synth.with_header(case_term_with_pin_and_import(), [
        'Example export header, line 1', 'Rule PT_0123456789ab_older version 1, label "Caf' + chr(0xe9) + '" \\ end',
        'A hostile line: ' + HOSTILE_VALUE.replace('\n', ' // ')])


CASES = {'older-removed-bytes-pin-import.yar': case_term_with_pin_and_import,
         'newer-modified-two-pins-string.yar': case_two_pins_and_a_string,
         'older-removed-strings-capabilities.yar': case_strings_and_capabilities,
         'newer-added-every-import-gate.yar': case_every_import_gate,
         'newer-modified-hostile-values.yar': case_hostile_values,
         'older-removed-export-header.yar': case_export_header}
CASE_IDS = ['term', 'pins', 'strings', 'gates', 'hostile', 'header']


# =================================================================================================================
# The engine as parser, linter and formatter
# =================================================================================================================

def read_back(rule_text: str) -> tuple:
    """What the engine itself makes of the text: (identifier, tags, [(meta key, value)], pattern identifiers, imports)."""
    compiler = yara_x.Compiler()
    compiler.add_source(rule_text)
    rules = compiler.build()
    (rule,) = list(rules)
    meta = [(key, value.decode('latin-1') if isinstance(value, bytes) else value) for key, value in rule.metadata]
    return rule.identifier, tuple(rule.tags), meta, [pattern.identifier for pattern in rule.patterns], tuple(rules.imports())


def fixed_point_clean(rule_text: str) -> None:
    """Compiles under R2's policy with no warning and no error, imports only `pe`, and is its own formatted text."""
    result = engine.lint('x', rule_text)
    assert result.ok and not result.errors and not result.warnings, (result.errors, result.warnings)
    assert result.imports == ('pe',) and result.formatter_stable
    assert engine.format_text(engine.format_text(rule_text)) == engine.format_text(rule_text)


@needs_engine
@pytest.mark.parametrize('name', list(CASES), ids=CASE_IDS)
def test_synth_is_formatter_fixed_point(name):   # a YARA-X bump that changes the layout fails here, in the bump PR
    fixed_point_clean(CASES[name]())


@needs_engine
def test_the_compile_policy_and_the_synthesis_agree_on_keys_name_and_tags():
    allowed = {key: required for key, _, required in engine.META}
    identifier, tags, meta, _, _ = read_back(render_everything())
    assert {key for key, _ in meta} == set(allowed)
    assert re.fullmatch(engine.RULE_NAME, identifier) and tags == ('patchtrace', 'newer_side')
    older_identifier, older_tags, older_meta, _, _ = read_back(render(window()))
    assert re.fullmatch(engine.RULE_NAME, older_identifier) and older_tags == ('patchtrace', 'older_side')
    assert set(tags) | set(older_tags) <= set(engine.TAGS)
    assert {key for key, _ in older_meta} == {key for key, required in allowed.items() if required} | {'function_older'}
    assert synth.STATEMENT in dict(older_meta).values()


@needs_engine
def test_the_engine_reads_back_exactly_the_values_that_went_in():
    _, tags, meta, patterns, imports = read_back(render_everything())
    assert meta == [
        ('patchtrace_rule_id', '0123456789ab.v2'), ('patchtrace_version', 2), ('patchtrace_project_id', 'project-1'),
        ('older_sha256', SHA_A), ('newer_sha256', SHA_B), ('side', 'newer'), ('change', 'modified'),
        ('function_older', '0x104d OldName'), ('function_newer', '0x108d NewName'), ('cve', 'CVE-2099-10001'),
        ('cve', 'CVE-2099-10002'), ('kb', 'KB5099001'), ('cwe', 'CWE-404'), ('capability', 'write file'),
        ('analyst_label', 'Example label'), ('statement', synth.STATEMENT)]
    assert patterns == ['$b', '$s1', '$s2'] and imports == ('pe',)


@needs_engine
def test_every_byte_value_survives_the_engine_alone_and_together():
    for data in (bytes(range(256)), *(bytes([value]) for value in range(256))):
        compiler = yara_x.Compiler()
        compiler.add_source(f'rule p {{ strings: $s = "{synth.escape_bytes(data)}" condition: $s }}')
        (rule,) = yara_x.Scanner(compiler.build()).scan(data).matching_rules
        (match,) = rule.patterns[0].matches
        assert (match.offset, match.length) == (0, len(data))


@needs_engine
def test_every_ascii_character_survives_a_meta_value():
    value = ''.join(map(chr, range(128)))
    compiler = yara_x.Compiler()
    compiler.add_source(f'rule m {{ meta: v = {synth.quote(value)} condition: true }}')
    ((_, got),) = list(list(compiler.build())[0].metadata)
    assert (got.decode('latin-1') if isinstance(got, bytes) else got) == value


def at_every_cap() -> str:
    """Values at their longest with every character four characters long in the source, patterns at their ceilings."""
    nuls = '\x00' * DEFAULT_LIMITS.meta_string_chars
    base = pair('modified')
    names = '\x00' * 256   # the longest FunctionRef name; the rule adds its RVA in front
    source = copy(base, project_id=nuls, older=copy(base.older, name=names), newer=copy(base.newer, name=names))
    tokens = [f'{(index * 37 + 11) % 256:02X}' for index in range(DEFAULT_LIMITS.hex_pattern_bytes)]
    starts = (20, 120, 220, 320)
    for start in starts:
        tokens[start:start + 4] = ['??'] * 4
    pins = tuple(c.CallPin.model_construct(disp_offset=start, end_offset=start + 4, dll=f'{n}' + nuls[1:], name=nuls)
                 for n, start in enumerate(starts))
    features = [copy(window(' '.join(tokens), 'newer', ()), pins=pins)]
    features += [text(bytes((index * 7 + shift) % 256 for index in range(DEFAULT_LIMITS.text_pattern_bytes)), mode, 'newer')
                 for shift, mode in enumerate(('ascii', 'wide', 'ascii-wide', 'ascii'), 1)]
    features += [copy(imported(side='newer'), dll=f'{n}' + nuls[:200], name=nuls[:200]) for n in range(8)]
    features += [copy(capability(side='newer'), rule_id=f'{n}' + nuls[:250]) for n in range(6)]
    ids = [tuple(f'{n:02d}' + '\x00' * 60 for n in range(synth.ADVISORY_IDS))] * 3
    return synth.render_rule(source, lineage_id=LINEAGE, direction='newer', version=DEFAULT_LIMITS.versions_per_lineage,
                             features=features, label='\x00' * DEFAULT_LIMITS.label_chars, cve=ids[0], kb=ids[1],
                             cwe=ids[2], include_names=True)


@needs_engine
def test_a_rule_with_every_value_at_its_cap_still_compiles_clean_and_is_a_fixed_point():
    rule = at_every_cap()
    assert DEFAULT_LIMITS.rule_text_bytes // 2 < len(rule) <= DEFAULT_LIMITS.rule_text_bytes
    fixed_point_clean(rule)
    _, _, meta, patterns, _ = read_back(rule)
    assert len(patterns) == 5 and len(meta) == 7 + 2 + 3 * synth.ADVISORY_IDS + 6 + 1 + 1


# --- every shape of the grammar, as a property ---------------------------------------------------------------------------
NAME = st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7e), min_size=1, max_size=12)


def named_pair(category: str) -> c.PairSource:
    older = None if category == 'added' else c.FunctionRef(name='OldName', rva=0x104d, size=24, extent='pdata')
    newer = None if category == 'removed' else c.FunctionRef(name='NewName', rva=0x108d, size=31, extent='pdata')
    return pair(category, older=older, newer=newer)


@st.composite
def feature_sets(draw):
    direction = draw(st.sampled_from(['older', 'newer']))
    category = draw(st.sampled_from(['modified', 'removed' if direction == 'older' else 'added']))
    features = []
    shape = draw(st.sampled_from([None, (TERM, ()), (TERM, (PIN,)), (TWO, ()), (TWO, (PIN_A,)), (TWO, (PIN_B,)),
                                  (TWO, (PIN_A, PIN_B))]))
    if shape:
        pins = tuple(copy(pin, dll=draw(NAME), name=draw(NAME)) for pin in shape[1])
        features.append(copy(window(shape[0], direction, ()), pins=pins))
    for blob in draw(st.lists(st.binary(min_size=4, max_size=40), max_size=4)):
        features.append(text(b'Pt3x' + blob, draw(st.sampled_from(['ascii', 'wide', 'ascii-wide'])), direction))
    for dll, name, ordinal, delay in draw(st.lists(st.tuples(NAME, NAME, st.none() | st.integers(1, 65535), st.booleans()),
                                                   max_size=4)):
        features.append(copy(imported(side=direction), dll=dll, name=None if ordinal else name, ordinal=ordinal,
                             delay=delay))
    if not features:
        features.append(imported(side=direction))   # a rule needs a discriminating clause; capabilities add metadata only
    for rule_id in draw(st.lists(HOSTILE.filter(bool), max_size=2)):
        features.append(copy(capability(side=direction), rule_id=rule_id))
    return direction, category, features


@needs_engine
@given(feature_sets(), st.integers(1, DEFAULT_LIMITS.versions_per_lineage), st.none() | HOSTILE.filter(bool), st.booleans(),
       st.randoms(use_true_random=False))
@settings(**SLOW)
def test_any_feature_set_serializes_compiles_clean_and_is_a_formatter_fixed_point(chosen, version, label, names, shuffler):
    direction, category, features = chosen
    label = label[:DEFAULT_LIMITS.label_chars] if label else None

    def build(order):
        return synth.render_rule(named_pair(category), lineage_id=LINEAGE, direction=direction, version=version,
                                 features=order, label=label, include_names=names)
    rule = build(features)
    fixed_point_clean(rule)
    shuffled = list(features)
    shuffler.shuffle(shuffled)
    assert build(shuffled) == rule
    identifier, _, meta, patterns, _ = read_back(rule)
    assert identifier == c.rule_name_for(LINEAGE, direction) and dict(meta)['patchtrace_version'] == version
    distinct_texts = {(f.text, f.encoding) for f in features if isinstance(f, c.StringFeature)}
    assert len(patterns) == len(distinct_texts) + any(isinstance(f, c.BytesFeature) for f in features)


# --- semantics against real PE images ------------------------------------------------------------------------------------
IMPORTS = {'KERNEL32.dll': ['TerminateProcess', 'CloseHandle', 'WriteFile', 12]}
NOPS = b'\x90' * 32
STRIDE = 31 + 8   # one copy of the two-call function and the NOPs between copies


def scan(rule_text: str, data: bytes) -> c.CellResult:
    """The cell the grid would show: policy compile (no warning allowed), one pass over `data`."""
    ruleset = engine.RuleSet.compile([c.WorkerRule(name='k', text=rule_text)])
    assert ruleset.lint[0].ok and not ruleset.lint[0].warnings, ruleset.lint[0]
    return ruleset.scan(data)[0]


def matches(rule_text: str, data: bytes) -> bool:
    """Plain compile and scan: the answer for data the facade would not even scan (not a PE image)."""
    compiler = yara_x.Compiler()
    compiler.add_source(rule_text)
    return bool(list(yara_x.Scanner(compiler.build()).scan(data).matching_rules))


def slot_rvas(data: bytes) -> dict[str, int]:
    imports = yara_x.Module('pe').invoke(data)['import_details']
    return {f['name']: f['rva'] for d in imports for f in d['functions']}


def two_calls(first: int, second: int) -> bytes:
    """The 31-byte function of TWO with chosen RIP displacements."""
    return (bytes.fromhex('4883EC2831C9BA01000000') + bytes.fromhex('48FF15') + (first % 2**32).to_bytes(4, 'little')
            + b'\x90' + bytes.fromhex('48FF15') + (second % 2**32).to_bytes(4, 'little') + bytes.fromhex('4883C428C3'))


def call_image(*functions: tuple[str, str], pad: int = 0) -> tuple[bytes, tuple[int, ...]]:
    """(image, RVAs of the functions): copy i has its two calls go through the import slots of `functions[i]`."""
    def build(displacements):
        code = b'\x90' * pad + (b'\x90' * 8).join(two_calls(*d) for d in displacements)
        spec = PeSpec(sections=[SectionSpec('.text', NOPS, CODE), SectionSpec('.code', code, CODE)], imports=IMPORTS)
        return build_pe_ex(spec)
    data, info = build([(0, 0)] * len(functions))
    slots, code_rva = slot_rvas(data), info['sections'][1][1]
    last = info['sections'][-1]
    assert slots['TerminateProcess'] == last[1] + info['first_thunk_off'] - last[3]   # the builder's layout agrees
    starts = tuple(code_rva + pad + i * STRIDE for i in range(len(functions)))
    shifts = [(slots[a] - (start + 18), slots[b] - (start + 26)) for (a, b), start in zip(functions, starts, strict=True)]
    return build(shifts)[0], starts


PINNED = render(window(TWO, pins=(PIN_A, PIN_B)))
LOOSE = render(window(TWO, pins=()))
RIGHT, WRONG = ('TerminateProcess', 'CloseHandle'), ('WriteFile', 'WriteFile')


@needs_engine
@pytest.mark.parametrize('functions,pad,hit', [
    ([RIGHT], 0, True), ([RIGHT], 37, True), ([('CloseHandle', 'TerminateProcess')], 0, False),
    ([('TerminateProcess', 'WriteFile')], 0, False), ([('WriteFile', 'CloseHandle')], 0, False), ([WRONG], 41, False),
    ([('TerminateProcess', 'TerminateProcess')], 0, False)],
    ids=['right', 'right-shifted', 'swapped', 'second-wrong', 'first-wrong', 'both-wrong', 'same-slot'])
def test_call_pins_tie_masked_calls_to_their_import_slots(functions, pad, hit):
    data, starts = call_image(*functions, pad=pad)
    loose, pinned = scan(LOOSE, data), scan(PINNED, data)
    assert loose.state == 'hit' and loose.rvas == starts   # masked bytes alone cannot tell where the calls go
    assert (pinned.state == 'hit') == hit and (pinned.rvas == starts if hit else pinned.rvas == ())


@needs_engine
def test_a_pin_takes_the_dll_name_without_regard_to_case_and_the_function_name_exactly():
    data, _ = call_image(RIGHT)
    assert scan(render(window(TWO, pins=(copy(PIN_A, dll='kernel32.DLL'), copy(PIN_B, dll='Kernel32.dll')))), data).state == 'hit'
    assert scan(render(window(TWO, pins=(copy(PIN_A, name='terminateprocess'), PIN_B))), data).state == 'no-hit'


@needs_engine
def test_every_pin_has_to_hold_for_the_same_match():
    data, _ = call_image(('TerminateProcess', 'WriteFile'), ('WriteFile', 'CloseHandle'))
    assert scan(LOOSE, data).hits == 2
    assert scan(PINNED, data).state == 'no-hit'   # pin 1 holds in copy 1 only, pin 2 in copy 2 only
    assert scan(PINNED, call_image(('TerminateProcess', 'WriteFile'), RIGHT)[0]).state == 'hit'


@needs_engine
def test_pins_look_at_the_first_matches_and_no_further():
    limit = synth.CHECKED_MATCHES
    assert scan(PINNED, call_image(*[WRONG] * (limit - 1), RIGHT)[0]).state == 'hit'
    assert scan(PINNED, call_image(*[WRONG] * limit, RIGHT)[0]).state == 'no-hit'


def delay_image(dll: str, functions: list) -> bytes:
    """A PE whose only imports are delay-load ones (the builder has no such table, so the descriptor is written here)."""
    rdata_rva = 0x2000
    blob = bytearray(64)

    def alloc(data: bytes, align: int = 2) -> int:
        while len(blob) % align:
            blob.append(0)
        blob.extend(data)
        return len(blob) - len(data)
    names, table = alloc(bytes(8 * (len(functions) + 1)), 8), alloc(bytes(8 * (len(functions) + 1)), 8)
    for index, function in enumerate(functions):
        value = function | 1 << 63 if isinstance(function, int) else rdata_rva + alloc(b'\0\0' + function.encode() + b'\0')
        struct.pack_into('<Q', blob, names + 8 * index, value)
        struct.pack_into('<Q', blob, table + 8 * index, value)
    library, handle = alloc(dll.encode() + b'\0', 1), alloc(bytes(8), 8)
    struct.pack_into('<8I', blob, 0, 1, rdata_rva + library, rdata_rva + handle, rdata_rva + table, rdata_rva + names, 0, 0, 0)
    spec = PeSpec(sections=[SectionSpec('.text', NOPS, CODE), SectionSpec('.rdata', bytes(blob), RDATA)],
                  extra_directories={13: (rdata_rva, 64)})
    data, info = build_pe_ex(spec)
    assert info['sections'][1][1] == rdata_rva
    return data


def plain_image() -> bytes:
    spec = PeSpec(sections=[SectionSpec('.text', NOPS, CODE)], imports={'KERNEL32.dll': ['TerminateProcess', 12]})
    return build_pe_ex(spec)[0]


@needs_engine
@pytest.mark.parametrize('feature,table,hit', [
    (imported(), 'plain', True), (imported('kernel32.DLL'), 'plain', True), (imported(name='CreateFileW'), 'plain', False),
    (imported(ordinal=12), 'plain', True), (imported(ordinal=13), 'plain', False), (imported(), 'delay', False),
    (imported('DELAY.dll', 'LoadIt', delay=True), 'delay', True), (imported('delay.DLL', 'LoadIt', delay=True), 'delay', True),
    (imported('DELAY.dll', 'Absent', delay=True), 'delay', False), (imported('DELAY.dll', ordinal=7, delay=True), 'delay', True),
    (imported('DELAY.dll', ordinal=8, delay=True), 'delay', False), (imported('DELAY.dll', 'LoadIt', delay=True), 'plain', False),
    (imported('KERNEL32.dll', 'TerminateProcess', delay=True), 'plain', False)],
    ids=['named', 'dll-case', 'absent', 'ordinal', 'other-ordinal', 'named-vs-delay', 'delay', 'delay-dll-case',
         'delay-absent', 'delay-ordinal', 'delay-other-ordinal', 'delay-vs-plain', 'delay-same-name'])
def test_import_gates_match_the_table_they_name_and_no_other(feature, table, hit):
    image = plain_image() if table == 'plain' else delay_image('DELAY.dll', ['LoadIt', 7])
    assert (scan(render(feature), image).state == 'hit') == hit


def widen(data: bytes) -> bytes:
    return b''.join(bytes([byte, 0]) for byte in data)


def rdata_image(data: bytes) -> bytes:
    sections = [SectionSpec('.text', NOPS, CODE), SectionSpec('.rdata', b'junk;' + data + b';junk', RDATA)]
    return build_pe_ex(PeSpec(sections=sections))[0]


@needs_engine
@pytest.mark.parametrize('payload,encoding,present,hit', [
    (b'say "hello" \\ world', 'ascii', b'say "hello" \\ world', True),
    (b'say "hello" \\ world', 'ascii', b'say hello world', False),
    (b'Wide text', 'wide', widen(b'Wide text'), True), (b'Wide text', 'wide', b'Wide text', False),
    (b'Both text', 'ascii-wide', b'Both text', True), (b'Both text', 'ascii-wide', widen(b'Both text'), True),
    (b'Both text', 'ascii', widen(b'Both text'), False), (b'Nul\x00and\xffhigh', 'ascii', b'Nul\x00and\xffhigh', True),
    (b'Nul\x00and\xffhigh', 'ascii', b'Nul\x00and\xfehigh', False),
    (b'ends in a slash \\', 'ascii', b'ends in a slash \\', True)],
    ids=['quotes', 'quotes-miss', 'wide', 'wide-miss', 'both-ascii', 'both-wide', 'ascii-vs-wide', 'nul-high',
         'nul-high-miss', 'slash'])
def test_text_patterns_match_exactly_their_bytes(payload, encoding, present, hit):
    assert (scan(render(text(payload, encoding)), rdata_image(present)).state == 'hit') == hit


@needs_engine
def test_the_pe_gate_the_machine_gate_and_the_executable_scope_all_have_to_hold():
    rule, code = render(window(pins=())), bytes.fromhex(TERM.replace('??', '00'))
    assert scan(rule, build_pe_ex(PeSpec(sections=[SectionSpec('.text', code, CODE)]))[0]).state == 'hit'
    assert scan(rule, build_pe_ex(PeSpec(sections=[SectionSpec('.data', code, DATA)]))[0]).state == 'no-hit'
    i386 = PeSpec(pe32plus=False, sections=[SectionSpec('.text', code, CODE)])
    assert scan(rule, build_pe_ex(i386)[0]).state == 'no-hit'
    assert not matches(rule, b'MZ' + bytes(62) + code) and not matches(rule, code)


@needs_engine
def test_the_executable_scope_is_any_executable_section_not_the_first():
    code = bytes.fromhex(TERM.replace('??', '00'))
    sections = [SectionSpec('.text', NOPS, CODE), SectionSpec('.data', code, DATA), SectionSpec('.code', code, CODE)]
    cell = scan(render(window(pins=())), build_pe_ex(PeSpec(sections=sections))[0])
    assert cell.state == 'hit' and cell.hits == 2   # the pattern is in the data section too; one in code is enough


# --- hostile values ----------------------------------------------------------------------------------------------------

@given(HOSTILE, HOSTILE_ASCII, HOSTILE_BYTES)
@settings(**FAST)
def test_hostile_values_cannot_change_the_template(value, exact, blob):
    hostile = populated(value, exact[:200] or 'x', blob[:256])
    assert skeleton(hostile) == skeleton(populated(*BENIGN))
    assert TypeAdapter(c.RuleText).validate_python(hostile) == hostile


NAMED_VALUES = [*ATOMS, HOSTILE_VALUE, '"' * 40, '\\' * 41, '\n' * 20, '\x00' * 25, '*/' * 30, '}' * 30]
NAMED_IDS = [f'atom{n}' for n in range(len(ATOMS))] + ['mixed', 'quotes', 'backslashes', 'newlines', 'nuls', 'comment-ends',
                                                       'braces']


@pytest.mark.parametrize('value', NAMED_VALUES, ids=NAMED_IDS)
def test_every_named_hostile_atom_stays_inside_its_literal(value):
    exact = ''.join(char for char in value if ord(char) < 128) or 'x'
    hostile = populated(value, exact, value.encode('utf-8', 'surrogatepass') or b'x')
    assert skeleton(hostile) == skeleton(populated(*BENIGN))


def expected_meta(value: str) -> list:
    label = value[:DEFAULT_LIMITS.label_chars] or 'x'

    def function(rva: int) -> str:
        return f'0x{rva:x}' + (' ' + lossy(value) if value else '')
    return [('patchtrace_rule_id', '0123456789ab.v3'), ('patchtrace_version', 3), ('patchtrace_project_id', lossy(value)),
            ('older_sha256', SHA_A), ('newer_sha256', SHA_B), ('side', 'newer'), ('change', 'modified'),
            ('function_older', function(0x104d)), ('function_newer', function(0x108d)),
            ('cve', lossy(value)), ('kb', lossy(value)), ('cwe', lossy(value)), ('capability', lossy(value)),
            ('analyst_label', lossy(label)), ('statement', synth.STATEMENT)]


@needs_engine
@given(HOSTILE, HOSTILE_ASCII, HOSTILE_BYTES)
@settings(**SLOW)
def test_hostile_values_compile_clean_and_the_engine_reads_back_the_template_and_the_values(value, exact, blob):
    rule = populated(value, exact[:200] or 'x', b'Pt3x' + blob[:240])
    fixed_point_clean(rule)
    identifier, tags, meta, patterns, imports = read_back(rule)
    benign = read_back(populated(*BENIGN))
    assert (identifier, tags, patterns, imports) == (benign[0], benign[1], benign[3], benign[4])
    assert meta == expected_meta(value)


@needs_engine
@pytest.mark.parametrize('value', NAMED_VALUES, ids=NAMED_IDS)
def test_every_named_hostile_atom_compiles_clean_and_reads_back(value):
    exact = ''.join(char for char in value if ord(char) < 128) or 'x'
    rule = populated(value, exact, b'Pt3x' + value.encode('utf-8', 'surrogatepass')[:200])
    fixed_point_clean(rule)
    assert read_back(rule)[2] == expected_meta(value)


@needs_engine
@given(HOSTILE_BYTES, st.sampled_from(['ascii', 'wide', 'ascii-wide']))
@settings(**SLOW)
def test_hostile_bytes_in_a_text_pattern_match_exactly_those_bytes(blob, encoding):
    payload = b'Pt3x' + blob[:240] + b'x3tP'
    rule = render(text(payload, encoding))
    broken = payload[:4] + bytes([payload[4] ^ 0xFF]) + payload[5:]
    for present, absent in {'ascii': [(payload, broken)], 'wide': [(widen(payload), widen(broken))],
                            'ascii-wide': [(payload, broken), (widen(payload), widen(broken))]}[encoding]:
        assert scan(rule, rdata_image(present)).state == 'hit'
        assert scan(rule, rdata_image(absent)).state == 'no-hit'


@needs_engine
@given(HOSTILE_BYTES)
@settings(**SLOW)
def test_the_engine_decodes_every_escaped_byte_string_to_the_bytes_that_went_in(blob):
    """Without the slow-pattern lint, so the edges of a pattern are hostile too: the whole haystack is the pattern."""
    data = blob[:256]
    compiler = yara_x.Compiler()
    compiler.add_source(f'rule p {{ strings: $s = "{synth.escape_bytes(data)}" condition: $s }}')
    (rule,) = yara_x.Scanner(compiler.build()).scan(data).matching_rules
    (match,) = rule.patterns[0].matches
    assert (match.offset, match.length) == (0, len(data))


@needs_engine
@given(st.lists(HOSTILE | st.text(max_size=40), min_size=1, max_size=6))
@settings(**FAST)
def test_header_lines_never_escape_their_comments(lines):
    rule = render(window(), imported())
    out = synth.with_header(rule, lines)
    head, _, rest = out.partition('\n\n')
    assert rest == rule and len(head.split('\n')) == len(lines) and all(line.startswith('//') for line in head.split('\n'))
    fixed_point_clean(out)


# --- goldens -------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('name', list(CASES), ids=CASE_IDS)
def test_goldens_match_byte_for_byte(name):
    expected = (GOLDEN / name).read_bytes()
    assert b'\r' not in expected, 'a golden has CRLF: `tests/fixtures/rules/** text eol=lf` and `*.yar text eol=lf` are missing'
    assert CASES[name]().encode('ascii') == expected


def test_the_golden_folder_holds_exactly_the_cases():
    assert sorted(path.name for path in GOLDEN.iterdir()) == sorted(CASES)


if __name__ == '__main__':   # PYTHONPATH=src python tests/test_rules_synth.py: rewrite the goldens, then review the diff
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for golden_name, build in CASES.items():
        (GOLDEN / golden_name).write_text(build(), encoding='utf-8', newline='\n')
