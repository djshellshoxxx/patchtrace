"""Closed-grammar YARA rule synthesis, `yrx-gen/1` (plan s6, s7). Pure: no Qt, no I/O, no `yara_x`.

Injection guard: rule text is rendered from a small typed tree (`ParsedRule`) and from nothing else. Every value that
reaches the tree is checked against a whitelist or escaped by one literal writer, and no input ever supplies a
keyword, operator, identifier or clause. `synthesize` then strictly re-parses its own output with a parser that only
accepts the lines the renderer can emit and fails unless the parsed tree equals the built one and re-renders to the
same bytes. The layout is the one `yara_x.Formatter` emits, so a formatter pass is a fixed point (pinned by the tests
against the engine).

Error messages name the offending field and never echo the input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .contracts import (
    BytesFeature,
    CapabilityFeature,
    Feature,
    ImportFeature,
    PairSource,
    Side,
    StringFeature,
)
from .errors import RulesError
from .limits import LIMITS

Scalar = str | int

# `re.fullmatch` everywhere: `$` would accept a trailing newline, and `\d` would accept non-ASCII digits.
_SHA = re.compile(r'[0-9a-f]{64}')
_DLL = re.compile(r'[A-Za-z0-9_.+~-]{1,255}')
_SYMBOL = re.compile(r'[A-Za-z0-9_@?$.]{1,255}')
_HEX_PATTERN = re.compile(r'(?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?))*')
_ANCHORS = {'cve': re.compile(r'CVE-[0-9]{4}-[0-9]{4,7}'), 'kb': re.compile(r'KB[0-9]{6,8}'),
            'cwe': re.compile(r'CWE-[0-9]{1,5}')}
# Accepted input form of a string feature's text: printable ASCII (a bare `"` included) plus a closed set of escapes.
_ESCAPED_TEXT = re.compile(r'(?:[ -\[\]-~]|\\[\\"nrt0]|\\x[0-9a-fA-F]{2})*')
_SIMPLE_ESCAPES = {'\\': 0x5C, '"': 0x22, 'n': 0x0A, 'r': 0x0D, 't': 0x09, '0': 0x00}
# What the renderer itself writes inside quotes: printable ASCII except `"` and `\`, which are escaped.
_LITERAL_BODY: Final = r'(?:[ !#-\[\]-~]|\\\\|\\")*'
_TEXT_BODY: Final = r'(?:[ !#-\[\]-~]|\\\\|\\"|\\x[0-9a-f]{2})*'

_META_KEYS: Final = frozenset({
    'patchtrace_rule_id', 'patchtrace_version', 'patchtrace_project_id', 'patchtrace_status', 'older_sha256',
    'newer_sha256', 'side', 'change', 'function_older', 'function_newer', 'function_older_name',
    'function_newer_name', 'cve', 'kb', 'cwe', 'capability', 'analyst_label', 'statement'})
_HEX_META: Final = frozenset({'function_older', 'function_newer'})
_INT_META: Final = _HEX_META | {'patchtrace_version'}
# Copy rules: a pattern in a file, never a claim about the file (plan s6).
_STATEMENTS: Final = {
    side: f'Pattern present in the {side} build and absent from the {other} build when analysed by PatchTrace. '
          'A match shows that a file contains the pattern and nothing else.'
    for side, other in (('older', 'newer'), ('newer', 'older'))}
_TEXT_MODIFIERS: Final = {'ascii': 'ascii', 'wide': 'wide', 'ascii-wide': 'ascii wide'}
_MODIFIER_ENCODINGS: Final = {value: key for key, value in _TEXT_MODIFIERS.items()}

_SECTION_CLAUSE: Final = ('for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and '
                          '$b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))')
_HEAD_CLAUSES: Final = ('uint16(0) == 0x5A4D', 'pe.is_pe', 'pe.machine == pe.MACHINE_AMD64')
# `{dll}`/`{name}` stand for quoted literals; the bounded range avoids `potentially_slow_loop` (plan s7).
_PIN_CLAUSE: Final = (
    'for any i in (1..8): (i <= #b and for any d in pe.import_details: (d.library_name iequals {dll} and '
    'for any f in d.functions: (f.name == {name} and pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] - '
    'pe.sections[pe.section_index(@b[i])].raw_data_offset + {end} + int32(@b[i] + {disp}) == f.rva)))')
_TEXT_CLAUSE: Final = 'all of ($t*)'
_IMPORT_CLAUSES: Final = {
    (False, 'name'): 'pe.imports({dll}, {name})',
    (False, 'ordinal'): 'pe.imports({dll}, {ordinal}) != 0',
    (True, 'name'): ('for any d in pe.delayed_import_details: (d.library_name iequals {dll} and '
                     'for any f in d.functions: (f.name == {name}))'),
    (True, 'ordinal'): ('for any d in pe.delayed_import_details: (d.library_name iequals {dll} and '
                        'for any f in d.functions: (f.ordinal == {ordinal}))'),
}
_API_CLAUSE: Final = 'for any d in pe.import_details: (for any f in d.functions: (f.name == {name}))'


def _bad(field: str) -> RulesError:
    return RulesError('PT-RULE-INPUT', f'{field} is not allowed in a generated rule')


@dataclass(frozen=True)
class PinIR:
    disp_offset: int
    end_offset: int
    dll: str
    name: str


@dataclass(frozen=True)
class HexIR:
    tokens: tuple[str, ...]
    pins: tuple[PinIR, ...] = ()


@dataclass(frozen=True)
class TextIR:
    value: bytes
    encoding: str  # ascii / wide / ascii-wide


@dataclass(frozen=True)
class ImportIR:
    dll: str
    name: str | None = None
    ordinal: int | None = None
    delay: bool = False


@dataclass(frozen=True)
class ParsedRule:
    """The whole grammar: everything the renderer may emit and the parser may accept."""
    name: str
    side: str
    meta: tuple[tuple[str, Scalar], ...]
    hex: HexIR | None = None
    texts: tuple[TextIR, ...] = ()
    imports: tuple[ImportIR, ...] = ()
    api_gates: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleSpec:
    """One candidate's inputs; only features with `included` set take part."""
    source: PairSource
    direction: Side
    lineage_id: str
    version: int
    features: tuple[Feature, ...]
    analyst_label: str = ''
    include_names: bool = False
    unvetted: bool = False
    cve: tuple[str, ...] = ()
    kb: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()


# ---- value checks -------------------------------------------------------------------------------------------------

def _exact_str(value: object, field: str) -> str:
    if type(value) is not str:  # no subclasses: they can override the methods the checks rely on
        raise _bad(field)
    return value


def _exact_int(value: object, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _bad(field)
    return value


def _whitelisted(value: object, pattern: re.Pattern[str], field: str) -> str:
    text = _exact_str(value, field)
    if not pattern.fullmatch(text):
        raise _bad(field)
    return text


def _closed(value: object, allowed: tuple[str, ...], field: str) -> str:
    if type(value) is not str or value not in allowed:
        raise _bad(field)
    return value


def _free_text(value: object, field: str) -> str:
    """Analyst or project text: printable ASCII only, anything else becomes `?` (never an escape or a newline)."""
    text = ''.join(ch if ' ' <= ch <= '~' else '?' for ch in _exact_str(value, field))
    if len(text) > LIMITS.meta_string_chars:
        raise RulesError('PT-RULE-LIMIT', f'{field} is too long')
    return text


def _unescape(body: str) -> str:
    return re.sub(r'\\(.)', lambda match: match[1], body)


def _decode_text(escaped: object, length: int) -> bytes:
    if type(escaped) is not str or not _ESCAPED_TEXT.fullmatch(escaped):
        raise _bad('string text')
    out = bytearray()
    index = 0
    while index < len(escaped):
        if escaped[index] != '\\':
            out.append(ord(escaped[index]))
            index += 1
        elif escaped[index + 1] == 'x':
            out.append(int(escaped[index + 2:index + 4], 16))
            index += 4
        else:
            out.append(_SIMPLE_ESCAPES[escaped[index + 1]])
            index += 2
    if not 1 <= len(out) <= LIMITS.text_pattern_bytes or len(out) != length:
        raise _bad('string length')
    return bytes(out)


# ---- building the tree from a spec --------------------------------------------------------------------------------

def _pin(pin: object, tokens: tuple[str, ...]) -> PinIR:
    disp = _exact_int(pin.disp_offset, 'pin offset', 0, len(tokens) - 4)
    end = _exact_int(pin.end_offset, 'pin offset', disp + 4, len(tokens))
    if any(token != '??' for token in tokens[disp:disp + 4]):
        raise _bad('pin displacement')  # a pin reads bytes the pattern must not fix
    return PinIR(disp, end, _whitelisted(pin.dll, _DLL, 'pin dll'), _whitelisted(pin.name, _SYMBOL, 'pin name'))


def _hex(feature: BytesFeature, direction: str) -> HexIR:
    if feature.side != direction:
        raise _bad('bytes side')
    tokens = tuple(_whitelisted(feature.pattern, _HEX_PATTERN, 'hex pattern').split(' '))
    if len(tokens) > LIMITS.hex_pattern_bytes or len(feature.pins) > LIMITS.call_pins:
        raise RulesError('PT-RULE-LIMIT', 'hex pattern or pin count is over its cap')
    pins = sorted({_pin(pin, tokens) for pin in feature.pins},
                  key=lambda p: (p.disp_offset, p.end_offset, p.dll.lower(), p.dll, p.name))
    return HexIR(tokens, tuple(pins))


def _text(feature: StringFeature, direction: str) -> TextIR:
    if feature.side != direction:
        raise _bad('string side')
    encoding = _closed(feature.encoding, tuple(_TEXT_MODIFIERS), 'string encoding')
    return TextIR(_decode_text(feature.text, feature.length), encoding)


def _import(feature: ImportFeature) -> ImportIR:
    dll = _whitelisted(feature.dll, _DLL, 'import dll')
    if type(feature.delay) is not bool:
        raise _bad('import delay')
    if feature.name is not None:
        return ImportIR(dll, name=_whitelisted(feature.name, _SYMBOL, 'import name'), delay=feature.delay)
    return ImportIR(dll, ordinal=_exact_int(feature.ordinal, 'import ordinal', 0, 0xFFFF), delay=feature.delay)


def _meta(spec: RuleSpec, capabilities: set[str]) -> tuple[tuple[str, Scalar], ...]:
    source = spec.source
    version = _exact_int(spec.version, 'version', 1, LIMITS.versions_per_lineage)
    meta: list[tuple[str, Scalar]] = [
        ('patchtrace_rule_id', f'{spec.lineage_id[:12]}.v{version}'), ('patchtrace_version', version),
        ('patchtrace_project_id', _free_text(source.project_id, 'project id'))]
    if spec.unvetted is True:
        meta.append(('patchtrace_status', 'unvetted'))
    meta += [('older_sha256', _whitelisted(source.older_sha256, _SHA, 'older sha256')),
             ('newer_sha256', _whitelisted(source.newer_sha256, _SHA, 'newer sha256')),
             ('side', spec.direction), ('change', _closed(source.category, ('modified', 'added', 'removed'), 'change'))]
    functions = (('older', source.older), ('newer', source.newer))
    meta += [(f'function_{side}', _exact_int(function.rva, 'function rva', 0, 2**32 - 1))
             for side, function in functions if function is not None]
    if spec.include_names is True:  # names may come from symbol files: opt-in only
        meta += [(f'function_{side}_name', _free_text(function.name, 'function name'))
                 for side, function in functions if function is not None and function.name]
    for key, values in (('cve', spec.cve), ('kb', spec.kb), ('cwe', (*spec.cwe, *source.cwe))):
        unique = sorted({_whitelisted(value, _ANCHORS[key], key) for value in values})
        if unique:
            meta.append((key, ' '.join(unique)))
    if capabilities:
        meta.append(('capability', '; '.join(sorted(capabilities))))
    if spec.analyst_label:
        meta.append(('analyst_label', _free_text(spec.analyst_label, 'analyst label')))
    meta.append(('statement', _STATEMENTS[spec.direction]))
    return tuple(meta)


def build_rule(spec: RuleSpec) -> ParsedRule:
    """Validate the spec and fold it into the canonical tree; feature order never matters."""
    direction = _closed(spec.direction, ('older', 'newer'), 'direction')
    lineage = _whitelisted(spec.lineage_id, _SHA, 'lineage id')
    hexes: list[HexIR] = []
    texts: set[TextIR] = set()
    imports: set[ImportIR] = set()
    api_gates: set[str] = set()
    capabilities: set[str] = set()
    for feature in spec.features:
        if feature.included is not True:
            continue
        if isinstance(feature, BytesFeature):
            hexes.append(_hex(feature, direction))
        elif isinstance(feature, StringFeature):
            texts.add(_text(feature, direction))
        elif isinstance(feature, ImportFeature):
            imports.add(_import(feature))
        elif isinstance(feature, CapabilityFeature):
            capabilities.add(_free_text(feature.rule_id, 'capability id'))
            api_gates.update(_whitelisted(gate, _SYMBOL, 'api gate') for gate in feature.api_gates)
        else:
            raise _bad('feature kind')
    if len(hexes) > LIMITS.hex_patterns_v1 or len(texts) > LIMITS.text_patterns_v1:
        raise RulesError('PT-RULE-LIMIT', 'too many included patterns')
    if not (hexes or texts or imports):  # capabilities are metadata and gates, never a pattern of their own
        raise _bad('empty feature set')
    return ParsedRule(
        name=f'PT_{lineage[:12]}_{direction}', side=direction, meta=_meta(spec, capabilities),
        hex=hexes[0] if hexes else None, texts=tuple(sorted(texts, key=lambda t: (t.value, t.encoding))),
        imports=tuple(sorted(imports, key=lambda i: (i.delay, i.dll.lower(), i.dll, i.name or '', i.ordinal or 0))),
        api_gates=tuple(sorted(api_gates)))


# ---- rendering ----------------------------------------------------------------------------------------------------

def _string_literal(value: str) -> str:
    """The one writer of quoted strings; only printable ASCII reaches it, `\\` and `"` are escaped."""
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _text_literal(value: bytes) -> str:
    out = []
    for byte in value:
        if byte in (0x22, 0x5C):
            out.append('\\' + chr(byte))
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f'\\x{byte:02x}')
    return '"' + ''.join(out) + '"'


def _meta_value(key: str, value: Scalar) -> str:
    if key in _HEX_META:
        return f'0x{value:x}'
    return str(value) if key in _INT_META else _string_literal(str(value))


def _import_clause(item: ImportIR) -> str:
    kind = 'name' if item.name is not None else 'ordinal'
    return _IMPORT_CLAUSES[(item.delay, kind)].format(
        dll=_string_literal(item.dll), name=_string_literal(item.name or ''), ordinal=item.ordinal)


def _clauses(rule: ParsedRule) -> list[str]:
    clauses = list(_HEAD_CLAUSES)
    if rule.hex is not None:
        clauses.append(_SECTION_CLAUSE)
        clauses += [_PIN_CLAUSE.format(dll=_string_literal(pin.dll), name=_string_literal(pin.name), end=pin.end_offset,
                                       disp=pin.disp_offset) for pin in rule.hex.pins]
    if rule.texts:
        clauses.append(_TEXT_CLAUSE)
    clauses += [_import_clause(item) for item in rule.imports]
    clauses += [_API_CLAUSE.format(name=_string_literal(name)) for name in rule.api_gates]
    return clauses


def _block(title: str, rows: list[tuple[str, str]]) -> list[str]:
    width = max(len(left) for left, _ in rows)
    return ['', f'  {title}:'] + [f'    {left:<{width}} = {right}' for left, right in rows]


def render_rule(rule: ParsedRule) -> str:
    """The `yara_x.Formatter` layout, byte for byte; LF only, one trailing newline."""
    lines = ['import "pe"', '', f'rule {rule.name}: patchtrace {rule.side}_side {{']
    lines += _block('meta', [(key, _meta_value(key, value)) for key, value in rule.meta])[1:]
    patterns: list[tuple[str, str]] = []
    if rule.hex is not None:
        patterns.append(('$b', '{ ' + ' '.join(rule.hex.tokens) + ' }'))
    patterns += [(f'$t{index}', f'{_text_literal(item.value)} {_TEXT_MODIFIERS[item.encoding]}')
                 for index, item in enumerate(rule.texts)]
    if patterns:
        lines += _block('strings', patterns)
    clauses = _clauses(rule)
    lines += ['', '  condition:'] + [f'    {clause} and' for clause in clauses[:-1]] + [f'    {clauses[-1]}', '}']
    return '\n'.join(lines) + '\n'


# ---- strict parser ------------------------------------------------------------------------------------------------

def _template_regex(template: str) -> re.Pattern[str]:
    out = []
    for index, part in enumerate(re.split(r'\{(\w+)\}', template)):
        if index % 2 == 0:
            out.append(re.escape(part))
        elif part in ('dll', 'name'):
            out.append(f'"(?P<{part}>{_LITERAL_BODY})"')
        else:
            out.append(f'(?P<{part}>[0-9]{{1,10}})')
    return re.compile(''.join(out))


_PIN_RX = _template_regex(_PIN_CLAUSE)
_IMPORT_RX = {key: _template_regex(template) for key, template in _IMPORT_CLAUSES.items()}
_API_RX = _template_regex(_API_CLAUSE)
_RULE_RX = re.compile(r'rule (PT_[0-9a-f]{12}_(older|newer)): patchtrace (older|newer)_side \{')
_META_RX = re.compile(rf'    ([a-z0-9_]+) += ("{_LITERAL_BODY}"|0x[0-9a-f]{{1,8}}|[0-9]{{1,3}})')
_PATTERN_RX = re.compile(
    r'    (\$b|\$t[0-9]{1,2}) += (?:\{ ((?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?))*) \}'
    rf'|"({_TEXT_BODY})" (ascii wide|ascii|wide))')


def _parse_error() -> RulesError:
    return RulesError('PT-RULE-INPUT', 'rule text is outside the generated grammar')


def _meta_scalar(key: str, raw: str) -> Scalar:
    if key not in _META_KEYS:
        raise _parse_error()
    if raw.startswith('"'):
        if key in _INT_META:
            raise _parse_error()
        return _unescape(raw[1:-1])
    if key not in _INT_META or raw.startswith('0x') != (key in _HEX_META):
        raise _parse_error()
    return int(raw, 16 if raw.startswith('0x') else 10)


def _unescape_text(body: str) -> bytes:
    out = bytearray()
    index = 0
    while index < len(body):
        if body[index] != '\\':
            out.append(ord(body[index]))
            index += 1
        elif body[index + 1] == 'x':
            out.append(int(body[index + 2:index + 4], 16))
            index += 4
        else:
            out.append(ord(body[index + 1]))
            index += 2
    return bytes(out)


def _take_block(lines: list[str], at: int, title: str) -> tuple[list[str], int]:
    if at >= len(lines) or lines[at] != f'  {title}:':
        raise _parse_error()
    end = at + 1
    while end < len(lines) and lines[end].startswith('    '):
        end += 1
    return lines[at + 1:end], end


def _parse_patterns(rows: list[str]) -> tuple[list[str] | None, tuple[TextIR, ...]]:
    tokens: list[str] | None = None
    texts: list[TextIR] = []
    for row in rows:
        match = _PATTERN_RX.fullmatch(row)
        if match is None:
            raise _parse_error()
        ident, hex_tokens, body, modifier = match.groups()
        if ident == '$b':
            if tokens is not None or texts:
                raise _parse_error()
            tokens = hex_tokens.split(' ')
        elif hex_tokens is not None or ident != f'$t{len(texts)}':
            raise _parse_error()
        else:
            texts.append(TextIR(_unescape_text(body), _MODIFIER_ENCODINGS[modifier]))
    return tokens, tuple(texts)


def _classify(clause: str) -> tuple[int, PinIR | ImportIR | str | None]:
    """Stage (pins, text, imports, api gates) and payload of one condition clause."""
    if (match := _PIN_RX.fullmatch(clause)) is not None:
        return 1, PinIR(int(match['disp']), int(match['end']), _unescape(match['dll']), _unescape(match['name']))
    if clause == _TEXT_CLAUSE:
        return 2, None
    for (delay, kind), regex in _IMPORT_RX.items():
        if (match := regex.fullmatch(clause)) is not None:
            dll = _unescape(match['dll'])
            if kind == 'name':
                return 3, ImportIR(dll, name=_unescape(match['name']), delay=delay)
            return 3, ImportIR(dll, ordinal=int(match['ordinal']), delay=delay)
    if (match := _API_RX.fullmatch(clause)) is not None:
        return 4, _unescape(match['name'])
    raise _parse_error()


def _parse_condition(clauses: list[str], has_hex: bool, has_texts: bool):
    expected = list(_HEAD_CLAUSES) + ([_SECTION_CLAUSE] if has_hex else [])
    if len(clauses) < len(expected) or clauses[:len(expected)] != expected:
        raise _parse_error()
    pins, imports, api_gates = [], [], []
    stage, seen_text = 0, False
    for clause in clauses[len(expected):]:
        clause_stage, payload = _classify(clause)
        if clause_stage < stage or (clause_stage == 2 and seen_text) or (clause_stage == 1 and not has_hex):
            raise _parse_error()
        stage, seen_text = clause_stage, seen_text or clause_stage == 2
        {1: pins, 3: imports, 4: api_gates}.get(clause_stage, []).append(payload)
    if seen_text != has_texts:
        raise _parse_error()
    return tuple(pins), tuple(imports), tuple(api_gates)


def _parse_meta(rows: list[str]) -> tuple[tuple[str, Scalar], ...]:
    out = []
    for row in rows:
        match = _META_RX.fullmatch(row)
        if match is None:
            raise _parse_error()
        out.append((match[1], _meta_scalar(match[1], match[2])))
    return tuple(out)


def parse_rule(text: str) -> ParsedRule:
    """Accept exactly the text `render_rule` can emit and nothing else (raises PT-RULE-INPUT)."""
    if type(text) is not str or not text.endswith('\n') or len(text) > LIMITS.rule_text_bytes:
        raise _parse_error()
    lines = text[:-1].split('\n')
    head = _RULE_RX.fullmatch(lines[2]) if len(lines) > 3 else None
    if lines[:2] != ['import "pe"', ''] or head is None or head[2] != head[3]:
        raise _parse_error()
    meta_rows, at = _take_block(lines, 3, 'meta')
    meta = _parse_meta(meta_rows)
    tokens, texts = None, ()
    if lines[at:at + 2] == ['', '  strings:']:
        pattern_rows, at = _take_block(lines, at + 1, 'strings')
        tokens, texts = _parse_patterns(pattern_rows)
    if lines[at:at + 2] != ['', '  condition:']:
        raise _parse_error()
    rows, at = _take_block(lines, at + 1, 'condition')
    if lines[at:] != ['}'] or not rows or not all(row.endswith(' and') for row in rows[:-1]):
        raise _parse_error()
    clauses = [row[4:-4] for row in rows[:-1]] + [rows[-1][4:]]
    pins, imports, api_gates = _parse_condition(clauses, tokens is not None, bool(texts))
    hex_ir = HexIR(tuple(tokens), pins) if tokens is not None else None
    return _validated(ParsedRule(head[1], head[2], meta, hex_ir, texts, imports, api_gates))


def _validated(rule: ParsedRule) -> ParsedRule:
    """Apply the builder's whitelists to a parsed tree: grammar-shaped text is not yet allowed text."""
    for item in rule.imports:
        _whitelisted(item.dll, _DLL, 'import dll')
        if item.name is not None:
            _whitelisted(item.name, _SYMBOL, 'import name')
    for name in rule.api_gates:
        _whitelisted(name, _SYMBOL, 'api gate')
    if rule.hex is not None:
        for pin in rule.hex.pins:
            _pin(pin, rule.hex.tokens)
    return rule


def synthesize(spec: RuleSpec) -> str:
    """Rule text for one candidate, or `RulesError`; the output is proven against its own strict re-parse."""
    rule = build_rule(spec)
    text = render_rule(rule)
    if len(text) > LIMITS.rule_text_bytes:
        raise RulesError('PT-RULE-LIMIT', 'rule text is over the size cap')
    parsed = parse_rule(text)
    if parsed != rule or render_rule(parsed) != text:
        raise RulesError('PT-RULE-INTEGRITY', 'generated rule text failed its strict re-parse')
    return text
