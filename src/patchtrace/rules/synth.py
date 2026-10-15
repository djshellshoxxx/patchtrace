r"""Closed-grammar rule synthesis (R1; contract `yara-rules/1`, grammar `yrx-gen/1`; plan s6 "Injection through rule text", s7).

`render_rule` is the one serializer that turns the included features of a candidate, or of the version an analyst
accepted, into rule text. Pure: stdlib and the contracts only, so the parent process, the CLI and the GUI can build text
without loading the engine. R2's compile policy (`engine.META`, `RULE_NAME`, `TAGS`) fixes what may be emitted and the
tests compare the two. The layout is the one `yara_x.Formatter` produces, so a generated rule equals its formatted self.

Injection model. The rule text is a template of constants and input reaches it in four closed ways only:
- inside a string literal (meta values, text patterns, import and DLL names), through `escape_bytes`, `quote` or
  `quote_exact`. They map every input onto printable ASCII minus the quote and the backslash, plus the escapes
  \\ \" \n \r \t \xNN, so a value can neither close its literal nor start a line;
- as a number: an `int` inside a range;
- as a hex token: `XX` or `??` separated by single spaces;
- as an identifier: the 12 hex digits of the lineage id and the word `older` or `newer` (rule name and tag).
Anything else is refused with a `RuleError` whose message is a fixed template: a value never becomes part of it.
Descriptive text (label, project id, function and capability names) is lossy: a character outside ASCII becomes `?`
(plan s6: "non-ASCII label exported as `?`"). A value the engine compares exactly (import and DLL names) is refused
instead, because a changed name would make a gate that never matches. No regex, jump or `include` is ever generated,
and the only comments are the export header lines of `with_header`.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import NamedTuple

from .contracts import (
    BytesFeature,
    CapabilityFeature,
    Feature,
    FunctionRef,
    ImportFeature,
    PairSource,
    Side,
    StringFeature,
    rule_name_for,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS as _L

STATEMENT = 'A match means a file contains this pattern. It does not show whether the file is affected by a flaw.'
HEX_PATTERNS = 1        # grammar yrx-gen/1: one byte pattern ($b) and up to four text patterns ($s1..$s4) per rule
TEXT_PATTERNS = 4
CHECKED_MATCHES = 8     # call pins look at the first matches of $b only: `(1..#b)` would be a potentially slow loop
ADVISORY_IDS = 16       # per kind (cve, kb, cwe): the bound of RuleDecision
MAX_ORDINAL = 65535

# --- string literals --------------------------------------------------------------------------------------------------
# One unit of an escaped literal: printable ASCII except quote and backslash, or one escape. The named escapes and
# lower-case hex digits are the canonical spelling, so one byte string has one text (and one hash).
_UNIT_PATTERN = r'[ !#-\[\]-~]|\\(?:["\\nrt]|x[0-9a-fA-F]{2})'
_UNIT = re.compile(_UNIT_PATTERN)
_ESCAPED = re.compile(f'(?:{_UNIT_PATTERN})+')
_NAMED = {0x22: '\\"', 0x5C: '\\\\', 0x0A: '\\n', 0x0D: '\\r', 0x09: '\\t'}
_NAMED_CODE = {text: code for code, text in _NAMED.items()}


def _refuse(reason: str, message: str, code: str = 'PT-RULE-INPUT') -> RuleError:
    return RuleError(code, message, reason=reason)


def _unit(code: int) -> str:
    named = _NAMED.get(code)
    if named is not None:
        return named
    return chr(code) if 0x20 <= code <= 0x7E else f'\\x{code:02x}'


def _unit_code(unit: str) -> int:
    if unit in _NAMED_CODE:
        return _NAMED_CODE[unit]
    return int(unit[2:], 16) if unit[0] == '\\' else ord(unit)


def escape_bytes(data: bytes) -> str:
    """The canonical escaped form of a text pattern's exact bytes (the `StringFeature.text` of the contract)."""
    if not isinstance(data, bytes):
        raise _refuse('not-bytes', 'A text pattern is a byte string')
    if not 1 <= len(data) <= _L.text_pattern_bytes:
        raise _refuse('bad-text-length', f'A text pattern is 1 to {_L.text_pattern_bytes} bytes', 'PT-RULE-LIMIT')
    return ''.join(_unit(code) for code in data)


def unescape(text: str) -> bytes:
    """The bytes an escaped literal stands for; refuses anything outside the escaped alphabet."""
    if isinstance(text, str) and len(text) > 4 * _L.text_pattern_bytes:   # four characters per byte at most
        raise _refuse('bad-text-length', f'A text pattern is 1 to {_L.text_pattern_bytes} bytes', 'PT-RULE-LIMIT')
    if not isinstance(text, str) or _ESCAPED.fullmatch(text) is None:
        raise _refuse('bad-escape', 'Text is not in the escaped alphabet of the rule grammar')
    return bytes(_unit_code(unit) for unit in _UNIT.findall(text))


def _quote(value: str, *, lossy: bool) -> str:
    if not isinstance(value, str):
        raise _refuse('not-text', 'A rule value is not text')
    if len(value) > _L.meta_string_chars:
        raise _refuse('value-too-long', f'A rule value is at most {_L.meta_string_chars} characters', 'PT-RULE-LIMIT')
    if not lossy and not value:
        raise _refuse('empty-value', 'An exact rule value is not empty')
    parts = []
    for char in value:
        code = ord(char)
        if code < 0x80:
            parts.append(_unit(code))
        elif lossy:
            parts.append('?')
        else:
            raise _refuse('non-ascii', 'An exact rule value is ASCII')
    return '"' + ''.join(parts) + '"'


def quote(value: str) -> str:
    """A string literal for descriptive text: a character outside ASCII becomes `?`, controls are escaped."""
    return _quote(value, lossy=True)


def quote_exact(value: str) -> str:
    """A string literal for a value the engine compares exactly (import and DLL names); non-ASCII is refused."""
    return _quote(value, lossy=False)


# --- the other closed inputs ------------------------------------------------------------------------------------------
_HEX_PATTERN = re.compile(r'(?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?))*')
_SHA256 = re.compile(r'[0-9a-f]{64}')
_TAG = {'older': 'older_side', 'newer': 'newer_side'}   # direction -> the tag the compile policy allows
_CHANGES = ('modified', 'added', 'removed')
_MODIFIERS = {'ascii': 'ascii', 'wide': 'wide', 'ascii-wide': 'ascii wide'}
_KINDS = (BytesFeature, StringFeature, ImportFeature, CapabilityFeature)


def _number(value: object, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _refuse('bad-number', 'A rule number is outside its range')
    return value


def _hex_pattern(pattern: str) -> str:
    if isinstance(pattern, str) and not 3 * _L.window_min_bytes - 1 <= len(pattern) <= 3 * _L.hex_pattern_bytes - 1:
        raise _refuse('bad-hex-length',
                      f'A byte pattern is {_L.window_min_bytes} to {_L.hex_pattern_bytes} bytes', 'PT-RULE-LIMIT')
    if not isinstance(pattern, str) or _HEX_PATTERN.fullmatch(pattern) is None:
        raise _refuse('bad-hex', 'A byte pattern is not a list of hex tokens')
    return pattern


def _sha256(value: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _refuse('bad-hash', 'A hash is 64 lower-case hex digits')
    return value


# --- import gates -----------------------------------------------------------------------------------------------------

def _gate(delay: bool, dll: str, name: str | None, ordinal: int | None) -> tuple[tuple, str]:
    """(duplicate and sort key, clause) of one positive import gate. `pe.imports` takes DLL names without regard to case,
    so spellings that differ only in case are one gate. The engine has no `pe.delayed_imports` (1.21.0): a delay-load
    import is a loop over `pe.delayed_import_details`."""
    if type(delay) is not bool or (name is None) == (ordinal is None):
        raise _refuse('bad-import', 'An import has a name or an ordinal, not both')
    library = quote_exact(dll)
    if name is not None:
        field, argument, ident = 'name', quote_exact(name), name
    else:
        field, argument, ident = 'ordinal', str(_number(ordinal, 1, MAX_ORDINAL)), ordinal
    if delay:
        clause = (f'for any d in pe.delayed_import_details: (d.library_name iequals {library} and '
                  f'for any f in d.functions: (f.{field} == {argument}))')
    else:
        clause = f'pe.imports({library}, {argument})' + ('' if name is not None else ' > 0')
    return (delay, dll.lower(), name is None, ident), clause


# --- the features of one direction -------------------------------------------------------------------------------------

class _Parts(NamedTuple):
    window: BytesFeature | None
    texts: tuple[tuple[str, str], ...]      # (escaped text, modifiers), sorted
    gates: tuple[str, ...]                  # import gate clauses, sorted
    capabilities: tuple[str, ...]           # capa rule ids, sorted


def _text_pattern(feature: StringFeature) -> tuple[str, str]:
    """(escaped text, modifiers). The text must already be the canonical spelling of its bytes."""
    if feature.encoding not in _MODIFIERS:
        raise _refuse('bad-encoding', 'A text pattern is ascii, wide or both')
    if escape_bytes(unescape(feature.text)) != feature.text:
        raise _refuse('text-not-canonical', 'A text pattern is not in its canonical escaped form')
    return feature.text, _MODIFIERS[feature.encoding]


def _collect(features: Sequence[Feature], direction: str) -> _Parts:
    if len(features) > _L.features_per_candidate:
        raise _refuse('too-many-features', 'A candidate has too many features', 'PT-RULE-LIMIT')
    windows: list[BytesFeature] = []
    texts: set[tuple[str, str]] = set()
    gates: dict[tuple, str] = {}
    capabilities: set[str] = set()

    def add_gate(delay: bool, dll: str, name: str | None, ordinal: int | None) -> None:
        key, clause = _gate(delay, dll, name, ordinal)
        gates[key] = min(clause, gates.get(key, clause))   # the least spelling wins: feature order never shows

    for feature in features:
        if not isinstance(feature, _KINDS):
            raise _refuse('bad-feature', 'A feature is not one of the four kinds')
        if not feature.included:
            continue
        if getattr(feature, 'side', direction) != direction or feature.separation != f'{direction}-only':
            raise _refuse('wrong-side', 'An included feature must exist in the rule\'s build only')
        if isinstance(feature, BytesFeature):
            windows.append(feature)
        elif isinstance(feature, StringFeature):
            texts.add(_text_pattern(feature))
        elif isinstance(feature, ImportFeature):
            add_gate(feature.delay, feature.dll, feature.name, feature.ordinal)
        else:
            capabilities.add(feature.rule_id)
            for api in feature.api_gates:
                add_gate(False, api.dll, api.name, None)
    if len(windows) > HEX_PATTERNS or len(texts) > TEXT_PATTERNS:
        raise _refuse('too-many-patterns',
                      f'A rule has {HEX_PATTERNS} byte pattern and {TEXT_PATTERNS} text patterns at most', 'PT-RULE-LIMIT')
    if not (windows or texts or gates):
        raise _refuse('no-discriminator', 'A rule needs a pattern or an import gate besides the PE gate')
    return _Parts(windows[0] if windows else None, tuple(sorted(texts)), tuple(gates[key] for key in sorted(gates)),
                  tuple(sorted(capabilities)))


# --- meta -------------------------------------------------------------------------------------------------------------

def _function(ref: FunctionRef, include_names: bool) -> str:
    rva = f'0x{_number(ref.rva, 0, 2**32 - 1):x}'
    return f'{rva} {ref.name}' if include_names and ref.name else rva


def _advisories(key: str, values: Iterable[str]) -> list[tuple[str, str]]:
    if isinstance(values, str | bytes):   # one id given where a list belongs would be read as its characters
        raise _refuse('not-a-list', 'Advisory ids are a list')
    unique = sorted(set(values))
    if len(unique) > ADVISORY_IDS:
        raise _refuse('too-many-ids', f'A rule names at most {ADVISORY_IDS} ids of one kind', 'PT-RULE-LIMIT')
    return [(key, quote(value)) for value in unique]


def _meta(source: PairSource, *, lineage_id: str, direction: str, version: int, parts: _Parts, label: str | None,
          cve: Iterable[str], kb: Iterable[str], cwe: Iterable[str], include_names: bool) -> list[tuple[str, str]]:
    """The provenance the compile policy requires, in the order of plan s7; the optional keys follow `function_*`."""
    if source.category not in _CHANGES:
        raise _refuse('bad-change', 'A pair is modified, added or removed')
    entries = [('patchtrace_rule_id', quote(f'{lineage_id[:12]}.v{version}')), ('patchtrace_version', str(version)),
               ('patchtrace_project_id', quote(source.project_id)), ('older_sha256', quote(_sha256(source.older_sha256))),
               ('newer_sha256', quote(_sha256(source.newer_sha256))), ('side', quote(direction)),
               ('change', quote(source.category))]
    for side in ('older', 'newer'):
        ref = getattr(source, side)
        if ref is not None:
            entries.append((f'function_{side}', quote(_function(ref, include_names))))
    entries += _advisories('cve', cve) + _advisories('kb', kb) + _advisories('cwe', cwe)
    entries += [('capability', quote(value)) for value in parts.capabilities]
    if label is not None:
        if isinstance(label, str) and not 1 <= len(label) <= _L.label_chars:
            raise _refuse('bad-label', f'An analyst label is 1 to {_L.label_chars} characters', 'PT-RULE-LIMIT')
        entries.append(('analyst_label', quote(label)))
    entries.append(('statement', quote(STATEMENT)))
    return entries


# --- strings and condition ----------------------------------------------------------------------------------------------
_BASE = 'uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64'
_EXECUTABLE = ('for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and '
               '$b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))')
_SECTION = 'pe.sections[pe.section_index(@b[i])]'


def _pin_lines(window: BytesFeature) -> list[str]:
    """Ties each masked `call [rip+disp32]` of a match of $b to the import address table slot of its named API: the match
    offset taken to an RVA through its section, plus the instruction end, plus the displacement must equal the RVA the
    import directory gives that function. Every pin must hold for the same match."""
    length = (len(window.pattern) + 1) // 3
    if len(window.pins) > _L.pins_per_feature:
        raise _refuse('too-many-pins', f'A byte pattern has at most {_L.pins_per_feature} call pins', 'PT-RULE-LIMIT')
    lines = [f'    and for any i in (1..{CHECKED_MATCHES}): (', '      i <= #b']
    for pin in window.pins:
        disp = _number(pin.disp_offset, 0, length - 4)
        end = _number(pin.end_offset, disp + 4, length)
        lines += ['      and for any d in pe.import_details: (',
                  f'        d.library_name iequals {quote_exact(pin.dll)}',
                  '        and for any f in d.functions: (',
                  f'          f.name == {quote_exact(pin.name)}',
                  f'          and f.rva == {_SECTION}.virtual_address + @b[i] + {end} - {_SECTION}.raw_data_offset'
                  f' + int32(@b[i] + {disp})',
                  '        )',
                  '      )']
    return [*lines, '    )']


def _aligned(entries: Sequence[tuple[str, str]]) -> list[str]:
    """`key = value` lines with the `=` aligned, as the Formatter lays out a section."""
    width = max(len(key) for key, _ in entries)
    return [f'    {key.ljust(width)} = {value}' for key, value in entries]


def _strings(parts: _Parts) -> list[tuple[str, str]]:
    entries = [('$b', '{ ' + _hex_pattern(parts.window.pattern) + ' }')] if parts.window is not None else []
    return entries + [(f'$s{index}', f'"{text}" {modifiers}') for index, (text, modifiers) in enumerate(parts.texts, 1)]


def _condition(parts: _Parts) -> list[str]:
    """The PE gate, the executable-section scope of $b, every text pattern, every import gate, then the call pins."""
    clauses = [_EXECUTABLE] if parts.window is not None else []
    clauses += [f'$s{index}' for index in range(1, len(parts.texts) + 1)]
    clauses += parts.gates
    lines = [f'    {_BASE}', *(f'    and {clause}' for clause in clauses)]
    if parts.window is not None and parts.window.pins:
        lines += _pin_lines(parts.window)
    return lines


# --- the rule ---------------------------------------------------------------------------------------------------------

def render_rule(source: PairSource, *, lineage_id: str, direction: Side, version: int, features: Sequence[Feature],
                label: str | None = None, cve: Iterable[str] = (), kb: Iterable[str] = (), cwe: Iterable[str] = (),
                include_names: bool = False) -> str:
    """The `yrx-gen/1` text of one rule: the pair's provenance as meta, one byte pattern and up to four text patterns, and
    a condition of the PE gate, the executable-section scope, every pattern, every import gate and the call pins.

    Only included features are used. They must describe `direction`'s build alone (a rule is never about the other side)
    and at least one must be a pattern or an import gate: the PE gate alone would match every x64 image. Feature order does
    not matter. `label`, `cve`, `kb` and `cwe` come from the analyst's accept decision; function names stay out unless
    `include_names`. Raises `RuleError` (`PT-RULE-INPUT`, `PT-RULE-LIMIT`) and never echoes a value."""
    if direction not in tuple(_TAG):
        raise _refuse('bad-direction', 'A rule describes the older or the newer build')
    if not isinstance(lineage_id, str) or _SHA256.fullmatch(lineage_id) is None:
        raise _refuse('bad-lineage', 'A lineage id is 64 lower-case hex digits')
    if getattr(source, direction) is None:
        raise _refuse('no-function', 'The pair has no function in the rule\'s build')
    version = _number(version, 1, _L.versions_per_lineage)
    parts = _collect(features, direction)
    meta = _meta(source, lineage_id=lineage_id, direction=direction, version=version, parts=parts, label=label, cve=cve,
                 kb=kb, cwe=cwe, include_names=include_names)
    strings = _strings(parts)
    lines = ['import "pe"', '', f'rule {rule_name_for(lineage_id, direction)}: patchtrace {_TAG[direction]} {{',
             '  meta:', *_aligned(meta), '']
    if strings:
        lines += ['  strings:', *_aligned(strings), '']
    text = '\n'.join([*lines, '  condition:', *_condition(parts), '}', ''])
    if len(text) > _L.rule_text_bytes:
        raise _refuse('rule-too-long', f'A rule text is at most {_L.rule_text_bytes} bytes', 'PT-RULE-LIMIT')
    return text


# --- export header ----------------------------------------------------------------------------------------------------

def comment_line(text: str) -> str:
    """One `//` line from free text: every character outside printable ASCII becomes `?`, so no value can end the comment."""
    if not isinstance(text, str):
        raise _refuse('not-text', 'A comment line is text')
    if len(text) > _L.meta_string_chars:
        raise _refuse('value-too-long', f'A comment line is at most {_L.meta_string_chars} characters', 'PT-RULE-LIMIT')
    return ('// ' + ''.join(char if ' ' <= char <= '~' else '?' for char in text)).rstrip()


def with_header(rule_text: str, lines: Iterable[str]) -> str:
    """`rule_text` under export header comments: one `comment_line` per entry of `lines`, then a blank line."""
    header = [comment_line(line) for line in lines]
    if not isinstance(rule_text, str) or not rule_text.startswith('import "pe"\n'):
        raise _refuse('not-a-rule', 'The text is not a generated rule')
    return '\n'.join([*header, '', rule_text]) if header else rule_text
