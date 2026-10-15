"""`canon/1`: canonical pseudo-code over Ghidriff's stored decompiler text (05 s2.4, s6). Pure and linear.

Comments and whitespace are dropped; locals, parameters and temporaries are alpha-renamed by first occurrence;
`LAB_`/`switchD_`/`caseD_` labels (they stay inside the function) are renamed by first occurrence; function labels
become the token of the matched row they map to, else a numbered unmapped token; data labels are always unmapped
without DATA-MAP (S0); with it (`data_labels`, S3) a data label that DATA-MAP/1 maps becomes the token of its datum pair
on both sides. Literals are compared by value; strings, operators, casts and call names are kept exactly.
An alpha-renamed unmapped label could hide a swapped global (R-02), so `Canon.unmapped` > 0 forbids COS-PSEUDO/1.
The scanner is hand-written around `re.match` and `str.find` so hostile text cannot make it quadratic.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from ..addressing import AddressMap
from ..limits import DEFAULT_LIMITS, UnifiedLimits

KEYWORDS = frozenset({
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default', 'break', 'continue', 'return', 'goto', 'sizeof',
    'struct', 'union', 'enum', 'typedef', 'static', 'const', 'volatile', 'extern', 'register', 'inline', 'void',
    'char', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned', 'bool', 'catch', 'try'})
RELATIONAL = frozenset({'==', '!=', '<', '<=', '>', '>='})
LOGICAL = frozenset({'&&', '||', '!'})
_TOKEN = re.compile(r'''\s*(?:
    (?P<hex>0[xX][0-9a-fA-F]+[uUlL]*)
  | (?P<float>(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?[fF]?)
  | (?P<dec>\d+[uUlL]*)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><<=|>>=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|::)
  | (?P<other>\S)
)''', re.X)
_PLAIN = {'"': re.compile(r'[^"\\\n]*'), "'": re.compile(r"[^'\\\n]*")}
_LOCAL = re.compile(r'^(?:[a-z]{1,4}Var\d+|[a-z]{1,4}Stack_[0-9a-fA-F]+|local_(?:res)?[0-9a-fA-F]+|param_\d+|'
                    r'in_[A-Za-z0-9_]+|unaff_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|stack0x[0-9a-fA-F]+)$')
_LOCAL_LABEL = re.compile(r'^(?:LAB|switchD|caseD)_[0-9a-fA-F]+$')
FUNC_LABEL = re.compile(r'^(?:thunk_)?FUN_([0-9a-fA-F]{6,16})$')
_DATA_LABEL = re.compile(r'^_?(?:PTR_)?(?:DAT|PTR|EXT|UNK|SUB|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|FUN)_'
                         r'([0-9a-fA-F]{6,16})$')


@dataclass(frozen=True)
class Canon:
    tokens: tuple[str, ...]
    calls: tuple[str, ...]
    numbers: tuple[str, ...]
    strings: tuple[str, ...]
    relational: tuple[str, ...]
    logical: tuple[str, ...]
    mapped: frozenset[str]
    unmapped: int


def _literal(code: str, start: int, quote: str, eol: int) -> int:
    """End (exclusive) of the string/char literal opening at `start` on its line, or -1 when it is unterminated."""
    plain, i = _PLAIN[quote], start + 1
    while i < eol:
        i = plain.match(code, i, eol).end()
        if i >= eol:
            return -1
        if code[i] == '\\':
            i += 2
        else:
            return i + 1
    return -1


def _scan(code: str) -> list[tuple[str, str]]:
    """Tokens as (kind, text). Literals never span lines. A failed opener makes every later quote of the same kind on
    its line futile (whether a quote is escaped depends only on the backslash run before it), which keeps the scan
    linear on hostile text."""
    out: list[tuple[str, str]] = []
    pos, size = 0, len(code)
    eol_cache, dead = -1, {'"': -1, "'": -1}
    while pos < size:
        match = _TOKEN.match(code, pos)
        if match is None:  # only whitespace is left
            break
        kind, text = match.lastgroup, match.group(match.lastgroup)
        start = match.start(kind)
        if kind == 'other':
            if text in ('"', "'"):
                if start >= eol_cache:
                    found = code.find('\n', start)
                    eol_cache = size if found < 0 else found
                end = -1 if start < dead[text] else _literal(code, start, text, eol_cache)
                if end < 0:
                    dead[text] = eol_cache
                else:
                    out.append(('string' if text == '"' else 'char', code[start:end]))
                    pos = end
                    continue
            elif text == '/':
                if code.startswith('//', start):
                    end = code.find('\n', start)
                    pos = size if end < 0 else end
                    continue
                if code.startswith('/*', start):
                    end = code.find('*/', start + 2)
                    pos = size if end < 0 else end + 2
                    continue
        out.append((kind, text))
        pos = match.end()
    return out


def _number(kind: str, text: str) -> str:
    try:
        if kind == 'hex':
            return f'#{int(text.rstrip("uUlL"), 16)}'
        if kind == 'dec':
            return f'#{int(text.rstrip("uUlL"))}'
        if kind == 'char':
            if len(text) == 3 and text[1] != '\\':
                return f'#{ord(text[1])}'
            value = ast.literal_eval(text)
            if isinstance(value, str) and len(value) == 1:
                return f'#{ord(value)}'
            return f'c:{text[:40]}'
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return f'{"c" if kind == "char" else "n"}:{text[:40]}'
    return f'f:{text.rstrip("fF") if text.lower().endswith("f") else text}'


def canonicalize(code: str, side: str, labels, addr: AddressMap, basis: str,
                 limits: UnifiedLimits = DEFAULT_LIMITS, data_labels=None) -> Canon:
    """`labels.token(side, rva)` gives the token of the matched row that owns a function RVA, or None;
    `data_labels.token(side, rva)` does the same for a datum mapped by DATA-MAP/1 (None: every data label is unmapped)."""
    raw = _scan(code)
    brace = next((i for i, (_k, t) in enumerate(raw) if t == '{'), len(raw))
    tokens: list[str] = []
    calls: list[str] = []
    numbers: list[str] = []
    strings: list[str] = []
    relational: list[str] = []
    logical: list[str] = []
    variables: dict[str, str] = {}
    local_labels: dict[str, str] = {}
    unmapped: dict[str, str] = {}
    mapped: set[str] = set()

    def rename(table: dict[str, str], name: str, prefix: str) -> str:
        if name not in table:
            table[name] = f'@{prefix}{len(table) + 1}'
        return table[name]

    for index, (kind, text) in enumerate(raw):
        if kind == 'ident':
            token = text
            if text in KEYWORDS:
                pass
            elif _LOCAL.match(text):
                token = rename(variables, text, 'v')
            elif _LOCAL_LABEL.match(text):
                token = rename(local_labels, text, 'L')
            elif (found := FUNC_LABEL.match(text)) is not None:
                rva = addr.to_rva(side, int(found.group(1), 16), basis)
                mapped_token = labels.token(side, rva) if rva is not None else None
                if mapped_token is not None:
                    token = mapped_token
                    mapped.add(token)
                else:
                    token = rename(unmapped, text, 'U')
            elif (found := _DATA_LABEL.match(text)) is not None:
                rva = addr.to_rva(side, int(found.group(1), 16), basis) if data_labels is not None else None
                mapped_token = data_labels.token(side, rva) if rva is not None else None
                if mapped_token is not None:
                    token = mapped_token
                    mapped.add(token)
                else:
                    token = rename(unmapped, text, 'U')
            if (index >= brace and index + 1 < len(raw) and raw[index + 1][1] == '(' and text not in KEYWORDS
                    and (index == 0 or raw[index - 1][1] not in ('.', '->'))):
                calls.append(token)
            tokens.append(token)
        elif kind in ('hex', 'dec', 'char', 'float'):
            token = _number(kind, text)
            numbers.append(token)
            tokens.append(token)
        elif kind == 'string':
            strings.append(text)
            tokens.append(text)
        else:
            if text in RELATIONAL:
                relational.append(text)
            elif text in LOGICAL:
                logical.append(text)
            tokens.append(text)
    return Canon(tokens=tuple(tokens), calls=tuple(calls), numbers=tuple(numbers), strings=tuple(strings),
                 relational=tuple(relational), logical=tuple(logical), mapped=frozenset(mapped),
                 unmapped=len(unmapped))
