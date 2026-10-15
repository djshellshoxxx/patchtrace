"""Lossless, total, bounded lexical tokens for decompiled C and Ghidra assembly text (WBQ S7, `codetext/1`). Pure.

A token list covers the text exactly: tokens are non-empty, adjacent, start at 0 and end at `len(text)`, so
`''.join(text[t.start:t.end] for t in tokens) == text` for every `str`, including lone surrogates and NUL. Newlines
are `ws` tokens and no other token contains one, so a caller can split by `\\n` and keep the offsets (a block comment
that spans lines is one `comment` token per line). The one exception is the plain tail below. The text is data: it is
never evaluated and no markup is built.

Bounds. Quantifiers are possessive and the last alternative matches any character, so each position is consumed once
and no input can force backtracking beyond the few alternatives tried at one position: the work is linear in the text.
A line longer than `MAX_LINE_CHARS` stays plain (one `other` token).
A document longer than `MAX_DOCUMENT_CHARS` is tokenized up to the end of its last whole line inside the cap and the
rest is a single `other` token, which may span lines: splitting it would cost work proportional to the excess.

Differences from Pygments, which only tests/test_codetext_tokens.py imports (a dev oracle): a backslash does not
continue a `//` comment or a string over a newline; preprocessor lines are not special; a number is a letter-and-digit
run (`0x20U`, `1e-5f`) and a leading sign is an operator; an unterminated quote runs to the end of its line.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal, NamedTuple

from .names import classify_name

Language = Literal['c', 'asm']
KINDS = ('ws', 'comment', 'string', 'char', 'number', 'keyword', 'type', 'auto_name', 'temp', 'ident', 'op',
         'mnemonic', 'register', 'size', 'symbol', 'punct', 'other')
MAX_LINE_CHARS = 4_096
MAX_DOCUMENT_CHARS = 1_048_576


class Token(NamedTuple):
    kind: str
    start: int
    end: int


class LineTokens(NamedTuple):
    tokens: tuple[Token, ...]  # offsets relative to the line
    in_comment: bool  # the next line starts inside a `/* ... */` comment


_QUOTED = r'''(?:[^"\\\n]++|\\.?+)*+"?'''
_CHAR = r"""(?:[^'\\\n]++|\\.?+)*+'?"""
_OTHER = r'(?P<other>[^\x00-\x7f]++|[\x00-\x08\x0e-\x1f\x7f]++|[\s\S])'
# Alternatives are ordered by how often they occur, within two constraints: a quote with its `L`/`u8` prefix must be
# tried before a word swallows the prefix, and comments and numbers must be tried before `op` (`/`, `.`).
_C_SCAN = re.compile(rf'''
    (?P<ws>[ \t\r\n\f\v]+)
  | (?P<string>(?:u8|[LuU])?"{_QUOTED})
  | (?P<char>(?:u8|[LuU])?'{_CHAR})
  | (?P<word>[A-Za-z_][A-Za-z0-9_]*+(?:::[A-Za-z_][A-Za-z0-9_]*+)*+)
  | (?P<punct>[()\[\]{{}},;:])
  | (?P<number>0[xX][0-9A-Fa-f]++(?:\.[0-9A-Fa-f]*+)?(?:[pP][+-]?[0-9]++)?[A-Za-z0-9_]*+
              |(?:[0-9]++\.[0-9]*+|\.[0-9]++|[0-9]++)(?:[eE][+-]?[0-9]++)?[A-Za-z0-9_]*+)
  | (?P<comment>//[^\n]*)
  | (?P<block>/\*)
  | (?P<op>->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||::|\.\.\.|[-+*/%&|^]=|[-+*/%&|^~!<>=?.])
  | {_OTHER}
''', re.VERBOSE | re.ASCII)
# Ghidra writes `MOV RAX,qword ptr [RSP + 0x28]` and `CALL qword ptr [->KERNEL32.DLL::CreateFileW]`: a name may
# carry `.`, `$`, `@`, `?` (decorated names) and `::`. A number precedes a word because `.5` is also a word start.
_ASM_SCAN = re.compile(rf'''
    (?P<ws>[ \t\r\n\f\v]+)
  | (?P<number>(?:0[xX][0-9A-Fa-f]++|[0-9]++(?:\.[0-9]++)?|\.[0-9]++)[A-Za-z0-9_]*+)
  | (?P<word>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*+(?:::[A-Za-z0-9_.$@?]++)*+)
  | (?P<punct>[()\[\]{{}},:])
  | (?P<op>->|[-+*/%&|^~<>=!])
  | (?P<comment>;[^\n]*)
  | (?P<string>"{_QUOTED})
  | (?P<char>'{_CHAR})
  | {_OTHER}
''', re.VERBOSE | re.ASCII)
# Only what decides whether a `/*` is open: strings and `//` hide a `/*`, the block comment itself is the result.
_BLOCK_SCAN = re.compile(r'''
    //[^\n]*+
  | "''' + _QUOTED + r'''
  | '(?:[^'\\\n]++|\\.?+)*+'?
  | (?P<block>/\*(?:[^*]++|\*(?!/))*+(?P<close>\*/)?)
''', re.VERBOSE)
_CALL = re.compile(r'[ \t]*\(')


def _kind_table(pattern: re.Pattern[str], *special: str) -> tuple[str | None, ...]:
    """Kind by group number; None marks a group that needs context (a word, a block comment opener)."""
    table: list[str | None] = [None] * (pattern.groups + 1)
    for name, index in pattern.groupindex.items():
        table[index] = None if name in special else name
    return tuple(table)


_C_KINDS = _kind_table(_C_SCAN, 'word', 'block')
_ASM_KINDS = _kind_table(_ASM_SCAN, 'word')
_C_BLOCK = _C_SCAN.groupindex['block']
# C keywords and calling conventions, then the C, stdint, Ghidra built-in and common Win32 type names.
_C_WORDS = dict.fromkeys((
    'auto break case const continue default do else enum extern for goto if inline register restrict return sizeof '
    'static struct switch typedef union volatile while try catch throw true false NULL nullptr '
    '_Alignas _Alignof _Atomic _Generic _Noreturn _Static_assert _Thread_local '
    '__cdecl __stdcall __fastcall __thiscall __vectorcall __declspec __unaligned __restrict __forceinline __inline'
).split(), 'keyword') | dict.fromkeys((
    'void char short int long float double signed unsigned bool _Bool _Complex wchar_t size_t ssize_t ptrdiff_t '
    'intptr_t uintptr_t int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t __int8 __int16 __int32 '
    '__int64 undefined undefined1 undefined2 undefined3 undefined4 undefined5 undefined6 undefined7 undefined8 '
    'byte word dword qword uchar ushort uint ulong longlong ulonglong float10 code '
    'BOOL BYTE WORD DWORD QWORD CHAR WCHAR SHORT USHORT INT UINT LONG ULONG LONGLONG ULONGLONG UCHAR SIZE_T '
    'ULONG_PTR HANDLE HMODULE HRESULT NTSTATUS PVOID LPVOID LPCSTR LPCWSTR LPSTR LPWSTR'
).split(), 'type')


def _numbered(prefix: str, count: int) -> list[str]:
    return [f'{prefix}{n}' for n in range(count)]


_REGISTERS = frozenset(
    ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
     'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'sil', 'dil',
     'bpl', 'spl', 'rip', 'eip', 'ip', 'rflags', 'eflags', 'flags', 'cs', 'ds', 'es', 'fs', 'gs', 'ss', 'mxcsr',
     'gdtr', 'ldtr', 'idtr', 'tr']
    + [f'r{n}{s}' for n in range(8, 16) for s in ('', 'd', 'w', 'b', 'l')]
    + _numbered('st', 8) + _numbered('mm', 8) + _numbered('k', 8) + _numbered('bnd', 4) + _numbered('cr', 16)
    + _numbered('dr', 16) + [f'tr{n}' for n in range(3, 8)]
    + [f'{v}mm{n}' for v in 'xyz' for n in range(32)])
_SIZES = frozenset(
    'byte word dword qword fword tbyte tword oword xmmword ymmword zmmword ptr short near far'.split())
_PREFIX_MNEMONICS = frozenset('lock rep repe repz repne repnz bnd notrack xacquire xrelease'.split())


# Decompiled text repeats a few hundred names; the class of a word does not depend on its neighbours, so it is
# remembered. Bounded so that a flood of distinct words cannot grow it: it is emptied when full and long words skip it.
_MEMO_MAX = 4_096
_MEMO_WORD_MAX = 64
_C_MEMO: dict[str, str] = {}
_ASM_MEMO: dict[str, str] = {}
_CALL_AHEAD = _CALL.match
# `tuple.__new__` builds a Token without running NamedTuple's Python-level `__new__`: a pane is tens of thousands of
# tokens and that call was a third of the scan time.
_new_token = tuple.__new__


def _remember(memo: dict[str, str], word: str, kind: str) -> str:
    if len(word) <= _MEMO_WORD_MAX:
        if len(memo) >= _MEMO_MAX:
            memo.clear()
        memo[word] = kind
    return kind


def _c_word_kind(word: str) -> str:
    """Keyword, type, auto_name, temp or the placeholder 'name' for any other word."""
    return _C_WORDS.get(word) or classify_name(word) or 'name'


def _scan_c(line: str, base: int, in_comment: bool, out: list[Token]) -> bool:
    """Append the tokens of one C line to `out` (offsets `base` + column); True when a `/*` is still open."""
    size, pos = len(line), 0
    if in_comment:
        close = line.find('*/')
        if close < 0:
            if size:
                out.append(Token('comment', base, base + size))
            return True
        pos = close + 2
        out.append(Token('comment', base, base + pos))
    append, kinds, memo, new = out.append, _C_KINDS, _C_MEMO, _new_token
    while pos < size:
        start = base + pos  # tokens are contiguous, so each starts where the previous one ended
        for match in _C_SCAN.finditer(line, pos):
            end = match.end()
            group = match.lastindex
            kind = kinds[group]
            if kind is None:
                if group == _C_BLOCK:
                    close = line.find('*/', end)
                    if close < 0:
                        append(new(Token, ('comment', start, base + size)))
                        return True
                    pos = close + 2
                    append(new(Token, ('comment', start, base + pos)))
                    break
                word = match.group()
                kind = memo.get(word) or _remember(memo, word, _c_word_kind(word))
                if kind == 'name':
                    # A named callee reads differently from a named variable; both stay unmasked downstream.
                    kind = 'symbol' if _CALL_AHEAD(line, end) else 'ident'
            stop = base + end
            append(new(Token, (kind, start, stop)))
            start = stop
        else:
            pos = size
    return False


def _asm_word_kind(word: str) -> str:
    lowered = word.lower()
    if lowered in _REGISTERS:
        return 'register'
    if lowered in _SIZES:
        return 'size'
    # Anything else is a name; an unrecognised register therefore errs towards "named, never masked".
    return classify_name(word) or 'symbol'


def _scan_asm(line: str, base: int, in_comment: bool, out: list[Token]) -> bool:
    """Append the tokens of one assembly line to `out`; assembly has no multi-line state, so this returns False."""
    append, kinds, memo, new = out.append, _ASM_KINDS, _ASM_MEMO, _new_token
    start, expect_mnemonic = base, True
    for match in _ASM_SCAN.finditer(line):
        end = match.end()
        kind = kinds[match.lastindex]
        if kind is None:
            word = match.group()
            kind = memo.get(word) or _remember(memo, word, _asm_word_kind(word))
            # The first word is the mnemonic (then a prefix such as `lock` or `rep` keeps the slot open), unless it
            # is a label: a generated name cannot be a mnemonic, and `name:` ends in a colon.
            if expect_mnemonic and kind != 'auto_name' and not (
                    line.startswith(':', end) and not line.startswith('::', end)):
                kind = 'mnemonic'
                expect_mnemonic = word.lower() in _PREFIX_MNEMONICS
        stop = base + end
        append(new(Token, (kind, start, stop)))
        start = stop
    return False


def _comment_open_after(line: str, in_comment: bool) -> bool:
    """Block-comment state at the end of a line without building tokens (used for over-long lines)."""
    pos = 0
    if in_comment:
        close = line.find('*/')
        if close < 0:
            return True
        pos = close + 2
    return any(m['block'] is not None and m['close'] is None for m in _BLOCK_SCAN.finditer(line, pos))


class _Scanner(NamedTuple):
    scan: Callable[[str, int, bool, list[Token]], bool]
    open_after: Callable[[str, bool], bool]  # block-comment state after a line that is too long to tokenize


_SCANNERS = {'c': _Scanner(_scan_c, _comment_open_after), 'asm': _Scanner(_scan_asm, lambda line, in_comment: False)}


def _scanner(language: str) -> _Scanner:
    try:
        return _SCANNERS[language]
    except KeyError:
        raise ValueError(f'unknown language {language!r}; expected one of {sorted(_SCANNERS)}') from None


def _scan_line(scanner: _Scanner, line: str, base: int, in_comment: bool, out: list[Token],
               max_line_chars: int) -> bool:
    if len(line) <= max_line_chars:
        return scanner.scan(line, base, in_comment, out)
    out.append(Token('other', base, base + len(line)))
    return scanner.open_after(line, in_comment)


def tokenize_line(line: str, language: Language, in_comment: bool = False, *,
                  max_chars: int = MAX_LINE_CHARS) -> LineTokens:
    """Tokens of one line (no newline) with offsets relative to it, given whether a `/*` is open at its start.

    Chain `in_comment` from line to line, or take the starting state from `open_comment_lines`, to tokenize a
    window without scanning what precedes it."""
    out: list[Token] = []
    state = _scan_line(_scanner(language), line, 0, in_comment, out, max_chars)
    return LineTokens(tuple(out), state)


def _document_cut(text: str, max_chars: int) -> int:
    """Where plain text starts: the end of the last whole line inside the cap, or 0 when the cap holds none."""
    if len(text) <= max_chars:
        return len(text)
    return text.rfind('\n', 0, max_chars) + 1


def tokenize(text: str, language: Language, *, max_line_chars: int = MAX_LINE_CHARS,
             max_chars: int = MAX_DOCUMENT_CHARS) -> tuple[Token, ...]:
    """Tokens covering all of `text`; see the module docstring for the guarantees and bounds."""
    scanner = _scanner(language)
    cut = _document_cut(text, max_chars)
    out: list[Token] = []
    lines = (text if cut == len(text) else text[:cut]).split('\n')
    base, in_comment, last = 0, False, len(lines) - 1
    for number, line in enumerate(lines):
        in_comment = _scan_line(scanner, line, base, in_comment, out, max_line_chars)
        base += len(line)
        if number < last:
            out.append(Token('ws', base, base + 1))
            base += 1
    if cut < len(text):
        out.append(Token('other', cut, len(text)))
    return tuple(out)


def open_comment_lines(text: str, *, max_chars: int = MAX_DOCUMENT_CHARS) -> frozenset[int]:
    """0-based numbers of the C lines that start inside a `/* ... */` comment, in one linear pass over `text`.

    Equal to chaining `tokenize_line` states from line 0, which a window needs only from its first line. Assembly
    has no block comments."""
    end = _document_cut(text, max_chars)
    lines: set[int] = set()
    line = cursor = 0  # `line` is the number of newlines before `cursor`
    for match in _BLOCK_SCAN.finditer(text, 0, end):
        if match['block'] is None:
            continue
        start, stop = match.span()
        inside = text.count('\n', start, stop)
        if inside:
            line += text.count('\n', cursor, start)
            lines.update(range(line + 1, line + 1 + inside))
            line += inside
            cursor = stop
    return frozenset(lines)
