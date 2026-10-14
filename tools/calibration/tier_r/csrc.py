"""C source tokenizer and function-definition locator (SPEC-32 s5.3, s8). Pure stdlib, no compiler needed.

Comment, string, character-literal and preprocessor aware; brace matching at file scope; ANSI and K&R definitions;
macro-wrapped definitions are found but their `name` is only a hint (labelling uses the debug-info name and line).
Never used to execute anything: it only reads text.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

_TOKEN = re.compile(r'''
    (?P<ws>[ \t\r\f\v]+|\\\r?\n)
  | (?P<nl>\n)
  | (?P<lcomment>//(?:\\\r?\n|[^\n])*)
  | (?P<bcomment>/\*.*?(?:\*/|\Z))
  | (?P<string>(?:u8|u|U|L)?"(?:\\.|[^"\\\n])*(?:"|(?=\n)|\Z))
  | (?P<char>(?:u8|u|U|L)?'(?:\\.|[^'\\\n])*(?:'|(?=\n)|\Z))
  | (?P<number>\.?[0-9](?:[eEpP][+-]|[0-9A-Za-z_.']|'(?=[0-9A-Za-z]))*)
  | (?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)
  | (?P<punct>\.\.\.|<<=|>>=|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\*=|/=|%=|\+=|-=|&=|\^=|\|=|\#\#|[][(){}.,;:?~!%^&*+\-=<>|/#@`\\])
  | (?P<other>.)
''', re.VERBOSE | re.DOTALL)
_PP = re.compile(r'[ \t]*#(?:\\\r?\n|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|[^\n])*', re.DOTALL)
NOT_NAMES = frozenset({'__attribute__', '__declspec', '__asm__', 'asm', '__asm', 'sizeof', '_Alignof', 'alignof',
                       '_Alignas', 'alignas', '__typeof__', 'typeof', '__typeof', '_Static_assert', 'static_assert',
                       'if', 'while', 'for', 'switch', 'return', 'defined', '__pragma', '_Pragma', '__extension__'})
KEYWORDS = frozenset({'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double', 'else', 'enum',
                      'extern', 'float', 'for', 'goto', 'if', 'inline', 'int', 'long', 'register', 'restrict',
                      'return', 'short', 'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
                      'unsigned', 'void', 'volatile', 'while', '_Bool', '_Complex', '_Noreturn', '__inline',
                      '__inline__', '__restrict', '__restrict__', '__volatile__', '__const'})
SIGNIFICANT = frozenset({'string', 'char', 'number', 'ident', 'punct', 'other', 'pp'})


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class FunctionDef:
    name: str
    start: int          # offset of the first token of the top-level declaration chunk
    body_open: int      # offset of '{'
    body_close: int     # offset of the matching '}'
    first_tok: int      # index into the significant-token list
    open_tok: int
    close_tok: int
    start_line: int
    end_line: int
    name_line: int
    is_static: bool
    is_inline: bool

    @property
    def end(self) -> int:
        return self.body_close + 1


class Source:
    """Tokenised view of one C file; `sig` holds the significant tokens (comments and whitespace dropped)."""

    def __init__(self, text: str):
        self.text = text
        self.tokens = tokenize(text)
        self.sig = [t for t in self.tokens if t.kind in SIGNIFICANT]
        self._lines = [0] + [m.end() for m in re.finditer(r'\n', text)]
        self._functions: list[FunctionDef] | None = None

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self._lines, offset)

    def col_of(self, offset: int) -> int:
        return offset - self._lines[self.line_of(offset) - 1] + 1

    @property
    def functions(self) -> list[FunctionDef]:
        if self._functions is None:
            self._functions = find_functions(self)
        return self._functions

    def function_at_line(self, line: int) -> FunctionDef | None:
        """The definition whose [start_line, end_line] contains `line` (e.g. a DWARF/PDB decl_line)."""
        hits = [f for f in self.functions if f.start_line <= line <= f.end_line]
        return min(hits, key=lambda f: f.end_line - f.start_line) if hits else None

    def by_name(self, name: str) -> list[FunctionDef]:
        return [f for f in self.functions if f.name == name]

    def sig_texts(self, first: int, last: int) -> list[str]:
        """Significant token texts in [first, last] (indices into `sig`), preprocessor lines whitespace-normalised."""
        return [(' '.join(t.text.split()) if t.kind == 'pp' else t.text) for t in self.sig[first:last + 1]]


def tokenize(text: str) -> list[Token]:
    out: list[Token] = []
    pos, n, line_start = 0, len(text), True
    while pos < n:
        if line_start:
            pp = _PP.match(text, pos)
            if pp and pp.group(0).strip().startswith('#'):
                lead = len(pp.group(0)) - len(pp.group(0).lstrip(' \t'))
                if lead:
                    out.append(Token('ws', text[pos:pos + lead], pos, pos + lead))
                out.append(Token('pp', pp.group(0)[lead:], pos + lead, pp.end()))
                pos, line_start = pp.end(), False
                continue
        m = _TOKEN.match(text, pos)
        kind = m.lastgroup
        out.append(Token(kind, m.group(0), pos, m.end()))
        if kind == 'nl':
            line_start = True
        elif kind not in {'ws', 'bcomment'}:
            line_start = False
        pos = m.end()
    return out


def _matching(sig: list[Token], index: int, open_: str, close: str) -> int:
    depth = 0
    for j in range(index, len(sig)):
        if sig[j].kind == 'punct':
            if sig[j].text == open_:
                depth += 1
            elif sig[j].text == close:
                depth -= 1
                if depth == 0:
                    return j
    return len(sig) - 1


def _name_in(sig: list[Token], lo: int, hi: int) -> tuple[str, int] | None:
    """Last identifier directly followed by '(' at the minimal paren depth of [lo, hi)."""
    best: tuple[int, int] | None = None
    depth = 0
    for j in range(lo, hi):
        t = sig[j]
        if t.kind == 'punct' and t.text in '([':
            depth += 1
        elif t.kind == 'punct' and t.text in ')]':
            depth -= 1
        elif (t.kind == 'ident' and t.text not in NOT_NAMES and t.text not in KEYWORDS and j + 1 < hi
              and sig[j + 1].kind == 'punct' and sig[j + 1].text == '('):
            if best is None or depth <= best[0]:
                best = (depth, j)
    return (sig[best[1]].text, best[1]) if best else None


def _chunk_ok(sig: list[Token], lo: int, hi: int) -> bool:
    """A top-level chunk can be a function header: no initializer '=' at paren depth 0, no aggregate keyword
    directly before the brace, and a ')' somewhere."""
    depth, saw_paren = 0, False
    for j in range(lo, hi):
        t = sig[j]
        if t.kind != 'punct':
            continue
        if t.text in '([':
            depth += 1
        elif t.text in ')]':
            depth -= 1
            saw_paren = True
        elif t.text == '=' and depth == 0:
            return False
    if hi - 1 >= lo and sig[hi - 1].kind == 'ident' and hi - 2 >= lo and sig[hi - 2].text in {'struct', 'union', 'enum'}:
        return False
    if hi - 1 >= lo and sig[hi - 1].text in {'struct', 'union', 'enum', '=', ','}:
        return False
    return saw_paren


def find_functions(src: Source) -> list[FunctionDef]:
    sig = src.sig
    out: list[FunctionDef] = []
    chunk_start = 0            # first significant token after the last top-level boundary
    pieces: list[int] = [0]    # starts of ';'-separated pieces since the last hard boundary (for K&R)
    i = 0
    while i < len(sig):
        t = sig[i]
        if t.kind == 'pp':
            chunk_start, pieces = i + 1, [i + 1]
            i += 1
            continue
        if t.kind == 'punct' and t.text in '([':
            i = _matching(sig, i, t.text, ')' if t.text == '(' else ']') + 1
            continue
        if t.kind == 'punct' and t.text == ';':
            pieces.append(i + 1)
            chunk_start = i + 1
            i += 1
            continue
        if t.kind == 'punct' and t.text == '{':
            close = _matching(sig, i, '{', '}')
            found, name_hi = None, i
            if i > chunk_start and _chunk_ok(sig, chunk_start, i) and sig[i - 1].text != ';':
                found = chunk_start
            elif i > 0 and sig[i - 1].text == ';':
                # K&R: `int f(a, b) int a; char *b; {` -- walk back over the parameter declarations to the piece
                # holding the declarator; any initializer or brace on the way means this is not a definition.
                for start in reversed(pieces[-33:-1]):
                    if any(sig[k].text in {'{', '}', '='} for k in range(start, i)):
                        break
                    end = next((k for k in range(start, i) if sig[k].text == ';'), i)
                    if _name_in(sig, start, end) and _chunk_ok(sig, start, end):
                        found, name_hi = start, end
                        break
            if found is not None:
                header_end = i
                named = _name_in(sig, found, name_hi)
                if named:
                    words = {sig[k].text for k in range(found, header_end) if sig[k].kind == 'ident'}
                    out.append(FunctionDef(
                        name=named[0], start=sig[found].start, body_open=t.start, body_close=sig[close].start,
                        first_tok=found, open_tok=i, close_tok=close, start_line=src.line_of(sig[found].start),
                        end_line=src.line_of(sig[close].start), name_line=src.line_of(sig[named[1]].start),
                        is_static='static' in words, is_inline=bool(words & {'inline', '__inline', '__inline__'})))
            i = close + 1
            # a top-level '}' ends a chunk unless a declarator follows (struct ... } name;): the ';' handles that
            if found is not None:
                chunk_start, pieces = i, [i]
            continue
        i += 1
    return out


def body_tokens(src: Source, fn: FunctionDef) -> list[Token]:
    """Significant tokens strictly inside the braces of `fn`."""
    return src.sig[fn.open_tok + 1:fn.close_tok]


def compare_spans(old: Source, old_fn: FunctionDef | None, new: Source, new_fn: FunctionDef | None) -> str:
    """'same-text' | 'layout-only' (tokens equal, comments/whitespace differ) | 'token-change' | 'unknown'."""
    if old_fn is None or new_fn is None:
        return 'unknown'
    if old.text[old_fn.start:old_fn.end] == new.text[new_fn.start:new_fn.end]:
        return 'same-text'
    if old.sig_texts(old_fn.first_tok, old_fn.close_tok) == new.sig_texts(new_fn.first_tok, new_fn.close_tok):
        return 'layout-only'
    return 'token-change'
