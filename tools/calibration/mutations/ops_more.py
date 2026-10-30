"""The nine LBL-06 source operators added to the first sixteen (LBL s7.2): `signedness-flip`, `callee-swap`,
`field-offset`, `global-swap`, `index-swap`, `branch-swap`, `buf-resize`, `string-literal`, `api-use`.

Same contract as `operators.py`: token-level proposals inside ONE located function body, no regex over the source;
the engine compile-checks every proposal and the masked-body rule decides acceptance. Operators that need a
declaration from outside the body (struct fields, globals, callee prototypes) read only the SAME file; a name that
is ambiguous there yields no site rather than a guess.
"""
from __future__ import annotations

from collections.abc import Iterator

from ..tier_r.csrc import KEYWORDS, FunctionDef, Source, Token, _matching, _name_in
from .operators import Ctx, Edit, Site, _args, _bump, _declared_names, _p, _params, _replace, _span, _stmt_end

__all__ = ['MORE_IMPL']

_INTS = frozenset({'int', 'char', 'short', 'long'})
_SCALAR = frozenset({'int', 'char', 'short', 'long', 'unsigned', 'signed', 'size_t', 'const', 'uint8_t', 'uint16_t',
                     'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t'})
_STORAGE = frozenset({'static', 'extern', 'inline', '__inline', '__inline__', 'register'})
_COMPOUND = frozenset({'if', 'for', 'while', 'do', 'switch', 'else'})
_NOT_DECL = frozenset({'return', 'case', 'goto', 'sizeof', 'typedef'})


# ---- signedness-flip ---------------------------------------------------------------------------------------------

def signedness_flip(ctx: Ctx) -> Iterator[Site]:
    """`int x` -> `unsigned int x` and back, in declarations and casts of the body (jl/jb, sign vs zero extension)."""
    sig, text = ctx.src.sig, ctx.src.text
    for i in _span(ctx):
        t, prev, nxt = sig[i], sig[i - 1], sig[i + 1]
        if t.kind != 'ident':
            continue
        if t.text == 'unsigned':
            if nxt.text in _INTS:
                yield Site((Edit(t.start, nxt.start, ''),), text[t.start:nxt.end], nxt.text)
            elif nxt.kind == 'ident' and nxt.text not in KEYWORDS:
                yield _replace(ctx, t, 'int')
        elif (t.text in _INTS and prev.text not in {'unsigned', 'signed', 'long', 'struct', 'union', 'enum', 'sizeof'}
              and nxt.text not in {'long', 'double', 'unsigned'} and not (prev.text == '(' and sig[i - 2].text == 'sizeof')
              and (prev.text in {'{', ';', '(', ',', 'const', 'static', 'register'} or prev.kind == 'ident')
              and (nxt.kind == 'ident' or nxt.text == ')') and nxt.text not in KEYWORDS - _INTS):
            yield _replace(ctx, t, 'unsigned ' + t.text)


# ---- callee-swap -------------------------------------------------------------------------------------------------

def _prototype(src: Source, fn: FunctionDef) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]] | None:
    """(return type tokens, parameter type tokens without names); None when the header is not a plain prototype."""
    sig = src.sig
    named = _name_in(sig, fn.first_tok, fn.open_tok)
    if not named:
        return None
    ret = tuple(t.text for t in sig[fn.first_tok:named[1]] if t.text not in _STORAGE)
    open_ = named[1] + 1
    close = _matching(sig, open_, '(', ')')
    params, cur = [], []
    for t in sig[open_ + 1:close]:
        if _p(t, ','):
            params.append(cur)
            cur = []
        else:
            cur.append(t.text)
    params.append(cur)
    if any(x in {'(', '['} for p in params for x in p):
        return None
    typed = tuple(tuple(p[:-1] if len(p) > 1 and p[-1] not in KEYWORDS and p[-1] != '*' else p) for p in params)
    return ret, typed


def callee_swap(ctx: Ctx) -> Iterator[Site]:
    """Call `f(...)` -> `g(...)` where `g` is an earlier definition in the file with the same prototype."""
    src, sig = ctx.src, ctx.src.sig
    protos: dict[str, tuple] = {}
    for fn in src.functions:
        if fn.start < ctx.fn.start and fn.name not in protos and (p := _prototype(src, fn)):
            protos[fn.name] = p
    for i in _span(ctx):
        t, prev = sig[i], sig[i - 1]
        if (t.kind != 'ident' or t.text not in protos or not _p(sig[i + 1], '(') or prev.text in {'.', '->'}
                or (prev.kind == 'ident' and prev.text not in {'return', 'else', 'case', 'do'})):
            continue
        for other in sorted(protos):
            if other != t.text and other != ctx.fn.name and protos[other] == protos[t.text]:
                yield _replace(ctx, t, other)


# ---- field-offset ------------------------------------------------------------------------------------------------

def _struct_fields(src: Source) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    """field name -> [(sibling name, sibling type)] for every `struct|union [tag] { ... }` body of the file."""
    sig = src.sig
    structs: list[list[tuple[str, tuple[str, ...]]]] = []
    for i, t in enumerate(sig):
        if t.text not in {'struct', 'union'}:
            continue
        j = i + 1 + (sig[i + 1].kind == 'ident' and sig[i + 1].text not in KEYWORDS)
        if j >= len(sig) or not _p(sig[j], '{'):
            continue
        close = _matching(sig, j, '{', '}')
        fields, chunk = [], []
        for t2 in sig[j + 1:close]:
            if _p(t2, ';'):
                if (len(chunk) >= 2 and chunk[-1].kind == 'ident' and chunk[-1].text not in KEYWORDS
                        and not any(c.text in {'(', '[', '{', ':', ','} for c in chunk)):
                    fields.append((chunk[-1].text, tuple(c.text for c in chunk[:-1])))
                chunk = []
            else:
                chunk.append(t2)
        structs.append(fields)
    owners: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
    counts: dict[str, int] = {}
    for fields in structs:
        for name, _ in fields:
            counts[name] = counts.get(name, 0) + 1
            owners[name] = fields
    return {name: owners[name] for name, n in counts.items() if n == 1}


def field_offset(ctx: Ctx) -> Iterator[Site]:
    """`p->a` -> `p->b` where `a` and `b` are same-typed fields of one struct defined in this file."""
    sig = ctx.src.sig
    fields = _struct_fields(ctx.src)
    for i in _span(ctx):
        t = sig[i]
        if t.kind != 'ident' or sig[i - 1].text not in {'.', '->'} or t.text not in fields:
            continue
        mine = dict(fields[t.text])[t.text]
        for name, typ in fields[t.text]:
            if name != t.text and typ == mine:
                yield _replace(ctx, t, name)


# ---- global-swap -------------------------------------------------------------------------------------------------

def _globals(src: Source) -> dict[str, tuple[int, tuple[str, ...]]]:
    """File-scope scalar variables: name -> (offset of the declaration end, type tokens)."""
    sig = src.sig
    spans = [(f.first_tok, f.close_tok) for f in src.functions]
    out: dict[str, tuple[int, tuple[str, ...]]] = {}
    chunk: list[Token] = []
    depth = 0
    i = 0
    while i < len(sig):
        for lo, hi in spans:
            if i == lo:
                chunk, i = [], hi + 1
                break
        else:
            t = sig[i]
            i += 1
            if t.kind == 'pp':
                continue
            if t.kind == 'punct' and t.text in '{([':
                depth += 1
            elif t.kind == 'punct' and t.text in '})]':
                depth -= 1
            if depth > 0 or (t.kind == 'punct' and t.text in '})'):
                chunk.append(t)
                continue
            if _p(t, ';'):
                if not any(c.text in {'(', ')', '[', '{', '}', 'typedef', ','} for c in chunk):
                    head = [c for c in chunk[:next((k for k, c in enumerate(chunk) if _p(c, '=')), len(chunk))]]
                    if len(head) >= 2 and head[-1].kind == 'ident' and head[-1].text not in KEYWORDS:
                        typ = tuple(c.text for c in head[:-1] if c.text not in {'static', 'extern'})
                        if typ and all(x in _SCALAR or x == '*' for x in typ):
                            out.setdefault(head[-1].text, (t.end, typ))
                chunk = []
            else:
                chunk.append(t)
    return out


def global_swap(ctx: Ctx) -> Iterator[Site]:
    """A use of file-scope variable `g` -> another file-scope variable of the same scalar type declared earlier."""
    sig, fn = ctx.src.sig, ctx.fn
    globs = {n: v for n, v in _globals(ctx.src).items() if v[0] <= fn.start}
    shadow = set(_declared_names(ctx)) | {t.text for t in sig[fn.first_tok:fn.open_tok] if t.kind == 'ident'}
    for i in _span(ctx):
        t = sig[i]
        if (t.kind != 'ident' or t.text not in globs or t.text in shadow or sig[i - 1].text in {'.', '->'}
                or _p(sig[i + 1], ':')):
            continue
        for other in sorted(globs):
            if other != t.text and other not in shadow and globs[other][1] == globs[t.text][1]:
                yield _replace(ctx, t, other)


# ---- index-swap --------------------------------------------------------------------------------------------------

def _int_names(ctx: Ctx) -> dict[str, int]:
    """Integer-typed parameters and simple locals -> token index of the declaration (-1 for parameters)."""
    sig = ctx.src.sig
    out: dict[str, int] = {}
    for chunk in _params(ctx):
        last = chunk[-1]
        if len(chunk) >= 2 and last.kind == 'ident' and last.text not in KEYWORDS and all(
                c.text in _SCALAR for c in chunk[:-1]):
            out.setdefault(last.text, -1)
    for i in _span(ctx):
        if (sig[i].text in {'int', 'short', 'long', 'unsigned', 'size_t'} and sig[i - 1].text in {'{', ';', '(', 'const'}
                and sig[i + 1].kind == 'ident' and sig[i + 1].text not in KEYWORDS
                and sig[i + 2].text in {',', ';', '='}):
            out.setdefault(sig[i + 1].text, i + 1)
    return out


def index_swap(ctx: Ctx) -> Iterator[Site]:
    """`a[i]` -> `a[j]` where `j` is another integer variable already in scope at the site."""
    sig = ctx.src.sig
    ints = _int_names(ctx)
    for i in _span(ctx):
        if (_p(sig[i], '[') and sig[i + 1].kind == 'ident' and _p(sig[i + 2], ']') and sig[i + 1].text in ints
                and (sig[i - 1].kind == 'ident' or sig[i - 1].text in {']', ')'})):
            cur = sig[i + 1]
            for name in ints:
                if name != cur.text and ints[name] < i:
                    yield _replace(ctx, cur, name)


# ---- branch-swap -------------------------------------------------------------------------------------------------

def _plain_branch(sig: list[Token], start: int, limit: int) -> int | None:
    """Last token of a braced block or a simple statement; None for if/for/while/do/switch (dangling-else risk)."""
    if sig[start].text in _COMPOUND:
        return None
    return _stmt_end(sig, start, limit)


def branch_swap(ctx: Ctx) -> Iterator[Site]:
    """`if (c) A else B` -> `if (c) B else A`."""
    sig, text = ctx.src.sig, ctx.src.text
    limit = ctx.fn.close_tok
    for i in _span(ctx):
        if sig[i].text != 'if' or sig[i].kind != 'ident' or not _p(sig[i + 1], '('):
            continue
        a0 = _matching(sig, i + 1, '(', ')') + 1
        a1 = _plain_branch(sig, a0, limit)
        if a1 is None or sig[a1 + 1].text != 'else':
            continue
        b0 = a1 + 2
        b1 = _plain_branch(sig, b0, limit)
        if b1 is None:
            continue
        a, b = text[sig[a0].start:sig[a1].end], text[sig[b0].start:sig[b1].end]
        if a != b:
            yield Site((Edit(sig[a0].start, sig[a1].end, b), Edit(sig[b0].start, sig[b1].end, a)),
                       a[:2000], b[:2000])


# ---- buf-resize --------------------------------------------------------------------------------------------------

def buf_resize(ctx: Ctx) -> Iterator[Site]:
    """Grow a one-dimensional automatic array (`char buf[64]` -> `char buf[80]`). Only the stack frame changes, so
    engines must land `review` (never cosmetic); `static` and `extern` arrays are data, not frame, and are skipped."""
    sig, fn = ctx.src.sig, ctx.fn
    names = set(_declared_names(ctx))
    for i in _span(ctx):
        n = sig[i + 1]
        if (sig[i].kind != 'ident' or sig[i].text not in names or not _p(n, '[') or sig[i + 2].kind != 'number'
                or not _p(sig[i + 3], ']') or sig[i + 4].text not in {';', '=', ','}):
            continue
        k = i
        while k > fn.open_tok and sig[k - 1].text not in {';', '{', '}'}:
            k -= 1
        head = sig[k:i]
        if (not head or head[0].text in _NOT_DECL or {'static', 'extern'} & {t.text for t in head}
                or any(t.kind != 'ident' and not _p(t, '*') for t in head)):
            continue
        if grown := _grow(sig[i + 2].text):
            yield _replace(ctx, sig[i + 2], grown)


def _grow(number: str) -> str | None:
    """The literal plus 16, keeping its radix and suffix; None when it is not a plain integer."""
    for _ in range(16):
        number = _bump(number)
        if number is None:
            return None
    return number


# ---- string-literal ----------------------------------------------------------------------------------------------

_NOT_STRING_CONTEXT = frozenset({'__attribute__', 'asm', '__asm__', '__asm', '_Static_assert', 'static_assert',
                                 '__declspec', '_Pragma'})


def string_literal(ctx: Ctx) -> Iterator[Site]:
    """Append one character to a plain string literal of the body (length and contents change)."""
    sig = ctx.src.sig
    for i in _span(ctx):
        t = sig[i]
        if (t.kind != 'string' or not t.text.startswith('"') or len(t.text) < 2 or not t.text.endswith('"')
                or sig[i - 1].kind == 'string' or sig[i + 1].kind == 'string'
                or sig[i - 2].text in _NOT_STRING_CONTEXT):
            continue
        new = t.text[:-1] + '!"'
        yield Site((Edit(t.start, t.end, new),), t.text[:2000], new[:2000])


# ---- api-use -----------------------------------------------------------------------------------------------------

# callee -> (replacement, index of the argument dropped or None). Replacements are the classic unbounded
# counterparts; the Windows-only names make the operator mingw-profile only (`registry.PROFILE_ONLY`).
API_SWAPS: dict[str, tuple[str, int | None]] = {
    'memcpy': ('memmove', None), 'memmove': ('memcpy', None), 'strncpy': ('strcpy', 2), 'strncat': ('strcat', 2),
    'snprintf': ('sprintf', 1), '_snprintf': ('sprintf', 1), 'vsnprintf': ('vsprintf', 1),
    'lstrcpynA': ('lstrcpyA', 2), 'lstrcpynW': ('lstrcpyW', 2), 'strncmp': ('strcmp', 2)}


def api_use(ctx: Ctx) -> Iterator[Site]:
    """Replace a bounded or checked API call by its unbounded sibling, dropping the size argument when needed."""
    sig, text = ctx.src.sig, ctx.src.text
    for i in _span(ctx):
        t = sig[i]
        if t.kind != 'ident' or t.text not in API_SWAPS or not _p(sig[i + 1], '(') or sig[i - 1].text in {'.', '->'}:
            continue
        new, drop = API_SWAPS[t.text]
        close = _matching(sig, i + 1, '(', ')')
        args = _args(sig, i + 1, close)
        if drop is None:
            yield _replace(ctx, t, new)
        elif len(args) > drop and all(b >= a for a, b in args):
            if drop == len(args) - 1:
                start, end = sig[args[drop - 1][1]].end, sig[args[drop][1]].end
            else:
                start, end = sig[args[drop][0]].start, sig[args[drop + 1][0]].start
            yield Site((Edit(t.start, t.end, new), Edit(start, end, '')),
                       text[t.start:sig[close].end][:2000], new)


MORE_IMPL = {'signedness-flip': signedness_flip, 'callee-swap': callee_swap, 'field-offset': field_offset,
             'global-swap': global_swap, 'index-swap': index_swap, 'branch-swap': branch_swap,
             'buf-resize': buf_resize, 'string-literal': string_literal, 'api-use': api_use}
