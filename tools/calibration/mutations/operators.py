"""Mutation operators (SPEC-32 s8). Each operator is a generator of `Site`s inside ONE function body that
`tier_r/csrc.py` located; it reads the significant-token list (comments, strings, character literals and preprocessor
lines are single tokens, so they are never edited by accident) and yields text edits at token offsets. No regex runs
over the file. Operators propose; the engine compile-checks, so a few proposals that do not compile are expected.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from ..common import det_uniform
from ..tier_r.csrc import KEYWORDS, NOT_NAMES, FunctionDef, Source, Token, _matching, _name_in, tokenize

__all__ = ['Edit', 'Site', 'Ctx', 'OPERATORS_IMPL', 'apply_edits']


@dataclass(frozen=True)
class Edit:
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class Site:
    edits: tuple[Edit, ...]
    before: str = ''
    after: str = ''
    helper: str | None = None
    moved: str | None = None


@dataclass(frozen=True)
class Ctx:
    src: Source
    fn: FunctionDef
    file: str
    seed: int
    operator: str


def apply_edits(text: str, edits: tuple[Edit, ...]) -> str:
    out, pos = [], 0
    for e in sorted(edits, key=lambda x: (x.start, x.end)):
        if e.start < pos or e.end < e.start or e.end > len(text):
            raise ValueError('overlapping or out-of-range edit')
        out.append(text[pos:e.start])
        out.append(e.text)
        pos = e.end
    out.append(text[pos:])
    return ''.join(out)


def _p(t: Token, text: str) -> bool:
    return t.kind == 'punct' and t.text == text


def _replace(ctx: Ctx, tok: Token, text: str) -> Site:
    return Site((Edit(tok.start, tok.end, text),), tok.text, text)


def _insert(pos: int, text: str) -> Site:
    return Site((Edit(pos, pos, text),), '', text.strip())


def _span(ctx: Ctx):
    return range(ctx.fn.open_tok + 1, ctx.fn.close_tok)


def _stmt_points(ctx: Ctx) -> Iterator[int]:
    """Offsets just after the body '{' and after each ';' ending a depth-1 statement. A ';' followed by `else` or
    `while` is skipped (it could end the body of an unbraced if or a do-statement)."""
    sig, fn = ctx.src.sig, ctx.fn
    yield sig[fn.open_tok].end
    parens = braces = 0
    for i in _span(ctx):
        t = sig[i]
        if t.kind != 'punct':
            continue
        if t.text in '([':
            parens += 1
        elif t.text in ')]':
            parens -= 1
        elif t.text == '{':
            braces += 1
        elif t.text == '}':
            braces -= 1
        elif t.text == ';' and parens == 0 and braces == 0:
            nxt = sig[i + 1]
            if nxt.text not in {'else', 'while'}:
                yield t.end


# ---- semantic operators ------------------------------------------------------------------------------------------

_FLIP = {'<': '>=', '>': '<=', '<=': '>', '>=': '<', '==': '!=', '!=': '=='}
_BOUND = {'<': '<=', '<=': '<', '>': '>=', '>=': '>'}
_INT = re.compile(r'^(0[xX][0-9a-fA-F]+|[1-9][0-9]*|0)([uUlL]{0,3})$')


def cmp_flip(ctx: Ctx) -> Iterator[Site]:
    sig = ctx.src.sig
    for i in _span(ctx):
        if sig[i].kind == 'punct' and sig[i].text in _FLIP:
            yield _replace(ctx, sig[i], _FLIP[sig[i].text])


def _bump(number: str) -> str | None:
    m = _INT.match(number)
    if not m:
        return None
    digits, suffix = m.groups()
    if digits[:2] in {'0x', '0X'}:
        body = digits[2:]
        value = format(int(body, 16) + 1, 'X' if any(c.isupper() for c in body) else 'x').zfill(len(body))
        return digits[:2] + value + suffix
    return str(int(digits) + 1) + suffix


def const_change(ctx: Ctx) -> Iterator[Site]:
    sig = ctx.src.sig
    for i in _span(ctx):
        t = sig[i]
        if t.kind == 'number' and sig[i - 1].text != 'case' and (new := _bump(t.text)):
            yield _replace(ctx, t, new)


def _params(ctx: Ctx) -> list[list[Token]]:
    sig, fn = ctx.src.sig, ctx.fn
    named = _name_in(sig, fn.first_tok, fn.open_tok)
    if not named:
        return []
    open_ = named[1] + 1
    close = _matching(sig, open_, '(', ')')
    chunks, cur, depth = [], [], 0
    for t in sig[open_ + 1:close]:
        if t.kind == 'punct' and t.text in '([':
            depth += 1
        elif t.kind == 'punct' and t.text in ')]':
            depth -= 1
        if depth == 0 and _p(t, ','):
            chunks.append(cur)
            cur = []
        else:
            cur.append(t)
    chunks.append(cur)
    return [c for c in chunks if c]


def bounds_check_insert(ctx: Ctx) -> Iterator[Site]:
    sig, fn = ctx.src.sig, ctx.fn
    named = _name_in(sig, fn.first_tok, fn.open_tok)
    if not named:
        return
    ret = [t.text for t in sig[fn.first_tok:named[1]]]
    star = '*' in ret
    if not star and {'struct', 'union'} & set(ret):
        return
    void = 'void' in ret and not star
    value = '' if void else ' 0'
    for chunk in _params(ctx):
        if not any(_p(t, '*') for t in chunk) or any(t.text in {'(', '['} for t in chunk):
            continue
        last = chunk[-1]
        if last.kind != 'ident' or last.text in KEYWORDS or len(chunk) < 3:
            continue
        text = f'\n    if ({last.text} == 0) {{\n        return{value};\n    }}'
        yield _insert(sig[fn.open_tok].end, text)


def _stmt_end(sig: list[Token], j: int, limit: int) -> int | None:
    """Index of the last token of the statement starting at j (a block or a single statement)."""
    if _p(sig[j], '{'):
        return _matching(sig, j, '{', '}')
    depth = 0
    for k in range(j, limit):
        t = sig[k]
        if t.kind == 'punct':
            if t.text in '([{':
                depth += 1
            elif t.text in ')]}':
                depth -= 1
            elif t.text == ';' and depth == 0:
                return k
    return None


def bounds_check_remove(ctx: Ctx) -> Iterator[Site]:
    sig, text = ctx.src.sig, ctx.src.text
    close_tok = ctx.fn.close_tok
    for i in _span(ctx):
        if sig[i].text != 'if' or sig[i].kind != 'ident' or not _p(sig[i + 1], '(') or sig[i - 1].text not in '{};':
            continue
        cond_close = _matching(sig, i + 1, '(', ')')
        if not any(sig[k].kind == 'punct' and sig[k].text in _FLIP for k in range(i + 2, cond_close)):
            continue
        end = _stmt_end(sig, cond_close + 1, close_tok)
        if end is None or sig[end + 1].text == 'else':
            continue
        if not any(sig[k].text in {'return', 'goto', 'break', 'continue'} for k in range(cond_close + 1, end + 1)):
            continue
        yield Site((Edit(sig[i].start, sig[end].end, ''),), text[sig[i].start:sig[end].end][:2000], '')


def _helper_name(ctx: Ctx, index: int) -> str:
    return 'ka_mut_' + format(int(det_uniform(ctx.seed, 'helper', ctx.file, ctx.fn.name, index) * 2**32), '08x')


def call_add(ctx: Ctx) -> Iterator[Site]:
    """Plant a call to a fresh `noinline` helper that writes a volatile sink: valid in freestanding code."""
    fn = ctx.fn
    for index, pos in enumerate(_stmt_points(ctx)):
        name = _helper_name(ctx, index)
        helper = (f'static volatile int {name}_sink;\nstatic __attribute__((noinline)) void {name}(void)\n{{\n'
                  f'    {name}_sink = {name}_sink + 1;\n}}\n\n')
        call = f'\n    {name}();'
        yield Site((Edit(fn.start, fn.start, helper), Edit(pos, pos, call)), '', call.strip(), helper=name)


def call_remove(ctx: Ctx) -> Iterator[Site]:
    sig, text = ctx.src.sig, ctx.src.text
    for i in _span(ctx):
        t = sig[i]
        if (t.kind == 'ident' and t.text not in KEYWORDS and t.text not in NOT_NAMES and _p(sig[i + 1], '(')
                and sig[i - 1].kind == 'punct' and sig[i - 1].text in {'{', '}', ';'}):
            close = _matching(sig, i + 1, '(', ')')
            if _p(sig[close + 1], ';'):
                end = sig[close + 1].end
                yield Site((Edit(t.start, end, ''),), text[t.start:end][:2000], '')


def _args(sig: list[Token], open_: int, close: int) -> list[tuple[int, int]]:
    """Token index ranges [first, last] of the top-level arguments of the call (open_, close)."""
    out, first, depth = [], open_ + 1, 0
    for k in range(open_ + 1, close):
        t = sig[k]
        if t.kind == 'punct' and t.text in '([{':
            depth += 1
        elif t.kind == 'punct' and t.text in ')]}':
            depth -= 1
        elif depth == 0 and _p(t, ','):
            out.append((first, k - 1))
            first = k + 1
    out.append((first, close - 1))
    return out


def arg_swap(ctx: Ctx) -> Iterator[Site]:
    sig, text = ctx.src.sig, ctx.src.text
    for i in _span(ctx):
        t = sig[i]
        prev = sig[i - 1]
        if (t.kind != 'ident' or t.text in KEYWORDS or t.text in NOT_NAMES or not _p(sig[i + 1], '(')
                or (prev.kind == 'ident' and prev.text not in {'return', 'else', 'case', 'do'})):
            continue
        close = _matching(sig, i + 1, '(', ')')
        args = _args(sig, i + 1, close)
        if len(args) < 2 or any(b < a for a, b in args[:2]):
            continue
        (a0, b0), (a1, b1) = args[0], args[1]
        s0, s1 = text[sig[a0].start:sig[b0].end], text[sig[a1].start:sig[b1].end]
        if s0 == s1:
            continue
        yield Site((Edit(sig[a0].start, sig[b0].end, s1), Edit(sig[a1].start, sig[b1].end, s0)),
                   f'{s0}, {s1}', f'{s1}, {s0}')


def loop_bound(ctx: Ctx) -> Iterator[Site]:
    """`for (; i < n; )` / `while (i < n)`: tighten the bound operand by one (`n` -> `n - 1`)."""
    sig = ctx.src.sig
    for i in _span(ctx):
        if sig[i].kind != 'ident' or sig[i].text not in {'for', 'while'} or not _p(sig[i + 1], '('):
            continue
        close = _matching(sig, i + 1, '(', ')')
        lo, hi = i + 2, close
        if sig[i].text == 'for':
            semis = [k for k in range(lo, hi) if _p(sig[k], ';')]
            if len(semis) != 2:
                continue
            lo, hi = semis[0] + 1, semis[1]
        if hi - lo < 3:
            continue
        operand = sig[hi - 1]
        if (operand.kind in {'ident', 'number'} and sig[hi - 2].kind == 'punct' and sig[hi - 2].text in _BOUND
                and operand.text not in KEYWORDS):
            yield _replace(ctx, operand, f'{operand.text} - 1')


def off_by_one(ctx: Ctx) -> Iterator[Site]:
    """Relax or tighten a boundary comparison (`<` <-> `<=`), or index one past (`a[i]` -> `a[i + 1]`)."""
    sig = ctx.src.sig
    for i in _span(ctx):
        t = sig[i]
        if t.kind == 'punct' and t.text in _BOUND:
            yield _replace(ctx, t, _BOUND[t.text])
        elif (_p(t, '[') and i + 2 < len(sig) and sig[i + 1].kind in {'ident', 'number'} and _p(sig[i + 2], ']')
              and (sig[i - 1].kind == 'ident' or sig[i - 1].text in {']', ')'})):
            yield _replace(ctx, sig[i + 1], f'{sig[i + 1].text} + 1')


_NARROW = {'int': 'short', 'long': 'int', 'short': 'char'}


def int_width(ctx: Ctx) -> Iterator[Site]:
    sig = ctx.src.sig
    for i in _span(ctx):
        t = sig[i]
        if (t.kind == 'ident' and t.text in _NARROW and sig[i - 1].text not in {'long', 'struct', 'union', 'enum'}
                and sig[i + 1].text not in {'long', 'double'}):
            yield _replace(ctx, t, _NARROW[t.text])


# ---- cosmetic operators ------------------------------------------------------------------------------------------

def ws_comment(ctx: Ctx) -> Iterator[Site]:
    for pos in _stmt_points(ctx):
        yield _insert(pos, '\n\n    /* planted comment */')


def dead_code(ctx: Ctx) -> Iterator[Site]:
    for pos in _stmt_points(ctx):
        yield _insert(pos, '\n    if (0) {\n        (void)0;\n    }')


def _gap_is_blank(src: Source, lo: int, hi: int) -> bool:
    return all(t.kind in {'ws', 'nl', 'lcomment', 'bcomment'} for t in tokenize(src.text[lo:hi]))


def reorder_defs(ctx: Ctx) -> Iterator[Site]:
    """Swap the target with the next and with the previous definition when only whitespace/comments separate them."""
    fns = ctx.src.functions
    idx = next((k for k, f in enumerate(fns) if f.start == ctx.fn.start), None)
    if idx is None:
        return
    text = ctx.src.text
    pairs = []
    if idx + 1 < len(fns):
        pairs.append((fns[idx], fns[idx + 1], fns[idx + 1].name))
    if idx > 0:
        pairs.append((fns[idx - 1], fns[idx], fns[idx - 1].name))
    for a, b, other in pairs:
        if a.end > b.start or not _gap_is_blank(ctx.src, a.end, b.start):
            continue
        swapped = text[b.start:b.end] + text[a.end:b.start] + text[a.start:a.end]
        first, second = (a, b) if ctx.fn.start == a.start else (b, a)
        yield Site((Edit(a.start, b.end, swapped),), f'{first.name} before {second.name}',
                   f'{second.name} before {first.name}', moved=other)


_TYPE_KW = frozenset({'int', 'char', 'short', 'long', 'unsigned', 'signed', 'float', 'double', '_Bool', 'const',
                      'volatile', 'register', 'static', 'void'})
_NOT_DECL_PREV = frozenset({'return', 'else', 'case', 'goto', 'sizeof', 'do', 'typedef', 'struct', 'union', 'enum'})
_DECL_AFTER = frozenset({',', ';', '=', ')', '['})


def _declared_names(ctx: Ctx) -> list[str]:
    sig, fn = ctx.src.sig, ctx.fn
    seen: list[str] = []
    for i in range(fn.first_tok + 1, fn.close_tok):
        t = sig[i]
        if t.kind != 'ident' or t.text in KEYWORDS or t.text in NOT_NAMES or sig[i + 1].text not in _DECL_AFTER:
            continue
        j = i - 1
        while j > fn.first_tok and _p(sig[j], '*'):
            j -= 1
        prev = sig[j]
        if prev.text in _NOT_DECL_PREV or not (prev.text in _TYPE_KW or prev.kind == 'ident' or _p(prev, '*')):
            continue
        if j != i - 1 and (prev.kind == 'ident' and prev.text not in _TYPE_KW) \
                and sig[j - 1].text not in {'{', ';', '(', ',', 'const', 'volatile', 'static', 'register'}:
            continue
        if t.text not in seen:
            seen.append(t.text)
    return seen


def local_rename(ctx: Ctx) -> Iterator[Site]:
    sig, fn = ctx.src.sig, ctx.fn
    idents = {t.text for t in ctx.src.sig if t.kind == 'ident'}
    pp_text = ' '.join(t.text for t in sig[fn.first_tok:fn.close_tok + 1] if t.kind == 'pp')
    for name in _declared_names(ctx):
        if re.search(rf'\b{re.escape(name)}\b', pp_text):
            continue
        n = 0
        while True:
            new = f'{name}_{int(det_uniform(ctx.seed, "rename", ctx.file, fn.name, name, n) * 2**24):06x}'
            if new not in idents:
                break
            n += 1
        edits = tuple(Edit(t.start, t.end, new) for k in range(fn.first_tok + 1, fn.close_tok)
                      if (t := sig[k]).kind == 'ident' and t.text == name and sig[k - 1].text not in {'.', '->'}
                      and not (_p(sig[k + 1], ':') and sig[k - 1].text in '{};'))
        if edits:
            yield Site(edits, name, new)


def macro_rewrite(ctx: Ctx) -> Iterator[Site]:
    """`return EXPR;` -> `return KA_ID(EXPR);` with `#define KA_ID(x) (x)` before the function."""
    sig, text, fn = ctx.src.sig, ctx.src.text, ctx.fn
    line_start = text.rfind('\n', 0, fn.start) + 1
    if text[line_start:fn.start].strip():
        return
    for i in _span(ctx):
        if sig[i].kind != 'ident' or sig[i].text != 'return':
            continue
        depth, end = 0, None
        for k in range(i + 1, fn.close_tok):
            t = sig[k]
            if t.kind == 'punct' and t.text in '([{':
                depth += 1
            elif t.kind == 'punct' and t.text in ')]}':
                depth -= 1
            elif _p(t, ';') and depth == 0:
                end = k
                break
        if end is None or end == i + 1:
            continue
        name = 'KA_MUT_ID_' + format(int(det_uniform(ctx.seed, 'macro', ctx.file, fn.name, i) * 2**32), '08X')
        yield Site((Edit(line_start, line_start, f'#define {name}(x) (x)\n'),
                    Edit(sig[i + 1].start, sig[i + 1].start, f'{name}('), Edit(sig[end].start, sig[end].start, ')')),
                   text[sig[i].start:sig[end].end][:2000], f'return {name}(...);')


def inline_toggle(ctx: Ctx) -> Iterator[Site]:
    sig, text, fn = ctx.src.sig, ctx.src.text, ctx.fn
    if not fn.is_static:
        return
    header = [sig[k] for k in range(fn.first_tok, fn.open_tok) if sig[k].kind == 'ident']
    inl = [t for t in header if t.text in {'inline', '__inline', '__inline__'}]
    if inl:
        t = inl[0]
        end = t.end + (1 if text[t.end:t.end + 1] == ' ' else 0)
        yield Site((Edit(t.start, end, ''),), t.text, '')
    else:
        static = next((t for t in header if t.text == 'static'), None)
        if static:
            yield Site((Edit(static.start, static.end, 'static inline'),), 'static', 'static inline')


Operator = Callable[[Ctx], Iterator[Site]]
OPERATORS_IMPL: dict[str, Operator] = {
    'cmp-flip': cmp_flip, 'const-change': const_change, 'bounds-check-insert': bounds_check_insert,
    'bounds-check-remove': bounds_check_remove, 'call-add': call_add, 'call-remove': call_remove,
    'arg-swap': arg_swap, 'loop-bound': loop_bound, 'off-by-one': off_by_one, 'int-width': int_width,
    'ws-comment': ws_comment, 'dead-code': dead_code, 'reorder-defs': reorder_defs, 'local-rename': local_rename,
    'macro-rewrite': macro_rewrite, 'inline-toggle': inline_toggle}
