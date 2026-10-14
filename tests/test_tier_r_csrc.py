"""SPEC-32 s5.3 C locator: tokenizer and function finder on hostile but valid C (pure, no compiler)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r.csrc import Source, body_tokens, compare_spans, tokenize  # noqa: E402

HOSTILE = r'''/* header { not a brace } */
#include "x.h"
#define BLOCK(x) do { if (x) { return; } } while (0) \
    /* continued { */
#if defined(A) && B > 2
#  define C 1
#endif
static const char *s = "brace { in string } /* not a comment */";
static const char c = '{';
struct point { int x, y; };
enum color { RED, GREEN };
typedef struct { int (*fp)(int); } ops_t;
int table[] = { 1, 2, 3 };
static struct point origin = { 0, 0 };

int plain(int a, int b)
{
    // comment with } brace
    if (a > b) { return a; }
    return b; /* } */
}

static inline int tiny(int v) { return v + '}'; }

int knr(a, b)
    int a;
    char *b;
{
    return a + (b != 0);
}

int (*get_handler(int which))(int)
{
    return which ? 0 : 0;
}

PNG_FUNCTION(void *, png_like, (int size), PNG_ALLOCATED)
{
    return (void *)0;
}

int __attribute__((noinline)) attributed(void) __attribute__((cold));
int __attribute__((noinline)) attributed(void)
{
#if FOO
    return 1;
#else
    return 2;
#endif
}
'''


def test_tokenizer_keeps_strings_comments_and_preprocessor_whole():
    toks = tokenize(HOSTILE)
    kinds = {t.kind for t in toks}
    assert {'bcomment', 'lcomment', 'string', 'char', 'pp'} <= kinds
    assert ''.join(t.text for t in toks) == HOSTILE  # lossless
    pp = [t.text for t in toks if t.kind == 'pp']
    assert pp[1].startswith('#define BLOCK') and pp[1].rstrip().endswith('*/')  # continuation joined


def test_finds_every_definition_and_nothing_else():
    src = Source(HOSTILE)
    names = [f.name for f in src.functions]
    assert names == ['plain', 'tiny', 'knr', 'get_handler', 'PNG_FUNCTION', 'attributed']
    tiny = src.by_name('tiny')[0]
    assert tiny.is_static and tiny.is_inline
    knr = src.by_name('knr')[0]
    assert src.text[knr.start:knr.start + 7] == 'int knr' and src.line_of(knr.body_open) == knr.start_line + 3
    plain = src.by_name('plain')[0]
    assert src.text[plain.body_close] == '}' and src.text[plain.start:plain.end].endswith('/* } */\n}')
    assert [t.text for t in body_tokens(src, tiny)] == ['return', 'v', '+', "'}'", ';']


def test_function_at_line_uses_debug_info_lines():
    src = Source(HOSTILE)
    png = next(f for f in src.functions if f.name == 'PNG_FUNCTION')
    assert src.function_at_line(png.name_line + 2) is png  # macro-wrapped: the debug-info name is used instead
    assert src.function_at_line(1) is None


def test_compare_spans_categories():
    old = Source('int f(int a)\n{\n    return a + 1; /* one */\n}\n')
    same = Source('int f(int a)\n{\n    return a + 1; /* one */\n}\n')
    layout = Source('\n\nint f(int a)\n{\n\n    return a + 1; /* changed comment */\n}\n')
    change = Source('int f(int a)\n{\n    return a + 2;\n}\n')
    fo = old.functions[0]
    assert compare_spans(old, fo, same, same.functions[0]) == 'same-text'
    assert compare_spans(old, fo, layout, layout.functions[0]) == 'layout-only'
    assert compare_spans(old, fo, change, change.functions[0]) == 'token-change'
    assert compare_spans(old, fo, change, None) == 'unknown'


def test_unterminated_constructs_do_not_hang():
    for text in ('int f(void) { return "abc', 'int f(void) { /* open', "char c = '", 'int f(void) {{{', '#define X \\'):
        src = Source(text)
        assert isinstance(src.functions, list)
