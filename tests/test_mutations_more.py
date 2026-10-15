"""LBL-06: the nine added source operators (signedness-flip, callee-swap, field-offset, global-swap, index-swap,
branch-swap, buf-resize, string-literal, api-use): sites with exact goldens, compile (clang -fsyntax-only; BLOCKED,
never a silent skip, without clang), determinism, rejections, the masked-body acceptance rule, profile gating."""
from __future__ import annotations

import pytest

from tools.calibration.mutations import contracts as MC
from tools.calibration.mutations import coverage
from tools.calibration.mutations import engine as E
from tools.calibration.mutations import labels as L
from tools.calibration.mutations.operators import apply_edits
from tools.calibration.mutations.registry import OPERATORS_IMPL, PROFILE_ONLY
from tools.calibration.tier_r import toolchain as T
from tools.calibration.tier_r.csrc import Source

NEW_OPS = ('signedness-flip', 'callee-swap', 'field-offset', 'global-swap', 'index-swap', 'branch-swap',
           'buf-resize', 'string-literal', 'api-use')
CODE = '''typedef unsigned long size_t;
void *memcpy(void *d, const void *s, size_t n);
char *strncpy(char *d, const char *s, size_t n);
char *strcpy(char *d, const char *s);
void *memmove(void *d, const void *s, size_t n);
int note(int v);
int emit(const char *s, int v);
struct pair { int first; int second; char tag; };
int g_a = 1;
int g_b = 2;
long g_wide = 3;

__attribute__((noinline)) static int twice(int v)
{
    return v * 2;
}

__attribute__((noinline)) static int thrice(int v)
{
    return v * 3;
}

int pick(const int *p, int i, int j)
{
    int k = 0;
    k = p[i] + p[j];
    return k;
}

int sgn(int a, int b)
{
    int d = a - b;
    if (d < 0) {
        return 1;
    }
    return 0;
}

int dispatch(int v)
{
    return twice(v) + 1;
}

int fields(struct pair *s)
{
    return s->first - s->second;
}

int glob(int v)
{
    return v + g_a;
}

int branch(int x, int y)
{
    int r;
    if (x > y) {
        r = x - y;
    } else {
        r = y - x + 7;
    }
    return r;
}

int frame(int n)
{
    char buf[64];
    int i;
    for (i = 0; i < 64; i++) {
        buf[i] = (char)(n + i);
    }
    return buf[n & 63];
}

int shout(int v)
{
    return emit("hello", v);
}

int strsz(void)
{
    return (int)sizeof("hello");
}

void copy(char *d, const char *s, size_t n)
{
    strncpy(d, s, n);
    memcpy(d, s, n);
}
'''
FILES = {'m.c': CODE}
BASE = MC.SourceRef(suite='_template/more', version='v1', license_spdx='MIT')
TARGET = {'signedness-flip': 'sgn', 'callee-swap': 'dispatch', 'field-offset': 'fields', 'global-swap': 'glob',
          'index-swap': 'pick', 'branch-swap': 'branch', 'buf-resize': 'frame', 'string-literal': 'shout',
          'api-use': 'copy'}
# (before, after) of the first candidate per operator on its target function, in source order: the goldens.
GOLDEN = {
    'signedness-flip': [('int', 'unsigned int')],
    'callee-swap': [('twice', 'thrice')],
    'field-offset': [('first', 'second'), ('second', 'first')],
    'global-swap': [('g_a', 'g_b')],
    'index-swap': [('i', 'k'), ('i', 'j'), ('j', 'k'), ('j', 'i')],
    'branch-swap': [('{\n        r = x - y;\n    }', '{\n        r = y - x + 7;\n    }')],
    'buf-resize': [('64', '80')],
    'string-literal': [('"hello"', '"hello!"')],
    'api-use': [('strncpy(d, s, n)', 'strcpy'), ('memcpy', 'memmove')],
}


@pytest.fixture(scope='module')
def chain():
    return T.probe(names=['clang'])


@pytest.fixture
def clang(chain, record_live_status):
    if not chain.get('clang').ok:
        record_live_status('mutations-clang', 'blocked', str(chain.get('clang').reason))
        pytest.skip(f'BLOCKED (recorded, not a pass): clang: {chain.get("clang").reason}')
    return chain


def plan(op, files=FILES, fn=None):
    return E.plan_mutants(files, op, seed=1, target=('m.c', fn or TARGET[op]))


def test_registry_has_all_25_source_operators_and_contracts_agree():
    assert set(OPERATORS_IMPL) == set(MC.SEMANTIC_OPERATORS) | set(MC.COSMETIC_OPERATORS[:6])
    assert len(OPERATORS_IMPL) == 25 and set(NEW_OPS) <= set(OPERATORS_IMPL)
    assert all(MC.kind_of(op) == 'semantic' for op in NEW_OPS)
    assert PROFILE_ONLY == {'api-use': ('mingw-gcc', 'mingw-clang')}
    assert coverage.unmapped_operators() == []


@pytest.mark.parametrize('op', NEW_OPS)
def test_golden_sites_in_source_order(op):
    cands = sorted(plan(op), key=lambda c: (c.line, c.column))
    assert [(c.before, c.after) for c in cands] == GOLDEN[op]
    assert all(c.operator == op and c.function == TARGET[op] for c in cands)
    assert len({c.key for c in cands}) == len(cands)
    assert plan(op) == plan(op)


@pytest.mark.parametrize('op', NEW_OPS)
def test_every_candidate_edits_only_its_function(op):
    for cand in plan(op):
        new = apply_edits(CODE, cand.edits)
        assert new != CODE
        old_src, new_src = Source(CODE), Source(new)
        for fn in old_src.functions:
            if fn.name == TARGET[op]:
                continue
            twin = new_src.by_name(fn.name)[0]
            assert old_src.text[fn.start:fn.end] == new_src.text[twin.start:twin.end]


@pytest.mark.parametrize('op', NEW_OPS)
def test_apply_compiles_records_and_is_deterministic(clang, op):
    kw = dict(seed=4, base=BASE, tools=clang, target=('m.c', TARGET[op]))
    out, again = E.apply_case(FILES, op, **kw), E.apply_case(FILES, op, **kw)
    assert out.files == again.files and out.case == again.case
    case = out.case
    assert (case.operator, case.kind, case.target_function) == (op, 'semantic', TARGET[op])
    assert (case.site.before, case.site.after) in GOLDEN[op]
    assert case.patch_sha256 == MC.patch_digest(FILES, out.files) and out.changed == ('m.c',)
    assert MC.load_case(MC.dump_case(case)) == case
    assert E.replay_case(FILES, case) == out.files


@pytest.mark.parametrize('op, hostile', [
    ('signedness-flip', '/* int x */ const char *s = "int x";\nint f(void)\n{\n    return sizeof(int);\n}\n'),
    ('string-literal', '#include "a.h"\nint f(void)\n{\n    return sizeof("a" "b");\n}\n'),
    ('branch-swap', 'int f(int a)\n{\n    if (a) return 1;\n    return 3;\n}\n'),
    ('buf-resize', 'int f(void)\n{\n    static char t[8];\n    return t[0];\n}\n'),
    ('callee-swap', 'int g(int);\nint f(int a)\n{\n    return g(a);\n}\n')])
def test_unsafe_constructs_are_not_sites(op, hostile):
    assert E.plan_mutants({'h.c': hostile}, op, seed=1, target=('h.c', 'f')) == []


def test_signedness_flip_reverses_unsigned_declarations():
    files = {'u.c': 'int f(unsigned int a)\n{\n    unsigned int b = a;\n    unsigned c = b;\n    return (int)c;\n}\n'}
    got = sorted((c.before, c.after) for c in E.plan_mutants(files, 'signedness-flip', seed=1))
    assert got == [('int', 'unsigned int'), ('unsigned', 'int'), ('unsigned int', 'int')]


def test_index_swap_only_uses_variables_declared_before_the_site():
    files = {'i.c': 'int f(const int *p, int i)\n{\n    int a = p[i];\n    int j = 2;\n    return a + p[j];\n}\n'}
    got = sorted((c.line, c.before, c.after) for c in E.plan_mutants(files, 'index-swap', seed=1))
    assert (3, 'i', 'j') not in got and (5, 'j', 'i') in got and (5, 'j', 'a') in got


def test_field_offset_and_global_swap_need_same_type_and_one_owner():
    ambiguous = {'a.c': 'struct x { int v; int w; };\nstruct y { int v; };\n'
                        'int f(struct x *p)\n{\n    return p->v;\n}\n'}
    assert E.plan_mutants(ambiguous, 'field-offset', seed=1, target=('a.c', 'f')) == []
    assert [c.after for c in plan('field-offset')] == ['second', 'first']
    assert not any(c.after == 'tag' for c in plan('field-offset'))
    wide = {'g.c': 'static int a;\nstatic long w;\nint f(void)\n{\n    return w;\n}\n'}
    assert E.plan_mutants(wide, 'global-swap', seed=1, target=('g.c', 'f')) == []
    shadowed = {'g.c': 'static int a;\nstatic int b;\nint f(int a)\n{\n    return a;\n}\n'}
    assert E.plan_mutants(shadowed, 'global-swap', seed=1, target=('g.c', 'f')) == []


def test_api_use_drops_the_size_argument_and_is_profile_gated(clang):
    out = E.apply_case(FILES, 'api-use', seed=1, base=BASE, tools=clang, target=('m.c', 'copy'), max_attempts=3,
                       profile='mingw-gcc')
    text = Source(out.files['m.c']).text
    assert 'strcpy(d, s);' in text or 'memmove(d, s, n);' in text
    for profile in ('msvc', 'clang-cl'):
        with pytest.raises(E.OperatorUnavailable, match='mingw'):
            E.apply_case(FILES, 'api-use', seed=1, base=BASE, tools=clang, profile=profile)
    other = E.apply_case(FILES, 'cmp-flip', seed=1, base=BASE, tools=clang, profile='msvc')
    assert other.case.operator == 'cmp-flip'


def test_api_use_middle_argument_drop():
    files = {'s.c': 'int snprintf(char *d, unsigned long n, const char *f, ...);\n'
                    'void f(char *d)\n{\n    snprintf(d, 8, "x%d", 1);\n}\n'}
    (cand,) = E.plan_mutants(files, 'api-use', seed=1, target=('s.c', 'f'))
    assert apply_edits(files['s.c'], cand.edits).endswith('    sprintf(d, "x%d", 1);\n}\n')


def test_rejections_are_recorded_and_the_next_site_is_tried():
    cands = plan('api-use')
    seen = []

    def checker(tree, rel):
        seen.append(rel)
        return 'synthetic' if len(seen) == 1 else None
    out = E.apply_case(FILES, 'api-use', seed=2, base=BASE, checker=checker, target=('m.c', 'copy'))
    assert len(cands) == 2 and out.case.attempts == 2
    assert [r.reason for r in out.case.rejected] == ['synthetic']


@pytest.mark.parametrize('op', ('callee-swap', 'global-swap'))
def test_swap_operators_compile_only_with_earlier_declarations(clang, op):
    for cand in plan(op):
        new = dict(FILES, **{'m.c': apply_edits(CODE, cand.edits)})
        assert E.make_compile_checker(clang)(new, 'm.c') is None


# ---- masked-body acceptance rule --------------------------------------------------------------------------------

def check_for(clang):
    return E.make_masked_body_check(FILES, clang)


@pytest.mark.parametrize('op', ('signedness-flip', 'field-offset', 'index-swap', 'branch-swap', 'buf-resize'))
def test_masked_body_rule_accepts_code_changing_operators(clang, op):
    out = E.apply_case(FILES, op, seed=3, base=BASE, tools=clang, target=('m.c', TARGET[op]), max_attempts=10,
                       extra_check=check_for(clang))
    assert out.case.attempts == len(out.case.rejected) + 1
    old, new = Source(CODE), Source(out.files['m.c'])
    fn = TARGET[op]
    assert old.text[old.by_name(fn)[0].start:old.by_name(fn)[0].end] != new.text[new.by_name(fn)[0].start:
                                                                                  new.by_name(fn)[0].end]


def test_masked_body_rule_rejects_address_only_changes_and_records_them(clang):
    # strings, callees and globals live behind masked symbols: the label noise the rule exists to catch
    for op, fn in (('string-literal', 'shout'), ('callee-swap', 'dispatch'), ('global-swap', 'glob'),
                   ('api-use', 'copy')):
        with pytest.raises(E.NoMutationSite) as err:
            E.apply_case(FILES, op, seed=3, base=BASE, tools=clang, target=('m.c', fn), max_attempts=10,
                         extra_check=check_for(clang))
        assert err.value.rejected and all('masked body' in r.reason for r in err.value.rejected), op


def test_masked_body_rule_accepts_a_string_that_changes_code(clang):
    out = E.apply_case(FILES, 'string-literal', seed=3, base=BASE, tools=clang, target=('m.c', 'strsz'),
                       extra_check=check_for(clang))
    assert (out.case.site.before, out.case.site.after) == ('"hello"', '"hello!"') and out.case.attempts == 1


def test_masked_body_rule_for_cosmetic_requires_equality(clang):
    check = check_for(clang)
    out = E.apply_case(FILES, 'dead-code', seed=3, base=BASE, tools=clang, target=('m.c', 'sgn'), extra_check=check)
    assert out.case.kind == 'cosmetic' and out.case.attempts == 1
    flipped = E.apply_case(FILES, 'cmp-flip', seed=3, base=BASE, tools=clang, target=('m.c', 'sgn'))
    cosmetic = plan('ws-comment', fn='sgn')[0]
    assert check(cosmetic, flipped.files) == 'cosmetic mutant changed the masked body'
    gone = plan('ws-comment', fn='missing_fn') or [cosmetic.__class__(**{**cosmetic.__dict__, 'function': 'nope'})]
    assert 'not comparable' in check(gone[0], FILES)


def test_labels_agree_with_the_source_layer_rule():
    for op in NEW_OPS:
        d = L.label_mutation(op, 't', [L.FunctionFact('t', True, True, True)])[0]
        assert (d.label, d.change_kind, d.check) == ('changed', op, 'disagree')
        d = L.label_mutation(op, 't', [L.FunctionFact('t', True, True, False)])[0]
        assert (d.label, d.check) == ('changed', 'ok')
