"""Deterministic freestanding-C generator for the G-U2 mutant classes (`classes.py`).

A `Module` is a class prelude plus `count` functions `ka_<class>_<NN>`. Each function is a `string.Template` with named
slots, so a planted edit is a change of slot values and never a text search: the edit of a function is a mapping
slot -> new value. Mutant `i` is the base module with function `i` rendered with one of its candidate edits; a function
has several candidates where the class allows it, so a mutant that turns out to be equivalent (the compiler produced the
same code) can be retried with the next one. Everything derives from `random.Random(<str>)`, which is stable across
platforms and Python versions. The code is original (MIT), freestanding C11, with external linkage everywhere.
"""
from __future__ import annotations

import random
import string
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .classes import BY_ID

MAX_COUNT = 99
HELPERS = 8
FIELDS = tuple(f'f{j}' for j in range(8))
_BASE = ('typedef unsigned char u8;\ntypedef unsigned int u32;\ntypedef unsigned long long u64;\n\n'
         'volatile int ka_sink;\n')
_REC = 'struct ka_rec {\n' + ''.join(f'    u32 {f};\n' for f in FIELDS) + '};\n'
_BUF_USE = ('__attribute__((noinline)) int ka_buf_use(u8 *p, int n)\n'
            '{\n    p[0] = (u8)n;\n    ka_sink = p[0];\n    return p[0] + n;\n}\n')
_DELTAS = (1, 2, 3, 16, 256)


@dataclass(frozen=True)
class Template:
    skeleton: str
    values: Mapping[str, str]
    edits: tuple[Mapping[str, str], ...]

    def render(self, edit: Mapping[str, str] | None = None) -> str:
        return string.Template(self.skeleton).substitute({**self.values, **(edit or {})})


@dataclass(frozen=True)
class Module:
    class_id: str
    seed: int
    prelude: str
    names: tuple[str, ...]
    templates: tuple[Template, ...]

    def function_source(self, index: int, attempt: int | None = None) -> str:
        template = self.templates[index]
        return template.render(None if attempt is None else template.edits[attempt])

    def attempts(self, index: int) -> int:
        return len(self.templates[index].edits)

    def _assemble(self, index: int | None, attempt: int | None) -> str:
        parts = [self.prelude]
        for i in range(len(self.names)):
            parts.append(self.function_source(i, attempt if i == index else None))
        return '\n'.join(parts)

    def base_source(self) -> str:
        return self._assemble(None, None)

    def mutant(self, index: int, attempt: int = 0) -> tuple[str, dict]:
        """(source, provenance) of the mutant that edits function `index` with its candidate `attempt`."""
        template, edit = self.templates[index], self.templates[index].edits[attempt]
        shown = sorted(edit)
        provenance = {'class': self.class_id, 'function': self.names[index], 'attempt': attempt, 'slots': dict(edit),
                      'before': '; '.join(f'{k}={template.values[k]!r}' for k in shown),
                      'after': '; '.join(f'{k}={edit[k]!r}' for k in shown)}
        return self._assemble(index, attempt), provenance


def _distinct(rng: random.Random, n: int) -> list[str]:
    """n distinct decimal literals above 255, so every immediate keeps one encoding length."""
    return [str(v) for v in rng.sample(range(257, 90000), n)]


def _helpers(rng: random.Random) -> str:
    """Eight non-inlinable helpers with one prototype and different bodies (callee swaps stay same-shape)."""
    a, b = rng.sample(range(11, 900), HELPERS), rng.sample(range(3, 90), HELPERS)
    return '\n'.join(f'__attribute__((noinline)) int ka_h{j}(int x)\n{{\n    ka_sink = x + {a[j]};\n'
                     f'    return x * {b[j]} - {j};\n}}\n' for j in range(HELPERS))


def _globals(rng: random.Random) -> str:
    """Eight initialised globals, each read by its own function so the data has users on both sides."""
    init, add = rng.sample(range(3, 4000), HELPERS), rng.sample(range(100, 900), HELPERS)
    decls = ''.join(f'int ka_gv_{j} = {init[j]};\n' for j in range(HELPERS))
    readers = '\n'.join(f'__attribute__((noinline)) int ka_gv_read_{j}(void)\n{{\n    return ka_gv_{j} + {add[j]};\n}}\n'
                        for j in range(HELPERS))
    return decls + '\n' + readers


def _numeric(rng: random.Random, name: str, shapes: tuple[tuple[str, tuple[str, ...]], ...]) -> Template:
    """A shape whose literals are the slots; a shift count (slot `s`) is edited only where the shape has one."""
    skeleton, slots = shapes[rng.randrange(len(shapes))]
    values = {'name': name, **dict(zip(slots, _distinct(rng, len(slots)), strict=True))}
    edits = [{slot: str(int(values[slot]) + rng.choice(_DELTAS))} for slot in slots]
    if '${s}' in skeleton:
        values['s'] = str(rng.randrange(3, 13))
        edits.append({'s': str(int(values['s']) + rng.choice(_DELTAS[:3]))})
    rng.shuffle(edits)
    return Template(skeleton, values, tuple(edits[:5]))


def _constant(rng: random.Random, name: str) -> Template:
    shapes = (
        ('u32 ${name}(u32 a, u32 b)\n{\n    u32 t = a * ${k1}u;\n    t ^= b + ${k2}u;\n    if (t & ${k3}u) {\n'
         '        t += ${k4}u;\n    }\n    return t >> ${s};\n}\n', ('k1', 'k2', 'k3', 'k4')),
        ('u32 ${name}(u32 x, u32 y)\n{\n    u32 r = (x << ${s}) - y * ${k1}u;\n    r += ${k2}u;\n    return r ^ ${k3}u;\n}\n',
         ('k1', 'k2', 'k3')),
        ('u32 ${name}(const u32 *p, u32 n)\n{\n    u32 acc = ${k1}u;\n    for (u32 i = 0; i < n; i++) {\n'
         '        acc = acc * ${k2}u + p[i];\n    }\n    return acc ^ ${k3}u;\n}\n', ('k1', 'k2', 'k3')),
    )
    return _numeric(rng, name, shapes)


_FLIP = {'==': ('!=', '<'), '!=': ('==', '>'), '<': ('>', '=='), '>': ('<', '!=')}


def _comparison(rng: random.Random, name: str) -> Template:
    op = rng.choice(sorted(_FLIP))
    k1, k2, k3 = _distinct(rng, 3)
    if rng.randrange(2):
        skeleton = ('int ${name}(int a, int b)\n{\n    if (a ${op} b) {\n        return a * ${k1} + ${k2};\n    }\n'
                    '    return b - ${k3};\n}\n')
    else:
        skeleton = ('u32 ${name}(u32 x, u32 y)\n{\n    u32 d = x ^ y;\n    if (d ${op} ${k1}u) {\n'
                    '        return d * ${k2}u;\n    }\n    return d + ${k3}u;\n}\n')
    return Template(skeleton, {'name': name, 'op': op, 'k1': k1, 'k2': k2, 'k3': k3},
                    tuple({'op': alt} for alt in _FLIP[op]))


def _bound(rng: random.Random, name: str) -> Template:
    k1, k2 = _distinct(rng, 2)
    shape = rng.randrange(3)
    if shape == 0:
        op, edit = '<', '<='
        skeleton = ('int ${name}(const int *p, u32 n)\n{\n    int s = ${k1};\n    for (u32 i = 0; i ${op} n; i++) {\n'
                    '        s += p[i] * ${k2};\n    }\n    return s;\n}\n')
    elif shape == 1:
        op, edit = rng.choice((('>', '>='), ('<', '<=')))
        skeleton = 'int ${name}(int x)\n{\n    if (x ${op} ${k1}) {\n        return x - ${k2};\n    }\n    return 0;\n}\n'
    else:
        op, edit = '<', '<='
        skeleton = ('u32 ${name}(const u32 *p, u32 n)\n{\n    u32 i = 0;\n    while (i ${op} n && p[i] != ${k1}u) {\n'
                    '        i++;\n    }\n    return i + ${k2}u;\n}\n')
    return Template(skeleton, {'name': name, 'op': op, 'k1': k1, 'k2': k2}, ({'op': edit},))


def _signedness(rng: random.Random, name: str) -> Template:
    ty = rng.choice(('int', 'unsigned'))
    k1, k2, k3 = _distinct(rng, 3)
    if rng.randrange(2):
        skeleton = ('int ${name}(int a, int b)\n{\n    if ((${ty})a < (${ty})b) {\n        return a * ${k1};\n    }\n'
                    '    return b + ${k2};\n}\n')
    else:
        skeleton = ('int ${name}(int a)\n{\n    if ((${ty})a > ${k1}) {\n        return a - ${k2};\n    }\n'
                    '    return ${k3};\n}\n')
    other = 'unsigned' if ty == 'int' else 'int'
    return Template(skeleton, {'name': name, 'ty': ty, 'k1': k1, 'k2': k2, 'k3': k3}, ({'ty': other},))


def _removed_check(rng: random.Random, name: str) -> Template:
    k1, k2 = _distinct(rng, 2)
    shape = rng.randrange(3)
    if shape == 0:
        skeleton = 'int ${name}(const u8 *p, u32 n, u32 i)\n{\n${check}    return p[i] ^ ${k1};\n}\n'
        check = '    if (i >= n) {\n        return -1;\n    }\n'
    elif shape == 1:
        skeleton = ('int ${name}(const struct ka_rec *r)\n{\n${check}    return (int)(r->f1 * ${k1}u + ${k2}u);\n}\n')
        check = '    if (r == 0) {\n        return -1;\n    }\n'
    else:
        skeleton = ('int ${name}(u8 *dst, const u8 *src, u32 n)\n{\n${check}    for (u32 i = 0; i < n; i++) {\n'
                    '        dst[i] = (u8)(src[i] + ${k1});\n    }\n    return 0;\n}\n')
        check = f'    if (n > {k2}u) {{\n        return -1;\n    }}\n'
    return Template(skeleton, {'name': name, 'check': check, 'k1': k1, 'k2': k2}, ({'check': ''},))


def _callee_swap(rng: random.Random, name: str) -> Template:
    k1, k2 = _distinct(rng, 2)
    names = [f'ka_h{j}' for j in range(HELPERS)]
    callee = rng.choice(names)
    others = rng.sample([n for n in names if n != callee], 3)
    if rng.randrange(2):
        skeleton = 'int ${name}(int x)\n{\n    int t = x + ${k1};\n    return ${callee}(t) + ${k2};\n}\n'
    else:
        skeleton = 'int ${name}(int x, int y)\n{\n    int t = ${callee}(x * ${k1});\n    return t ^ y;\n}\n'
    return Template(skeleton, {'name': name, 'callee': callee, 'k1': k1, 'k2': k2},
                    tuple({'callee': o} for o in others))


def _field_offset(rng: random.Random, name: str) -> Template:
    k1, k2 = _distinct(rng, 2)
    fld = rng.choice(FIELDS)
    others = rng.sample([f for f in FIELDS if f != fld], 3)
    if rng.randrange(2):
        skeleton = 'u32 ${name}(const struct ka_rec *r)\n{\n    return r->${fld} * ${k1}u + ${k2}u;\n}\n'
    else:
        skeleton = 'void ${name}(struct ka_rec *r, u32 v)\n{\n    r->${fld} = v + ${k1}u;\n}\n'
    return Template(skeleton, {'name': name, 'fld': fld, 'k1': k1, 'k2': k2}, tuple({'fld': o} for o in others))


def _added_block(rng: random.Random, name: str) -> Template:
    k1, k2, k3 = _distinct(rng, 3)
    if rng.randrange(2):
        skeleton = 'u32 ${name}(u32 a, u32 b)\n{\n    u32 t = a * ${k1}u + b;\n${extra}    return t ^ ${k2}u;\n}\n'
        extra = f'    if (t > {k3}u) {{\n        ka_sink = (int)t;\n    }}\n'
    else:
        skeleton = 'int ${name}(int x)\n{\n    int r = x * ${k1} - ${k2};\n${extra}    return r;\n}\n'
        extra = f'    if (r < {k3}) {{\n        ka_sink = r;\n    }}\n'
    return Template(skeleton, {'name': name, 'extra': '', 'k1': k1, 'k2': k2}, ({'extra': extra},))


def _global_swap(rng: random.Random, name: str) -> Template:
    k1, k2 = _distinct(rng, 2)
    names = [f'ka_gv_{j}' for j in range(HELPERS)]
    g = rng.choice(names)
    others = rng.sample([n for n in names if n != g], 3)
    if rng.randrange(2):
        skeleton = 'u32 ${name}(u32 x)\n{\n    return x * ${k1}u + (u32)${g};\n}\n'
    else:
        skeleton = 'int ${name}(int x)\n{\n    if (x > ${k1}) {\n        return ${g};\n    }\n    return x + ${k2};\n}\n'
    return Template(skeleton, {'name': name, 'g': g, 'k1': k1, 'k2': k2}, tuple({'g': o} for o in others))


def _index_swap(rng: random.Random, name: str) -> Template:
    """64-bit indices arrive in their own registers, so the index register sits inside the address operand itself."""
    k1 = _distinct(rng, 1)[0]
    ix = rng.choice(('i', 'j'))
    if rng.randrange(2):
        skeleton = 'int ${name}(const int *p, u64 i, u64 j)\n{\n    return p[${ix}] * ${k1} + (int)j;\n}\n'
    else:
        skeleton = 'u64 ${name}(const u64 *p, u64 i, u64 j)\n{\n    return p[${ix}] + j * ${k1}ull;\n}\n'
    return Template(skeleton, {'name': name, 'ix': ix, 'k1': k1}, ({'ix': 'j' if ix == 'i' else 'i'},))


def _branch_swap(rng: random.Random, name: str) -> Template:
    """The two arms trade places whole, so the multiset of blocks stays and only the successor wiring changes."""
    k1, k2, k3 = _distinct(rng, 3)
    a, b = rng.sample(range(HELPERS), 2)
    arm_a, arm_b = f'ka_h{a}(a) + {k2}', f'ka_h{b}(b) + {k3}'
    skeleton = ('int ${name}(u32 c, int a, int b)\n{\n    if (c > ${k1}u) {\n        return ${t};\n    } else {\n'
                '        return ${e};\n    }\n}\n')
    return Template(skeleton, {'name': name, 't': arm_a, 'e': arm_b, 'k1': k1}, ({'t': arm_b, 'e': arm_a},))


def _buf_resize(rng: random.Random, name: str) -> Template:
    k1 = _distinct(rng, 1)[0]
    size = 16 * rng.randrange(4, 20)
    grown = rng.sample((1, 2, 4, 8), 3)
    return Template('int ${name}(int n)\n{\n    u8 buf[${size}];\n    return ka_buf_use(buf, n) + ${k1};\n}\n',
                    {'name': name, 'size': str(size), 'k1': k1}, tuple({'size': str(size + 16 * g)} for g in grown))


BUILDERS: dict[str, Callable[[random.Random, str], Template]] = {
    'constant': _constant, 'comparison': _comparison, 'bound': _bound, 'signedness': _signedness,
    'removed-check': _removed_check, 'callee-swap': _callee_swap, 'field-offset': _field_offset,
    'added-block': _added_block, 'global-swap': _global_swap, 'index-swap': _index_swap,
    'branch-swap': _branch_swap, 'buf-resize': _buf_resize}
PRELUDES: dict[str, Callable[[random.Random], str]] = {
    'removed-check': lambda rng: _REC, 'field-offset': lambda rng: _REC, 'callee-swap': _helpers,
    'branch-swap': _helpers, 'global-swap': _globals, 'buf-resize': lambda rng: _BUF_USE}


def generate(class_id: str, count: int, *, seed: int) -> Module:
    if class_id not in BY_ID:
        raise KeyError(class_id)
    if not 1 <= count <= MAX_COUNT:
        raise ValueError(f'count must be 1..{MAX_COUNT}')
    stem = 'ka_' + class_id.replace('-', '_') + '_'
    names = tuple(f'{stem}{i:02d}' for i in range(count))
    prelude = _BASE + '\n' + PRELUDES.get(class_id, lambda rng: '')(random.Random(f'ka-mut:{seed}:{class_id}:prelude'))
    templates = tuple(BUILDERS[class_id](random.Random(f'ka-mut:{seed}:{class_id}:{i}'), names[i])
                      for i in range(count))
    return Module(class_id, seed, prelude, names, templates)
