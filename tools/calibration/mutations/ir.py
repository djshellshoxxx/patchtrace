"""IR layer (LBL s7, LBL-07): an independent second truth source for the source-layer mutation labels.

The source operators locate their sites with the C locator in `tier_r/csrc.py`. This module applies the same semantic
edits to the textual LLVM IR of the old tree (`clang -S -emit-llvm -O0 -Xclang -disable-O0-optnone -g`), so it sees the
post-preprocessor program and shares no code with the locator. Its whitelist is `icmp` predicates, integer constants,
`getelementptr` indices, `br` successors and `call` callees. `normalise_function` makes two IR texts comparable
(names renumbered, debug and metadata dropped), `ir_changed` is the observation, and `agreement_by_operator` reports,
per operator, how often that observation matches the label the source layer gave: a direct estimate of source-layer
label noise. Only pure text work is done here; the clang steps are thin wrappers that raise `Blocked` without clang and
`ToolError` when clang rejects the input.
"""
from __future__ import annotations

import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..common import det_uniform
from ..tier_r.toolchain import Toolchain, ToolError, probe, run_tool
from .contracts import kind_of
from .operators import Edit, apply_edits

__all__ = ['IR_OPERATORS', 'IrMutation', 'IrSite', 'LayerVerdict', 'NoIrSite', 'OperatorAgreement',
           'agreement_by_operator', 'compile_ir_object', 'emit_ir', 'ir_changed', 'ir_layer_status', 'ir_sites',
           'mutate_ir', 'normalise_function', 'optimise_ir']

IR_OPERATORS = ('cmp-flip', 'const-change', 'field-offset', 'index-swap', 'branch-swap', 'callee-swap')
_FLIP = {'eq': 'ne', 'ne': 'eq', 'slt': 'sge', 'sge': 'slt', 'sle': 'sgt', 'sgt': 'sle',
         'ult': 'uge', 'uge': 'ult', 'ule': 'ugt', 'ugt': 'ule'}
_ICMP = re.compile(r'= icmp (?:samesign )?(\w+) ')
_ARITH = re.compile(r'= (?:add|sub|mul|and|or|xor|shl|lshr|ashr|sdiv|udiv|srem|urem|icmp \w+)(?: (?:nsw|nuw|exact))*'
                    r' i(\d+) [^,\n]+, (-?\d+)(?=[,\s]|$)', re.M)
_STORE = re.compile(r'\bstore i(\d+) (-?\d+),')
_RET = re.compile(r'\bret i(\d+) (-?\d+)(?=\s|$)', re.M)
_BR = re.compile(r'\bbr i1 [^,\n]+, label (%[\w.]+), label (%[\w.]+)')
_GEP = re.compile(r'\bgetelementptr (?:inbounds |nuw |nusw )*(.+?), ptr [^,\n]+((?:, i\d+ [^,\n]+?)+)(?=\s*(?:,\s*!|$))', re.M)
_INDEX = re.compile(r', (i\d+) (-?\d+|%[\w.]+)')
_CALL = re.compile(r'\bcall\b([^\n@]*)@([\w.$]+)\(')
_PROTO = re.compile(r'^(?:declare|define)\b([^\n@]*)@([\w.$]+)\(([^)\n]*)\)', re.M)
_STRUCT_DEF = re.compile(r'^(%(?:struct|union)\.[\w.]+) = type \{(.*)\}', re.M)


class NoIrSite(RuntimeError):
    """The IR of the function offers no edit site for the operator."""


@dataclass(frozen=True)
class IrSite:
    edits: tuple[Edit, ...]
    line: int   # 1-based line in the module text
    before: str
    after: str


@dataclass(frozen=True)
class IrMutation:
    text: str
    site: IrSite


def _function_span(ll: str, name: str) -> tuple[int, int]:
    """Offsets of the `define ... {` .. `}` block of `name` (the closing brace is always at line start in LLVM IR)."""
    for m in re.finditer(r'^define\b[^\n]*@' + re.escape(name) + r'\(', ll, re.M):
        end = ll.find('\n}', m.start())
        if end >= 0:
            return m.start(), end + 2
    raise NoIrSite(f'function {name!r} is not defined in the IR')


def _site(ll: str, start: int, end: int, text: str) -> IrSite:
    return IrSite((Edit(start, end, text),), ll.count('\n', 0, start) + 1, ll[start:end], text)


def _bump(bits: str, value: str) -> str | None:
    """value + 1 when it stays in the signed range of an iN (N >= 2); wider-than-range results are not proposed."""
    width = int(bits)
    new = int(value) + 1
    return str(new) if width >= 2 and new < 2 ** (width - 1) else None


def _cmp_flip(ll: str, lo: int, hi: int, fn: str) -> list[IrSite]:
    return [_site(ll, m.start(1), m.end(1), _FLIP[m.group(1)])
            for m in _ICMP.finditer(ll, lo, hi) if m.group(1) in _FLIP]


def _const_change(ll: str, lo: int, hi: int, fn: str) -> list[IrSite]:
    out = []
    for rx, bits_g, val_g in ((_ARITH, 1, 2), (_STORE, 1, 2), (_RET, 1, 2)):
        for m in rx.finditer(ll, lo, hi):
            new = _bump(m.group(bits_g), m.group(val_g))
            if new is not None:
                out.append(_site(ll, m.start(val_g), m.end(val_g), new))
    return sorted(out, key=lambda s: s.edits[0].start)


def _struct_fields(ll: str) -> dict[str, int]:
    counts = {}
    for m in _STRUCT_DEF.finditer(ll):
        depth, n = 0, 1 if m.group(2).strip() else 0
        for ch in m.group(2):
            depth += ch in '{[<('
            depth -= ch in '}]>)'
            n += ch == ',' and depth == 0
        counts[m.group(1)] = n
    return counts


def _gep_sites(ll: str, lo: int, hi: int, *, struct: bool) -> list[IrSite]:
    fields = _struct_fields(ll)
    out = []
    for m in _GEP.finditer(ll, lo, hi):
        src_type, indices = m.group(1).strip(), list(_INDEX.finditer(m.group(2)))
        if not indices or not re.fullmatch(r'-?\d+', indices[-1].group(2)):
            continue
        last, value = indices[-1], int(indices[-1].group(2))
        base = m.start(2)
        is_struct = src_type in fields and len(indices) >= 2
        if is_struct != struct or (struct and last.group(1) != 'i32'):
            continue
        bound = fields.get(src_type) if struct else None
        if not struct and (arr := re.match(r'\[(\d+) x ', src_type)):
            bound = int(arr.group(1))
        new = (value + 1) % bound if bound else value + 1
        if bound == 1 or new == value:
            continue
        out.append(_site(ll, base + last.start(2), base + last.end(2), str(new)))
    return out


def _branch_swap(ll: str, lo: int, hi: int, fn: str) -> list[IrSite]:
    out = []
    for m in _BR.finditer(ll, lo, hi):
        if m.group(1) != m.group(2):
            out.append(IrSite((Edit(m.start(1), m.end(1), m.group(2)), Edit(m.start(2), m.end(2), m.group(1))),
                              ll.count('\n', 0, m.start()) + 1, f'{m.group(1)}, {m.group(2)}',
                              f'{m.group(2)}, {m.group(1)}'))
    return out


def _signatures(ll: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    """name -> (return type, parameter types) of every non-variadic, non-intrinsic function in the module."""
    sigs = {}
    for m in _PROTO.finditer(ll):
        name, params = m.group(2), m.group(3)
        if name.startswith('llvm.') or '...' in params or not m.group(1).split():
            continue
        types, depth, cur = [], 0, ''
        for ch in params + ',':
            depth += ch in '({'
            depth -= ch in ')}'
            if ch == ',' and depth == 0:
                if cur.split():
                    types.append(cur.split()[0])
                cur = ''
            else:
                cur += ch
        sigs[name] = (m.group(1).split()[-1], tuple(types))
    return sigs


def _callee_swap(ll: str, lo: int, hi: int, fn: str) -> list[IrSite]:
    sigs, out = _signatures(ll), []
    for m in _CALL.finditer(ll, lo, hi):
        callee, prefix = m.group(2), m.group(1).split()
        if callee not in sigs or not prefix or prefix[-1].endswith(')'):
            continue
        for other in sorted(n for n, s in sigs.items() if s == sigs[callee] and n not in {callee, fn}):
            out.append(_site(ll, m.start(2), m.end(2), other))
    return out


_FINDERS = {
    'cmp-flip': _cmp_flip, 'const-change': _const_change, 'branch-swap': _branch_swap, 'callee-swap': _callee_swap,
    'field-offset': lambda ll, lo, hi, fn: _gep_sites(ll, lo, hi, struct=True),
    'index-swap': lambda ll, lo, hi, fn: _gep_sites(ll, lo, hi, struct=False)}


def ir_sites(ll: str, function: str, operator: str) -> list[IrSite]:
    """Every edit site of `operator` inside `function`, in text order. Raises ValueError for an operator without an
    IR counterpart and `NoIrSite` for an undefined function."""
    if operator not in _FINDERS:
        raise ValueError(f'operator {operator!r} has no IR layer implementation')
    lo, hi = _function_span(ll, function)
    return sorted(_FINDERS[operator](ll, lo, hi, function), key=lambda s: (s.edits[0].start, s.after))


def mutate_ir(ll: str, function: str, operator: str, seed: int) -> IrMutation:
    sites = ir_sites(ll, function, operator)
    if not sites:
        raise NoIrSite(f'{operator} has no site in {function}')
    site = sites[int(det_uniform(seed, operator, function, 'ir') * len(sites))]
    return IrMutation(apply_edits(ll, site.edits), site)


# ---- comparing two IR texts ---------------------------------------------------------------------------------------

_LOCAL = re.compile(r'%(?!(?:struct|union)\.)[\w.$-]+')
_LABEL_DEF = re.compile(r'^([\w.$-]+):')
_TRAILER = re.compile(r'(?:, )?!(?:dbg|tbaa|llvm\.\w+|prof|range|nonnull|noundef|srcloc|annotation)\s+!\d+')


def normalise_function(ll: str, name: str) -> tuple[str, ...]:
    """The instruction lines of `name` with debug intrinsics, metadata trailers, comments and attribute groups removed
    and every local value and label renumbered `%v<k>` by first appearance, so two builds compare equal iff the
    function computes the same way."""
    lo, hi = _function_span(ll, name)
    lines = ll[lo:hi].splitlines()[1:-1]
    ids: dict[str, str] = {}

    def rename(token: str) -> str:
        return ids.setdefault(token, f'%v{len(ids)}')

    out = []
    for raw in lines:
        line = raw.split(';', 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith('#dbg_') or '@llvm.dbg.' in line:
            continue
        line = _TRAILER.sub('', line).strip()
        if m := _LABEL_DEF.match(line):
            out.append(rename('%' + m.group(1)) + ':')
        else:
            out.append(_LOCAL.sub(lambda t: rename(t.group(0)), line))
    return tuple(out)


def ir_changed(old_ll: str, new_ll: str, function: str) -> bool | None:
    """True iff the normalised IR of `function` differs. None when the function is missing from one side (the
    observation is unknown, never a disagreement)."""
    try:
        return normalise_function(old_ll, function) != normalise_function(new_ll, function)
    except NoIrSite:
        return None


# ---- agreement between the source label and the IR observation ---------------------------------------------------

@dataclass(frozen=True)
class LayerVerdict:
    operator: str
    case_id: str
    expected_changed: bool          # what the source layer's label says: a semantic mutant changes the body
    observed_changed: bool | None   # what the IR shows; None = could not be observed

    @classmethod
    def for_case(cls, operator: str, case_id: str, observed_changed: bool | None) -> LayerVerdict:
        return cls(operator, case_id, kind_of(operator) == 'semantic', observed_changed)


@dataclass(frozen=True)
class OperatorAgreement:
    operator: str
    compared: int
    agreed: int
    unknown: int

    @property
    def rate(self) -> float | None:
        """Agreement rate; None (not 0) when nothing was compared. 1 - rate estimates the source-layer label noise."""
        return self.agreed / self.compared if self.compared else None


def agreement_by_operator(verdicts: Iterable[LayerVerdict]) -> dict[str, OperatorAgreement]:
    """Per operator: how many cases the IR could judge, how many of those match the source label, how many were
    unobservable. Operators are never pooled."""
    tally: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for v in verdicts:
        row = tally[v.operator]
        if v.observed_changed is None:
            row[2] += 1
        else:
            row[0] += 1
            row[1] += v.observed_changed == v.expected_changed
    return {op: OperatorAgreement(op, *row) for op, row in sorted(tally.items())}


# ---- clang wrappers -----------------------------------------------------------------------------------------------

def ir_layer_status(tools: Toolchain | None = None) -> str | None:
    """None when the IR layer can run here, else the BLOCKED reason (listed in reports, never skipped)."""
    tool = (tools if tools is not None else probe(names=['clang'])).get('clang')
    return None if tool.ok else f'clang: {tool.reason}'


def _clang(tools: Toolchain | None) -> str:
    return (tools if tools is not None else probe(names=['clang'])).path('clang')


def _run_in_tree(files: Mapping[str, str], argv_tail: Sequence[str], clang: str, out: str, timeout: float) -> bytes:
    with tempfile.TemporaryDirectory(prefix='pt-ir-') as tmp:
        root = Path(tmp)
        for rel, text in files.items():
            if rel.startswith('/') or '..' in rel.split('/'):
                raise ValueError(f'unsafe relative path {rel!r}')
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding='utf-8', newline='\n')
        result = run_tool([clang, *argv_tail, '-o', out], cwd=root, timeout=timeout)
        if result.returncode != 0 or not (root / out).is_file():
            tail = (result.stderr_tail or result.log_tail or result.reason or '')[-300:]
            raise ToolError(f'clang failed on the IR layer input: {tail}')
        return (root / out).read_bytes()


def emit_ir(files: Mapping[str, str], rel: str, tools: Toolchain | None = None, *, flags: Sequence[str] = (),
            timeout: float = 120.0) -> str:
    """Textual unoptimised IR of one C file of the tree (freestanding, `-O0` without `optnone`, with debug info)."""
    tail = ['-S', '-emit-llvm', '-O0', '-Xclang', '-disable-O0-optnone', '-g', '-x', 'c', '-ffreestanding',
            '-Wno-everything', '-I.', *flags, rel]
    return _run_in_tree(files, tail, _clang(tools), 'out.ll', timeout).decode('utf-8', errors='replace')


def optimise_ir(ll: str, tools: Toolchain | None = None, *, timeout: float = 120.0) -> str:
    """The `-O2` IR of a (possibly mutated) module: the form comparable with the source layer's optimised body."""
    return _run_in_tree({'x.ll': ll}, ['-S', '-emit-llvm', '-O2', '-x', 'ir', 'x.ll'], _clang(tools), 'out.ll',
                        timeout).decode('utf-8', errors='replace')


def compile_ir_object(ll: str, tools: Toolchain | None = None, *, timeout: float = 120.0) -> bytes:
    """`clang -O2 -c x.ll`: the object file of a mutated module (the link step belongs to the farm)."""
    return _run_in_tree({'x.ll': ll}, ['-c', '-O2', '-x', 'ir', 'x.ll'], _clang(tools), 'out.o', timeout)
