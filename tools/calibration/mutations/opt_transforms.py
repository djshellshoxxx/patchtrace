"""Opt layer (LBL s7, LBL-07): stock `opt -passes=` transforms that preserve semantics, so the target is
`cosmetic(<pass>)` and every symbol the pass creates has no counterpart in the old image. The N tag of the noise
taxonomy is recorded with the result. Linux leg only: when `opt` (or the clang that emits its input) is absent the
result is `blocked` with the reason, which reports list; a missing tool is never a pass and never a silent skip.

The input module is emitted with `-O1 -Xclang -disable-llvm-passes`: unlike the `-O0` form it carries neither
`optnone` nor `noinline`, which would stop every one of these passes. A pass that finds nothing to do returns
`unchanged` (the farm treats it as a rejected attempt, like a source mutant that fails its acceptance rule).
"""
from __future__ import annotations

import os
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..tier_r.contracts import OPT_OPERATORS
from ..tier_r.toolchain import TOOL_ENV_PREFIX, Tool, Toolchain, probe
from .ir import run_in_tree

__all__ = ['OPT_PASSES', 'OptPass', 'OptResult', 'apply_opt', 'cosmetic_target', 'defined_symbols', 'emit_opt_input',
           'find_opt', 'opt_layer_status']

_VERSIONS = ('', '-18', '-19', '-20', '-17')


@dataclass(frozen=True)
class OptPass:
    pipeline: str            # the `-passes=` value, with the stock canonicalisation the pass needs in front
    args: tuple[str, ...]    # extra opt flags
    n_tag: str               # noise taxonomy class the transform stands for


OPT_PASSES: dict[str, OptPass] = {
    'loop-extract': OptPass('function(mem2reg,loop-simplify),loop-extract', (), 'N4'),
    'hotcoldsplit': OptPass('function(mem2reg),hotcoldsplit', ('-hotcoldsplit-threshold=-1',), 'N10'),
    'mergefunc': OptPass('mergefunc', (), 'N1'),
    'always-inline': OptPass('always-inline', (), 'N4'),
    'partial-inliner': OptPass('function(mem2reg,simplifycfg),partial-inliner', (), 'N4'),
}
assert tuple(OPT_PASSES) == OPT_OPERATORS


@dataclass(frozen=True)
class OptResult:
    operator: str
    status: str                       # ok | unchanged | blocked
    n_tag: str
    reason: str | None = None
    ir: str | None = None
    new_symbols: tuple[str, ...] = ()       # defined only after the pass: `no-counterpart`
    removed_symbols: tuple[str, ...] = ()   # defined only before (merged or inlined away)

    @property
    def blocked(self) -> bool:
        return self.status == 'blocked'


def cosmetic_target(operator: str) -> str:
    """The label the target function carries: the pass preserves semantics, so it is cosmetic."""
    _pass(operator)
    return f'cosmetic({operator})'


def _pass(operator: str) -> OptPass:
    if operator not in OPT_PASSES:
        raise ValueError(f'{operator!r} is not an opt operator')
    return OPT_PASSES[operator]


def find_opt(tools: Toolchain | None = None, environ: Mapping[str, str] | None = None) -> Tool:
    """`opt` from the supplied toolchain, else `PATCHTRACE_KA_OPT`, else PATH (versioned names too). `Toolchain`
    discovery in `tier_r` does not know `opt`, so the layer finds it itself."""
    if tools is not None and tools.get('opt').ok:
        return tools.get('opt')
    env = os.environ if environ is None else environ
    override = env.get(TOOL_ENV_PREFIX + 'OPT')
    if override:
        ok = Path(override).is_absolute() and Path(override).is_file()
        return Tool('opt', override if ok else None,
                    reason=None if ok else f'override {override!r} is not an absolute file')
    for name in ('opt' + v for v in _VERSIONS):
        if hit := shutil.which(name, path=env.get('PATH')):
            return Tool('opt', os.path.abspath(hit))
    return Tool('opt', None, reason='not installed (not on PATH)')


def opt_layer_status(tools: Toolchain | None = None, environ: Mapping[str, str] | None = None) -> str | None:
    """None when the opt layer can run here, else the BLOCKED reason."""
    chain = tools if tools is not None else probe(environ, names=['clang'])
    missing = [f'{t.name}: {t.reason}' for t in (find_opt(chain, environ), chain.get('clang')) if not t.ok]
    return '; '.join(missing) or None


def emit_opt_input(files: Mapping[str, str], rel: str, tools: Toolchain | None = None, *,
                   flags: Sequence[str] = (), timeout: float = 120.0) -> str:
    """Textual IR of one C file in the form `opt` can transform (no `optnone`, no `noinline`, no debug info)."""
    chain = tools if tools is not None else probe(names=['clang'])
    tail = ['-S', '-emit-llvm', '-O1', '-Xclang', '-disable-llvm-passes', '-g0', '-x', 'c', '-ffreestanding',
            '-Wno-everything', '-I.', *flags, rel]
    return run_in_tree(files, tail, chain.path('clang'), 'out.ll', timeout).decode('utf-8', errors='replace')


_DEFINE = re.compile(r'^define\b[^\n]*@([\w.$]+)\(', re.M)


def defined_symbols(ll: str) -> tuple[str, ...]:
    return tuple(sorted(set(_DEFINE.findall(ll))))


def apply_opt(ll: str, operator: str, tools: Toolchain | None = None, *, environ: Mapping[str, str] | None = None,
              timeout: float = 120.0) -> OptResult:
    """Run the operator's pass over a module. `blocked` (with the reason) when `opt` is unavailable."""
    spec = _pass(operator)
    opt = find_opt(tools, environ)
    if not opt.ok:
        return OptResult(operator, 'blocked', spec.n_tag, reason=f'opt: {opt.reason}')
    tail = [f'-passes={spec.pipeline}', *spec.args, '-S', 'in.ll']
    out = run_in_tree({'in.ll': ll}, tail, opt.path, 'out.ll', timeout).decode('utf-8', errors='replace')
    before, after = set(defined_symbols(ll)), set(defined_symbols(out))
    status = 'unchanged' if _strip_header(out) == _strip_header(ll) else 'ok'
    return OptResult(operator, status, spec.n_tag, ir=out, new_symbols=tuple(sorted(after - before)),
                     removed_symbols=tuple(sorted(before - after)))


def _strip_header(ll: str) -> list[str]:
    """Lines that carry the program (opt rewrites the ModuleID and comment lines, which say nothing)."""
    return [ln for ln in ll.splitlines() if ln.strip() and not ln.startswith(';')]

