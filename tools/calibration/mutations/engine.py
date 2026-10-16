"""Planning and applying planted mutations (SPEC-32 s8): `plan_mutants` orders every candidate site by
`det_uniform(seed, operator, file, function, site)`; `apply_case` walks that order, rejecting a mutant that does not
compile (bounded attempts, every rejection recorded) and returns the mutated tree plus the `mutation-case/1` record;
`replay_case` re-derives the same bytes from a record. Sources are only read and written as text.
"""
from __future__ import annotations

import re
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..common import det_uniform
from ..tier_r.csrc import Source
from ..tier_r.toolchain import Toolchain, probe, run_tool
from . import contracts as C
from .operators import Ctx, Edit, apply_edits
from .registry import OPERATORS_IMPL, PROFILE_ONLY

__all__ = ['Candidate', 'Checker', 'MutationOutcome', 'NoMutationSite', 'OperatorUnavailable', 'apply_case',
           'make_compile_checker', 'make_masked_body_check', 'plan_mutants', 'replay_case']

MAX_ATTEMPTS = 200
Checker = Callable[[Mapping[str, str], str], 'str | None']   # (files, mutated rel path) -> None or rejection reason
ExtraCheck = Callable[['Candidate', Mapping[str, str]], 'str | None']


class NoMutationSite(RuntimeError):
    """No candidate site was accepted (none exists, or every tried site was rejected; see `.rejected`)."""

    def __init__(self, message: str, rejected: Sequence[C.Rejection] = ()):
        super().__init__(message)
        self.rejected = tuple(rejected)


class OperatorUnavailable(ValueError):
    """The operator is restricted to other toolchain profiles (`registry.PROFILE_ONLY`)."""


@dataclass(frozen=True)
class Candidate:
    operator: str
    file: str
    function: str
    site: int
    key: float
    edits: tuple[Edit, ...]
    line: int
    column: int
    before: str
    after: str
    helper: str | None = None
    moved: str | None = None


@dataclass(frozen=True)
class MutationOutcome:
    files: dict[str, str]
    case: C.MutationCase
    candidate: Candidate

    @property
    def changed(self) -> tuple[str, ...]:
        return (self.case.target_file,)


def _check_rel(rel: str) -> None:
    parts = rel.split('/')
    if not rel or rel.startswith('/') or '..' in parts or '' in parts or ':' in rel or '\\' in rel:
        raise ValueError(f'source path {rel!r} must be relative, "/"-separated and without ".."')


def plan_mutants(files: Mapping[str, str], operator: str, *, seed: int,
                 target: tuple[str, str] | None = None, suffixes: Sequence[str] = ('.c',)) -> list[Candidate]:
    """Every candidate site of `operator`, ordered by det_uniform(seed, operator, file, function, site)."""
    if operator not in OPERATORS_IMPL:
        raise ValueError(f'unknown mutation operator {operator!r}')
    gen = OPERATORS_IMPL[operator]
    out: list[Candidate] = []
    for rel in sorted(files):
        _check_rel(rel)
        if not rel.endswith(tuple(suffixes)) or (target and rel != target[0]):
            continue
        src = Source(files[rel])
        counters: dict[str, int] = {}
        for fn in src.functions:
            n = counters.get(fn.name, 0)
            if target and fn.name != target[1]:
                continue
            for site in gen(Ctx(src, fn, rel, seed, operator)):
                first = min(site.edits, key=lambda e: e.start).start
                out.append(Candidate(
                    operator, rel, fn.name, n, det_uniform(seed, operator, rel, fn.name, n), site.edits,
                    src.line_of(first), src.col_of(first), site.before[:2000], site.after[:2000], site.helper,
                    site.moved))
                n += 1
            counters[fn.name] = n
    out.sort(key=lambda c: (c.key, c.file, c.function, c.site))
    return out


@contextmanager
def _tree(files: Mapping[str, str]) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix='pt-mut-') as tmp:
        root = Path(tmp)
        for name, text in files.items():
            _check_rel(name)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
        yield root


def _clang_argv(clang: str, rel: str, mode: Sequence[str], flags: Sequence[str]) -> list[str]:
    parent = rel.rpartition('/')[0]
    argv = [clang, *mode, '-x', 'c', '-ffreestanding', '-Wno-everything', '-Werror=implicit-function-declaration',
            '-Werror=implicit-int', '-I.']
    if parent:
        argv.append(f'-I{parent}')
    return [*argv, *flags, rel]


def make_compile_checker(tools: Toolchain | None = None, *, flags: Sequence[str] = (),
                         timeout: float = 120.0) -> Checker:
    """`clang -fsyntax-only` over the mutated file inside a private copy of the tree (freestanding, C). Raises
    `toolchain.Blocked` when clang is unavailable: a missing compiler is never a pass and never a silent skip."""
    chain = tools if tools is not None else probe(names=['clang'])
    clang = chain.path('clang')

    def check(files: Mapping[str, str], rel: str) -> str | None:
        with _tree(files) as root:
            result = run_tool(_clang_argv(clang, rel, ['-fsyntax-only'], flags), cwd=root, timeout=timeout)
        if result.returncode == 0 and not result.reason:
            return None
        text = result.stderr_tail or result.log_tail or result.reason or f'exit {result.returncode}'
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        line = next((ln for ln in lines if 'error' in ln), lines[0] if lines else 'compile failed')
        return line[:300]
    return check


_ASM_LABEL = re.compile(r'\.L[\w.$]+')
# COFF quotes string literal symbols (for example "??_C@...@hello?$AA@").
# They are address-only references just like unquoted ELF symbols, not code changes.
_ASM_SYMBOL = re.compile(r'(?:"[^"\r\n]+"|[^\s,()]+)(?=\(%rip\))')
_ASM_BRANCH = re.compile(r'^(call\w*|j\w+)\s+\S+$')


def _masked_function_asm(files: Mapping[str, str], rel: str, name: str, clang: str, flags: Sequence[str],
                         timeout: float) -> tuple[str, ...] | None:
    """Optimised assembly of `name` with every address-dependent operand masked as `tier_r/bodyhash.py` does for
    images (local labels, symbols, rip displacements, branch and call targets); None if the function is not emitted."""
    with _tree(files) as root:
        out = root / '_masked.s'
        argv = _clang_argv(clang, rel, ['-O2', '-S', '-g0', '-fno-asynchronous-unwind-tables', '-fno-stack-protector',
                                        '-o', out.name], flags)
        if run_tool(argv, cwd=root, timeout=timeout).returncode != 0 or not out.is_file():
            return None
        lines = out.read_text(encoding='utf-8', errors='replace').splitlines()
    start = next((k for k, ln in enumerate(lines) if ln.split('#', 1)[0].strip() == f'{name}:'), None)
    if start is None:
        return None
    body: list[str] = []
    for line in lines[start + 1:]:
        insn = line.split('#', 1)[0].strip()
        # COFF does not emit ELF's .Lfunc_end. Stop before the next
        # function or data section so unrelated code cannot change this label.
        directive = insn.split(maxsplit=1)[0] if insn else ''
        if (insn.startswith('.Lfunc_end')
                or directive in {'.seh_endproc', '.cfi_endproc', '.def', '.section', '.data', '.text'}
                or (insn.endswith(':') and not insn.startswith(('.L', 'LBB')))):
            break
        if not insn or insn.startswith('.') or insn.endswith(':'):
            continue
        insn = _ASM_SYMBOL.sub('SYM', _ASM_LABEL.sub('.L', insn))
        body.append(_ASM_BRANCH.sub(lambda m: m.group(1) + ' T', insn))
    return tuple(body)


def make_masked_body_check(files: Mapping[str, str], tools: Toolchain | None = None, *, flags: Sequence[str] = (),
                           timeout: float = 120.0) -> ExtraCheck:
    """The source-layer form of the SPEC-32 s7 acceptance rule, for `apply_case(extra_check=...)`: a semantic mutant is
    accepted only if the optimised, address-masked body of the target differs from `files`; a cosmetic one only if it
    is equal. A body that cannot be compared (function not emitted, compile failure) is rejected, never accepted."""
    chain = tools if tools is not None else probe(names=['clang'])
    clang = chain.path('clang')
    baseline: dict[tuple[str, str], tuple[str, ...] | None] = {}

    def check(cand: Candidate, new: Mapping[str, str]) -> str | None:
        key = (cand.file, cand.function)
        if key not in baseline:
            baseline[key] = _masked_function_asm(files, cand.file, cand.function, clang, flags, timeout)
        before = baseline[key]
        after = _masked_function_asm(new, cand.file, cand.function, clang, flags, timeout)
        if before is None or after is None:
            return 'masked body not comparable (function not emitted at -O2)'
        equal = before == after
        if C.kind_of(cand.operator) == 'semantic':
            return 'masked body unchanged' if equal else None
        return None if equal else 'cosmetic mutant changed the masked body'
    return check


def _apply(files: Mapping[str, str], cand: Candidate) -> dict[str, str]:
    new = dict(files)
    new[cand.file] = apply_edits(files[cand.file], cand.edits)
    return new


def _build_case(files, new, cand: Candidate, *, seed: int, base: C.SourceRef, attempts: int,
                rejected: Sequence[C.Rejection], case_id: str | None) -> C.MutationCase:
    digest = C.patch_digest(files, new)
    return C.MutationCase(
        contract='mutation-case/1', case_id=case_id or C.case_id(cand.operator, seed, digest), base=base,
        operator=cand.operator, kind=C.kind_of(cand.operator), seed=seed, target_file=cand.file,
        target_function=cand.function,
        site=C.MutationSite(file=cand.file, line=cand.line, column=cand.column, before=cand.before, after=cand.after),
        attempts=attempts, rejected=tuple(rejected), helper=cand.helper, moved_function=cand.moved,
        patch_sha256=digest)


def apply_case(files: Mapping[str, str], operator: str, *, seed: int, base: C.SourceRef,
               tools: Toolchain | None = None, checker: Checker | None = None,
               target: tuple[str, str] | None = None, max_attempts: int = 25,
               extra_check: ExtraCheck | None = None, suffixes: Sequence[str] = ('.c',),
               case_id: str | None = None, profile: str | None = None) -> MutationOutcome:
    """Pick the first site in det_uniform order whose mutant compiles (and passes `extra_check`, e.g. tier_r's
    "masked body differs" gate for semantic operators). Raises `Blocked` without clang (unless a `checker` is
    given) and `NoMutationSite` when `max_attempts` sites were rejected or none exists. With a `profile`, an operator
    restricted to other profiles (`api-use`: mingw only) raises `OperatorUnavailable`."""
    if profile is not None and operator in PROFILE_ONLY and profile not in PROFILE_ONLY[operator]:
        raise OperatorUnavailable(f'{operator} needs a {"/".join(PROFILE_ONLY[operator])} build, not {profile}')
    if not 1 <= max_attempts <= MAX_ATTEMPTS:
        raise ValueError(f'max_attempts must be 1..{MAX_ATTEMPTS}')
    check = checker if checker is not None else make_compile_checker(tools)
    plan = plan_mutants(files, operator, seed=seed, target=target, suffixes=suffixes)
    rejected: list[C.Rejection] = []
    for cand in plan[:max_attempts]:
        reason = None
        new: dict[str, str] = {}
        try:
            new = _apply(files, cand)
            moved = Source(new[cand.file])
            if new[cand.file] == files[cand.file]:
                reason = 'edit left the source unchanged'
            elif not moved.by_name(cand.function):
                reason = 'target function not found after the edit'
        except ValueError as exc:
            reason = f'edit failed: {exc}'
        if reason is None:
            reason = check(new, cand.file)
        if reason is None and extra_check is not None:
            reason = extra_check(cand, new)
        if reason is not None:
            rejected.append(C.Rejection(line=cand.line, column=cand.column, reason=reason[:300]))
            continue
        case = _build_case(files, new, cand, seed=seed, base=base, attempts=len(rejected) + 1, rejected=rejected,
                           case_id=case_id)
        return MutationOutcome(new, case, cand)
    where = f'{operator} in {target[0]}::{target[1]}' if target else operator
    detail = f'{len(plan)} candidate site(s), {len(rejected)} rejected' + (
        f' (last: {rejected[-1].reason})' if rejected else '')
    raise NoMutationSite(f'no accepted {where} mutation: {detail}', rejected)


def replay_case(files: Mapping[str, str], case: C.MutationCase, *, suffixes: Sequence[str] = ('.c',)) -> dict[str, str]:
    """Re-derive the mutated tree of a recorded case from the same base files (no compiler needed) and verify the
    recorded site and patch digest."""
    plan = plan_mutants(files, case.operator, seed=case.seed, target=(case.target_file, case.target_function),
                        suffixes=suffixes)
    site = case.site
    cand = next((c for c in plan if (c.line, c.column, c.before, c.after) == (site.line, site.column, site.before,
                                                                             site.after)), None)
    if cand is None:
        raise ValueError('recorded site is not a candidate of the base files')
    new = _apply(files, cand)
    if C.patch_digest(files, new) != case.patch_sha256:
        raise ValueError('patch digest does not match the recorded case')
    return new
