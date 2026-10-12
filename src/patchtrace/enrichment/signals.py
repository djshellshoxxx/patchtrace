"""B1 deterministic change-signal detectors over immutable match views (SPEC-07 §5). Pure.

Input is Ghidra *decompiled C text*, not typed IR, so every rule here is a lexical
heuristic: confidences stay at the conservative §5 defaults and `typed_evidence` is
always False. A signal says "this edit looks like a guard worth reading first", never
"this was the vulnerability".

Example (synthetic records; no GUI, engine or network involved):

>>> from patchtrace.models import FunctionMatch, FunctionRecord
>>> from patchtrace.enrichment.views import match_view
>>> old = 'int f(char *b, int n, int i) {\\n  return b[i];\\n}'
>>> new = 'int f(char *b, int n, int i) {\\n  if (i >= n) {\\n    return -1;\\n  }\\n  return b[i];\\n}'
>>> rec = lambda side, code: FunctionRecord(artifact_id=side, run_id='r', name='f', code=code)
>>> m = FunctionMatch(run_id='r', category='modified', older=[rec('a-old', old)], newer=[rec('a-new', new)])
>>> view = match_view(m, '0' * 64, {'older': 'a-old', 'newer': 'a-new'})
>>> result = detect(view)
>>> result.status, sorted(s.detector for s in result.signals)
('complete', ['BND', 'ERR'])
>>> len({s.group_key for s in result.signals})  # both fire on the same added predicate
1

Shared conventions, each chosen to suppress a known false-positive class:

* Cross-side comparisons use a *normalized* form: comment/string contents are blanked,
  whitespace collapses through tokenization, and decompiler-generated names (`iVar1`,
  `local_38`, `param_2`, `DAT_...`, `FUN_...`) collapse to `$v`, because Ghidra renumbers
  them between builds. Cost: an edit that only swaps one temporary for another is
  invisible (false negative), which is the conservative direction.
* "Added" means absent from the *entire* older function, not just the paired hunk, so
  optimizer/decompiler reordering that moves an unchanged line is not a new guard.
* Same-object linkage within the newer side uses raw text (no `$v` collapse), so two
  different locals are never treated as the same object.
* Regexes are applied to single tokens or short lines only; all structure is found by
  linear scans over pre-split tokens, so no input can trigger catastrophic backtracking.
"""
from __future__ import annotations

import re
import threading
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from . import identity
from .contracts import ChangeSignal, DetectorOutcome, SignalSet, SourceLocation, Status
from .views import MAX_CHARS, MAX_LINES, FunctionView, MatchView

WINDOW = 6
CANCEL_EVERY = 256
SUPPORTED_CATEGORIES: tuple[str, ...] = ('modified', 'split', 'merged', 'ambiguous')
COMMON_PREREQUISITES: tuple[str, ...] = (
    'two-sided 1:1 pairing', 'decompiled code on both sides', 'at least one non-noise changed hunk')
COMMON_LIMITATIONS: tuple[str, ...] = (
    'decompiled-text heuristic; no typed IR', 'linkage limited to changed hunk plus 6 lines of context',
    'decompiler temporaries normalized; temp-for-temp swaps are invisible')

_TOKEN = re.compile(r'[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+|::|->|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\|'
                    r'|[-+*/%&|^]=|\+\+|--|\S')
_TEMP = re.compile(r'[a-z]{1,5}Var\d+|[a-z]{1,5}Stack_[0-9a-fA-F_]+|(?:local|param|in|extraout|unaff'
                   r'|DAT|LAB|FUN|PTR|switchD|caseD|joined|stack)_\w+')
_TYPE = re.compile(r'(?:unsigned|signed|const|volatile|struct|enum|void|bool|char|short|int|long|float'
                   r'|double|u?int\d*(?:_t)?|u?long(?:long)?|u?short|u?char|s?byte|size_t|ssize_t'
                   r'|undefined\d*|s?word|s?dword|s?qword|ulonglong|longlong|uint|ushort|uchar|ulong'
                   r'|BYTE|WORD|DWORD|QWORD|U?LONG|U?SHORT|U?CHAR|U?INT|SIZE_T|U?LONG64|U?LONG_PTR'
                   r'|U?INT_PTR|DWORD64|DWORD_PTR|BOOL|BOOLEAN|NTSTATUS|HRESULT|PVOID|LPVOID)')
_NUMBER = re.compile(r'0[xX][0-9A-Fa-f]+|\d+')
_IDENT = re.compile(r'[A-Za-z_]\w*')
_MACRO = re.compile(r'[A-Z][A-Z0-9_]*')
_KEYWORDS = frozenset({'if', 'while', 'for', 'switch', 'return', 'sizeof', 'goto', 'do', 'else', 'case',
                       'break', 'continue', 'NULL', 'true', 'false'})
_CONTROL = frozenset({'if', 'while', 'for', 'switch'})
_REL = frozenset({'<', '<=', '>', '>=', '==', '!='})
_ORDER = frozenset({'<', '<=', '>', '>='})
_FLIP = {'>': '<', '>=': '<=', '<': '<', '<=': '<=', '==': '==', '!=': '!='}
_STRICT_PAIR = {('<', '<='), ('<=', '<')}
_STOP = frozenset({'&&', '||', ',', ';', '?', ':', '=', '{', '}', '!', 'return', 'if', 'while', 'for',
                   '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>='}) | _REL

# (dst, src, size) argument indexes.
_COPY = {'memcpy': (0, 1, 2), 'memmove': (0, 1, 2), 'RtlCopyMemory': (0, 1, 2), 'RtlMoveMemory': (0, 1, 2),
         'CopyMemory': (0, 1, 2), 'MoveMemory': (0, 1, 2), 'RtlCopyBytes': (0, 1, 2),
         'memcpy_s': (0, 2, 3), 'memmove_s': (0, 2, 3), 'copy_to_user': (0, 1, 2),
         'copy_from_user': (0, 1, 2), '__copy_to_user': (0, 1, 2), '__copy_from_user': (0, 1, 2)}
# Size argument indexes; calloc contributes both factors.
_ALLOC = {'malloc': (0,), 'calloc': (0, 1), 'realloc': (1,), 'kmalloc': (0,), 'kzalloc': (0,),
          'vmalloc': (0,), 'operator_new': (0,), 'ExAllocatePool': (1,), 'ExAllocatePoolWithTag': (1,),
          'ExAllocatePoolWithQuotaTag': (1,), 'ExAllocatePoolZero': (1,), 'ExAllocatePool2': (1,),
          'ExAllocatePool3': (1,), 'HeapAlloc': (2,), 'HeapReAlloc': (3,), 'RtlAllocateHeap': (2,),
          'VirtualAlloc': (1,), 'LocalAlloc': (1,), 'GlobalAlloc': (1,), 'CoTaskMemAlloc': (0,)}
_ZERO = {'RtlZeroMemory': 0, 'RtlSecureZeroMemory': 0, 'SecureZeroMemory': 0, 'ZeroMemory': 0,
         'bzero': 0, 'explicit_bzero': 0}
_CHECKED = re.compile(r'(?:Rtl)?(?:U?Long(?:Long|Ptr|64)?|SizeT|Size|U?Int(?:Ptr|8|16|32|64)?|DWord(?:Ptr|64)?'
                      r'|U?Short|Byte)(?:Add|Sub|Mult)|__builtin_\w{1,16}_overflow|S?CARRY\d|SBORROW\d'
                      r'|_addcarry_u\d+|_subborrow_u\d+')
_VALIDATOR = re.compile(r'ProbeFor(?:Read|Write)|\w*(?:Validate|Check)\w*')
_PROBE = re.compile(r'ProbeFor(?:Read|Write)')
_STATUS_OK = frozenset({'STATUS_SUCCESS', 'STATUS_PENDING', 'STATUS_REPARSE', 'STATUS_MORE_ENTRIES',
                        'STATUS_BUFFER_OVERFLOW', 'STATUS_NO_MORE_ENTRIES', 'STATUS_WAIT_0', 'STATUS_TIMEOUT'})


class _Cancelled(Exception):
    pass


def _clean(lines: tuple[str, ...]) -> list[str]:
    """Blank comment bodies and string/char literal contents, keeping line numbering."""
    out, in_block = [], False
    for line in lines:
        buf, i, n = [], 0, len(line)
        while i < n:
            c = line[i]
            if in_block:
                if line.startswith('*/', i):
                    in_block, i = False, i + 2
                else:
                    i += 1
                continue
            if line.startswith('/*', i):
                in_block, i = True, i + 2
                buf.append(' ')
            elif line.startswith('//', i):
                break
            elif c in '"\'':
                j = i + 1
                while j < n and line[j] != c:
                    j += 2 if line[j] == '\\' else 1
                buf.append(c + c)
                i = j + 1
            else:
                buf.append(c)
                i += 1
        out.append(''.join(buf))
    return out


def _norm_token(token: str) -> str:
    return '$v' if _TEMP.fullmatch(token) else token


def _join(tokens: Iterable[str]) -> str:
    return ' '.join(tokens)


def _is_var(tokens: list[str], index: int) -> bool:
    """Identifier that names data: not a type, keyword, macro, callee, or struct base."""
    token = tokens[index]
    if not _IDENT.fullmatch(token) or token in _KEYWORDS or _TYPE.fullmatch(token) or _MACRO.fullmatch(token):
        return False
    following = tokens[index + 1] if index + 1 < len(tokens) else ''
    return following not in ('(', '->', '.', '::')


def _strip_casts(tokens: list[str]) -> tuple[list[str], tuple[str, ...]]:
    out, casts, i = [], [], 0
    while i < len(tokens):
        if tokens[i] == '(':
            j = i + 1
            while j < len(tokens) and (tokens[j] == '*' or _TYPE.fullmatch(tokens[j])):
                j += 1
            if j > i + 1 and j < len(tokens) and tokens[j] == ')':
                casts.append(_join(tokens[i:j + 1]))
                i = j + 1
                continue
        out.append(tokens[i])
        i += 1
    return out, tuple(casts)


def _strip_object(tokens: list[str]) -> str:
    stripped, _ = _strip_casts(tokens)
    while stripped and stripped[0] == '&':
        stripped = stripped[1:]
    while len(stripped) >= 2 and stripped[0] == '(' and stripped[-1] == ')':
        stripped = stripped[1:-1]
    return _join(stripped)


def _split_top(tokens: list[str], sep: str) -> list[list[str]]:
    parts, depth, current = [], 0, []
    for token in tokens:
        if token in '([':
            depth += 1
        elif token in ')]':
            depth -= 1
        if token == sep and depth == 0:
            parts.append(current)
            current = []
        else:
            current.append(token)
    parts.append(current)
    return parts


@dataclass(frozen=True)
class _Cmp:
    line: int
    left: tuple[str, ...]
    op: str
    right: tuple[str, ...]

    def canonical(self) -> tuple[tuple[str, ...], str, tuple[str, ...]]:
        """`b > a` and `a < b` are the same comparison; only `<`, `<=`, `==`, `!=` remain."""
        if self.op in ('>', '>='):
            return self.right, _FLIP[self.op], self.left
        return self.left, self.op, self.right

    def norm(self) -> tuple[str, str, str]:
        left, op, right = self.canonical()
        return _join(map(_norm_token, left)), op, _join(map(_norm_token, right))


def _comparisons(tokens: list[str], line: int) -> list[_Cmp]:
    out = []
    for i, token in enumerate(tokens):
        if token not in _REL:
            continue
        left, depth, j = [], 0, i - 1
        while j >= 0:
            t = tokens[j]
            if t == ')':
                depth += 1
            elif t == '(':
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and t in _STOP:
                break
            left.append(t)
            j -= 1
        left.reverse()
        right, depth, j = [], 0, i + 1
        while j < len(tokens):
            t = tokens[j]
            if t == '(':
                depth += 1
            elif t == ')':
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and t in _STOP:
                break
            right.append(t)
            j += 1
        # `FeatureImpl<Traits>::IsEnabled` and similar C++ names are not comparisons.
        if not left or not right or '::' in left or '::' in right or (j < len(tokens) and tokens[j] == '::'):
            continue
        out.append(_Cmp(line, tuple(left), token, tuple(right)))
    return out


@dataclass(frozen=True)
class _Call:
    line: int
    name: str
    args: tuple[tuple[str, ...], ...]
    start: int


def _calls(tokens: list[str], line: int) -> list[_Call]:
    out = []
    for i in range(len(tokens) - 1):
        name = tokens[i]
        if tokens[i + 1] != '(' or not _IDENT.fullmatch(name) or name in _KEYWORDS or _TYPE.fullmatch(name):
            continue
        depth, j, args, current = 0, i + 2, [], []
        while j < len(tokens):
            t = tokens[j]
            if t in '([':
                depth += 1
            elif t in ')]':
                if depth == 0:
                    break
                depth -= 1
            if t == ',' and depth == 0:
                args.append(tuple(current))
                current = []
            else:
                current.append(t)
            j += 1
        if j >= len(tokens):
            continue  # call spans lines; argument positions are unknown
        if current or args:
            args.append(tuple(current))
        out.append(_Call(line, name, tuple(args), i))
    return out


@dataclass
class _Side:
    view: FunctionView
    raw: tuple[str, ...]
    tokens: list[list[str]]
    norm: list[str]
    cmps: list[list[_Cmp]]
    calls: list[list[_Call]]
    norm_set: set[str] = field(default_factory=set)
    cmp_set: set[tuple[str, str, str]] = field(default_factory=set)
    call_count: Counter = field(default_factory=Counter)

    def control(self, index: int) -> bool:
        toks = self.tokens[index]
        return bool(toks) and (toks[0] in _CONTROL or toks[0] in ('&&', '||', '(') or
                               (len(toks) > 1 and toks[0] == '}' and toks[1] == 'while'))


@dataclass(frozen=True)
class _Edit:
    ordinal: int
    old: range
    new: range


class _Context:
    def __init__(self, view: MatchView, cancel: threading.Event | None):
        self.view, self.cancel, self._ticks = view, cancel, 0
        self.older = self._side(view.older[0])
        self.newer = self._side(view.newer[0])
        self.truncated = view.older[0].truncated or view.newer[0].truncated
        edits = []
        for ordinal, hunk in enumerate(view.hunks):
            if hunk.operation == 'equal':
                continue
            old, new = range(hunk.old_start, hunk.old_end), range(hunk.new_start, hunk.new_end)
            # Whitespace-, comment- and rename-only hunks, and pure reorderings inside a hunk,
            # carry no semantic edit and must not seed any signal.
            if Counter(self.older.norm[i] for i in old) == Counter(self.newer.norm[i] for i in new):
                continue
            edits.append(_Edit(ordinal, old, new))
        self.edits = tuple(edits)
        self.new_edit = {i: e for e in self.edits for i in e.new}
        self.old_edit = {i: e for e in self.edits for i in e.old}

    def tick(self) -> None:
        self._ticks += 1
        if self._ticks % CANCEL_EVERY == 0 and self.cancel is not None and self.cancel.is_set():
            raise _Cancelled

    def _side(self, view: FunctionView) -> _Side:
        raw = view.code or ()
        tokens, norm, cmps, calls = [], [], [], []
        for index, line in enumerate(_clean(raw)):
            self.tick()
            toks = _TOKEN.findall(line)
            tokens.append(toks)
            norm.append(_join(map(_norm_token, toks)))
            cmps.append(_comparisons(toks, index))
            calls.append(_calls(toks, index))
        side = _Side(view, raw, tokens, norm, cmps, calls)
        side.norm_set = {n for n in norm if n}
        side.cmp_set = {c.norm() for row in cmps for c in row}
        side.call_count = Counter(c.name for row in calls for c in row)
        return side

    def window(self, edit: _Edit) -> range:
        return range(max(0, edit.new.start - WINDOW), min(len(self.newer.raw), edit.new.stop + WINDOW))

    def added_line(self, index: int) -> bool:
        return bool(self.newer.norm[index]) and self.newer.norm[index] not in self.older.norm_set

    def group(self, edit: _Edit, newer_line: int) -> str:
        text = self.newer.norm[newer_line]
        return identity.domain_id('edit', 1, {'text': text, 'hunk': edit.ordinal})


@dataclass(frozen=True)
class _Finding:
    group_key: str
    locations: tuple[SourceLocation, ...]
    rationale: str
    confidence: str = ''


@dataclass(frozen=True)
class Detector:
    id: str
    version: int
    confidence: str
    categories: tuple[str, ...]
    prerequisites: tuple[str, ...]
    limitations: tuple[str, ...]
    rule: Callable[[_Context], list[_Finding]] = field(repr=False, compare=False)

    def run(self, view: MatchView, cancel: threading.Event | None = None
            ) -> tuple[DetectorOutcome, tuple[ChangeSignal, ...]]:
        reason = _unavailable_reason(self, view)
        if reason:
            return _outcome(view, self.id, 'unavailable', reason), ()
        try:
            return self._evaluate(_Context(view, cancel))
        except _Cancelled:
            return _outcome(view, self.id, 'cancelled', 'cancelled'), ()

    def _evaluate(self, ctx: _Context) -> tuple[DetectorOutcome, tuple[ChangeSignal, ...]]:
        view = ctx.view
        if not ctx.edits:
            return _outcome(view, self.id, 'complete', 'no non-noise changed hunk'), ()
        limitations = list(self.limitations)
        if view.category == 'ambiguous':
            limitations.append('ambiguous-match')
        if ctx.truncated:
            limitations.append('function-too-large')
        signals = {}
        for finding in self.rule(ctx):
            locs = [loc.model_dump() for loc in finding.locations]
            sid = identity.signal_id(view.pairing_id, self.id, self.version, finding.group_key, locs)
            signals.setdefault(sid, ChangeSignal(
                signal_id=sid, pairing_id=view.pairing_id, match_id=view.match_id, detector=self.id,
                detector_version=self.version, confidence=finding.confidence or self.confidence,
                group_key=finding.group_key, locations=finding.locations, rationale=finding.rationale,
                limitations=tuple(limitations), typed_evidence=False))
        status: Status = 'partial' if ctx.truncated else 'complete'
        reason = f'function-too-large: scanned first {MAX_LINES} lines / {MAX_CHARS} chars' if ctx.truncated else ''
        return (_outcome(view, self.id, status, reason),
                tuple(sorted(signals.values(), key=lambda s: s.signal_id)))


def _outcome(view: MatchView, detector: str, status: Status, reason: str) -> DetectorOutcome:
    return DetectorOutcome(pairing_id=view.pairing_id, detector=detector, status=status, reason=reason)


def _unavailable_reason(detector: Detector, view: MatchView) -> str:
    if view.category not in detector.categories:
        return f'category {view.category!r} has no two-sided changed code for this detector'
    if not view.two_sided:
        return 'one side of the pairing is absent'
    if len(view.older) != 1 or len(view.newer) != 1:
        return f'{view.category} pairing has more than one function per side; hunks exist only for 1:1'
    if view.older[0].code is None or view.newer[0].code is None:
        return 'decompiled code missing on a required side'
    return ''


# --- shared linkage helpers -------------------------------------------------

def _vars(tokens: Iterable[str]) -> set[str]:
    toks = list(tokens)
    return {toks[i] for i in range(len(toks)) if _is_var(toks, i)}


def _size_args(call: _Call) -> list[tuple[str, ...]]:
    if call.name in _COPY:
        index = _COPY[call.name][2]
        return [call.args[index]] if index < len(call.args) else []
    if call.name in _ALLOC:
        return [call.args[i] for i in _ALLOC[call.name] if i < len(call.args)]
    return []


def _indexed_uses(tokens: list[str], var: str) -> bool:
    """`var` inside `[...]`, or inside a `*( ... + ... )` dereference group."""
    stack: list[tuple[str, bool, bool]] = []  # (open, is_deref, has_arith)
    for i, token in enumerate(tokens):
        if token in '([':
            stack.append((token, token == '(' and i > 0 and tokens[i - 1] == '*', False))
        elif token in ')]':
            if stack:
                stack.pop()
        elif token in ('+', '-') and stack:
            opened, deref, _ = stack[-1]
            stack[-1] = (opened, deref, True)
        elif token == var and _is_var(tokens, i):
            if any(o == '[' for o, _, _ in stack):
                return True
            # arithmetic may follow the var, so look ahead within the innermost deref group
            if stack and stack[-1][1]:
                depth = 0
                for t in tokens[i:]:
                    if t in '([':
                        depth += 1
                    elif t in ')]':
                        if depth == 0:
                            break
                        depth -= 1
                    if t in ('+', '-'):
                        return True
                if stack[-1][2]:
                    return True
    return False


def _sized_by(ctx: _Context, lines: Iterable[int], names: set[str]) -> int | None:
    for index in lines:
        for call in ctx.newer.calls[index]:
            for arg in _size_args(call):
                if names & set(arg):
                    return index
    return None


def _loc(side: _Side, start: int, end: int | None = None) -> SourceLocation:
    return side.view.location(start + 1, (start if end is None else end) + 1)


def _added_cmps(ctx: _Context, edit: _Edit) -> Iterable[_Cmp]:
    for index in edit.new:
        ctx.tick()
        if not ctx.newer.control(index):
            continue
        for cmp in ctx.newer.cmps[index]:
            if cmp.norm() not in ctx.older.cmp_set:
                yield cmp


def _is_const(tokens: Iterable[str]) -> bool:
    toks = [t for t in _strip_casts(list(tokens))[0] if t not in ('(', ')', '-')]
    return bool(toks) and all(_NUMBER.fullmatch(t) or _MACRO.fullmatch(t) for t in toks)


def _is_zero(tokens: Iterable[str]) -> bool:
    toks = [t for t in _strip_casts(list(tokens))[0] if t not in ('(', ')')]
    return toks in (['0'], ['0x0'], ['NULL'], ['0x00'])


# --- detector rules ---------------------------------------------------------

def _bnd(ctx: _Context) -> list[_Finding]:
    out = []
    for edit in ctx.edits:
        window = ctx.window(edit)
        for cmp in _added_cmps(ctx, edit):
            if cmp.op not in _ORDER:
                continue
            left, _, right = cmp.canonical()
            # `x < 0` / `0 < x` are sign tests, not bounds.
            if _is_zero(left) or _is_zero(right):
                continue
            names = _vars(left) | _vars(right)
            use = None
            for index in window:
                ctx.tick()
                toks = ctx.newer.tokens[index]
                if any(_indexed_uses(toks, name) for name in names if name in toks):
                    use = index
                    break
            if use is None:
                use = _sized_by(ctx, window, names)
            if use is None:
                continue
            first, last = sorted((cmp.line, use))
            out.append(_Finding(ctx.group(edit, cmp.line), (_loc(ctx.newer, first, last),),
                                f'added bound comparison `{_join(cmp.left)} {cmp.op} {_join(cmp.right)}` '
                                f'on a variable used as index/offset/size at newer line {use + 1}'))
    return out


def _int(ctx: _Context) -> list[_Finding]:
    out = []
    for edit in ctx.edits:
        removed = [c for i in edit.old for c in ctx.older.cmps[i] if c.norm() not in ctx.newer.cmp_set]
        added = [c for i in edit.new for c in ctx.newer.cmps[i] if c.norm() not in ctx.older.cmp_set]
        for new in added:
            ctx.tick()
            nl, nop, nr = new.canonical()
            for old in removed:
                ol, oop, orr = old.canonical()
                kind = ''
                if (oop, nop) in _STRICT_PAIR and old.norm()[0::2] == new.norm()[0::2]:
                    kind, raw_same = 'strictness', (ol, orr) == (nl, nr)
                else:
                    (osl, ocl), (osr, ocr) = _strip_casts(list(ol)), _strip_casts(list(orr))
                    (nsl, ncl), (nsr, ncr) = _strip_casts(list(nl)), _strip_casts(list(nr))
                    same = ([_norm_token(t) for t in osl + ['|'] + osr] ==
                            [_norm_token(t) for t in nsl + ['|'] + nsr])
                    if same and (oop == nop or (oop, nop) in _STRICT_PAIR) and (ocl, ocr) != (ncl, ncr):
                        kind, raw_same = 'signedness/width cast', (osl, osr) == (nsl, nsr)
                if not kind:
                    continue
                out.append(_Finding(
                    ctx.group(edit, new.line), (_loc(ctx.older, old.line), _loc(ctx.newer, new.line)),
                    f'{kind} change on the same operands: `{_join(old.left)} {old.op} {_join(old.right)}` -> '
                    f'`{_join(new.left)} {new.op} {_join(new.right)}`',
                    'moderate' if raw_same else 'weak'))
    return out


def _ovf_guard(cmp: _Cmp, defs: dict[str, list[str]]) -> bool:
    left, op, right = cmp.canonical()
    if op not in ('<', '<='):
        return False
    # Ghidra usually spills the sum first (`uVar1 = a + b; if (uVar1 < a)`), so substitute a
    # single-identifier operand by its nearest preceding definition in the window.
    if len(left) == 1 and left[0] in defs:
        left = tuple(defs[left[0]])
    summands = [_join(_strip_casts(p)[0]) for p in _split_top(list(left), '+')]
    if len(summands) > 1 and _join(_strip_casts(list(right))[0]) in summands:
        return True  # a + b < a: wrapped sum
    for side, other in ((left, right), (right, left)):
        for sep in ('-', '/'):
            parts = _split_top(list(side), sep)
            if len(parts) == 2 and _is_const(parts[0]) and parts[1] and not _is_const(other):
                return True  # MAX - y < x / MAX / y < x
    return False


def _ovf(ctx: _Context) -> list[_Finding]:
    out = []
    for edit in ctx.edits:
        window = ctx.window(edit)
        for index in edit.new:
            ctx.tick()
            if not ctx.added_line(index):
                continue
            names: set[str] = set()
            what = ''
            if ctx.newer.control(index):
                defs = {}
                for j in range(window.start, index):
                    toks = ctx.newer.tokens[j]
                    if len(toks) > 3 and toks[1] == '=' and toks[-1] == ';' and _IDENT.fullmatch(toks[0]):
                        defs[toks[0]] = toks[2:-1]
                for cmp in ctx.newer.cmps[index]:
                    if cmp.norm() not in ctx.older.cmp_set and _ovf_guard(cmp, defs):
                        names |= _vars(cmp.left + cmp.right)
                        what = f'`{_join(cmp.left)} {cmp.op} {_join(cmp.right)}`'
            for call in ctx.newer.calls[index]:
                if _CHECKED.fullmatch(call.name) and ctx.newer.call_count[call.name] > ctx.older.call_count[call.name]:
                    names |= _vars(t for arg in call.args for t in arg)
                    what = what or f'checked arithmetic `{call.name}`'
            if not names:
                continue
            # one hop: `n = a + b;` in the window makes n carry the guarded arithmetic
            linked = set(names)
            for j in window:
                toks = ctx.newer.tokens[j]
                if '=' in toks and names & set(toks[toks.index('=') + 1:]):
                    linked |= _vars(toks[:toks.index('=')])
            use = _sized_by(ctx, window, linked)
            if use is None:
                continue
            first, last = sorted((index, use))
            out.append(_Finding(ctx.group(edit, index), (_loc(ctx.newer, first, last),),
                                f'added overflow guard {what} linked to the size/alloc/copy at newer line {use + 1}'))
    return out


def _checked_use(side: _Side, index: int, call: _Call) -> bool:
    toks = side.tokens[index]
    if side.control(index):
        return True
    if call.start >= 2 and toks[call.start - 1] == '=' and _IDENT.fullmatch(toks[call.start - 2]):
        target = toks[call.start - 2]
        return any(side.control(j) and target in side.tokens[j]
                   for j in range(index + 1, min(len(side.raw), index + 1 + WINDOW)))
    return False


def _val(ctx: _Context) -> list[_Finding]:
    out = []
    old_checked = Counter(c.name for i, row in enumerate(ctx.older.calls) for c in row
                          if _checked_use(ctx.older, i, c))
    for edit in ctx.edits:
        for index in edit.new:
            ctx.tick()
            if not ctx.added_line(index):
                continue
            for call in ctx.newer.calls[index]:
                new_call = ctx.newer.call_count[call.name] > ctx.older.call_count[call.name]
                checked = _checked_use(ctx.newer, index, call)
                toks = ctx.newer.tokens[index]
                returned = call.start >= 1 and toks[call.start - 1] == 'return'
                if new_call and _PROBE.fullmatch(call.name):
                    why = f'added probe call `{call.name}`'
                elif new_call and _VALIDATOR.fullmatch(call.name) and (checked or returned):
                    why = f'added validation call `{call.name}` whose status is consumed'
                elif (not new_call and checked and ctx.older.call_count[call.name] > 0
                      and old_checked[call.name] == 0):
                    why = f'return value of existing call `{call.name}` is newly checked'
                else:
                    continue
                out.append(_Finding(ctx.group(edit, index), (_loc(ctx.newer, index),), why))
    return out


def _error_value(tokens: list[str]) -> bool:
    toks = [t for t in _strip_casts(tokens)[0] if t not in ('(', ')', ';')]
    if len(toks) == 2 and toks[0] == '-' and _NUMBER.fullmatch(toks[1]):
        return int(toks[1], 0) != 0
    if len(toks) == 1 and _NUMBER.fullmatch(toks[0]):
        return 0xC0000000 <= int(toks[0], 0) <= 0xFFFFFFFF  # NTSTATUS error severity
    return len(toks) == 1 and toks[0].startswith('STATUS_') and toks[0] not in _STATUS_OK


def _err(ctx: _Context) -> list[_Finding]:
    out = []
    for edit in ctx.edits:
        lines = list(edit.new)
        for pos, index in enumerate(lines):
            ctx.tick()
            if not (ctx.newer.control(index) and ctx.added_line(index)):
                continue
            body = lines[pos:pos + 4]
            assigned_error = False
            for j in body:
                toks = ctx.newer.tokens[j]
                start = toks.index('return') if 'return' in toks else -1
                if start >= 0 and _error_value(toks[start + 1:]):
                    hit = j
                    break
                if '=' in toks and _error_value(toks[toks.index('=') + 1:]):
                    assigned_error = True
                if 'goto' in toks and assigned_error:
                    hit = j
                    break
            else:
                continue
            out.append(_Finding(ctx.group(edit, index), (_loc(ctx.newer, index, hit),),
                                f'added predicate-controlled early exit with error status at newer line {hit + 1}'))
    return out


def _size(ctx: _Context) -> list[_Finding]:
    out = []
    def sites(side: _Side) -> dict[str, list[_Call]]:
        found: dict[str, list[_Call]] = {}
        for row in side.calls:
            for call in row:
                if call.name in _COPY or call.name in _ALLOC:
                    found.setdefault(call.name, []).append(call)
        return found
    old_sites, new_sites = sites(ctx.older), sites(ctx.newer)
    for name in sorted(set(old_sites) & set(new_sites)):
        ctx.tick()
        # An inserted or deleted callsite shifts ordinals; comparing then would be a guess.
        if len(old_sites[name]) != len(new_sites[name]):
            continue
        for old, new in zip(old_sites[name], new_sites[name], strict=True):
            edit = ctx.new_edit.get(new.line)
            if edit is None:
                continue
            old_size = [_join(map(_norm_token, a)) for a in _size_args(old)]
            new_size = [_join(map(_norm_token, a)) for a in _size_args(new)]
            if not new_size or old_size == new_size:
                continue
            out.append(_Finding(ctx.group(edit, new.line), (_loc(ctx.older, old.line), _loc(ctx.newer, new.line)),
                                f'size argument of `{name}` changed at the same call ordinal: '
                                f'`{" , ".join(_join(a) for a in _size_args(old))}` -> '
                                f'`{" , ".join(_join(a) for a in _size_args(new))}`'))
    return out


def _zeroed_object(side: _Side, index: int) -> list[str]:
    objects = []
    for call in side.calls[index]:
        if call.name == 'memset' and len(call.args) >= 2 and _is_zero(call.args[1]):
            objects.append(_strip_object(list(call.args[0])))
        elif call.name == 'RtlFillMemory' and len(call.args) >= 3 and _is_zero(call.args[2]):
            objects.append(_strip_object(list(call.args[0])))
        elif call.name in _ZERO and call.args:
            objects.append(_strip_object(list(call.args[_ZERO[call.name]])))
    toks = side.tokens[index]
    if '&=' in toks and toks[-1:] == [';']:
        at = toks.index('&=')
        if _is_const(toks[at + 1:-1]):
            objects.append(_strip_object(toks[:at]))
    return [o for o in objects if o]


def _same_object(zeroed: str, source: str) -> bool:
    if zeroed == source:
        return True
    longer, shorter = (zeroed, source) if len(zeroed) > len(source) else (source, zeroed)
    return any(longer.startswith(shorter + sep) for sep in (' . ', ' -> ', ' ['))


def _scrub(ctx: _Context) -> list[_Finding]:
    out = []
    for edit in ctx.edits:
        stop = ctx.window(edit).stop
        for index in edit.new:
            ctx.tick()
            if not ctx.added_line(index):
                continue
            for obj in _zeroed_object(ctx.newer, index):
                for j in range(index + 1, stop):
                    hit = next((c for c in ctx.newer.calls[j] if c.name in _COPY and len(c.args) > _COPY[c.name][1]
                                and _same_object(obj, _strip_object(list(c.args[_COPY[c.name][1]])))), None)
                    if hit is not None:
                        out.append(_Finding(ctx.group(edit, index), (_loc(ctx.newer, index, j),),
                                            f'added zeroing/masking of `{obj}` before `{hit.name}` reads it '
                                            f'at newer line {j + 1}'))
                        break
    return out


def _detector(id_: str, confidence: str, rule, prerequisites: tuple[str, ...], limitations: tuple[str, ...]):
    return Detector(id_, 1, confidence, SUPPORTED_CATEGORIES, COMMON_PREREQUISITES + prerequisites,
                    COMMON_LIMITATIONS + limitations, rule)


DETECTORS: tuple[Detector, ...] = (
    _detector('BND', 'moderate', _bnd, ('added/changed ordered comparison against a non-zero bound',),
              ('strong confidence requires typed IR, unavailable in this release',
               'pointer arithmetic recognized only inside *( ... ) dereferences')),
    _detector('INT', 'weak', _int, ('removed and added comparison in the same hunk',),
              ('operands must match textually after temp normalization',
               'semantically equivalent rewrites such as `i < n` -> `i <= n - 1` are not detected')),
    _detector('OVF', 'moderate', _ovf, ('added overflow guard', 'guard operand reaches a size/alloc/copy argument'),
              ('linkage follows at most one assignment hop',)),
    _detector('VAL', 'weak', _val, ('added validator/probe call or newly checked existing call',),
              ('validator recognized by name pattern only', 'status use limited to 6 following lines')),
    _detector('ERR', 'weak', _err, ('added predicate with error exit within 3 lines',),
              ('error values: negative literals, 0xC0000000-0xFFFFFFFF, non-success STATUS_* names',)),
    _detector('SIZE', 'moderate', _size, ('same callee with equal callsite count on both sides',),
              ('single-line calls only', 'inserted/deleted callsites of the same callee suppress the detector')),
    _detector('SCRUB', 'moderate', _scrub, ('added zeroing/masking of an object read by a later copy',),
              ('object identity is textual within the newer side; aliases are not tracked',)),
)
_BY_ID = {d.id: d for d in DETECTORS}


def detect(view: MatchView, enabled: Iterable[str] | None = None,
           cancel: threading.Event | None = None) -> SignalSet:
    ids = [d.id for d in DETECTORS] if enabled is None else list(dict.fromkeys(enabled))
    unknown = [i for i in ids if i not in _BY_ID]
    if unknown:
        raise ValueError(f'unknown B1 detector ids: {unknown}')
    detectors = [_BY_ID[i] for i in ids]
    outcomes: list[DetectorOutcome] = []
    signals: list[ChangeSignal] = []
    ctx: _Context | None = None
    cancelled = False
    for detector in detectors:
        reason = _unavailable_reason(detector, view)
        if cancelled or (cancel is not None and cancel.is_set()):
            cancelled = True
            outcomes.append(_outcome(view, detector.id, 'cancelled', 'cancelled'))
            continue
        if reason:
            outcomes.append(_outcome(view, detector.id, 'unavailable', reason))
            continue
        try:
            ctx = ctx or _Context(view, cancel)
            outcome, found = detector._evaluate(ctx)
        except _Cancelled:
            cancelled = True
            outcomes.append(_outcome(view, detector.id, 'cancelled', 'cancelled'))
            continue
        outcomes.append(outcome)
        signals.extend(found)
    statuses = {o.status for o in outcomes}
    status: Status
    if 'cancelled' in statuses:
        status = 'cancelled'
    elif statuses <= {'complete'}:
        status = 'complete'
    elif statuses == {'unavailable'}:
        status = 'unavailable'
    else:
        status = 'partial'
    return SignalSet(pairing_id=view.pairing_id, match_id=view.match_id, category=view.category,
                     signals=tuple(sorted(signals, key=lambda s: (s.detector, s.signal_id))),
                     outcomes=tuple(outcomes), status=status)
