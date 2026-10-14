"""YARA-X facade (R2). With `worker.py` (and the R4 mask adapter for `iced_x86`) the only module that imports the engine
extension: the parent process, the GUI and the CLI never load the `.pyd`, because a scan holds the GIL for its whole
duration, the extension's classes are not thread-safe and a Rust panic is a `BaseException` (plan s2, s6). Everything
here runs inside the capped worker child; tests call it in-process.

Rule text is untrusted data. It is compiled, never executed, with the PatchTrace linters (required provenance metadata,
a rule-name regex, a tag whitelist, no includes, slow patterns are errors) and its imports, rule count and pattern count
are checked. Rules are built from our own text only, never deserialized. Targets are scanned as in-memory bytes (the
engine's file API memory-maps and a truncation under it raises SIGBUS). Compiler diagnostics are reduced to a code, a
bounded clean one-line title (which may name the offending token, such as an unknown identifier) and a position: the
engine's rendered source excerpts quote whole rule lines and are dropped.

The per-file timeout has the engine's one-second granularity: its timer ticks on a grid of its own, so a limit of T
seconds aborts a scan between T-1 and T seconds after it starts (measured). It is a bound, not a stopwatch.
"""
from __future__ import annotations

import io
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import metadata

import yara_x
from pydantic import ValidationError

from .contracts import (
    DECODER_PIN,
    ENGINE_PIN,
    CellResult,
    Diagnostic,
    EngineStamp,
    LintResult,
    WorkerLimits,
    WorkerRule,
    clean_line,
)
from .errors import RuleError

_T = yara_x.MetaType
META = (  # (identifier, type, required): the provenance every generated rule carries (grammar yrx-gen/1)
    ('patchtrace_rule_id', _T.STRING, True), ('patchtrace_version', _T.INTEGER, True),
    ('patchtrace_project_id', _T.STRING, True), ('older_sha256', _T.SHA256, True), ('newer_sha256', _T.SHA256, True),
    ('side', _T.STRING, True), ('change', _T.STRING, True), ('statement', _T.STRING, True),
    ('function_older', _T.STRING, False), ('function_newer', _T.STRING, False), ('cve', _T.STRING, False),
    ('kb', _T.STRING, False), ('cwe', _T.STRING, False), ('capability', _T.STRING, False),
    ('analyst_label', _T.STRING, False))
RULE_NAME = r'^PT_[0-9a-f]{12}_(older|newer)$'
TAGS = ('patchtrace', 'older_side', 'newer_side')
IMPORTS = ('pe',)
DEFAULT_LIMITS = WorkerLimits()
_PROBE_RULE = ('import "pe"\nrule patchtrace_probe {\n  strings:\n    $a = { 4D 5A }\n  condition:\n'
               '    $a at 0 and uint16(0) == 0x5A4D and not pe.is_pe\n}\n')
_PROBE_DATA = b'MZ' + bytes(62)
_BROKEN = CellResult(state='error', reason='compile-failed')
_LISTED = 16  # identifiers and imports reported per rule


# --- identity -------------------------------------------------------------------------------------------------------

def installed_version(distribution: str, pin: str) -> tuple[str, str]:
    """(version, source). A frozen build may lack the distribution metadata; then the pinned version is stated."""
    try:
        return metadata.version(distribution), 'metadata'
    except metadata.PackageNotFoundError:
        return pin, 'pin'


def decoder_stamp() -> tuple[str, str | None]:
    """The mask decoder this installation has, found by importing it (a broken extension is simply unavailable)."""
    try:
        import iced_x86  # noqa: F401
    except Exception:
        return 'none', None
    return 'iced-x86', installed_version('iced-x86', DECODER_PIN)[0]


def stamp(*, decoder: bool = False) -> EngineStamp:
    """Who produced a result. Only the probe pays for the decoder check; scan and lint results state `none`."""
    version, source = installed_version('yara-x', ENGINE_PIN)
    name, decoder_version = decoder_stamp() if decoder else ('none', None)
    return EngineStamp(version=version, version_source=source, decoder=name, decoder_version=decoder_version)


def probe() -> tuple[EngineStamp, tuple[str, ...]]:
    """Start-up check: compile and scan one tiny rule (this exercises the engine's JIT, which Arbitrary Code Guard or
    an EDR can block) and report the stamp and the module list. Raises `PT-RULE-UNAVAILABLE` (blocked state R1)."""
    try:
        compiler = yara_x.Compiler()
        compiler.add_source(_PROBE_RULE)
        matched = [r.identifier for r in yara_x.Scanner(compiler.build()).scan(_PROBE_DATA).matching_rules]
        modules = tuple(yara_x.module_names())
    except Exception:
        raise RuleError('PT-RULE-UNAVAILABLE', 'The rule engine did not pass its start-up check',
                        reason='probe-failed') from None
    if matched != ['patchtrace_probe'] or 'pe' not in modules:
        raise RuleError('PT-RULE-UNAVAILABLE', 'The rule engine gave an unexpected start-up answer',
                        reason='probe-mismatch')
    return stamp(decoder=True), modules


# --- compile and lint -------------------------------------------------------------------------------------------------

def format_text(text: str) -> str:
    """The text as `yara_x.Formatter` lays it out (the layout `yrx-gen/1` emits, so a stable rule equals this)."""
    out = io.BytesIO()
    yara_x.Formatter().format(io.BytesIO(text.encode('utf-8')), out)
    return out.getvalue().decode('utf-8')


def _compiler(limits: WorkerLimits) -> yara_x.Compiler:
    compiler = yara_x.Compiler(error_on_slow_pattern=True, includes_enabled=False)
    compiler.max_warnings(limits.diagnostics_per_rule)
    for identifier, kind, required in META:
        compiler.allowed_metadata(identifier, kind, required=required, error=True)
    compiler.allowed_rule_name(RULE_NAME, error=True)
    compiler.allowed_tags(list(TAGS), error=True)
    return compiler


def _position(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value < 2**31 else None


def _diagnostic(item: dict) -> Diagnostic:
    code, title = str(item.get('code') or ''), clean_line(item.get('title'), 200)
    try:
        return Diagnostic(code=code, title=title or code, line=_position(item.get('line')),
                          column=_position(item.get('column')))
    except ValidationError:  # a code of a shape this release does not know
        return Diagnostic(code='unknown', title=title or 'unknown', line=_position(item.get('line')),
                          column=_position(item.get('column')))


def _diagnostics(items: Sequence[dict], limit: int) -> tuple[Diagnostic, ...]:
    return tuple(_diagnostic(item) for item in items[:limit])


def lint(name: str, text: str, limits: WorkerLimits = DEFAULT_LIMITS) -> LintResult:
    """Compile one rule text with the PatchTrace linters. `ok` also needs exactly one rule, only `import "pe"` and at
    most `patterns_per_rule` patterns; `formatter_stable` is reported on its own (see `LintResult`)."""
    compiler = _compiler(limits)
    try:
        compiler.add_source(text)
    except yara_x.CompileError:
        errors = _diagnostics(compiler.errors(), limits.diagnostics_per_rule) or (
            Diagnostic(code='compile_error', title='the rule does not compile'),)
        return LintResult(name=name, ok=False, errors=errors,
                          warnings=_diagnostics(compiler.warnings(), limits.diagnostics_per_rule))
    warnings = _diagnostics(compiler.warnings(), limits.diagnostics_per_rule)  # before build(): it resets the compiler
    rules = compiler.build()
    found, imports = list(rules), tuple(sorted(rules.imports()))
    patterns = sum(len(rule.patterns) for rule in found)
    facts = {'identifiers': tuple(rule.identifier for rule in found)[:_LISTED], 'imports': imports[:_LISTED],
             'patterns': patterns}
    problems = []
    if len(found) != 1:
        problems.append(Diagnostic(code='pt_rule_count', title=f'the text defines {len(found)} rules; exactly one'))
    if imports != IMPORTS:
        problems.append(Diagnostic(code='pt_imports', title='the only allowed import is "pe"'))
    if patterns > limits.patterns_per_rule:
        problems.append(Diagnostic(code='pt_patterns',
                                   title=f'{patterns} patterns exceed the limit of {limits.patterns_per_rule}'))
    if problems:
        return LintResult(name=name, ok=False, errors=tuple(problems), warnings=warnings, **facts)
    return LintResult(name=name, ok=True, warnings=warnings, formatter_stable=format_text(text) == text, **facts)


# --- scan -------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PeMap:
    """What the engine's own PE parser says about a target: enough to turn file offsets into module-relative addresses."""
    headers: int
    sections: tuple[tuple[int, int, int], ...]  # (raw offset, raw size, rva)


def pe_map(data: bytes) -> PeMap | None:
    """None when the engine does not see a PE image (the same `pe.is_pe` the rules use, so "not a PE image" and a rule
    that cannot match can never be confused)."""
    out = yara_x.Module('pe').invoke(data)
    if not out.get('is_pe'):
        return None
    sections = tuple((s['raw_data_offset'], s['raw_data_size'], s['virtual_address'])
                     for s in out.get('sections') or ())
    return PeMap(out.get('size_of_headers') or 0, sections)


def offset_to_rva(pe: PeMap, offset: int) -> int | None:
    """Module-relative address of a file offset; None in the overlay or between sections."""
    if offset < pe.headers:
        return offset
    for raw, size, rva in pe.sections:
        if raw <= offset < raw + size:
            result = rva + (offset - raw)
            return result if result < 2**32 else None
    return None


class RuleSet:
    """The rules of one request compiled together: each in its own namespace, so versions of one lineage that share a
    YARA identifier stay apart, and one pass over a target serves every rule. A rule that fails its lint is not
    compiled; its cells read `error` (`compile-failed`) while the others are scanned normally."""

    def __init__(self, lint_results: tuple[LintResult, ...], namespaces: tuple[str | None, ...],
                 rules: yara_x.Rules | None, limits: WorkerLimits):
        self.lint = lint_results
        self._namespaces = namespaces
        self._limits = limits
        self._scanner = None
        if rules is not None:
            self._scanner = yara_x.Scanner(rules)
            self._scanner.set_timeout(limits.target_timeout_s)
            self._scanner.max_matches_per_pattern(limits.max_matches_per_pattern)

    @classmethod
    def compile(cls, rules: Sequence[WorkerRule], limits: WorkerLimits = DEFAULT_LIMITS) -> RuleSet:
        results = tuple(lint(rule.name, rule.text, limits) for rule in rules)
        compiler = _compiler(limits)
        namespaces: list[str | None] = []
        for index, (rule, result) in enumerate(zip(rules, results, strict=True)):
            if not result.ok:
                namespaces.append(None)
                continue
            compiler.new_namespace(f'n{index}')
            compiler.add_source(rule.text)
            namespaces.append(f'n{index}')
        return cls(results, tuple(namespaces), compiler.build() if any(namespaces) else None, limits)

    def _row(self, make: Callable[[str], CellResult]) -> tuple[CellResult, ...]:
        """One cell per rule in request order; a rule that did not compile reads `error` on every target."""
        return tuple(_BROKEN if ns is None else make(ns) for ns in self._namespaces)

    def skip(self, reason: str) -> tuple[CellResult, ...]:
        """The row for a target that could not be scanned for a reason of the closed `not-scanned` list."""
        return self._row(lambda ns: CellResult(state='not-scanned', reason=reason))

    def scan(self, data: bytes) -> tuple[CellResult, ...]:
        """One cell per rule, in request order. Never raises for a bad target: not a PE image, a timeout and an engine
        scan error become cells. Everything else (a panic, memory) is the worker's to classify."""
        if self._scanner is None:
            return self._row(lambda ns: _BROKEN)
        started = time.monotonic()

        def elapsed() -> int:
            return int((time.monotonic() - started) * 1000)
        pe = pe_map(data)
        if pe is None:
            return self.skip('not-pe')
        try:
            matched = {r.namespace: r for r in self._scanner.scan(data).matching_rules}
        except yara_x.TimeoutError:
            spent = elapsed()
            return self._row(lambda ns: CellResult(state='timeout', elapsed_ms=spent))
        except yara_x.ScanError:
            spent = elapsed()
            return self._row(lambda ns: CellResult(state='error', reason='scan-error', elapsed_ms=spent))
        spent = elapsed()  # one reading per target: every rule shares the single pass over it
        return self._row(lambda ns: self._cell(matched.get(ns), pe, spent))

    def _cell(self, rule: yara_x.Rule | None, pe: PeMap, elapsed_ms: int) -> CellResult:
        if rule is None:
            return CellResult(state='no-hit', hits=0, elapsed_ms=elapsed_ms)
        matches: list = []
        for pattern in rule.patterns:  # declaration order: the first pattern that matched is the rule's anchor
            matches = list(pattern.matches)
            if matches:
                break
        offsets = tuple(sorted({m.offset for m in matches})[:self._limits.offsets_per_cell])
        return CellResult(state='hit', hits=len(matches) or 1, offsets=offsets,
                          rvas=tuple(offset_to_rva(pe, o) for o in offsets), elapsed_ms=elapsed_ms)
