"""YARA-X facade for the capped worker process (plan s6, s7). The parent never imports this module.

Only the worker loads `yara_x` (through `optional_deps`, so a missing wheel is a clear unavailable state). Rules are
compiled from PatchTrace's own text only, never deserialized. A file the engine did not read is `not-scanned`
with a reason from a closed list, never a no-hit.
"""
from __future__ import annotations

import hashlib
import struct
import time
from collections.abc import Sequence
from importlib import metadata

from .. import optional_deps
from .contracts import CellResult, EngineStamp, LintFinding, RuleText, WorkerTarget
from .errors import RulesError

ENGINE_PIN = '1.21.0'
RULE_NAME_REGEX = r'^PT_[0-9a-f]{12}_(older|newer)$'
NOT_SCANNED = {'too-large': 'file is larger than the limit', 'unreadable': 'file could not be read',
               'not-pe': 'not a PE image', 'changed': 'file changed while reading'}
_MESSAGE_CHARS = 512
Sections = list[tuple[int, int, int]]


def _yara_x():
    module = optional_deps.yara_x
    if module is None:
        raise RulesError('PT-RULE-UNAVAILABLE', 'The rule engine (YARA-X) is not available in this installation.')
    return module


def _installed(distribution: str) -> str | None:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:  # frozen builds may lack dist-info
        return None


def stamp() -> EngineStamp:
    _yara_x()
    version = _installed('yara-x')
    decoder_version = _installed('iced-x86')  # the decoder serves bytes features (R4), not the scan
    return EngineStamp(version=version or ENGINE_PIN, version_source='metadata' if version else 'pin',
                       decoder='iced-x86' if decoder_version else 'none', decoder_version=decoder_version or 'none')


def _compiler():
    compiler = _yara_x().Compiler(error_on_slow_pattern=True, includes_enabled=False)
    compiler.allowed_rule_name(RULE_NAME_REGEX, error=True)
    return compiler


def _finding(rule_name: str, item: dict, severity: str) -> LintFinding:
    return LintFinding(rule_name=rule_name, code=str(item.get('code', 'unknown'))[:64], severity=severity,
                       message=str(item.get('title', ''))[:_MESSAGE_CHARS])


def lint(rules: Sequence[RuleText]) -> tuple[LintFinding, ...]:
    """Compile each rule alone with the linters on; warnings are read before `build()` resets them."""
    yara_x = _yara_x()
    findings: list[LintFinding] = []
    for rule in rules:
        compiler = _compiler()
        try:
            compiler.add_source(rule.text)
        except yara_x.CompileError:
            findings.extend(_finding(rule.name, e, 'error') for e in compiler.errors())
        findings.extend(_finding(rule.name, w, 'warning') for w in compiler.warnings())
    return tuple(findings)


def _compile(rules: Sequence[RuleText]):
    yara_x = _yara_x()
    compiler = _compiler()
    try:
        for rule in rules:
            compiler.add_source(rule.text)
        return compiler.build()
    except yara_x.CompileError:
        title = (compiler.errors() or [{}])[0].get('title', 'invalid rule')
        raise RulesError('PT-RULE-COMPILE', f'A rule failed to compile: {title}'[:_MESSAGE_CHARS]) from None


def pe_sections(data: bytes) -> Sections | None:
    """(rva, raw offset, raw size) per section, or None when `data` is not a PE image."""
    if len(data) < 0x40 or data[:2] != b'MZ':
        return None
    (lfanew,) = struct.unpack_from('<I', data, 0x3C)
    if lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b'PE\0\0':
        return None
    (count,) = struct.unpack_from('<H', data, lfanew + 6)
    (optional_size,) = struct.unpack_from('<H', data, lfanew + 20)
    table = lfanew + 24 + optional_size
    sections: Sections = []
    for index in range(min(count, 96)):
        base = table + 40 * index
        if base + 40 > len(data):
            break
        _, rva, raw_size, raw_ptr = struct.unpack_from('<IIII', data, base + 8)
        sections.append((rva, raw_ptr, raw_size))
    return sections


def offset_to_rva(sections: Sections, offset: int) -> int | None:
    for rva, raw_ptr, raw_size in sections:
        if raw_ptr <= offset < raw_ptr + raw_size:
            return rva + offset - raw_ptr
    return None


def _read(target: WorkerTarget, max_bytes: int) -> tuple[bytes | None, str]:
    """(bytes, '') or (None, NOT_SCANNED key). One read, so the hash covers exactly what is scanned."""
    try:
        with open(target.path, 'rb') as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None, 'unreadable'
    if len(data) > max_bytes:
        return None, 'too-large'
    if len(data) != target.size or (target.sha256 and hashlib.sha256(data).hexdigest() != target.sha256):
        return None, 'changed'
    return (data, '') if pe_sections(data) is not None else (None, 'not-pe')


def _uniform(rules: Sequence[RuleText], target: WorkerTarget, state: str, reason: str) -> list[CellResult]:
    return [CellResult(rule_name=r.name, target_id=target.target_id, state=state, reason=reason) for r in rules]


def _cells(rules: Sequence[RuleText], target: WorkerTarget, result, data: bytes, elapsed_ms: int,
           offsets_cap: int) -> list[CellResult]:
    sections = pe_sections(data) or []
    matched = {rule.identifier: rule for rule in result.matching_rules}
    cells = []
    for rule in rules:
        hit = matched.get(rule.name)
        if hit is None:
            cells.append(CellResult(rule_name=rule.name, target_id=target.target_id, state='no-hit',
                                    elapsed_ms=elapsed_ms))
            continue
        found = sorted(m.offset for pattern in hit.patterns for m in pattern.matches)
        rvas = [r for r in (offset_to_rva(sections, o) for o in found) if r is not None]
        cells.append(CellResult(rule_name=rule.name, target_id=target.target_id, state='hit', hits=max(1, len(found)),
                                offsets=tuple(found[:offsets_cap]), rvas=tuple(rvas[:offsets_cap]),
                                elapsed_ms=elapsed_ms))
    return cells


def scan(rules: Sequence[RuleText], targets: Sequence[WorkerTarget], limits: dict[str, int]) -> tuple[CellResult, ...]:
    yara_x = _yara_x()
    scanner = yara_x.Scanner(_compile(rules))
    scanner.set_timeout(limits['target_timeout_s'])
    scanner.max_matches_per_pattern(limits['max_matches_per_pattern'])
    cells: list[CellResult] = []
    for target in targets:
        data, key = _read(target, limits['target_file_bytes'])
        if data is None:
            cells.extend(_uniform(rules, target, 'not-scanned', NOT_SCANNED[key]))
            continue
        started = time.monotonic()
        try:
            result = scanner.scan(data)
        except yara_x.TimeoutError:
            cells.extend(_uniform(rules, target, 'timeout', 'scan exceeded the time limit'))
        except yara_x.ScanError:
            cells.extend(_uniform(rules, target, 'error', 'the engine could not scan this file'))
        else:
            cells.extend(_cells(rules, target, result, data, int((time.monotonic() - started) * 1000),
                                limits['cell_offsets']))
    return tuple(cells)
