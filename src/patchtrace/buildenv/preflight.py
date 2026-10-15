"""Pre-flight warnings shown while the analysis is still starting (DIE plan s7). Nothing here blocks a run.

Severity: a caution needs signature-level evidence (a shared type set from the `diec` adapter) or a medium section
layout hint; heuristic detections and low hints are at most notices and never a caution.
"""
from __future__ import annotations

from ..intelligence.tools.common import display_text
from ..intelligence.tools.diec import PACKED_TYPES, PROTECTED_TYPES
from .contracts import BuildFact, BuildFingerprint, FactSource, PreflightWarning, Severity, ToolchainVerdict
from .copy import GLYPHS, NOTICES

OVERLAY_LARGE = 1024 * 1024  # bytes; PatchTrace's own threshold, the source documents none
_SIDES = ('older', 'newer')
_NAME_LIMIT = 60


def human_size(size: int) -> str:
    for unit, scale in (('MiB', 1024 ** 2), ('KiB', 1024)):
        if size >= scale:
            return f'{size / scale:.1f} {unit}'
    return f'{size} B'


def _warning(code, side, severity: Severity, variant: str, basis: tuple[FactSource, ...], teach: str | None,
             **values) -> PreflightWarning:
    text, detail = NOTICES[variant]
    fill = {'SIDE': side.upper(), 'name': '', 'size': '', 'n': 0, **values}
    summary = GLYPHS[severity] + text.format(**fill)
    return PreflightWarning(code=code, side=side, severity=severity, summary=display_text(summary, 160),
                            detail=detail.format(**fill), basis=basis, teach_id=teach)


def _name(fact: BuildFact) -> str:
    return display_text(fact.label(), _NAME_LIMIT)


def _signature_facts(fp: BuildFingerprint, key: str, types: frozenset[str]) -> list[BuildFact]:
    return [f for f in fp.facts if f.key == key and f.certainty == 'signature' and f.raw_value('raw_type') in types]


def _packed(fp: BuildFingerprint) -> list[PreflightWarning]:
    side = fp.side
    found = _signature_facts(fp, 'packer', PACKED_TYPES)
    if found:
        return [_warning('packed', side, 'caution', 'packed', ('diec',), 'build.packed', name=_name(found[0]))]
    hints = [f for f in fp.facts if f.key == 'packer' and f.source == 'sections']
    strong = [f for f in hints if f.certainty == 'derived']
    pick = (strong or hints)[:1]
    if not pick:
        return []
    return [_warning('packed', side, 'caution' if strong else 'notice', 'packed-hint', ('sections',), 'build.packed',
                     name=_name(pick[0]))]


def _protected(fp: BuildFingerprint) -> list[PreflightWarning]:
    found = _signature_facts(fp, 'protector', PROTECTED_TYPES) + _signature_facts(fp, 'obfuscator', PROTECTED_TYPES)
    if not found:
        return []
    return [_warning('protected', fp.side, 'caution', 'protected', ('diec',), 'build.packed', name=_name(found[0]))]


def _managed(fp: BuildFingerprint) -> list[PreflightWarning]:
    fact = next((f for f in fp.facts if f.key == 'managed'), None)
    if fact is None:
        return []
    il_only = fact.value == 'il-only'
    return [_warning('managed', fp.side, 'caution' if il_only else 'notice', 'managed' if il_only else 'managed-mixed',
                     ('clr-header',), 'build.managed')]


def _installer(fp: BuildFingerprint) -> list[PreflightWarning]:
    found = [f for f in fp.facts if f.key == 'installer' and f.certainty == 'signature']
    if not found:
        return []
    return [_warning('installer', fp.side, 'notice', 'installer', ('diec',), 'build.installer', name=_name(found[0]))]


def _overlay(fp: BuildFingerprint) -> list[PreflightWarning]:
    size = fp.pe.overlay_size if fp.pe else 0
    if size < OVERLAY_LARGE:
        return []
    return [_warning('overlay-large', fp.side, 'notice', 'overlay-large', ('sections',), None, size=human_size(size))]


def _heuristics(fp: BuildFingerprint) -> list[PreflightWarning]:
    weak = [f for f in fp.facts if f.source == 'diec' and f.certainty == 'heuristic']
    if not weak:
        return []
    return [_warning('heuristic-only', fp.side, 'notice', 'heuristic-only', ('diec',), None, n=len(weak))]


def _side_warnings(fp: BuildFingerprint) -> list[PreflightWarning]:
    return (_packed(fp) + _protected(fp) + _managed(fp) + _installer(fp) + _overlay(fp) + _heuristics(fp))


def _one_sided_packing(found: dict[str, list[PreflightWarning]]) -> list[PreflightWarning]:
    packed = [side for side in _SIDES if any(w.code == 'packed' and w.severity == 'caution' for w in found[side])]
    if len(packed) != 1:
        return []
    return [_warning('packed-one-side', packed[0], 'caution', 'packed-one-side', ('diec', 'sections'),
                     'build.packed')]


def _pair_warnings(older: BuildFingerprint, newer: BuildFingerprint, toolchain: ToolchainVerdict,
                   reasons: tuple[str, ...], toolchain_text: str,
                   basis: tuple[FactSource, ...]) -> list[PreflightWarning]:
    out: list[PreflightWarning] = []
    if not (older.die and older.die.produced()) and not (newer.die and newer.die.produced()):
        out.append(_warning('tool-unavailable', 'both', 'notice', 'tool-unavailable', ('diec',), 'build.tool_missing'))
    if 'die-versions-differ' in reasons:
        out.append(_warning('stale-evidence', 'both', 'notice', 'stale-evidence', ('diec',), None))
    if 'sources-disagree' in reasons:
        out.append(_warning('sources-disagree', 'both', 'notice', 'sources-disagree', ('diec', 'rich-header'), None))
    if toolchain == 'differs':
        out.append(_warning('toolchain-differs', 'both', 'notice', 'toolchain', basis,
                            'build.toolchain_differs', name=display_text(toolchain_text, _NAME_LIMIT)))
    return out


def build_preflight(older: BuildFingerprint, newer: BuildFingerprint, toolchain: ToolchainVerdict,
                    reasons: tuple[str, ...], toolchain_text: str,
                    basis: tuple[FactSource, ...]) -> tuple[PreflightWarning, ...]:
    """Cautions first, then notices; each group keeps the order older, newer, pair."""
    per_side = {fp.side: _side_warnings(fp) for fp in (older, newer)}
    ordered = [w for side in _SIDES for w in per_side[side]] + _one_sided_packing(per_side) \
        + _pair_warnings(older, newer, toolchain, reasons, toolchain_text, basis)
    return tuple(sorted(ordered, key=lambda w: w.severity != 'caution'))[:16]
