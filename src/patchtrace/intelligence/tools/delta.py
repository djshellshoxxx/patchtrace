"""Older/newer deltas of tool evidence (SPEC-29 tools T6). Pure: no Qt, no I/O.

Never averages, scores or ranks: an entry says what changed, where (only from genuine localization) and why the
change may not be a behaviour change. Added behaviour in a function the analysis pairs as unchanged is
`newly-detectable` (same code, different detection), not `newly-introduced`. Entries without a function the tool
itself reported are `unlocalized`; without pairing they are `unknown`. Quality flags (DiE toolchain/packing, capa
limitations, function-recovery shifts) annotate but never reclassify, and DiE is never presented as reducing false
leads (`value_gate: 'unvalidated'`).
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Literal

from pydantic import Field

from .common import (
    CONTRACT,
    LOCALIZED,
    CapabilityEvidence,
    Engine,
    EvidenceLink,
    StringEvidence,
    ToolEvidenceSet,
    ToolRun,
    _Strict,
    redacted_display,
)
from .normalize import FunctionPairing, comparability

MAX_LOCATIONS = 16
MAX_STRING_CHANGES = 10_000
DISTORTION_NOTE = 'comparison may be distorted by a toolchain change or packing (see flags)'
Classification = Literal['newly-introduced', 'newly-detectable', 'removed-with-code', 'no-longer-detected',
                         'unlocalized', 'unknown', 'unchanged']
FlagCode = Literal['toolchain-changed', 'packed', 'protected', 'heuristic-only', 'environment-unknown',
                   'capa-limitation', 'function-recovery-shift']


class CapabilityChange(_Strict):
    rule_id: str = Field(max_length=256)
    namespace: str | None = Field(default=None, max_length=256)
    scope: str = Field(max_length=16)
    kind: Literal['capability', 'library']
    change: Literal['added', 'removed', 'unchanged']
    classification: Classification
    older: tuple[EvidenceLink, ...] = Field(default=(), max_length=MAX_LOCATIONS)
    newer: tuple[EvidenceLink, ...] = Field(default=(), max_length=MAX_LOCATIONS)
    older_matches: int = 0
    newer_matches: int = 0
    notes: tuple[str, ...] = ()


class StringChange(_Strict):
    value_hash: str
    display_value: str = Field(max_length=256)
    secret_kind: str | None = None
    length: int
    change: Literal['added', 'removed', 'unchanged', 'representation-changed']
    older_types: tuple[str, ...] = ()
    newer_types: tuple[str, ...] = ()
    older: tuple[EvidenceLink, ...] = Field(default=(), max_length=MAX_LOCATIONS)
    newer: tuple[EvidenceLink, ...] = Field(default=(), max_length=MAX_LOCATIONS)


class EnvironmentChange(_Strict):
    category: str
    label: str = Field(max_length=200)
    certainty: str
    heuristic: bool
    change: Literal['added', 'removed', 'unchanged']
    detect_string: str = Field(default='', max_length=200)


class QualityFlag(_Strict):
    code: FlagCode
    detail: str = Field(max_length=500)
    source: Engine


class ToolDelta(_Strict):
    contract: Literal['tool-evidence/1'] = CONTRACT
    engine: Engine
    older_run_id: str | None
    newer_run_id: str | None
    comparable: bool
    reasons: tuple[str, ...] = ()
    pairing: Literal['available', 'unavailable'] = 'unavailable'
    capabilities: tuple[CapabilityChange, ...] = ()
    strings: tuple[StringChange, ...] = ()
    environment: tuple[EnvironmentChange, ...] = ()
    flags: tuple[QualityFlag, ...] = ()
    counts: dict[str, int] = Field(default_factory=dict)
    notes: tuple[str, ...] = ()
    truncated: bool = False
    value_gate: Literal['unvalidated'] = 'unvalidated'


def _function_rva(link: EvidenceLink) -> int | None:
    return int(link.function_id[6:], 16) if link.function_id else None


def resolve(link: EvidenceLink, side: str, pairing: FunctionPairing, notes: set[str]) -> EvidenceLink:
    """Attach the project's function id when exactly one project record starts at the tool-reported function."""
    rva = _function_rva(link)
    if rva is None or link.attribution not in LOCALIZED:
        return link
    project_id, ambiguous = pairing.project_function(side, rva)
    if ambiguous:
        notes.add(f'function-ambiguous:{side}:0x{rva:x}')
    return link.model_copy(update={'project_function_id': project_id}) if project_id else link


def _classify(links: Sequence[EvidenceLink], side: str, pairing: FunctionPairing) -> Classification:
    labels = set()
    for link in links:
        rva = _function_rva(link)
        if link.attribution not in LOCALIZED or rva is None:
            labels.add('unlocalized')
            continue
        status = pairing.status(side, rva)
        if side == 'newer':
            labels.add({'added': 'newly-introduced', 'modified': 'newly-introduced',
                        'unchanged': 'newly-detectable'}.get(status, 'unknown'))
        else:
            labels.add({'removed': 'removed-with-code', 'modified': 'removed-with-code',
                        'unchanged': 'no-longer-detected'}.get(status, 'unknown'))
    for label in ('newly-introduced', 'removed-with-code', 'unknown', 'newly-detectable', 'no-longer-detected'):
        if label in labels:
            return label
    return 'unlocalized'


def _capabilities(older: ToolEvidenceSet, newer: ToolEvidenceSet,
                  pairing: FunctionPairing, notes: set[str]) -> list[CapabilityChange]:
    groups: dict[tuple, dict[str, list[CapabilityEvidence]]] = defaultdict(lambda: {'older': [], 'newer': []})
    for side, evidence in (('older', older), ('newer', newer)):
        for item in evidence.capabilities:
            if item.kind != 'limitation':
                groups[(item.kind, item.rule_id, item.scope)][side].append(item)
    changes = []
    for (kind, rule_id, scope), sides in sorted(groups.items(), key=lambda kv: (kv[0][0] != 'capability', kv[0])):
        old, new = sides['older'], sides['newer']
        old_links = [resolve(i.location, 'older', pairing, notes) for i in old]
        new_links = [resolve(i.location, 'newer', pairing, notes) for i in new]
        if old and new:
            change, label = 'unchanged', 'unchanged'
        elif new:
            change, label = 'added', _classify(new_links, 'newer', pairing)
        else:
            change, label = 'removed', _classify(old_links, 'older', pairing)
        entry_notes = []
        if old and new and len(old) != len(new):
            entry_notes.append(f'match count {len(old)} -> {len(new)}')
        sample = (old or new)[0]
        changes.append(CapabilityChange(
            rule_id=rule_id, namespace=sample.namespace, scope=scope, kind=kind, change=change, classification=label,
            older=tuple(old_links[:MAX_LOCATIONS]), newer=tuple(new_links[:MAX_LOCATIONS]), older_matches=len(old),
            newer_matches=len(new), notes=tuple(entry_notes)))
    return changes


def _strings(older: ToolEvidenceSet, newer: ToolEvidenceSet, show_secrets: bool,
             include_unchanged: bool) -> tuple[list[StringChange], int, bool]:
    groups: dict[str, dict[str, list[StringEvidence]]] = defaultdict(lambda: {'older': [], 'newer': []})
    for side, evidence in (('older', older), ('newer', newer)):
        for item in evidence.strings:
            groups[item.value_hash][side].append(item)
    changes, unchanged = [], 0
    for value_hash in sorted(groups):
        old, new = groups[value_hash]['older'], groups[value_hash]['newer']
        old_types, new_types = tuple(sorted({s.type for s in old})), tuple(sorted({s.type for s in new}))
        if old and new:
            change = 'unchanged' if old_types == new_types else 'representation-changed'
        else:
            change = 'added' if new else 'removed'
        if change == 'unchanged':
            unchanged += 1
            if not include_unchanged:
                continue
        sample = (new or old)[0]
        display = sample.display_value if show_secrets else redacted_display(sample.display_value, sample.secret_kind)
        changes.append(StringChange(
            value_hash=value_hash, display_value=display, secret_kind=sample.secret_kind, length=sample.length,
            change=change, older_types=old_types, newer_types=new_types,
            older=tuple(s.source_location for s in old[:MAX_LOCATIONS]),
            newer=tuple(s.source_location for s in new[:MAX_LOCATIONS])))
    truncated = len(changes) > MAX_STRING_CHANGES
    return changes[:MAX_STRING_CHANGES], unchanged, truncated


def _environment(older: ToolEvidenceSet, newer: ToolEvidenceSet) -> list[EnvironmentChange]:
    def key(item) -> tuple:
        label = item.toolchain or item.packer or item.protector or item.detector_rule
        return item.category, label, item.certainty, item.heuristic

    olds = {key(e): e for e in older.environment}
    news = {key(e): e for e in newer.environment}
    out = []
    for k in sorted(set(olds) | set(news)):
        item = news.get(k) or olds[k]
        change = 'unchanged' if k in olds and k in news else ('added' if k in news else 'removed')
        out.append(EnvironmentChange(category=k[0], label=k[1], certainty=k[2], heuristic=k[3], change=change,
                                     detect_string=item.detect_string))
    return out


def quality_flags(diec: tuple[ToolEvidenceSet | None, ToolEvidenceSet | None] = (None, None),
                  capa: tuple[ToolEvidenceSet | None, ToolEvidenceSet | None] = (None, None)) -> tuple[QualityFlag, ...]:
    """T6.4 informational flags. Missing evidence raises no flag (unknown is not a negative vote)."""
    flags: list[QualityFlag] = []
    old_env, new_env = diec
    if old_env is not None and new_env is not None:
        def toolchain(s: ToolEvidenceSet) -> set[tuple[str, str]]:
            return {(e.category, e.toolchain or e.detector_rule) for e in s.environment
                    if e.certainty == 'signature' and e.category in ('compiler', 'linker', 'tool')}
        old_tc, new_tc = toolchain(old_env), toolchain(new_env)
        if old_tc and new_tc and old_tc != new_tc:
            flags.append(QualityFlag(code='toolchain-changed', source='diec', detail=(
                'older: ' + '; '.join(sorted(n for _, n in old_tc)) + ' | newer: '
                + '; '.join(sorted(n for _, n in new_tc)))[:500]))
        for side, evidence in (('older', old_env), ('newer', new_env)):
            for item in evidence.environment:
                if item.certainty != 'signature':
                    continue
                if item.category in ('packer', 'cryptor', 'sfx', 'installer'):
                    flags.append(QualityFlag(code='packed', source='diec', detail=f'{side}: {item.detect_string}'))
                elif item.category == 'protector':
                    flags.append(QualityFlag(code='protected', source='diec', detail=f'{side}: {item.detect_string}'))
        weak = [f'{side}: {e.detect_string}' for side, s in (('older', old_env), ('newer', new_env))
                for e in s.environment if e.certainty == 'heuristic']
        if weak:
            flags.append(QualityFlag(code='heuristic-only', source='diec', detail=(
                'weak heuristic detections, not used as evidence: ' + '; '.join(weak))[:500]))
        unknown = [side for side, s in (('older', old_env), ('newer', new_env))
                   if any(e.certainty == 'unknown' for e in s.environment) or (
                       not any(e.certainty == 'signature' and e.category in ('compiler', 'linker', 'tool')
                               for e in s.environment))]
        if unknown:
            flags.append(QualityFlag(code='environment-unknown', source='diec', detail=(
                'no signature-level toolchain detection on: ' + ', '.join(unknown)
                + '; a toolchain change cannot be confirmed or excluded')))
    old_capa, new_capa = capa
    if old_capa is not None and new_capa is not None:
        limits = sorted({f'{side}: {c.rule_id}' for side, s in (('older', old_capa), ('newer', new_capa))
                         for c in s.capabilities if c.kind == 'limitation'})
        if limits:
            flags.append(QualityFlag(code='capa-limitation', source='capa', detail='; '.join(limits)[:500]))
        a, b = old_capa.analysis.get('functions_recovered'), new_capa.analysis.get('functions_recovered')
        if isinstance(a, int) and isinstance(b, int) and min(a, b) > 0 and max(a, b) > 2 * min(a, b):
            flags.append(QualityFlag(code='function-recovery-shift', source='capa', detail=(
                f'capa recovered {a} functions in the older and {b} in the newer artifact')))
    return tuple(dict.fromkeys(flags))


def compute(older_run: ToolRun | None, older: ToolEvidenceSet | None, newer_run: ToolRun | None,
            newer: ToolEvidenceSet | None, *, pairing: FunctionPairing | None = None,
            flags: Iterable[QualityFlag] = (), show_secrets: bool = False,
            include_unchanged_strings: bool = False) -> ToolDelta:
    engine = (older_run or newer_run).engine
    pairing = pairing or FunctionPairing.empty()
    reasons: list[str] = []
    if older_run is None or newer_run is None:
        missing = [side for side, run in (('older', older_run), ('newer', newer_run)) if run is None]
        reasons.append('no stored run for the ' + ' and '.join(missing) + ' artifact')
    else:
        reasons += comparability(older_run, newer_run)
        for side, run, evidence in (('older', older_run, older), ('newer', newer_run, newer)):
            if not reasons and evidence is None:
                reasons.append(f'{side} evidence is missing')
            elif evidence is not None and (evidence.cache_key != run.cache_key
                                           or evidence.artifact_sha256 != run.input_artifact_hash):
                reasons.append(f'{side} evidence does not belong to the {side} run')
    flags = tuple(flags)
    base = dict(engine=engine, older_run_id=older_run.run_id if older_run else None,
                newer_run_id=newer_run.run_id if newer_run else None, flags=flags,
                pairing='available' if pairing.available else 'unavailable', notes=tuple(pairing.notes))
    if reasons:
        return ToolDelta(comparable=False, reasons=tuple(reasons), **base)
    notes: set[str] = set()
    capabilities = _capabilities(older, newer, pairing, notes)
    distorted = any(f.code in ('toolchain-changed', 'packed', 'protected') for f in flags)
    if distorted:
        capabilities = [c.model_copy(update={'notes': (*c.notes, DISTORTION_NOTE)})
                        if c.classification in ('newly-introduced', 'removed-with-code') else c for c in capabilities]
    strings, unchanged_strings, truncated = _strings(older, newer, show_secrets, include_unchanged_strings)
    environment = _environment(older, newer) if engine == 'diec' else []
    counts: dict[str, int] = defaultdict(int)
    for change in capabilities:
        counts[f'capabilities_{change.change}'] += 1
        if change.change != 'unchanged':
            counts[f'classification_{change.classification}'] += 1
    for change in strings:
        counts[f'strings_{change.change}'] += 1
    counts['strings_unchanged'] = unchanged_strings
    for change in environment:
        counts[f'environment_{change.change}'] += 1
    return ToolDelta(comparable=True, capabilities=tuple(capabilities), strings=tuple(strings),
                     environment=tuple(environment), counts=dict(counts),
                     truncated=truncated or older.truncated or newer.truncated,
                     **(base | {'notes': (*base['notes'], *sorted(notes))}))


def has_changes(delta: ToolDelta) -> bool:
    return any(c.change != 'unchanged' for c in delta.capabilities) or any(
        s.change != 'unchanged' for s in delta.strings) or any(e.change != 'unchanged' for e in delta.environment)
