"""Per-side build-environment fingerprint from two independent channels (DIE plan s7).

Channel A is PatchTrace's own PE facts, channel B the stored `diec` signature detections. Facts are labelled
with their certainty and never merged: both channels stay visible, and a missing channel adds nothing.
"""
from __future__ import annotations

import re

from ..intelligence.tools.common import EnvironmentEvidence, ToolEvidenceSet, display_text
from ..pe_overview.models import PackerHint
from .contracts import (
    FACTS_VERSION,
    MAX_ANOMALIES,
    MAX_FACTS,
    BuildEnvError,
    BuildFact,
    BuildFingerprint,
    BuiltFrom,
    DieSummary,
    FactKey,
    FactSource,
    PeBuildFacts,
    Side,
)

# EnvironmentEvidence.category -> fact key; categories without a key (format, library, ...) are not build facts.
_DIEC_KEYS: dict[str, FactKey] = {
    'compiler': 'compiler', 'linker': 'linker', 'tool': 'build_tool', 'packer': 'packer', 'cryptor': 'packer',
    'protector': 'protector', 'installer': 'installer', 'sfx': 'installer', 'language': 'language',
    'os': 'target_os'}
# Warning-free upstream types that still say something about protection; listed under `protector`, never raise a caution.
_NEUTRAL_PROTECTION = frozenset({'virtual machine', 'dongle protection', 'joiner', 'stub', 'loader'})
_VERSION_PREFIX = re.compile(r'^(\d+)\.(\d+)')


def _fact(key: FactKey, value: str, source: FactSource, certainty, *, version: str = '', ref: str = '',
          raw: tuple[tuple[str, str], ...] = ()) -> BuildFact:
    return BuildFact(key=key, value=display_text(value, 200), version=display_text(version, 120), source=source,
                     certainty=certainty, ref=ref[:64], raw=raw)


def _dotted(pair: tuple[int, int]) -> str:
    return f'{pair[0]}.{pair[1]}'


def _checksum_text(ok: bool | None) -> str:
    return 'unknown' if ok is None else 'ok' if ok else 'failed'


def _rich_fact(pe: PeBuildFacts) -> list[BuildFact]:
    if pe.rich is None:
        return []
    raw = (('checksum', _checksum_text(pe.rich.checksum_ok)), ('entries', str(len(pe.rich.entries))),
           ('truncated', 'yes' if pe.rich.truncated else 'no'))
    return [_fact('rich_signature', pe.rich.signature, 'rich-header', 'derived', raw=raw)]


def _managed_fact(pe: PeBuildFacts) -> list[BuildFact]:
    if pe.clr is None:
        return []
    value = 'il-only' if pe.clr.il_only else 'mixed' if pe.clr.has_native_header else 'managed'
    return [_fact('managed', value, 'clr-header', 'exact-field', version=pe.clr.metadata_version or '')]


def _option_facts(pe: PeBuildFacts) -> list[BuildFact]:
    guard = pe.guard_flags
    cfg_on = 'GUARD_CF' in pe.dll_characteristics or (guard is not None and 'CF_INSTRUMENTED' in guard)
    facts = [_fact('cfg', 'on' if cfg_on else 'off', 'load-config' if guard is not None else 'pe-header',
                   'exact-field'),
             _fact('aslr', 'on' if 'DYNAMIC_BASE' in pe.dll_characteristics else 'off', 'pe-header', 'exact-field'),
             _fact('repro', 'yes' if pe.repro else 'no', 'debug-directory', 'exact-field')]
    if pe.security_cookie_set is not None:
        facts.append(_fact('gs_cookie', 'set' if pe.security_cookie_set else 'unset', 'load-config', 'exact-field'))
    if pe.debug_entry_types:
        types = ','.join(str(t) for t in sorted(set(pe.debug_entry_types)))
        facts.append(_fact('debug_entry_types', types, 'debug-directory', 'exact-field'))
    return facts


def _field_facts(pe: PeBuildFacts) -> list[BuildFact]:
    pairs = (('linker_field', pe.linker_field), ('os_version_field', pe.os_field),
             ('image_version_field', pe.image_field), ('subsystem_version_field', pe.subsystem_field))
    facts = [_fact(key, _dotted(pair), 'pe-header', 'exact-field') for key, pair in pairs if pair is not None]
    if pe.subsystem:
        facts.append(_fact('subsystem', pe.subsystem, 'pe-header', 'exact-field'))
    return facts


def pe_build_facts(pe: PeBuildFacts, hints: tuple[PackerHint, ...] = ()) -> list[BuildFact]:
    """Channel A. Header fields are exact reads, never brand claims; section-layout hints are weak."""
    facts = _field_facts(pe) + _rich_fact(pe) + _option_facts(pe) + _managed_fact(pe)
    facts += [_fact('runtime_family', family, 'imports', 'derived') for family in pe.runtime_families]
    if pe.entropy_exec_max is not None:
        facts.append(_fact('entropy_exec', f'{pe.entropy_exec_max:.2f}', 'sections', 'derived'))
    facts.append(_fact('overlay', str(pe.overlay_size), 'sections', 'exact-field',
                       raw=(() if pe.overlay_entropy is None else (('entropy', f'{pe.overlay_entropy:.2f}'),))))
    facts += [_fact('packer', hint.name, 'sections', 'derived' if hint.confidence == 'medium' else 'heuristic',
                    raw=(('hint', hint.confidence),)) for hint in hints]
    return facts


def _diec_key(item: EnvironmentEvidence) -> FactKey | None:
    if item.category == 'protector' and 'obfuscator' in item.raw_type:
        return 'obfuscator'
    if item.category == 'other' and item.raw_type in _NEUTRAL_PROTECTION:
        return 'protector'
    return _DIEC_KEYS.get(item.category)


def diec_build_facts(evidence: ToolEvidenceSet) -> list[BuildFact]:
    """Channel B. `raw_type` stays on the fact so pre-flight can apply the shared type sets."""
    facts: list[BuildFact] = []
    for item in evidence.environment:
        key = _diec_key(item)
        if key is None or item.certainty == 'unknown':
            continue
        raw = (('raw_type', item.raw_type), ('detect', item.detect_string[:120]))
        facts.append(_fact(key, item.detector_rule, 'diec', item.certainty, version=item.version,
                           ref=item.source_run_id, raw=raw))
    return list(dict.fromkeys(facts))


def _linker_disagreement(facts: list[BuildFact]) -> bool:
    """The header linker field against the version in a `diec` linker name; shown as a row status only."""
    header = next((f.value for f in facts if f.key == 'linker_field'), None)
    named = [m for f in facts if f.key == 'linker' and f.certainty == 'signature'
             for m in [_VERSION_PREFIX.match(f.version)] if m]
    return header is not None and any(f'{m.group(1)}.{m.group(2)}' != header for m in named)


def _check_evidence(artifact_sha256: str, side: Side, die: DieSummary, evidence: ToolEvidenceSet) -> None:
    if (evidence.artifact_sha256, evidence.side, evidence.run_id) != (artifact_sha256, side, die.run_id):
        raise BuildEnvError('PT-BUILD-STALE', 'the tool evidence belongs to a different file or run')


def build_fingerprint(artifact_sha256: str, side: Side, *, pe: PeBuildFacts | None = None,
                      hints: tuple[PackerHint, ...] = (), die: DieSummary | None = None,
                      evidence: ToolEvidenceSet | None = None) -> BuildFingerprint:
    """A produced run needs its evidence rows; rows for another file or run are `PT-BUILD-STALE`."""
    produced = die is not None and die.produced()
    if produced:
        if evidence is None:
            raise BuildEnvError('PT-BUILD-INPUT', 'a produced diec run needs its stored evidence')
        _check_evidence(artifact_sha256, side, die, evidence)
    facts = (pe_build_facts(pe, hints) if pe else []) + (diec_build_facts(evidence) if produced else [])
    anomalies = list(pe.anomalies) if pe else []
    if produced:
        anomalies += [name for name, on in (('die-truncated', evidence.truncated),
                                            ('vocabulary-drift', bool(evidence.analysis.get('vocabulary_drift'))))
                      if on]
    if _linker_disagreement(facts):
        anomalies.append('linker-version-sources-disagree')
    if len(facts) > MAX_FACTS:
        facts, anomalies = facts[:MAX_FACTS], [*anomalies, 'facts-truncated']
    return BuildFingerprint(
        artifact_sha256=artifact_sha256, side=side, pe=pe, die=die, facts=tuple(facts),
        anomalies=tuple(dict.fromkeys(anomalies))[:MAX_ANOMALIES],
        built_from=BuiltFrom(pe_facts_version=pe.facts_version if pe else FACTS_VERSION,
                             die_cache_key=die.cache_key if produced else None))
