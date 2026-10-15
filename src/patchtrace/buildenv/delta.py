"""Pair delta of two build-environment fingerprints with explicit orientation (DIE plan s7, Rules).

Semantics: a fact missing on one side is `one-sided-unknown`, never a difference (only presence facts of a channel
that ran on both sides may be `added` or `removed`). The toolchain verdict is `differs` only for a strong change
(`diec` signatures on both sides, or Rich pairs with valid checksums on both sides) that the other channel does not
contradict. Header fields alone and heuristics never produce `differs`.
"""
from __future__ import annotations

from collections import defaultdict

from ..enrichment.identity import domain_id
from .contracts import (
    MAP_VERSION,
    BuildChange,
    BuildEnvDelta,
    BuildEnvError,
    BuildFact,
    BuildFingerprint,
    ChangeKind,
    FactKey,
    FactSource,
    Strength,
    ToolchainVerdict,
)
from .noise_map import noise_reasons
from .preflight import build_preflight

KEY_ORDER: tuple[FactKey, ...] = (
    'compiler', 'compiler_version', 'linker', 'linker_rich', 'build_tool', 'rich_signature', 'linker_field',
    'language', 'target_os', 'runtime_family', 'packer', 'protector', 'obfuscator', 'installer', 'managed',
    'gs_cookie', 'cfg', 'aslr', 'repro', 'debug_entry_types', 'subsystem', 'os_version_field',
    'subsystem_version_field', 'image_version_field', 'entropy_exec', 'overlay')
DIEC_TOOLCHAIN = frozenset({'compiler', 'compiler_version', 'linker', 'linker_rich', 'build_tool'})
TOOLCHAIN_KEYS = DIEC_TOOLCHAIN | {'rich_signature', 'linker_field'}
OPTION_KEYS = frozenset({'gs_cookie', 'cfg', 'aslr', 'repro', 'debug_entry_types'})
# Presence facts: when their channel ran on both sides, "not found" on one side is information.
PRESENCE_KEYS = frozenset({'managed', 'runtime_family', 'packer', 'protector', 'installer', 'obfuscator'})
FIRM = ('exact-field', 'derived', 'signature')
# Origin of a change for corroboration: the header linker field and the `diec` linker name share one origin.
_ORIGIN: dict[str, str] = {'linker': 'linker-field', 'linker_field': 'linker-field', 'rich_signature': 'rich'}


def _facts_by_key(fp: BuildFingerprint, use_die: bool) -> dict[str, list[BuildFact]]:
    out: dict[str, list[BuildFact]] = defaultdict(list)
    for fact in fp.facts:
        if fact.certainty in FIRM and (use_die or fact.source != 'diec'):
            out[fact.key].append(fact)
    return out


def _labels(facts: list[BuildFact]) -> str | None:
    return '; '.join(sorted({f.label() for f in facts}))[:200] if facts else None


def _strength(key: str, older: list[BuildFact], newer: list[BuildFact]) -> Strength:
    if key in DIEC_TOOLCHAIN:
        both = older and newer and all(f.source == 'diec' and f.certainty == 'signature' for f in older + newer)
    elif key == 'rich_signature':
        both = older and newer and all(f.raw_value('checksum') == 'ok' for f in older + newer)
    else:
        both = False
    return 'strong' if both else 'weak'


def _change_kind(key: str, older: list[BuildFact], newer: list[BuildFact], ran: dict[str, bool]) -> ChangeKind:
    if older and newer:
        return 'unchanged' if _labels(older) == _labels(newer) else 'changed'
    if key == 'rich_signature':
        return 'changed'  # present -> absent is a weak change; the Rich header is optional and forgeable
    source = (older or newer)[0].source
    if key in PRESENCE_KEYS and ran['diec' if source == 'diec' else 'pe']:
        return 'added' if newer else 'removed'
    return 'one-sided-unknown'


def _one_change(key: FactKey, older: list[BuildFact], newer: list[BuildFact], ran: dict[str, bool]) -> BuildChange:
    basis: tuple[FactSource, ...] = tuple(sorted({f.source for f in older + newer}))[:4]
    kind = 'toolchain' if key in TOOLCHAIN_KEYS else 'option' if key in OPTION_KEYS else 'descriptive'
    return BuildChange(key=key, older=_labels(older), newer=_labels(newer), change=_change_kind(key, older, newer, ran),
                       kind=kind, strength=_strength(key, older, newer), basis=basis)


def _channel_verdicts(changes: list[BuildChange]) -> dict[str, ToolchainVerdict]:
    strong = [c for c in changes if c.kind == 'toolchain' and c.strength == 'strong']
    verdicts: dict[str, ToolchainVerdict] = {}
    for channel, keys in (('diec', DIEC_TOOLCHAIN), ('rich', {'rich_signature'})):
        mine = [c for c in strong if c.key in keys]
        verdicts[channel] = ('differs' if any(c.change == 'changed' for c in mine)
                             else 'same' if any(c.change == 'unchanged' for c in mine) else 'unknown')
    return verdicts


def _toolchain(changes: list[BuildChange]) -> tuple[ToolchainVerdict, bool]:
    """(verdict, disagreement between channels)."""
    seen = {v for v in _channel_verdicts(changes).values() if v != 'unknown'}
    if seen == {'differs', 'same'}:
        return 'unknown', True
    return (next(iter(seen)) if seen else 'unknown'), False


def _changed_basis(changes: list[BuildChange]) -> tuple[FactSource, ...]:
    return tuple(sorted({s for c in changes if c.kind == 'toolchain' and c.change == 'changed' for s in c.basis}))[:4]


def _corroborated(changes: list[BuildChange]) -> bool:
    origins = {_ORIGIN.get(c.key, c.key) for c in changes if c.kind == 'toolchain' and c.change == 'changed'}
    return len(origins) >= 2


def toolchain_text(changes: list[BuildChange]) -> str:
    """Short 'older -> newer' summary: the first changed name-level fact (compiler, build tool, linker)."""
    for key in ('compiler', 'build_tool', 'linker'):
        change = next((c for c in changes if c.key == key and c.change == 'changed'), None)
        if change is not None:
            return f'{change.older} -> {change.newer}'
    return 'build tools differ'


def _die_state(older: BuildFingerprint, newer: BuildFingerprint) -> tuple[bool, str | None]:
    """(comparable, reason slug when not)."""
    a, b = older.die, newer.die
    has = (a is not None and a.produced(), b is not None and b.produced())
    if has == (False, False):
        return False, 'die-not-run'
    if has != (True, True):
        return False, 'die-one-side'
    return (True, None) if a.identity() == b.identity() else (False, 'die-versions-differ')


def delta_id(older: BuildFingerprint, newer: BuildFingerprint) -> str:
    return domain_id('build-env-delta', 1, {'older': older.entry_id(), 'newer': newer.entry_id(),
                                            'orientation': 'older->newer', 'map_version': MAP_VERSION})


def _order(change: BuildChange) -> tuple[int, int]:
    rank = {'changed': 0, 'added': 0, 'removed': 0, 'one-sided-unknown': 1, 'unchanged': 2}[change.change]
    return rank, KEY_ORDER.index(change.key)


def compute_delta(older: BuildFingerprint, newer: BuildFingerprint) -> BuildEnvDelta:
    """Pure and idempotent. Swapping the arguments is `PT-BUILD-MISMATCH`: orientation is explicit."""
    if (older.side, newer.side) != ('older', 'newer'):
        raise BuildEnvError('PT-BUILD-MISMATCH', 'the fingerprints are not given as older then newer')
    use_die, die_reason = _die_state(older, newer)
    pe_ok = older.pe is not None and newer.pe is not None
    ran = {'diec': use_die, 'pe': pe_ok}
    before, after = _facts_by_key(older, use_die), _facts_by_key(newer, use_die)
    changes = [_one_change(key, before.get(key, []), after.get(key, []), ran)
               for key in KEY_ORDER if key in before or key in after]
    changes.sort(key=_order)
    toolchain, disagree = _toolchain(changes)
    reasons = [r for r, on in ((die_reason, die_reason), ('headers-unreadable', not pe_ok),
                               ('sources-disagree', disagree)) if on]
    if toolchain == 'unknown' and not disagree and (use_die or pe_ok):
        changed = any(c.kind == 'toolchain' and c.change == 'changed' for c in changes)
        reasons.append('header-only' if changed else 'no-comparable-facts')
    comparable = pe_ok or use_die
    tags = tuple(reasons)
    return BuildEnvDelta(
        delta_id=delta_id(older, newer), older_sha256=older.artifact_sha256, newer_sha256=newer.artifact_sha256,
        comparable=comparable, reasons=tags, toolchain=toolchain,
        toolchain_corroborated=toolchain == 'differs' and _corroborated(changes),
        options_changed=tuple(c.key for c in changes if c.kind == 'option' and c.change != 'unchanged'
                              and c.change != 'one-sided-unknown')[:8],
        changes=tuple(changes[:128]),
        preflight=build_preflight(older, newer, toolchain, tags, toolchain_text(changes), _changed_basis(changes)),
        noise=noise_reasons(toolchain), limits_hit=('changes-truncated',) if len(changes) > 128 else (),
        counts={name: sum(1 for c in changes if c.change == change) for name, change in (
            ('changed', 'changed'), ('added', 'added'), ('removed', 'removed'), ('unchanged', 'unchanged'),
            ('unknown', 'one-sided-unknown'))})
