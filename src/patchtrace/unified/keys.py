"""SPEC-31 identities and cache keys (02 s5): every input digest, nothing else. Pure.

Each key is `enrichment.identity.domain_id(<domain>, 1, payload)` over canonical JSON; domains are listed in
`DOMAINS`. Timestamps, absolute paths and display preferences are never hashed, except the event identity
`unified_run_id`, whose payload is defined to include `started_utc` (02 s4).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from ..enrichment.identity import domain_id
from .contracts import IrKeyInputs, ResultKeyInputs, SourceRef, UnifiedResultManifest, canonical_utc
from .limits import DEFAULT_LIMITS, UnifiedLimits

DOMAINS = ('unified-ir', 'unified-result', 'unified-config', 'unified-manual', 'unified-row', 'unified-run',
           'unified-limits', 'unified-ingest-limits', 'unified-sources')
ENGINE_VERSION = 'ude/1'
_RVA_MAX = 2**32 - 1
_SHA256 = re.compile(r'[0-9a-f]{64}')
_HEX_ADDRESS = re.compile(r'0x[0-9a-f]{1,16}')
_DIGIT = re.compile(r'[0-9]')


def _sha(value, what: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f'{what} must be a 64-character lower-case hex digest')
    return value


def _source_rows(sources: Iterable[SourceRef]) -> list[list]:
    rows = sorted({(s.source, s.entry_id, s.file_sha256 or '', s.version) for s in sources})
    return [[source, entry, sha or None, version] for source, entry, sha, version in rows]


def limits_digest(limits: UnifiedLimits = DEFAULT_LIMITS) -> str:
    """Only the content-affecting limits (domain version 2): a UI, retention or timeout knob never re-keys results."""
    return domain_id('unified-limits', 2, limits.content_dict())


def ingest_limits_digest(limits: UnifiedLimits = DEFAULT_LIMITS) -> str:
    """Only the limits that change IR content: a ladder or facts threshold never invalidates IR (R-09)."""
    return domain_id('unified-ingest-limits', 1, limits.ingest_dict())


def ir_key(inputs: IrKeyInputs) -> str:
    return domain_id('unified-ir', 1, inputs.model_dump(mode='json'))


def ir_cache_eligible(inputs: IrKeyInputs) -> bool:
    """`unknown`, empty or placeholder versions (`n/a`, `none`, `?`, `latest`: anything without a digit) keep the IR
    usable in the project but never in the global cache (02 s5)."""
    return all(_DIGIT.search(v) and not v.strip().lower().startswith('unknown')
               for v in (inputs.ghidra, inputs.pyghidra, inputs.python))


def source_set_digest(sources: Iterable[SourceRef]) -> str:
    return domain_id('unified-sources', 1, _source_rows(sources))


def result_key(inputs: ResultKeyInputs) -> str:
    payload = inputs.model_dump(mode='json')
    payload['sources'] = _source_rows(inputs.sources)  # order-independent
    return domain_id('unified-result', 1, payload)


def result_key_inputs(manifest: UnifiedResultManifest) -> ResultKeyInputs:
    """Every result_key input is in the manifest, so a manifest certifies its own `result_id`."""
    return ResultKeyInputs(
        older_sha256=manifest.older_sha256, newer_sha256=manifest.newer_sha256, orientation=manifest.orientation,
        ghidriff_raw_sha256=manifest.ghidriff_raw_sha256,
        ir_older_digest=manifest.ir_older.content_digest if manifest.ir_older else None,
        ir_newer_digest=manifest.ir_newer.content_digest if manifest.ir_newer else None,
        sources=manifest.sources, manual_digest=manifest.manual_digest, config_digest=manifest.config_digest)


def changed_inputs(stored: ResultKeyInputs, current: ResultKeyInputs) -> tuple[str, ...]:
    """Names of the result_key inputs that differ (read model state U6 says which input changed)."""
    a, b = stored.model_dump(mode='json'), current.model_dump(mode='json')
    a['sources'], b['sources'] = _source_rows(stored.sources), _source_rows(current.sources)
    return tuple(name for name in ResultKeyInputs.model_fields if a[name] != b[name])


def _versions(mapping: Mapping[str, int], what: str) -> dict[str, int]:
    out = dict(mapping)
    if any(not isinstance(k, str) or not k or type(v) is not int or v < 1 for k, v in out.items()):
        raise ValueError(f'{what} map non-empty names to positive ints')  # True would hash as `true`, not as 1
    return out


def config_digest(*, pass_table_digest: str, registry_digest: str, channel_versions: Mapping[str, int],
                  proof_versions: Mapping[str, int], limits_digest: str, engine_version: str = ENGINE_VERSION) -> str:
    """Every component is checked: a malformed string must never become a plausible-looking cache key."""
    if not isinstance(engine_version, str) or not engine_version:
        raise ValueError('engine_version must be a non-empty string')
    return domain_id('unified-config', 1, {
        'engine_version': engine_version, 'pass_table_digest': _sha(pass_table_digest, 'pass_table_digest'),
        'registry_digest': _sha(registry_digest, 'registry_digest'),
        'channel_versions': _versions(channel_versions, 'channel_versions'),
        'proof_versions': _versions(proof_versions, 'proof_versions'),
        'limits_digest': _sha(limits_digest, 'limits_digest')})


def _rvas(values: Sequence[int], side: str) -> list[int]:
    out = []
    for value in values:
        if type(value) is not int or not 0 <= value <= _RVA_MAX:
            raise ValueError(f'{side} rva must be an int in 0..2**32-1')
        out.append(value)
    if len(set(out)) != len(out):
        raise ValueError(f'{side} rvas must be unique')
    return sorted(out)


def row_id(older_sha256: str, newer_sha256: str, older_rvas: Sequence[int], newer_rvas: Sequence[int]) -> str:
    """Stable across runs for the same pairing; order of the rva lists does not matter."""
    older, newer = _rvas(older_rvas, 'older'), _rvas(newer_rvas, 'newer')
    if not older and not newer:
        raise ValueError('a row id needs at least one rva')
    return domain_id('unified-row', 1, {'older_sha256': _sha(older_sha256, 'older_sha256'),
                                        'newer_sha256': _sha(newer_sha256, 'newer_sha256'),
                                        'older_rvas': older, 'newer_rvas': newer})


def _address(value) -> str:
    """Ints and `0x` text fold to one lower-case hex spelling (`0X010` == `0x10` == 16); other text is only trimmed
    and lower-cased (a decimal-looking string is ambiguous, so it is never converted)."""
    if type(value) is int and value >= 0:
        return hex(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if _HEX_ADDRESS.fullmatch(text):
            return hex(int(text, 16))
        if text:
            return text
    raise ValueError('manual correction addresses are non-negative ints or non-empty text')


def manual_digest(corrections: Iterable[tuple[str, Sequence, Sequence]]) -> str:
    """Sorted `(category, older addresses, newer addresses)` of manual corrections; each side is a set."""
    rows = set()
    for category, older, newer in corrections:
        if not isinstance(category, str):
            raise ValueError('manual correction categories are text')  # str(1) would fold with '1'
        rows.add((category, tuple(sorted({_address(a) for a in older})), tuple(sorted({_address(a) for a in newer}))))
    return domain_id('unified-manual', 1, [[c, list(o), list(n)] for c, o, n in sorted(rows)])


def unified_run_id(result_key_value: str, started_utc: str) -> str:
    """Entry id of a `unified-run` row (02 s4); the instant is canonicalised, so `Z` and `+00:00` agree."""
    return domain_id('unified-run', 1, {'result_key': _sha(result_key_value, 'result_key'),
                                        'started_utc': canonical_utc(started_utc)})
