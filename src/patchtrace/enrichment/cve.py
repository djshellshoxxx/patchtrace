"""B3 pure CVE normalization and contextual reranking (SPEC-07 §8). No I/O, no network.

Provider schemas are pinned to the trimmed real responses in tests/fixtures/cve/ (retrieved
2026-10-12): NVD CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities) and the MSRC
Security Update Guide per-CVE entity ``/sug/v2.0/en-US/vulnerability/<CVE>``
(https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API).

Advisory text is context, not evidence: contextual ranking only *reorders* B1 results when a
context term coincides with something observed in the binary, never changes a B1 score, and a
description never proves code behavior. Provider disagreements are recorded and block the
affected contribution instead of being merged.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from pydantic import ValidationError

from . import identity
from .contracts import (
    AttributedText,
    AttributedValue,
    ContextContribution,
    ContextualEntry,
    ContextualRanking,
    CveSnapshot,
    CvssRecord,
    EnrichmentError,
    FeatureTransition,
    RankingResult,
    SignalSet,
    Status,
)

NORMALIZATION_VERSION = 1
DICTIONARY_VERSION = 1
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,19}', re.ASCII)  # ASCII digits only: \d alone also matches Unicode digits
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_TERMS = 256
MAX_LIST = 64
PROVIDERS = ('msrc', 'nvd')
# "CWE-787" or "CWE-787: Out-of-bounds Write"; the number must end at a token boundary, or "CWE-1234567" and
# "CWE-787-foo" would turn into identifiers the provider never wrote (audit C-10).
_CWE = re.compile(r'CWE-([0-9]{1,6})(?![\w-])')
_SURROGATE_ESCAPE = re.compile(rb'\\u[dD][89a-fA-F][0-9a-fA-F]{2}')
_TOKEN = re.compile(r'[A-Za-z_][A-Za-z0-9_]{2,}')
_CAMEL = re.compile(r'[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])')

# Dictionary version 1. Stopwords are English function words plus advisory boilerplate that
# appears in nearly every Windows CVE title ("Windows ... Remote Code Execution
# Vulnerability"); matching those against function names would only add noise, so generic
# words contribute 0 by construction. Ghidra placeholder names (FUN_, sub_, thunk_) are also
# stopwords because they say nothing about the code.
STOPWORDS = frozenset('''
the and for with from that this which when where while into onto than then there their
are was were has have had not but can could may might will would should does did via its
all any each other such only also more most some very been being use used using
vulnerability vulnerabilities security feature bypass remote code execution elevation
privilege privileges information disclosure denial service spoofing tampering windows
microsoft attacker attackers exploit exploited exploitation successfully could allow
affected version versions update updates issue issues component system server client
fun sub thunk func function lab dat ptr param local var undefined
'''.split())
# Generic memory-safety words: true of thousands of functions, so a match is no binary support.
GENERIC = frozenset('memory buffer overflow underflow integer heap stack pointer read write '
                    'free after use out bounds data driver kernel user mode handle object'.split())
SYNONYMS: dict[str, str] = {'datagrams': 'datagram', 'packets': 'packet', 'reassembly': 'reassemble',
                            'fragments': 'fragment', 'fragmentation': 'fragment', 'ioctls': 'ioctl',
                            'requests': 'request', 'tokens': 'token'}
CWE_DETECTORS: dict[str, tuple[str, ...]] = {
    'CWE-787': ('BND', 'SIZE'), 'CWE-125': ('BND', 'SIZE'), 'CWE-119': ('BND', 'SIZE'),
    'CWE-120': ('BND', 'SIZE'), 'CWE-122': ('BND', 'SIZE'), 'CWE-121': ('BND', 'SIZE'),
    'CWE-190': ('OVF', 'INT'), 'CWE-191': ('OVF', 'INT'), 'CWE-680': ('OVF', 'INT'),
    'CWE-200': ('SCRUB',), 'CWE-908': ('SCRUB',), 'CWE-909': ('SCRUB',),
    'CWE-20': ('VAL',), 'CWE-1284': ('VAL', 'BND'),
}
ALIGNING_CONFIDENCE = frozenset({'strong', 'moderate'})


def _err(message: str) -> EnrichmentError:
    return EnrichmentError('PT-ENRICH-PROVIDER', message)


def _reject_constant(name: str):
    raise ValueError(f'non-finite JSON constant {name}')


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON key')
        out[key] = value
    return out


def _has_unpaired_surrogate(value) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode('utf-8')
            except UnicodeEncodeError:
                return True
        elif isinstance(item, dict):
            stack.extend(item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _parse_strict(data: bytes, parse_float):
    """Strict JSON: UTF-8, no duplicate keys, no NaN/Infinity, no unpaired surrogate escape (``"\\ud800"`` is legal
    JSON but not text, and the strict models cannot hold it). Raises ValueError, UnicodeDecodeError or
    RecursionError."""
    text = data.decode('utf-8')
    value = json.loads(text, parse_float=parse_float, parse_constant=_reject_constant, object_pairs_hook=_pairs)
    if _SURROGATE_ESCAPE.search(data) and _has_unpaired_surrogate(value):
        raise ValueError('unpaired surrogate')
    return value


def _strict_json(data: bytes, provider: str):
    if type(data) is not bytes:
        raise EnrichmentError('PT-ENRICH-INPUT', f'{provider} response must be bytes')
    if len(data) > MAX_RESPONSE_BYTES:
        raise EnrichmentError('PT-ENRICH-LIMIT', f'{provider} response exceeds 4 MiB')
    try:
        # Decimal keeps CVSS scores exact (9.8 → 98 tenths) without binary float drift.
        return _parse_strict(data, Decimal)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _err(f'{provider} response is not strict JSON') from None


def _reject_float(text: str):
    raise ValueError('a snapshot holds no floating-point number')


def parse_snapshots(data: bytes) -> list[CveSnapshot]:
    """Snapshots from a saved file (one object or an array of them), imported as strict, bounded JSON like every
    other PatchTrace import (AGENTS.md; audit C-09). The file cannot be re-verified against provider bodies, so the
    caller still treats the result as unverified. Raises EnrichmentError (INPUT or LIMIT)."""
    if type(data) is not bytes:
        raise EnrichmentError('PT-ENRICH-INPUT', 'snapshot file must be bytes')
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise EnrichmentError('PT-ENRICH-LIMIT', f'snapshot file exceeds {MAX_SNAPSHOT_BYTES} bytes')
    try:
        value = _parse_strict(data, _reject_float)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnrichmentError('PT-ENRICH-INPUT', 'snapshot file is not strict JSON') from None
    snapshots = []
    for index, item in enumerate(value if isinstance(value, list) else [value]):
        if not isinstance(item, dict):
            raise EnrichmentError('PT-ENRICH-INPUT', f'snapshot {index} is not an object')
        try:
            snapshot = CveSnapshot.model_validate_json(json.dumps(item))
        except ValidationError as exc:
            problem = exc.errors()[0]
            where = '.'.join(str(part) for part in problem.get('loc', ()))
            raise EnrichmentError('PT-ENRICH-INPUT', f'snapshot {index} is not an enrichment/1 record '
                                  f'({where}: {problem.get("msg", "invalid")})'[:300]) from None
        try:
            _timestamp(snapshot.retrieved_at)
        except EnrichmentError:
            raise EnrichmentError('PT-ENRICH-INPUT', f'snapshot {index} retrieved_at is not ISO 8601 with a '
                                  'timezone') from None
        if snapshot.snapshot_id != _snapshot_id(snapshot.cve_id, snapshot.normalization_version,
                                                snapshot.response_digests):
            raise EnrichmentError('PT-ENRICH-INPUT', f'snapshot {index} snapshot_id does not match its '
                                  'provider digests')
        snapshots.append(snapshot)
    return snapshots


def _snapshot_id(cve_id: str, normalization_version: int, digests: Mapping[str, str]) -> str:
    return identity.domain_id('cve-snapshot', 1, {
        'cve_id': cve_id, 'normalization_version': normalization_version, 'response_digests': dict(digests)})


def _tenths(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, Decimal, str)):
        raise _err('CVSS base score has an unexpected type')
    try:
        number = Decimal(value) * 10
    except InvalidOperation:
        raise _err('CVSS base score is not a number') from None
    if number != number.to_integral_value() or not 0 <= number <= 100:
        raise _err('CVSS base score is not a tenth in 0.0..10.0')
    return int(number)


def _str(value, what: str, limit: int = 2000) -> str:
    if not isinstance(value, str):
        raise _err(f'{what} is not a string')
    if len(value) > limit:
        raise EnrichmentError('PT-ENRICH-LIMIT', f'{what} exceeds {limit} characters')
    return value


def _list(value, what: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _err(f'{what} is not a list')
    return value


def _dict(value, what: str) -> dict:
    if not isinstance(value, dict):
        raise _err(f'{what} is not an object')
    return value


def _cwe_ids(texts: Iterable[str]) -> list[str]:
    # Only explicit CWE-<n> values count; NVD's NVD-CWE-noinfo / NVD-CWE-Other carry no class.
    return [f'CWE-{int(m.group(1))}' for t in texts if (m := _CWE.match(t))]


def _parse_nvd(cve_id: str, doc) -> dict:
    doc = _dict(doc, 'NVD document')
    vulns = _list(doc.get('vulnerabilities'), 'NVD vulnerabilities')
    if len(vulns) != 1:
        raise _err(f'NVD returned {len(vulns)} records for the requested CVE')
    cve = _dict(_dict(vulns[0], 'NVD vulnerability').get('cve'), 'NVD cve')
    if cve.get('id') != cve_id:
        raise _err('NVD response is for a different CVE')
    out: dict = {'descriptions': [], 'cwes': [], 'cvss': [], 'products': [], 'advisories': [], 'published': []}
    for d in _list(cve.get('descriptions'), 'NVD descriptions'):
        d = _dict(d, 'NVD description')
        out['descriptions'].append(AttributedText(source='nvd', lang=_str(d.get('lang', 'en'), 'lang', 16),
                                                  text=_str(d.get('value'), 'description', 20000)))
    texts = []
    for w in _list(cve.get('weaknesses'), 'NVD weaknesses'):
        for d in _list(_dict(w, 'NVD weakness').get('description'), 'NVD weakness description'):
            texts.append(_str(_dict(d, 'NVD weakness value').get('value'), 'CWE'))
    out['cwes'] = _cwe_ids(texts)
    metrics = _dict(cve.get('metrics', {}), 'NVD metrics')
    for key in sorted(metrics):
        if not key.startswith('cvssMetricV'):
            continue
        for m in _list(metrics[key], key):
            m = _dict(m, key)
            data = _dict(m.get('cvssData'), 'cvssData')
            severity = data.get('baseSeverity', m.get('baseSeverity', ''))
            out['cvss'].append(CvssRecord(
                source='nvd:' + _str(m.get('source', ''), 'CVSS source', 100),
                version=_str(data.get('version'), 'CVSS version', 8),
                vector=_str(data.get('vectorString'), 'CVSS vector', 200),
                base_score_tenths=_tenths(data.get('baseScore')),
                severity=_str(severity, 'severity', 16).upper()))
    for a in _list(cve.get('affected'), 'NVD affected'):
        for item in _list(_dict(a, 'NVD affected').get('affectedData'), 'affectedData'):
            product = _dict(item, 'affectedData').get('product')
            if product is not None:
                out['products'].append(_str(product, 'product'))
    for conf in _list(cve.get('configurations'), 'NVD configurations'):
        for node in _list(_dict(conf, 'configuration').get('nodes'), 'nodes'):
            for match in _list(_dict(node, 'node').get('cpeMatch'), 'cpeMatch'):
                parts = _str(_dict(match, 'cpeMatch').get('criteria', ''), 'cpe').split(':')
                if len(parts) > 4 and parts[4] not in ('*', '-'):
                    out['products'].append(parts[4])
    for r in _list(cve.get('references'), 'NVD references'):
        out['advisories'].append(_str(_dict(r, 'reference').get('url'), 'reference url'))
    if cve.get('published') is not None:
        out['published'].append(_str(cve['published'], 'published', 64))
    return out


def _parse_msrc(cve_id: str, doc) -> dict:
    doc = _dict(doc, 'MSRC document')
    if doc.get('cveNumber') != cve_id:
        raise _err('MSRC response is for a different CVE')
    out: dict = {'descriptions': [], 'cwes': [], 'cvss': [], 'products': [], 'advisories': [], 'published': []}
    if doc.get('cveTitle') is not None:
        out['descriptions'].append(AttributedText(source='msrc', lang='en',
                                                  text=_str(doc['cveTitle'], 'title', 20000)))
    out['cwes'] = _cwe_ids(_str(c, 'CWE') for c in _list(doc.get('cweList'), 'cweList'))
    vector = doc.get('vectorString')
    if vector:
        vector = _str(vector, 'CVSS vector', 200)
        version = vector.split('/', 1)[0].removeprefix('CVSS:') if vector.startswith('CVSS:') else ''
        score = doc.get('baseScore')
        # MSRC `severity` is Microsoft's own rating (Critical/Important), not a CVSS severity,
        # so it is never placed in CvssRecord.severity where it could be compared with NVD's.
        out['cvss'].append(CvssRecord(source='msrc', version=version[:8], vector=vector,
                                      base_score_tenths=_tenths(score) if score not in (None, '') else None,
                                      severity=''))
    if doc.get('tag'):
        out['products'].append(_str(doc['tag'], 'tag'))
    if doc.get('releaseNumber'):
        out['advisories'].append('MSRC ' + _str(doc['releaseNumber'], 'releaseNumber', 64))
    if doc.get('releaseDate'):
        out['published'].append(_str(doc['releaseDate'], 'releaseDate', 64))
    return out


_PARSERS = {'nvd': _parse_nvd, 'msrc': _parse_msrc}
_CVSS3_BASE = ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')


def _base_vector(record: CvssRecord) -> str:
    # MSRC appends temporal metrics (E/RL/RC); only base metrics are comparable with NVD.
    if record.version.startswith('3'):
        parts = dict(p.split(':', 1) for p in record.vector.split('/')[1:] if ':' in p)
        return '/'.join(f'{k}:{parts.get(k, "?")}' for k in _CVSS3_BASE)
    return record.vector


def _conflicts(cwes_by: dict[str, list[str]], cvss: list[CvssRecord]) -> list[str]:
    conflicts = []
    populated = {p: sorted(set(v)) for p, v in cwes_by.items() if v}
    if len({tuple(v) for v in populated.values()}) > 1:
        conflicts.append('cwe: ' + '; '.join(f'{p}={",".join(v)}' for p, v in sorted(populated.items())))
    by_version: dict[str, dict[str, list[CvssRecord]]] = {}
    for record in cvss:
        by_version.setdefault(record.version, {}).setdefault(record.source.split(':', 1)[0], []).append(record)
    for version, providers in sorted(by_version.items()):
        # Conflicts are only meaningful across providers: NVD's own Primary and Secondary entries
        # routinely differ and stay in `cvss` without being a disagreement (SPEC-07h H12).
        pairs = {p: {(_base_vector(r), r.base_score_tenths) for r in rs} for p, rs in providers.items()}
        if len(pairs) > 1 and not set.intersection(*pairs.values()):
            conflicts.append(f'cvss {version}: ' + '; '.join(
                f'{p}={",".join(sorted({str(r.base_score_tenths) for r in rs}))}'
                for p, rs in sorted(providers.items())))
        severities = {p: {r.severity for r in rs if r.severity} for p, rs in providers.items()}
        severities = {p: v for p, v in severities.items() if v}
        if len(severities) > 1 and not set.intersection(*severities.values()):
            conflicts.append(f'severity {version}: ' + '; '.join(
                f'{p}={",".join(sorted(v))}' for p, v in sorted(severities.items())))
    return conflicts


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        raise EnrichmentError('PT-ENRICH-INPUT', 'timestamp must be ISO 8601 with a timezone')
    return parsed


def normalize(cve_id: str, responses: Mapping[str, bytes], retrieved_at: str) -> CveSnapshot:
    if type(cve_id) is not str or len(cve_id) > 24 or not CVE_PATTERN.fullmatch(cve_id):
        raise EnrichmentError('PT-ENRICH-INPUT', 'invalid CVE identifier')
    _timestamp(retrieved_at)
    if not responses or any(p not in _PARSERS for p in responses):
        raise EnrichmentError('PT-ENRICH-INPUT', 'responses must be a non-empty mapping of msrc/nvd bytes')
    try:
        return _snapshot(cve_id, responses, retrieved_at)
    except ValidationError:  # a value the strict snapshot models refuse (empty, over-long): never a raw pydantic error
        raise _err('a provider value does not fit the enrichment/1 snapshot contract') from None


def _snapshot(cve_id: str, responses: Mapping[str, bytes], retrieved_at: str) -> CveSnapshot:
    parsed = {p: _PARSERS[p](cve_id, _strict_json(responses[p], p)) for p in sorted(responses)}
    digests = {p: hashlib.sha256(responses[p]).hexdigest() for p in sorted(responses)}

    def attributed(field: str) -> tuple[AttributedValue, ...]:
        seen = {}
        for provider, data in parsed.items():
            for value in data[field][:MAX_LIST]:
                seen.setdefault((provider, value), AttributedValue(source=provider, value=value))
        return tuple(seen[k] for k in sorted(seen))

    cvss = [r for data in parsed.values() for r in data['cvss']]
    return CveSnapshot(
        snapshot_id=_snapshot_id(cve_id, NORMALIZATION_VERSION, digests),
        cve_id=cve_id, normalization_version=NORMALIZATION_VERSION, response_digests=digests,
        retrieved_at=retrieved_at,
        descriptions=tuple(d for data in parsed.values() for d in data['descriptions']),
        cwes=attributed('cwes'), cvss=tuple(cvss), products=attributed('products'),
        advisories=attributed('advisories'), published=attributed('published'),
        # Neither provider documents a WIL feature-ID field, so normalization never asserts one.
        feature_ids=(),
        conflicts=tuple(_conflicts({p: d['cwes'] for p, d in parsed.items()}, cvss)))


def is_stale(snapshot: CveSnapshot, now: datetime, max_age_days: int) -> bool:
    if type(max_age_days) is not int or max_age_days < 0:
        raise EnrichmentError('PT-ENRICH-CONFIG', 'max_age_days must be a non-negative integer')
    if now.tzinfo is None:
        raise EnrichmentError('PT-ENRICH-INPUT', 'now must be timezone-aware')
    age = now.astimezone(UTC) - _timestamp(snapshot.retrieved_at).astimezone(UTC)
    # A retrieval time in the future cannot be trusted as fresh.
    return age.total_seconds() < 0 or age.days * 86400 + age.seconds > max_age_days * 86400


def _provider(source: str) -> str:
    return source.split(':', 1)[0]


def _merge_snapshots(cve_id: str, chosen: Mapping[str, CveSnapshot]) -> CveSnapshot:
    """One snapshot built from each provider's newest data. Same recipe as `normalize`, so a merged
    snapshot and a fresh one over identical responses share an ID. `retrieved_at` is the OLDEST
    contributing time (conservative for staleness; spec-decisions-20261014)."""
    providers = sorted(chosen)
    digests = {p: chosen[p].response_digests[p] for p in providers}

    def attributed(field: str) -> tuple[AttributedValue, ...]:
        seen = {}
        for p in providers:
            for item in getattr(chosen[p], field):
                if _provider(item.source) == p:
                    seen.setdefault((p, item.value), item)
        return tuple(seen[k] for k in sorted(seen))

    cvss = tuple(r for p in providers for r in chosen[p].cvss if _provider(r.source) == p)
    cwes = attributed('cwes')
    contributors = {id(s): s for s in chosen.values()}.values()
    oldest = min(contributors, key=lambda s: (_timestamp(s.retrieved_at).astimezone(UTC), s.snapshot_id))
    cwes_by: dict[str, list[str]] = {p: [] for p in providers}
    for c in cwes:
        cwes_by.setdefault(c.source, []).append(c.value)
    return CveSnapshot(
        snapshot_id=_snapshot_id(cve_id, NORMALIZATION_VERSION, digests),
        cve_id=cve_id, normalization_version=NORMALIZATION_VERSION, response_digests=digests,
        retrieved_at=oldest.retrieved_at,
        descriptions=tuple(d for p in providers for d in chosen[p].descriptions if _provider(d.source) == p),
        cwes=cwes, cvss=cvss, products=attributed('products'), advisories=attributed('advisories'),
        published=attributed('published'), feature_ids=(),
        conflicts=tuple(_conflicts(cwes_by, list(cvss))))


def select_latest(snapshots: Iterable[CveSnapshot]) -> tuple[tuple[CveSnapshot, ...], tuple[CveSnapshot, ...]]:
    """One snapshot per CVE. Per provider, the newest snapshot containing that provider wins (ties:
    smallest snapshot_id), so a newer partial fetch never drops another provider's older data. When
    one snapshot supplies every provider it is returned unchanged; otherwise a merged snapshot is
    synthesized (see `_merge_snapshots`). Returns (kept sorted by CVE, snapshots that contributed
    nothing sorted by CVE/snapshot_id)."""
    by_cve: dict[str, list[CveSnapshot]] = {}
    for snap in sorted(snapshots, key=lambda x: (x.cve_id, x.snapshot_id)):
        by_cve.setdefault(snap.cve_id, []).append(snap)
    kept, ignored = [], []
    for cve_id in sorted(by_cve):
        group = by_cve[cve_id]
        chosen: dict[str, CveSnapshot] = {}
        for snap in sorted(group, key=lambda x: (-_timestamp(x.retrieved_at).timestamp(), x.snapshot_id)):
            for provider in snap.response_digests:
                chosen.setdefault(provider, snap)
        contributors = {s.snapshot_id: s for s in chosen.values()}
        if not contributors:  # no provider digests at all: fall back to the newest snapshot
            newest = min(group, key=lambda x: (-_timestamp(x.retrieved_at).timestamp(), x.snapshot_id))
            contributors = {newest.snapshot_id: newest}
            chosen = {}
        kept.append(next(iter(contributors.values())) if len(contributors) == 1
                    else _merge_snapshots(cve_id, chosen))
        ignored.extend(s for s in group if s.snapshot_id not in contributors)
    return tuple(kept), tuple(sorted(ignored, key=lambda x: (x.cve_id, x.snapshot_id)))


def _canon(token: str) -> str:
    token = token.lower()
    return SYNONYMS.get(token, token)


def _meaningful(token: str) -> bool:
    return len(token) >= 3 and token not in STOPWORDS and token not in GENERIC


def context_terms(snapshots: Sequence[CveSnapshot]) -> tuple[tuple[str, str], ...]:
    """Ordered unique (term, cve_id[source]) pairs, before the 256 cap."""
    terms: dict[str, str] = {}
    for snapshot in sorted(snapshots, key=lambda s: s.cve_id):
        for d in snapshot.descriptions:
            # Translations repeat the English text; their tokens are only noise here.
            if not d.lang.lower().startswith('en'):
                continue
            for token in _TOKEN.findall(d.text):
                term = _canon(token)
                if _meaningful(term):
                    terms.setdefault(term, f'{snapshot.cve_id} description[{d.source}]')
    return tuple(terms.items())


def name_terms(name: str) -> set[str]:
    """A function/callee name's tokens: whole token, underscore parts and camelCase parts."""
    out = set()
    for token in _TOKEN.findall(name):
        out.add(_canon(token))
        for part in token.split('_'):
            out.add(_canon(part))
            out.update(_canon(p) for p in _CAMEL.findall(part))
    return {t for t in out if _meaningful(t)}


def _module_words(product: str) -> set[str]:
    # "Windows TCP/IP" → {"windows", "tcpip"}: punctuation inside a word is dropped so module
    # names like tcpip.sys can match, but whole-word equality avoids substring false positives.
    return {re.sub(r'[^a-z0-9]', '', w.lower()) for w in product.split()}


def _artifact_stem(name: str) -> str:
    base = re.split(r'[\\/]', name)[-1].lower()
    return base.rsplit('.', 1)[0] if '.' in base else base


def contextual_rank(ranking: RankingResult, signal_sets: Iterable[SignalSet],
                    transitions: Iterable[FeatureTransition], snapshots: Sequence[CveSnapshot],
                    artifact_names: Iterable[str], match_names: Mapping[str, Iterable[str]], *,
                    now: datetime | None = None, max_age_days: int | None = None) -> ContextualRanking:
    """Rerank B1 entries with advisory context. `match_names` maps pairing_id → function/callee names.

    `ranking` is read only; its entries and scores are copied, never modified.
    """
    snapshots = tuple(sorted(snapshots, key=lambda s: s.cve_id))
    signals = {s.pairing_id: s.signals for s in signal_sets}
    qualifying: dict[str, set[int]] = {}
    qualifying_ids: dict[str, list[str]] = {}
    for t in transitions:
        if t.qualifies:
            qualifying_ids.setdefault(t.pairing_id, []).append(t.transition_id)
            if t.feature_id is not None:
                qualifying.setdefault(t.pairing_id, set()).add(t.feature_id)
    all_terms = context_terms(snapshots)
    terms = dict(all_terms[:MAX_TERMS])
    cwe_sources: dict[str, set[str]] = {}
    cwe_blocked: dict[str, set[str]] = {}
    for s in snapshots:
        agreed = {c.value for c in s.cwes}
        if any(c.startswith('cwe:') for c in s.conflicts):
            # Only values reported by every CWE-reporting provider survive a disagreement.
            by_provider: dict[str, set[str]] = {}
            for c in s.cwes:
                by_provider.setdefault(c.source, set()).add(c.value)
            agreed = set.intersection(*by_provider.values()) if by_provider else set()
            disputed = {c.value for c in s.cwes} - agreed
            if disputed:
                cwe_blocked[s.cve_id] = disputed
        for c in s.cwes:
            if c.value in agreed:
                cwe_sources.setdefault(c.value, set()).add(f'{s.cve_id}[{c.source}]')
    features = {f: s.cve_id for s in snapshots for f in s.feature_ids}
    stems = {_artifact_stem(n) for n in artifact_names}
    product_hits = sorted(
        (f'{s.cve_id} product[{p.source}]', stem)
        for s in snapshots for p in s.products for stem in stems
        if _meaningful(stem) and stem in _module_words(p.value))

    rows = []
    for entry in ranking.entries:
        contribs: list[ContextContribution] = []
        names = sorted(set(match_names.get(entry.pairing_id, ())))
        hits = {}
        for name in names:
            for term in sorted(name_terms(name)):
                if term in terms and term not in hits:
                    hits[term] = name
        pairing_signals = sorted(signals.get(entry.pairing_id, ()), key=lambda s: s.signal_id)
        # SPEC-07 §8 / 07h H4: a name alone is metadata. Every contribution needs change evidence in
        # the binary: a signal of any detector (confidence other than unavailable) or a qualifying transition.
        evidence = [s for s in pairing_signals if s.confidence != 'unavailable']
        evidence_ref = (f'signal:{evidence[0].signal_id}' if evidence
                        else f'transition:{min(qualifying_ids[entry.pairing_id])}'
                        if qualifying_ids.get(entry.pairing_id) else '')
        points = 0
        for term in sorted(hits if evidence_ref else ()):
            if points >= 24:
                break
            contribs.append(ContextContribution(kind='identifier', points=12,
                                                context_field=f'{terms[term]}:{term}'[:200],
                                                binary_ref=evidence_ref[:200], detail=f'name:{hits[term]}'[:200]))
            points += 12
        cwe_points = 0
        credited: set[str] = set()  # edit groups already credited to a CWE (audit C-04)
        for cwe in sorted(cwe_sources):
            if cwe_points >= 20:
                break
            detectors = CWE_DETECTORS.get(cwe, ())
            # Sibling CWEs (787 and 125, 190 and 191) share detectors, and signals of one underlying edit share a
            # group: one observation counts once, however many CWE labels the advisory attaches to it.
            match = next((s for s in pairing_signals if s.detector in detectors
                          and s.confidence in ALIGNING_CONFIDENCE and s.group_key not in credited), None)
            if match is not None:
                contribs.append(ContextContribution(
                    kind='cwe', points=10, context_field=f'{cwe} {",".join(sorted(cwe_sources[cwe]))}'[:200],
                    binary_ref=f'signal:{match.signal_id}', detail=f'{match.detector} {match.confidence}'))
                credited.add(match.group_key)
                cwe_points += 10
        blocked = [] if evidence_ref or not hits else ['no-binary-evidence']
        for cve_id, cwes in sorted(cwe_blocked.items()):
            would = sorted(c for c in cwes if any(
                s.detector in CWE_DETECTORS.get(c, ()) and s.confidence in ALIGNING_CONFIDENCE
                for s in pairing_signals))
            if would:
                blocked.append(f'cwe: {cve_id} providers disagree ({",".join(would)})')
        shared = sorted(qualifying.get(entry.pairing_id, set()) & set(features))
        if shared:
            contribs.append(ContextContribution(kind='feature', points=8,
                                                context_field=f'{features[shared[0]]} feature_ids',
                                                binary_ref=f'feature:{shared[0]}'))
        # The product match is artifact-wide and so identical for every pairing; it may only
        # corroborate pairing-specific support, otherwise it would lift unsupported entries.
        if product_hits and contribs:
            field, stem = product_hits[0]
            contribs.append(ContextContribution(kind='product', points=4, context_field=field[:200],
                                                binary_ref=f'artifact:{stem}'[:200]))
        adjustment = min(30, sum(c.points for c in contribs))
        rows.append((min(100, entry.score + adjustment), entry, adjustment, tuple(contribs), tuple(blocked)))
    rows.sort(key=lambda r: (-r[0], -r[1].score, r[1].pairing_id))
    entries = tuple(ContextualEntry(
        pairing_id=e.pairing_id, match_id=e.match_id, base_score=e.score, base_rank=e.rank,
        adjustment=adj, context_score=score, context_rank=index, contributions=contribs, blocked=blocked)
        for index, (score, e, adj, contribs, blocked) in enumerate(rows, 1))
    stale = ()
    if now is not None and max_age_days is not None:
        stale = tuple(s.cve_id for s in snapshots if is_stale(s, now, max_age_days))
    status: Status = 'unavailable' if not snapshots else (
        'partial' if stale or len(all_terms) > MAX_TERMS else 'complete')
    return ContextualRanking(
        ranking_input=identity.domain_id('context-input', 1, {
            'ranking_input': ranking.input_digest, 'config_digest': ranking.config_digest}),
        snapshot_ids=tuple(sorted(s.snapshot_id for s in snapshots)), dictionary_version=DICTIONARY_VERSION,
        entries=entries, status=status, stale_snapshots=stale)
