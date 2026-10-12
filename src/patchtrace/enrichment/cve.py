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
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,19}')
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TERMS = 256
MAX_LIST = 64
PROVIDERS = ('msrc', 'nvd')
_CWE = re.compile(r'CWE-(\d{1,6})')
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


def _strict_json(data: bytes, provider: str):
    if type(data) is not bytes:
        raise EnrichmentError('PT-ENRICH-INPUT', f'{provider} response must be bytes')
    if len(data) > MAX_RESPONSE_BYTES:
        raise EnrichmentError('PT-ENRICH-LIMIT', f'{provider} response exceeds 4 MiB')
    try:
        # Decimal keeps CVSS scores exact (9.8 → 98 tenths) without binary float drift.
        return json.loads(data.decode('utf-8'), parse_float=Decimal, parse_constant=_reject_constant,
                          object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _err(f'{provider} response is not strict JSON') from None


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
    by_version: dict[str, list[CvssRecord]] = {}
    for record in cvss:
        by_version.setdefault(record.version, []).append(record)
    for version, records in sorted(by_version.items()):
        if len({(_base_vector(r), r.base_score_tenths) for r in records}) > 1:
            conflicts.append(f'cvss {version}: ' + '; '.join(
                f'{r.source}={r.base_score_tenths}' for r in records))
        severities = {r.severity for r in records if r.severity}
        if len(severities) > 1:
            conflicts.append(f'severity {version}: ' + '; '.join(
                f'{r.source}={r.severity}' for r in records if r.severity))
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
        snapshot_id=identity.domain_id('cve-snapshot', 1, {
            'cve_id': cve_id, 'normalization_version': NORMALIZATION_VERSION, 'response_digests': digests}),
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
    for t in transitions:
        if t.qualifies and t.feature_id is not None:
            qualifying.setdefault(t.pairing_id, set()).add(t.feature_id)
    all_terms = context_terms(snapshots)
    terms = dict(all_terms[:MAX_TERMS])
    cwe_sources: dict[str, set[str]] = {}
    cwe_blocked: dict[str, set[str]] = {}
    for s in snapshots:
        if any(c.startswith('cwe:') for c in s.conflicts):
            cwe_blocked[s.cve_id] = {c.value for c in s.cwes}
            continue
        for c in s.cwes:
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
        points = 0
        for term in sorted(hits):
            if points >= 24:
                break
            contribs.append(ContextContribution(kind='identifier', points=12,
                                                context_field=f'{terms[term]}:{term}'[:200],
                                                binary_ref=f'name:{hits[term]}'[:200]))
            points += 12
        cwe_points = 0
        pairing_signals = sorted(signals.get(entry.pairing_id, ()), key=lambda s: s.signal_id)
        for cwe in sorted(cwe_sources):
            if cwe_points >= 20:
                break
            detectors = CWE_DETECTORS.get(cwe, ())
            match = next((s for s in pairing_signals
                          if s.detector in detectors and s.confidence in ALIGNING_CONFIDENCE), None)
            if match is not None:
                contribs.append(ContextContribution(
                    kind='cwe', points=10, context_field=f'{cwe} {",".join(sorted(cwe_sources[cwe]))}'[:200],
                    binary_ref=f'signal:{match.signal_id}', detail=f'{match.detector} {match.confidence}'))
                cwe_points += 10
        blocked = []
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
    status: Status = 'unavailable' if not snapshots else ('partial' if len(all_terms) > MAX_TERMS else 'complete')
    return ContextualRanking(
        ranking_input=identity.domain_id('context-input', 1, {
            'ranking_input': ranking.input_digest, 'config_digest': ranking.config_digest}),
        snapshot_ids=tuple(sorted(s.snapshot_id for s in snapshots)), dictionary_version=DICTIONARY_VERSION,
        entries=entries, status=status, stale_snapshots=stale)
