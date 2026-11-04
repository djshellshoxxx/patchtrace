"""Snapshot (v1 dict) + optional sections -> validated `Report2` (SPEC-50 7.1, 7.3). Pure; the clock is injected."""
from __future__ import annotations

from datetime import UTC, datetime

from .. import __version__
from . import text
from .calibration_block import build_calibration_block
from .contracts import (
    ATTENTION_LABEL,
    SECTION_KEYS,
    Calibration,
    Orientation,
    Provenance,
    Redaction,
    Report2,
    Tool,
)
from .inputs import RedactionProfile, SectionInputs

_VERBATIM_CAPS = {'code': text.CAP_CODE, 'assembly': text.CAP_CODE, 'text': text.CAP_EVIDENCE}
_NAME_KEYS = frozenset({'name', 'fullname', 'sig', 'functions'})
_MARKERS = {'credential': '[REDACTED]', 'path': '[PATH REDACTED]', 'credential-url': '[CREDENTIAL URL REDACTED]'}
_ABSENT = {
    'engine_evidence': 'Cross-engine evidence not included: no secondary engine result was supplied.',
    'series': 'Series context not included: this export has no series input.',
    'unified_result': 'Unified result reference not included: no stored unified result.',
    'build_facts': 'Build facts not included: none were parsed or supplied.',
    'symbols': 'Symbol mode not included: no symbol run is recorded.',
    'advisories': 'Advisories not included: none were fetched or supplied.',
    'leads': 'Leads not included: no lead input was supplied.',
}


def _cap(key: str | None, section: str | None) -> tuple[bool, int]:
    if key in _VERBATIM_CAPS:
        return True, text.CAP_NOTES if section == 'annotations' and key == 'text' else _VERBATIM_CAPS[key]
    if key == 'analyst_conclusion':
        return False, text.CAP_NOTES
    return False, text.CAP_NAME if key in _NAME_KEYS else text.CAP_EVIDENCE


def normalize_tree(value, key: str | None = None, section: str | None = None):
    """7.3 applied once to every string of the v1 snapshot, by field role; the report states that it was applied."""
    if isinstance(value, str):
        verbatim, cap = _cap(key, section)
        return text.normalize_text(value, verbatim=verbatim, max_chars=cap)
    if isinstance(value, list):
        return [normalize_tree(v, key, section) for v in value]
    if isinstance(value, dict):
        return {k: normalize_tree(v, k, section) for k, v in value.items()}
    return value


def _ranking(ranking: dict | None) -> dict | None:
    """Key stays; the score is exported under `attention_index` with the ordinal label (7.4 / section 6)."""
    if ranking is None:
        return None
    entries = [{('attention_index' if k == 'score' else k): v for k, v in entry.items()}
               for entry in ranking['entries']]
    return {**ranking, 'entries': entries, 'display_label': ATTENTION_LABEL}


def _redaction_counts(snapshot: dict) -> dict[str, int]:
    blob = text.json_dumps(snapshot)
    counts = {rule: blob.count(marker) for rule, marker in _MARKERS.items()}
    return {rule: n for rule, n in counts.items() if n}


def _with_policy(sections: SectionInputs, profile: RedactionProfile) -> dict:
    """Optional sections after the profile: ordinal index only on request, URLs as inert or defanged text."""
    found = {key: getattr(sections, key) for key in SECTION_KEYS}
    evidence = found['engine_evidence']
    if evidence is not None and not profile.include_ordinal_index:
        rows = [row.model_copy(update={'ordinal_index': None}) for row in evidence.rows]
        found['engine_evidence'] = evidence.model_copy(update={'rows': rows})
    if found['advisories'] is not None:
        found['advisories'] = [a.model_copy(update={'url_text': text.display_url(a.url_text, profile.urls)})
                               if a.url_text else a for a in found['advisories']]
    for key in ('build_facts', 'leads'):
        if found[key] is not None:
            found[key] = list(found[key])
    return found


def _orientation(artifacts: list[dict]) -> Orientation:
    sides = {a['side']: a['sha256'] for a in artifacts}
    return Orientation(older_sha256=sides.get('older'), newer_sha256=sides.get('newer'))


def _stale(found: dict, ranking: dict | None) -> list[str]:
    stale = [key for key in SECTION_KEYS if getattr(found[key], 'stale', False) is True]
    return sorted(stale + (['change_ranking'] if ranking and ranking.get('stale') else []))


def _absent_notes(found: dict) -> list[str]:
    return [_ABSENT[key] for key in SECTION_KEYS if found[key] is None]


def build_report(snapshot: dict, *, include_code: bool, include_notes: bool, sections: SectionInputs | None = None,
                 profile: RedactionProfile | None = None, calibration: Calibration | None = None,
                 generated_at: str | None = None) -> Report2:
    sections, profile = sections or SectionInputs(), profile or RedactionProfile()
    data = {key: normalize_tree(value, key, key) for key, value in snapshot.items()}
    data['change_ranking'] = _ranking(data['change_ranking'])
    found = _with_policy(sections, profile)
    unknowns = [*_absent_notes(found), *(text.normalize_text(u, max_chars=text.CAP_NAME) for u in sections.unknowns)]
    present = sorted([k for k in SECTION_KEYS if found[k] is not None]
                     + (['change_ranking'] if data['change_ranking'] is not None else []))
    return Report2(
        **data, **found, content_digest=None,
        generated_at=generated_at or datetime.now(UTC).isoformat(), sections_present=present,
        stale_sections=_stale(found, data['change_ranking']), tool=Tool(version=__version__),
        orientation=_orientation(data['artifacts']), calibration=calibration or build_calibration_block(),
        redaction=Redaction(profile=profile.name, paths=True, code=include_code, notes=include_notes,
                            urls=profile.urls, rules_applied=_redaction_counts(snapshot)),
        provenance=Provenance(revision=snapshot['revision']), unknowns=unknowns,
        truncated=list(sections.truncated))
