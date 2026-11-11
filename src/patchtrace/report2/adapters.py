"""Headless section adapters (SPEC-50 RPT2-6): read the stored producers of one `ProjectService` into `SectionInputs`.

Qt-free and read-only. Like `EnrichmentStore`, `collect_from_service` runs only on the thread that owns the project
store (the GUI opens the dialog on it; the CLI is single-threaded). Every producer is read inside its own guard: a
producer that raises leaves its section `None` and adds a line to `unknowns`; it never aborts the export. A contract
refusal by a section builder (`PT-EXPORT-SECTION`) is not a producer failure and still stops the export (7.3).

Sections without a stored producer stay `None`: `series` (an `nway/1` series lives in a series folder with its own
`series.json`, not in a project, so no project-scoped record exists to read).

`advisories` has two producers, each behind its own guard: the project's CSAF store and the KB context a project made
by `kb import-pair` or `kb attach` carries (amendment A-2, `kb_context`). The KB records follow the CSAF records; a
project without a KB context exports what it did before.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import TypeVar

from . import text
from .inputs import SectionInputs
from .sections import collect
from .sections.advisories import AdvisoryRecord
from .sections.build_facts import FactRecord
from .sections.leads import LeadRecord

T = TypeVar('T')
MAX_UNKNOWN_WARNINGS = 5
KNOWN_ENGINES = ('rz-diff', 'bindiff')
FACTS_NOT_PARSED = ('build_facts: signer_subject, manifest_exec_level, original_filename and company_name are not '
                    'read by any available producer; unknown, not absent')


class _Unknowns(list):
    def attempt(self, section: str, producer: Callable[[], T], omitted: str = 'section omitted') -> T | None:
        try:
            return producer()
        except Exception as exc:  # noqa: BLE001 - a failing producer degrades its section only
            self.append(f'{section}: producer failed ({type(exc).__name__}); {omitted}')
            return None


@dataclass(frozen=True)
class _EvidencePort:
    value: object
    stale: bool

    def assessment(self):
        return self.value

    def is_stale(self) -> bool:
        return self.stale


@dataclass(frozen=True)
class _Loaded:
    value: object

    def load(self):
        return self.value


@dataclass(frozen=True)
class _Rows:
    rows: tuple

    def advisories(self) -> Sequence:
        return self.rows

    def facts(self) -> Sequence:
        return self.rows

    def leads(self) -> Sequence:
        return self.rows


class UnifiedReferencePort:
    """The verified pointer of the stored unified result for the plan that most closely matches it, so a result made
    with `--sources`, `--no-extract` or `--no-residual` is not exported as stale (read model `resolve_best`)."""

    def __init__(self, service):
        self._service = service

    def load(self):
        from ..unified import pipeline
        from ..unified.limits import UnifiedError
        from ..unified.read_model import capture_candidates, resolve_best
        try:
            plan = resolve_best(capture_candidates(self._service))
        except UnifiedError:
            plan = None
        return pipeline.load_current(self._service, plan)


def _pair(project) -> tuple[str, str] | None:
    sides = {a.side: a.sha256 for a in project.artifacts}
    return (sides['older'], sides['newer']) if {'older', 'newer'} <= sides.keys() else None


def _evidence(service, unknowns: _Unknowns) -> _EvidencePort | None:
    from ..enrichment.storage import EnrichmentStore
    from ..secondary import load_secondary
    from ..secondary.evidence import assess_reports
    from ..secondary.reconcile import reconcile
    from ..secondary.store import select_current
    project, pair = service.project, _pair(service.project)
    chosen, _ = select_current(load_secondary(EnrichmentStore(service.store)), pair)
    if not chosen:
        return None
    sets = [match_set for _, match_set in chosen]
    assessment = assess_reports(tuple(reconcile(project.matches, s) for s in sets))
    stored = {s.engine for s in sets}
    unknowns.extend(f'engine_evidence: {engine} has no stored match set; unknown, not a negative result'
                    for engine in KNOWN_ENGINES if engine not in stored)
    return _EvidencePort(assessment, any((s.older_sha256, s.newer_sha256) != pair for s in sets))


def _advisory_text(advisory, vulnerability) -> str:
    facts = advisory.facts
    note = '; superseded by a newer revision' if advisory.superseded else ''
    title = f'{vulnerability.title}: ' if vulnerability.title else ''
    return f'{title}{facts.title} (tracking id {facts.tracking_id}, revision {facts.revision}{note})'


def _advisories(service, unknowns: _Unknowns) -> _Rows | None:
    from ..enrichment.storage import EnrichmentStore
    from ..intelligence.storage import AdvisoryStore
    project = service.project
    stored, warnings = AdvisoryStore(service.root, EnrichmentStore(service.store), project.id,
                                     project.revision).advisories()
    unknowns.extend(f'advisories: {w}' for w in warnings[:MAX_UNKNOWN_WARNINGS])
    records: list[AdvisoryRecord] = []
    for advisory in stored:
        source = advisory.source
        common = dict(vendor=source.publisher_name, url=source.uri or '', fetched_at=source.retrieved_at,
                      snapshot_digest=source.sha256)
        for vulnerability in advisory.facts.vulnerabilities:
            if vulnerability.cve:
                records.append(AdvisoryRecord('cve', vulnerability.cve, _advisory_text(advisory, vulnerability),
                                              **common))
            if vulnerability.cwe:
                records.append(AdvisoryRecord('cwe', vulnerability.cwe.id, vulnerability.cwe.name, **common))
    return _Rows(tuple(records)) if records else None


def _kb_context(service, unknowns: _Unknowns) -> tuple[AdvisoryRecord, ...]:
    """The `kb` and `cve` records of the KB context the project carries (A-2). Read-only: `entries` creates no
    table, and the guard keeps that true if the store ever changes. A context prepared for another file pair says
    nothing about these two files, so it is named in `unknowns` and left out."""
    import json

    from ..enrichment.storage import EnrichmentStore
    from . import kb_context
    if not _has_enrichment(service):
        return ()
    bundle = kb_context.latest(json.dumps(e.body) for e in EnrichmentStore(service.store).entries('kb-context'))
    if bundle is None:
        return ()
    if (bundle.older_sha, bundle.newer_sha) != _pair(service.project):
        unknowns.append(kb_context.NOTE_OTHER_PAIR)
        return ()
    records, notes = kb_context.records(bundle)
    unknowns.extend(notes)
    return records


def _with_kb_context(advisories: _Rows | None, kb_rows: tuple[AdvisoryRecord, ...] | None) -> _Rows | None:
    if not kb_rows:
        return advisories
    return _Rows((*(advisories.rows if advisories else ()), *kb_rows))


def _pe_facts(artifact, root, unknowns: _Unknowns) -> list[FactRecord]:
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..intelligence.csaf.identity import read_version_info
    from ..pe_overview import inspect_pe
    side, facts = artifact.side, []
    try:
        with VerifiedArtifactReader.open_artifact(artifact, root) as reader:
            overview = inspect_pe(reader)
            if overview.status in ('not_pe', 'cancelled'):
                return facts
            version = read_version_info(reader, overview)
    except ArtifactBytesError as exc:
        unknowns.append(f'build_facts: {side} artifact could not be read ({exc.code}); its facts are unknown')
        return facts
    if version.file_version:
        facts.append(FactRecord(side, 'file_version', version.file_version, 'pe-version-resource'))
    if version.product_version:
        facts.append(FactRecord(side, 'product_version', version.product_version, 'pe-version-resource'))
    if overview.codeview is not None:
        guid = ''.join(c for c in overview.codeview.guid if c in '0123456789abcdefABCDEF').upper()
        if len(guid) == 32:
            facts.append(FactRecord(side, 'pdb_guid_age', f'{guid}{overview.codeview.age:X}', 'pe-codeview'))
    stamp = overview.coff_timestamp
    if stamp is not None:
        shown = stamp.iso_utc or f'raw 0x{stamp.raw:08X}'
        facts.append(FactRecord(side, 'timestamp_claim', f'claimed {shown}; {stamp.note}', 'pe-coff-header'))
    return facts


def _build_facts(service, unknowns: _Unknowns) -> _Rows | None:
    records = []
    for artifact in sorted(service.project.artifacts, key=lambda a: a.side):
        if artifact.side in ('older', 'newer'):
            records.extend(_pe_facts(artifact, service.root, unknowns))
    if not records:
        return None
    unknowns.append(FACTS_NOT_PARSED)
    return _Rows(tuple(records))


def _known(project) -> dict[str, object]:
    from ..pilot import store
    sides = {a.side: a.sha256 for a in project.artifacts}
    run = store.completed_run(project)
    return {'older_sha256': sides.get('older'), 'newer_sha256': sides.get('newer'),
            'ghidriff_run_id': run.id if run else None, 'raw_sha256': run.raw_sha256 if run else None}


def _lead_record(lead, channels_of: dict[str, str]) -> LeadRecord | None:
    channels = tuple(sorted({channels_of[i] for i in lead.support_ids if i in channels_of}))
    if not channels:
        return None
    gate = f'advisory {lead.cve}, gate {lead.gate}' if lead.cve else 'code evidence only, no advisory'
    statement = (f'Candidate function pair, class {lead.lead_class}, mechanism {lead.mechanism}, identity '
                 f'{lead.identity}; {gate}; {lead.components.count} independent origin component(s); position '
                 f'{lead.tie.first}-{lead.tie.last} of a ranked list. A rank, not a probability.')
    lead_id = f'{lead.candidate_key[:16]}:{lead.cve}' if lead.cve else lead.candidate_key[:16]
    return LeadRecord(lead_id, lead.lead_class, channels, statement,
                      tuple(sorted(lead.support_ids))[:64])


def _has_enrichment(service) -> bool:
    """The pilot store creates the enrichment tables on first use; an export must not write to the project."""
    row = service.store.connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone()
    return row is not None


def _leads(service, unknowns: _Unknowns) -> _Rows | None:
    from ..enrichment.storage import EnrichmentStore
    from ..pilot import store
    if not _has_enrichment(service):
        return None
    loaded = store.load(EnrichmentStore(service.store), _known(service.project))
    if loaded.state == 'none':
        return None
    if loaded.state != 'current':
        unknowns.append(f'leads: the stored pilot result is {loaded.state} ({loaded.reason or "unverified"}); '
                        'leads omitted')
        return None
    assessment = loaded.assessment
    channels_of = {o.obs_id: o.channel for o in assessment.observations}
    records = [r for lead in assessment.leads if (r := _lead_record(lead, channels_of)) is not None]
    return _Rows(tuple(records)) if records else None


def collect_from_service(service) -> SectionInputs:
    """Every optional section a stored producer can supply, plus `unknowns` for what could not be read."""
    unknowns = _Unknowns()
    evidence = unknowns.attempt('engine_evidence', lambda: _evidence(service, unknowns))
    advisories = unknowns.attempt('advisories', lambda: _advisories(service, unknowns))
    advisories = _with_kb_context(advisories, unknowns.attempt(
        'advisories (KB context)', lambda: _kb_context(service, unknowns), 'its kb and cve records are omitted'))
    facts = unknowns.attempt('build_facts', lambda: _build_facts(service, unknowns))
    leads = unknowns.attempt('leads', lambda: _leads(service, unknowns))
    unified = unknowns.attempt('unified_result', UnifiedReferencePort(service).load)
    sections = collect(evidence=evidence, unified=_Loaded(unified), build_facts=facts,
                       advisories=advisories, leads=leads)
    return _with_unknowns(sections, unknowns)


def _with_unknowns(sections: SectionInputs, unknowns: _Unknowns) -> SectionInputs:
    return replace(sections, unknowns=tuple(text.normalize_text(u, max_chars=text.CAP_NAME) for u in unknowns))
