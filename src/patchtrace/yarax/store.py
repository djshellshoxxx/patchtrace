"""Append-only persistence of rule rows as the reserved enrichment kinds `rule-*` (plan s7). Rows are written on the
thread that owns the `EnrichmentStore`; none is a derived kind, so retention never deletes them.

Row id `<kind>:<id>`, guard `(project_id, 'rules', sha256(older:newer), row digest)`. A row is never rewritten: storing
the same content again is a no-op, different content under an existing id is `PT-RULE-INTEGRITY`. A matrix over 1 MiB
goes to the hash-verified sidecar `<project>/rules/tests/<sha256>.json`. Readers skip rows that no longer validate and
ignore unknown top-level fields of rows a newer client wrote.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from ..enrichment.identity import canonical_json, domain_id
from ..enrichment.storage import EnrichmentError, EnrichmentStore, Guard
from . import gates as gate_checks
from .contracts import (
    CONTRACT,
    CellResult,
    DecisionAction,
    ExportRecord,
    MatrixRun,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
    text_sha256,
)
from .errors import RulesError
from .limits import LIMITS, RuleLimits
from .matrix import synth_writer
from .synth import RuleSpec, synthesize

GUARD_RUN_ID = 'rules'
DIRECTORY = 'rules/tests'
CANDIDATE, DECISION, VERSION, TEST, EXPORT = 'rule-candidate', 'rule-decision', 'rule-version', 'rule-test', 'rule-export'
Clock = Callable[[], str]


def utc_now() -> str:
    return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def _utc(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-', suffix='.part')
    try:
        with os.fdopen(handle, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _model[M: BaseModel](cls: type[M], record: object) -> M | None:
    if not isinstance(record, dict):
        return None
    known = {key: value for key, value in record.items() if key in cls.model_fields}
    try:
        return cls.model_validate_json(json.dumps(known))
    except ValidationError:
        return None


class RuleStore:
    def __init__(self, enrichment: EnrichmentStore, project_dir: Path, project_id: str, revision: int,
                 limits: RuleLimits = LIMITS):
        self.enrichment = enrichment
        self.project_dir = Path(project_dir)
        self.project_id = project_id
        self.revision = revision
        self.limits = limits

    # ---- writing ----------------------------------------------------------------------------------------------------

    def _append(self, kind: str, key: str, older: str, newer: str, status: str, body: dict) -> str:
        entry_id = f'{kind}:{key}'
        body = json.loads(canonical_json({'contract': CONTRACT, **body}))
        existing = next((e for e in self._entries(kind) if e.id == entry_id), None)
        if existing is not None:
            if existing.body != body:
                raise RulesError('PT-RULE-INTEGRITY', 'A stored rule row cannot be changed; save a new version.')
            return entry_id
        guard = Guard(self.project_id, GUARD_RUN_ID, hashlib.sha256(f'{older}:{newer}'.encode()).hexdigest(),
                      hashlib.sha256(canonical_json(body)).hexdigest())
        try:
            self.enrichment.publish(kind, guard, guard, self.revision, status, body, entry_id)
        except EnrichmentError as exc:
            raise RulesError('PT-RULE-STORAGE', f'The rule was not saved ({exc.code}).') from None
        return entry_id

    def add_candidate(self, candidate: RuleCandidate) -> str:
        source = candidate.source
        return self._append(CANDIDATE, candidate.candidate_id, source.older_sha256, source.newer_sha256, 'proposed',
                            {'record': candidate.model_dump(mode='json')})

    def add_decision(self, decision: RuleDecision, candidate: RuleCandidate) -> str:
        source = candidate.source
        return self._append(DECISION, decision.decision_id, source.older_sha256, source.newer_sha256, decision.action,
                            {'record': decision.model_dump(mode='json'), 'lineage_id': candidate.lineage_id})

    def add_version(self, version: RuleVersion) -> str:
        source = version.source
        return self._append(VERSION, version.version_id, source.older_sha256, source.newer_sha256, 'accepted',
                            {'record': version.model_dump(mode='json')})

    def add_export(self, record: ExportRecord, version: RuleVersion) -> str:
        return self._append(EXPORT, record.export_id, version.source.older_sha256, version.source.newer_sha256,
                            'exported', {'record': record.model_dump(mode='json')})

    def add_checkpoint(self, cache_key: str, older: str, newer: str, cells: Sequence[CellResult]) -> None:
        """Scanned cells of one finished chunk, so a crashed run resumes without rescanning them."""
        records = [c.model_dump(mode='json') for c in cells if c.state in ('hit', 'no-hit')]
        if records:
            digest = domain_id('rule-test', 1, {'cache_key': cache_key, 'cells': records})
            self._append(TEST, f'ck-{digest}', older, newer, 'checkpoint',
                         {'kind': 'checkpoint', 'cache_key': cache_key, 'cells': records})

    def add_test(self, run: MatrixRun, versions: Sequence[RuleVersion]) -> str:
        """The finished grid; inline up to 1 MiB, else a sidecar with a hash-checked pointer row."""
        source = versions[0].source
        record = run.model_dump(mode='json')
        text = canonical_json(record)
        header = {'kind': 'matrix', 'run_id': run.run_id, 'cache_key': run.cache_key,
                  'version_ids': sorted(v.version_id for v in versions),
                  'rule_sha256s': sorted(v.rule_sha256 for v in versions)}
        if len(text) <= self.limits.matrix_inline_bytes:
            body = {**header, 'record': record}
        else:
            digest = hashlib.sha256(text).hexdigest()
            relative = f'{DIRECTORY}/{digest}.json'
            atomic_write(self.project_dir / relative, text)
            body = {**header, 'sidecar': relative, 'sidecar_sha256': digest, 'size': len(text)}
        return self._append(TEST, run.run_id, source.older_sha256, source.newer_sha256, run.status, body)

    # ---- reading ----------------------------------------------------------------------------------------------------

    def _entries(self, kind: str):
        return [e for e in self.enrichment.entries(kind, on_corrupt=lambda _id: None)
                if e.guard.project_id == self.project_id and e.guard.run_id == GUARD_RUN_ID
                and isinstance(e.body, dict) and e.body.get('contract') == CONTRACT]

    def _records[M: BaseModel](self, kind: str, cls: type[M]) -> list[M]:
        return [m for m in (_model(cls, e.body.get('record')) for e in self._entries(kind)) if m is not None]

    def candidates(self) -> list[RuleCandidate]:
        return self._records(CANDIDATE, RuleCandidate)

    def decisions(self) -> list[RuleDecision]:
        return self._records(DECISION, RuleDecision)

    def versions(self, lineage_id: str | None = None) -> list[RuleVersion]:
        found = [v for v in self._records(VERSION, RuleVersion) if lineage_id in (None, v.lineage_id)]
        return sorted(found, key=lambda v: (v.lineage_id, v.version))

    def exports(self) -> list[ExportRecord]:
        return self._records(EXPORT, ExportRecord)

    def checkpoint_cells(self, cache_key: str) -> list[CellResult]:
        out = []
        for entry in self._entries(TEST):
            if entry.body.get('kind') == 'checkpoint' and entry.body.get('cache_key') == cache_key:
                out += [c for c in (_model(CellResult, r) for r in entry.body.get('cells', ())) if c is not None]
        return out

    def _run_of(self, body: dict) -> MatrixRun | None:
        record = body.get('record')
        if 'sidecar' in body:
            path = (self.project_dir / str(body['sidecar'])).resolve()
            if (self.project_dir / DIRECTORY).resolve() not in path.parents or not path.is_file():
                return None
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != body.get('sidecar_sha256'):
                raise RulesError('PT-RULE-INTEGRITY', 'A stored rule test failed its SHA-256 check.')
            record = json.loads(data)
        return _model(MatrixRun, record)

    def latest_test(self, version_id: str) -> tuple[MatrixRun, str] | None:
        """The newest finished grid that includes this version, with the UTC time it was saved."""
        for entry in self._entries(TEST):
            if entry.body.get('kind') == 'matrix' and version_id in entry.body.get('version_ids', ()):
                run = self._run_of(entry.body)
                if run is not None:
                    return run, _utc(entry.created)
        return None

    def candidate_for(self, version: RuleVersion) -> RuleCandidate | None:
        return next((c for c in self.candidates() if c.candidate_id == version.candidate_id), None)

    # ---- decisions --------------------------------------------------------------------------------------------------

    def decide(self, candidate: RuleCandidate, action: DecisionAction, *, label: str = '', note: str = '',
               cve: Sequence[str] = (), kb: Sequence[str] = (), cwe: Sequence[str] = (),
               now: Clock = utc_now) -> tuple[RuleDecision, RuleVersion | None]:
        """Record the analyst's decision; accepting also saves the next immutable version of the lineage.

        Both ids are content derived, so a crash between the two writes is repaired by repeating the call. A hard
        gate failure refuses the accept (`unknown` never blocks: it is not a negative).
        """
        failed = gate_checks.refused(candidate.gates)
        if action == 'accept' and failed:
            raise RulesError('PT-RULE-GATE', 'Accept refused, a check failed: ' + ', '.join(failed))
        self.add_candidate(candidate)
        fields = {'label': label, 'note': note, 'cve': sorted(cve), 'kb': sorted(kb), 'cwe': sorted(cwe)}
        decision_id = domain_id('rule-decision', 1, {'candidate': candidate.candidate_id, 'action': action, **fields})
        try:
            decision = RuleDecision(decision_id=decision_id, candidate_id=candidate.candidate_id, action=action,
                                    analyst_label=label, note=note, cve=tuple(sorted(cve)), kb=tuple(sorted(kb)),
                                    cwe=tuple(sorted(cwe)), decided_at=now())
        except ValidationError as exc:
            raise RulesError('PT-RULE-INPUT', f'Invalid decision: {exc.errors()[0]["msg"]}') from None
        stored = next((d for d in self.decisions() if d.decision_id == decision_id), None)
        decision = stored or decision
        if stored is None:
            self.add_decision(decision, candidate)
        return decision, (self._accept(candidate, decision) if action == 'accept' else None)

    def _accept(self, candidate: RuleCandidate, decision: RuleDecision) -> RuleVersion:
        lineage = self.versions(candidate.lineage_id)
        version_id = domain_id('rule-version', 1, {'lineage': candidate.lineage_id, 'candidate': candidate.candidate_id,
                                                   'decision': decision.decision_id})
        existing = next((v for v in lineage if v.version_id == version_id), None)
        if existing is not None:
            return existing
        number = len(lineage) + 1
        if number > self.limits.versions_per_lineage:
            raise RulesError('PT-RULE-LIMIT', f'At most {self.limits.versions_per_lineage} versions per rule.')
        text = synth_writer(version=number, analyst_label=decision.analyst_label, cve=decision.cve, kb=decision.kb,
                            cwe=decision.cwe)(candidate.source, direction=candidate.direction,
                                              rule_name=candidate.rule_name,
                                              features=[f for f in candidate.features if f.included])
        version = RuleVersion(
            version_id=version_id, lineage_id=candidate.lineage_id, version=number,
            supersedes=lineage[-1].version_id if lineage else None, candidate_id=candidate.candidate_id,
            decision_id=decision.decision_id, rule_text=text, rule_sha256=text_sha256(text), source=candidate.source,
            engine=candidate.engine, created_at=decision.decided_at)
        self.add_version(version)
        return version

    def resynthesize(self, version: RuleVersion, candidate: RuleCandidate, decision: RuleDecision | None, *,
                     include_names: bool) -> str:
        """The version's rule text, optionally with function names (they may come from symbol files)."""
        if not include_names:
            return version.rule_text
        spec = RuleSpec(source=version.source, direction=candidate.direction, lineage_id=version.lineage_id,
                        version=version.version, features=tuple(f for f in candidate.features if f.included),
                        analyst_label=decision.analyst_label if decision else '', include_names=True,
                        unvetted=candidate.unvetted, cve=decision.cve if decision else (),
                        kb=decision.kb if decision else (), cwe=decision.cwe if decision else ())
        return synthesize(spec)

    def decision_of(self, version: RuleVersion) -> RuleDecision | None:
        return next((d for d in self.decisions() if d.decision_id == version.decision_id), None)


def lineage_status(store: RuleStore) -> dict[str, str]:
    """candidate_id -> 'Proposed' / 'Accepted vN' / 'Rejected' / 'Deferred' / 'Archived' (the latest decision wins)."""
    versions = {v.decision_id: v for v in store.versions()}
    status: dict[str, str] = {}
    for decision in sorted(store.decisions(), key=lambda d: d.decided_at):
        version = versions.get(decision.decision_id)
        status[decision.candidate_id] = (f'Accepted v{version.version}' if version else
                                         {'accept': 'Accepted', 'reject': 'Rejected', 'defer': 'Deferred',
                                          'archive': 'Archived'}[decision.action])
    return {c.candidate_id: status.get(c.candidate_id, 'Proposed') for c in store.candidates()}

