"""Append-only storage of rule work in the project (YRX-integration-plan section 7, "Storage, keys, limits").

Five reserved enrichment kinds, none of them derived (retention never deletes them): `rule-candidate`, `rule-decision`,
`rule-version`, `rule-test` and `rule-export`. A row id is `<kind>:<content id>`; the guard is
`(project_id, 'rules', sha256(older:newer), digest of the row)`. A row is written once: writing the same content again
changes nothing, and different content under an existing id is `PT-RULE-INTEGRITY`, never an overwrite. A revision of a
rule is a new version, a changed mind is a new decision. A test grid over 1 MiB goes to the hash-verified sidecar
`<project>/rules/tests/<sha256>.json`; the row keeps its identity and the hash.

Accepting is two rows (a decision, then the version it makes). The version is a pure function of the stored candidate and
decision, and its timestamp is the decision's, so a crash between the two rows is finished by repeating the same command
(`pending_accepts` lists them) and nothing is duplicated.

Reading never fails for one bad row: a row that does not hold its hash or its contract is skipped and listed in `skipped`
so a caller can say the picture is partial. Rows written under a newer contract are not this reader's and are left alone.

Thread ownership: like every enrichment store, this one uses the project connection on the thread that owns it.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.identity import canonical_json, domain_id
from ..enrichment.storage import EnrichmentStore, Guard
from . import synth
from .contracts import (
    CONTRACT,
    ExportRecord,
    MatrixRun,
    PairSource,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
)
from .errors import RuleError
from .limits import DEFAULT_LIMITS

CANDIDATE, DECISION, VERSION, TEST, EXPORT = 'rule-candidate', 'rule-decision', 'rule-version', 'rule-test', 'rule-export'
GUARD_RUN = 'rules'
SIDECAR_DIR = 'rules/tests'
INLINE_LIMIT = 1024 * 1024
_M = TypeVar('_M', bound=BaseModel)


def pair_key(pair: tuple[str, str]) -> str:
    """The guard's `raw_sha256`: the two builds a row is about."""
    return hashlib.sha256(f'{pair[0]}:{pair[1]}'.encode('ascii')).hexdigest()


def decision_for(candidate: RuleCandidate, action: str, decided_at: str, *, label: str | None = None, note: str = '',
                 cve=(), kb=(), cwe=()) -> RuleDecision:
    """The analyst's decision on a candidate. The id covers what was decided and when, so a changed mind is a new row."""
    advisories = {name: sorted(set(values)) for name, values in (('cve', cve), ('kb', kb), ('cwe', cwe))}
    identity = {'candidate_id': candidate.candidate_id, 'action': action, 'label': label, 'note': note,
                'decided_at': decided_at, **advisories}
    try:
        return RuleDecision(decision_id=domain_id(DECISION, 1, identity), candidate_id=candidate.candidate_id,
                            action=action, analyst_label=label, note=note, decided_at=decided_at,
                            **{name: tuple(values) for name, values in advisories.items()})
    except ValidationError:
        raise RuleError('PT-RULE-INPUT', 'The decision is not valid: check the label and the advisory ids',
                        reason='bad-decision') from None


def accepted_text(candidate: RuleCandidate, decision: RuleDecision, version: int, *, include_names: bool = False) -> str:
    """The rule of the candidate as the analyst accepted it: its included features, the version number and the label and
    advisory ids of the decision as meta."""
    return synth.render_rule(candidate.source, lineage_id=candidate.lineage_id, direction=candidate.direction,
                             version=version, features=[f for f in candidate.features if f.included],
                             label=decision.analyst_label, cve=decision.cve, kb=decision.kb, cwe=decision.cwe,
                             include_names=include_names)


def version_for(candidate: RuleCandidate, decision: RuleDecision, previous: RuleVersion | None, text: str) -> RuleVersion:
    """The version an accept decision makes: the next of its lineage, superseding `previous`."""
    number = 1 if previous is None else previous.version + 1
    if number > DEFAULT_LIMITS.versions_per_lineage:
        raise RuleError('PT-RULE-LIMIT', f'A rule has at most {DEFAULT_LIMITS.versions_per_lineage} versions',
                        reason='versions')
    digest = hashlib.sha256(text.encode('ascii')).hexdigest()
    identity = {'lineage_id': candidate.lineage_id, 'version': number, 'rule_sha256': digest,
                'decision_id': decision.decision_id}
    return RuleVersion(version_id=domain_id(VERSION, 1, identity), lineage_id=candidate.lineage_id, version=number,
                       supersedes=None if previous is None else previous.version_id,
                       candidate_id=candidate.candidate_id, decision_id=decision.decision_id, rule_text=text,
                       rule_sha256=digest, source=candidate.source, engine=candidate.engine,
                       created_at=decision.decided_at)


def _atomic_write(path: Path, data: bytes) -> None:
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


class RuleStore:
    def __init__(self, enrichment: EnrichmentStore, project_dir: Path, project_id: str, revision: int):
        self.enrichment = enrichment
        self.project_dir = Path(project_dir)
        self.project_id = project_id
        self.revision = revision
        self.skipped: list[str] = []

    # ---- writes -------------------------------------------------------------------------------------------------

    def _append(self, kind: str, pair: tuple[str, str], content_id: str, body: dict) -> bool:
        """Write one row once. True when written, False when the same row was already there."""
        entry_id = f'{kind}:{content_id}'
        body = json.loads(canonical_json(body))
        existing = next((e for e in self._entries(kind) if e.id == entry_id), None)
        if existing is not None:
            if canonical_json(existing.body) != canonical_json(body):
                raise RuleError('PT-RULE-INTEGRITY', 'A stored rule row would be changed; rows are append-only',
                                reason='row-differs')
            return False
        guard = Guard(self.project_id, GUARD_RUN, pair_key(pair), hashlib.sha256(canonical_json(body)).hexdigest())
        try:
            self.enrichment.publish(kind, guard, guard, self.revision, 'ok', body, entry_id)
        except EnrichmentError as exc:
            raise RuleError('PT-RULE-STORAGE', f'The rule row was not stored ({exc.code})', reason='publish') from None
        return True

    def add_candidate(self, candidate: RuleCandidate) -> bool:
        return self._append(CANDIDATE, _pair(candidate.source), candidate.candidate_id, _body(candidate))

    def add_decision(self, decision: RuleDecision, source: PairSource) -> bool:
        return self._append(DECISION, _pair(source), decision.decision_id, _body(decision))

    def add_version(self, version: RuleVersion) -> bool:
        """Stores the next version of its lineage; a version that does not follow the stored chain is refused."""
        chain = self.versions(version.lineage_id)
        if version.version_id not in {v.version_id for v in chain}:
            tip = chain[-1] if chain else None
            if (tip.version_id if tip else None) != version.supersedes or version.version != len(chain) + 1:
                raise RuleError('PT-RULE-INTEGRITY', 'A version must follow the stored versions of its rule',
                                reason='version-chain')
        return self._append(VERSION, _pair(version.source), version.version_id, _body(version))

    def add_test(self, run: MatrixRun, source: PairSource) -> bool:
        body = _body(run)
        text = canonical_json(body)
        if len(text) > INLINE_LIMIT:
            digest = hashlib.sha256(text).hexdigest()
            relative = f'{SIDECAR_DIR}/{digest}.json'
            _atomic_write(self.project_dir / relative, text)
            body = {'contract': CONTRACT, 'kind': 'sidecar', 'run_id': run.run_id, 'cache_key': run.cache_key,
                    'status': run.status, 'finished_at': run.finished_at, 'sidecar': relative,
                    'sidecar_sha256': digest, 'size': len(text)}
        return self._append(TEST, _pair(source), run.run_id, body)

    def add_export(self, record: ExportRecord, source: PairSource) -> bool:
        return self._append(EXPORT, _pair(source), record.export_id, _body(record))

    # ---- reads --------------------------------------------------------------------------------------------------

    def _entries(self, kind: str):
        return self.enrichment.entries(kind, on_corrupt=lambda row: self.skipped.append(row))

    def _read(self, kind: str, model: type[_M], load: Callable[[dict], dict] = lambda body: body) -> list[_M]:
        found = []
        for entry in self._entries(kind):
            if entry.guard.run_id != GUARD_RUN or entry.body.get('contract') != CONTRACT:
                continue
            try:
                found.append(model.model_validate_json(json.dumps(load(entry.body))))
            except (ValidationError, RuleError):
                self.skipped.append(entry.id)
        return found

    def candidates(self) -> list[RuleCandidate]:
        return sorted(self._read(CANDIDATE, RuleCandidate), key=lambda c: (c.lineage_id, c.candidate_id))

    def candidate(self, candidate_id: str) -> RuleCandidate | None:
        return next((c for c in self.candidates() if c.candidate_id == candidate_id), None)

    def decisions(self, candidate_id: str | None = None) -> list[RuleDecision]:
        """Oldest first; the last one of a candidate is the one in force."""
        found = [d for d in self._read(DECISION, RuleDecision) if candidate_id in (None, d.candidate_id)]
        return sorted(found, key=lambda d: (d.decided_at, d.decision_id))

    def versions(self, lineage_id: str | None = None) -> list[RuleVersion]:
        found = [v for v in self._read(VERSION, RuleVersion) if lineage_id in (None, v.lineage_id)]
        return sorted(found, key=lambda v: (v.lineage_id, v.version))

    def version(self, version_id: str) -> RuleVersion | None:
        return next((v for v in self.versions() if v.version_id == version_id), None)

    def tests(self) -> list[MatrixRun]:
        """Newest first."""
        return sorted(self._read(TEST, MatrixRun, self._inline), key=lambda r: (r.finished_at, r.run_id), reverse=True)

    def find_test(self, cache_key: str) -> MatrixRun | None:
        return next((r for r in self.tests() if r.cache_key == cache_key and r.status == 'complete'), None)

    def exports(self, version_id: str | None = None) -> list[ExportRecord]:
        found = [e for e in self._read(EXPORT, ExportRecord) if version_id in (None, e.version_id)]
        return sorted(found, key=lambda e: (e.exported_at, e.export_id))

    def pending_accepts(self) -> list[RuleDecision]:
        """Accept decisions in force whose version was never written (a crash between the two rows)."""
        made = {v.decision_id for v in self.versions()}
        latest: dict[str, RuleDecision] = {}
        for decision in self.decisions():
            latest[decision.candidate_id] = decision
        return [d for d in latest.values() if d.action == 'accept' and d.decision_id not in made]

    def _inline(self, body: dict) -> dict:
        """The full run behind a sidecar pointer, after its hash holds."""
        if body.get('kind') != 'sidecar':
            return body
        relative = body.get('sidecar')
        root = (self.project_dir / SIDECAR_DIR).resolve()
        path = (self.project_dir / str(relative)).resolve()
        if not isinstance(relative, str) or root not in path.parents or not path.is_file():
            raise RuleError('PT-RULE-INTEGRITY', 'A stored test grid is missing', reason='sidecar-missing')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != body.get('sidecar_sha256'):
            raise RuleError('PT-RULE-INTEGRITY', 'A stored test grid failed its hash check', reason='sidecar-hash')
        return json.loads(data)


def _pair(source: PairSource) -> tuple[str, str]:
    return source.older_sha256, source.newer_sha256


def _body(model: BaseModel) -> dict:
    return model.model_dump(mode='json')

