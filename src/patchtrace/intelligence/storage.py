"""Append-only advisory source snapshots inside a project (SPEC-28 section I).

Exact source bytes and normalized facts live in content-addressed sidecar files under
``<project>/intelligence/csaf/{sources,facts}/``; the enrichment store keeps only small pointer rows of the
reserved kinds ``advisory-source`` (one per acquisition) and ``advisory-facts`` (one per content and
normalizer version). Rows are never rewritten: an existing row id is skipped. Every sidecar read is verified
by SHA-256. Staleness (a superseded revision of the same tracking id) is derived at read time, so nothing is
mutated when a newer revision arrives. An import validates and normalizes completely before the first write,
so a rejected document leaves every earlier row and file untouched (last known-good).

Thread ownership: like ``EnrichmentStore``, use only on the thread that owns the project store.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Guard
from ..ingestion import safe_path
from .contracts import AdvisoryFacts, AdvisorySource, IntelError
from .csaf import normalize as norm
from .csaf.applicability import supersession
from .csaf.validate import VALIDATOR_VERSION, load_document

SOURCE_KIND = 'advisory-source'
FACTS_KIND = 'advisory-facts'
GUARD_RUN = 'intelligence'
SOURCES_DIR = 'intelligence/csaf/sources'
FACTS_DIR = 'intelligence/csaf/facts'


@dataclass(frozen=True)
class StoredAdvisory:
    source: AdvisorySource  # the most recent acquisition of these exact bytes
    facts: AdvisoryFacts
    superseded: bool
    retrievals: int


def _facts_digest() -> str:
    return f'normalizer/{norm.NORMALIZER_VERSION}/validator/{VALIDATOR_VERSION}'


class AdvisoryStore:
    def __init__(self, root: Path, store: EnrichmentStore, project_id: str, revision: int):
        self.root = Path(root)
        self.store = store
        self.project_id = project_id
        self.revision = revision

    # ------------------------------------------------------------------ files
    def _path(self, relative: str) -> Path:
        try:
            return safe_path(self.root, relative)
        except ValueError as exc:
            raise IntelError('PT-INTEL-STORAGE', str(exc)) from None

    def _write(self, relative: str, data: bytes) -> None:
        """Content-addressed, atomic and idempotent: an identical file is kept, a damaged one is replaced."""
        path = self._path(relative)
        digest = hashlib.sha256(data).hexdigest()
        try:
            if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest:
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix='.partial-', dir=path.parent)
            try:
                with os.fdopen(fd, 'wb') as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(name, path)
            except BaseException:
                Path(name).unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise IntelError('PT-INTEL-STORAGE', f'cannot write {relative}: {exc.strerror or exc}') from None

    def read_verified(self, relative: str, sha256: str) -> bytes:
        try:
            data = self._path(relative).read_bytes()
        except OSError:
            raise IntelError('PT-INTEL-INTEGRITY', f'{relative} is missing or unreadable') from None
        if hashlib.sha256(data).hexdigest() != sha256:
            raise IntelError('PT-INTEL-INTEGRITY', f'{relative} does not match its recorded SHA-256')
        return data

    # ------------------------------------------------------------------ rows
    def _guard(self, sha256: str, digest: str) -> Guard:
        return Guard(self.project_id, GUARD_RUN, sha256, digest)

    def _publish(self, kind: str, row_id: str, sha256: str, digest: str, body: dict) -> bool:
        try:
            if any(entry.id == row_id for entry in self.store.entries(kind)):
                return False  # append-only: never rewrite an existing row
            guard = self._guard(sha256, digest)
            self.store.publish(kind, guard, guard, self.revision, 'complete', body, row_id)
            return True
        except EnrichmentError as exc:
            raise IntelError('PT-INTEL-STORAGE', f'cannot record the advisory: {exc.message}') from None

    # ------------------------------------------------------------------ import
    def add(self, raw: bytes, *, origin: str, uri: str | None, file_name: str, retrieved_at: str,
            authenticity_state: str | None = None, cancel: threading.Event | None = None) -> StoredAdvisory:
        """Validate, normalize, then persist. Nothing is written unless the document is fully accepted."""
        doc, report = load_document(raw, cancel=cancel)
        sha = hashlib.sha256(raw).hexdigest()
        facts = norm.normalize(doc, report, sha, cancel=cancel)
        source = norm.make_source(doc, raw, origin=origin, uri=uri, file_name=file_name, retrieved_at=retrieved_at,
                                  authenticity_state=authenticity_state)
        facts_bytes = facts.model_dump_json().encode('utf-8')
        facts_sha = hashlib.sha256(facts_bytes).hexdigest()
        if cancel is not None and cancel.is_set():
            raise IntelError('PT-INTEL-CANCEL', 'import cancelled before anything was written', recoverable=True)
        self._write(source.raw_path, raw)
        facts_path = f'{FACTS_DIR}/{facts.facts_id}.json'
        self._write(facts_path, facts_bytes)
        self._publish(FACTS_KIND, f'{FACTS_KIND}:{facts.facts_id}', sha, _facts_digest(),
                      {'contract': 'intelligence/1', 'facts_id': facts.facts_id, 'source_id': sha, 'path': facts_path,
                       'sha256': facts_sha, 'normalizer_version': norm.NORMALIZER_VERSION,
                       'validator_version': VALIDATOR_VERSION, 'tracking_id': facts.tracking_id,
                       'revision': facts.revision, 'cves': list(facts.cves())})
        self._publish(SOURCE_KIND, f'{SOURCE_KIND}:{sha}:{source.retrieval_id}', sha, source.retrieval_id,
                      {'contract': 'intelligence/1', 'source': source.model_dump(mode='json')})
        stored = {s.source.sha256: s for s in self.advisories()[0]}
        return stored[sha]

    # ------------------------------------------------------------------ read
    def _facts(self, source: AdvisorySource, rows: dict[str, dict], warnings: list[str]) -> AdvisoryFacts:
        facts_id = norm.facts_id_for(source.sha256)
        row = rows.get(f'{FACTS_KIND}:{facts_id}')
        if row is not None and row.get('normalizer_version') == norm.NORMALIZER_VERSION:
            try:
                data = self.read_verified(row['path'], row['sha256'])
                return AdvisoryFacts.model_validate_json(data)
            except (IntelError, ValidationError, KeyError, TypeError):
                warnings.append(f'{source.tracking_id} r{source.revision}: stored facts unusable; recomputed from '
                                'the verified source bytes')
        raw = self.read_verified(source.raw_path, source.sha256)
        doc, report = load_document(raw)
        return norm.normalize(doc, report, source.sha256)

    def advisories(self) -> tuple[list[StoredAdvisory], list[str]]:
        """Every stored advisory (one per distinct content), with derived supersession, plus warnings for rows
        or files that could not be used. Unusable sources are skipped, never guessed."""
        warnings: list[str] = []
        try:
            source_rows = self.store.entries(SOURCE_KIND, on_corrupt=lambda rid: warnings.append(
                f'advisory source row {rid[:40]} failed its integrity hash; skipped'))
            fact_rows = {e.id: e.body for e in self.store.entries(FACTS_KIND, on_corrupt=lambda rid: warnings.append(
                f'advisory facts row {rid[:40]} failed its integrity hash; ignored'))}
        except EnrichmentError as exc:
            raise IntelError('PT-INTEL-STORAGE', exc.message) from None
        latest: dict[str, tuple[AdvisorySource, int]] = {}
        for entry in source_rows:
            try:
                source = AdvisorySource.model_validate_json(_json(entry.body.get('source')))
            except (ValidationError, TypeError, ValueError):
                warnings.append(f'advisory source row {entry.id[:40]} is not a valid intelligence/1 record; skipped')
                continue
            seen, count = latest.get(source.sha256, (None, 0))
            if seen is None or (source.retrieved_at, source.retrieval_id) > (seen.retrieved_at, seen.retrieval_id):
                seen = source
            latest[source.sha256] = (seen, count + 1)
        loaded: list[tuple[AdvisorySource, AdvisoryFacts, int]] = []
        for sha in sorted(latest):
            source, count = latest[sha]
            try:
                loaded.append((source, self._facts(source, fact_rows, warnings), count))
            except IntelError as exc:
                warnings.append(f'{source.tracking_id} r{source.revision}: {exc.code}: {exc.message}; skipped')
        superseded = supersession([facts for _, facts, _ in loaded])
        result = [StoredAdvisory(source=s, facts=f, superseded=superseded[f.facts_id], retrievals=n)
                  for s, f, n in loaded]
        result.sort(key=lambda a: (a.facts.tracking_id, a.facts.current_release_date, a.source.sha256))
        return result, warnings

    def for_cve(self, cve: str) -> tuple[list[StoredAdvisory], list[str]]:
        advisories, warnings = self.advisories()
        return [a for a in advisories if a.facts.vulnerability(cve) is not None], warnings


def _json(value) -> str:
    return json.dumps(value, sort_keys=True)
