"""Single-writer project operations; candidate snapshots commit before publication."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .ingestion import inspect_artifact, safe_path
from .models import AnalysisRun, AnalystAnnotation, ComparisonProject, FunctionMatch, InterpretationRun
from .normalization import normalize_ghidriff, verify_diff_identity
from .persistence import ProjectStore, strict_json

MAX_RAW_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class PreparedImport:
    project_id: str
    revision: int
    run: AnalysisRun
    matches: tuple[FunctionMatch, ...]
    fingerprint: tuple


class ProjectService:
    def __init__(self, root: Path, project: ComparisonProject, store: ProjectStore):
        self.root = Path(root).resolve()
        self.project = project
        self.store = store
        self._prepared: dict[str, tuple[PreparedImport, AnalysisRun, tuple[FunctionMatch, ...]]] = {}

    @classmethod
    def create(cls, older: Path, newer: Path, name: str, root: Path) -> ProjectService:
        root = Path(root).resolve()
        store = ProjectStore(root, create=True)
        try:
            artifacts = [inspect_artifact(older, 'older', root), inspect_artifact(newer, 'newer', root)]
            project = ComparisonProject(name=name.strip() or 'Untitled comparison', artifacts=artifacts)
            if artifacts[0].sha256 == artifacts[1].sha256:
                project.runs.append(AnalysisRun(status='identical', backend='none', backend_version='none',
                                                settings={'reason': 'Input SHA-256 hashes are identical'}))
            project = store.save(project)
            return cls(root, project, store)
        except Exception:
            store.close()
            # No snapshot was committed; permit retry without presenting a corrupt project.
            (root / 'project.sqlite3').unlink(missing_ok=True)
            raise

    @classmethod
    def open(cls, root: Path) -> ProjectService:
        store = ProjectStore(root)
        try:
            return cls(store.root, store.load(), store)
        except Exception:
            store.close()
            raise

    @classmethod
    def sample(cls, root: Path) -> ProjectService:
        from .sample import create_sample
        return create_sample(root)

    def _commit(self, candidate: ComparisonProject) -> None:
        self.project = self.store.save(candidate)

    def save(self) -> None:
        self._commit(self.project)

    def close(self) -> None:
        self._prepared.clear()
        self.store.close()

    def backup(self, destination: Path) -> Path:
        # load() may persist interrupted-run recovery; keep the service on the committed snapshot.
        self.project = self.store.load()
        return self.store.backup(destination)

    @staticmethod
    def _invalidate(candidate: ComparisonProject) -> None:
        candidate.revision += 1
        for interpretation in candidate.interpretations:
            interpretation.context.stale = True
            for finding in interpretation.findings:
                finding.stale = True
        for annotation in candidate.annotations:
            annotation.stale = True

    def prepare_import(self, path: Path) -> PreparedImport:
        run = AnalysisRun(status='completed', backend='ghidriff-import', backend_version='unknown',
                          settings={'source': 'analyst import; input identity verified'})
        return self._prepare_analysis(path, run)

    def import_diff(self, path: Path) -> None:
        self.apply_import(self.prepare_import(path))

    def apply_analysis(self, raw_path: Path, run: AnalysisRun) -> None:
        if run.status == 'identical':
            self.record_terminal_run(run)
        else:
            self.apply_import(self._prepare_analysis(raw_path, run))

    def prepare_analysis(self, raw_path: Path, run: AnalysisRun) -> PreparedImport:
        return self._prepare_analysis(raw_path, run)

    def _prepare_analysis(self, raw_path: Path, run: AnalysisRun) -> PreparedImport:
        self.store._check_open()
        snapshot = self.project.model_copy(deep=True)
        source = Path(raw_path)
        if run.status != 'completed':
            raise ValueError('PT-SCHEMA: applying a diff requires a completed analysis run')
        existing = next((item for item in self.project.runs if item.id == run.id), None)
        if existing is not None and existing.status not in {'queued', 'running'}:
            raise ValueError('PT-SCHEMA: terminal analysis runs cannot be overwritten')
        try:
            before = source.stat()
            if not source.is_file() or before.st_size > MAX_RAW_BYTES or before.st_size < 2:
                raise ValueError('PT-SCHEMA: raw diff must be a regular JSON file up to 100 MiB')
            with source.open('rb') as stream:
                raw_bytes = stream.read(MAX_RAW_BYTES + 1)
            after = source.stat()
            if len(raw_bytes) > MAX_RAW_BYTES or (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError('PT-SCHEMA: raw analysis output changed while reading')
            raw = strict_json(raw_bytes.decode('utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('PT-SCHEMA: analysis output is unreadable or malformed UTF-8 JSON') from exc
        if not isinstance(raw, dict):
            raise ValueError('PT-SCHEMA: analysis output root must be an object')
        verify_diff_identity(raw, snapshot)
        candidate = snapshot
        owned_run = run.model_copy(deep=True)
        candidate.runs = [item for item in candidate.runs if item.id != run.id] + [owned_run]
        normalized = normalize_ghidriff(raw, candidate, run.id)
        # Preserve exact bytes, including unrecognized metadata; normalized views never replace raw evidence.
        # A fresh owned path also protects against malicious caller-supplied run IDs/path traversal.
        from uuid import UUID
        try:
            UUID(run.id)
        except ValueError as exc:
            raise ValueError('PT-SCHEMA: analysis run ID must be a UUID') from exc
        relative = f'runs/{run.id}/raw/result.ghidriff.json'
        destination = safe_path(self.root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if destination.exists():
            if destination.read_bytes() != raw_bytes:
                raise ValueError('PT-STORAGE: preserved raw output cannot be replaced')
        else:
            fd, temporary = tempfile.mkstemp(prefix='.raw-', dir=destination.parent)
            stage = Path(temporary)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(stage, destination)
                destination.chmod(0o444)
            finally:
                stage.unlink(missing_ok=True)
        owned_run.raw_path, owned_run.raw_sha256 = relative, digest
        prepared = PreparedImport(candidate.id, candidate.revision, owned_run, tuple(normalized),
                                  self.store.file_fingerprint(destination))
        self._prepared[run.id] = (prepared, owned_run.model_copy(deep=True),
                                  tuple(match.model_copy(deep=True) for match in normalized))
        return prepared

    def apply_import(self, prepared: PreparedImport) -> None:
        self.store._check_open()
        owned = self._prepared.get(prepared.run.id)
        if owned is None or owned[0] is not prepared:
            raise ValueError('PT-SCHEMA: import was not prepared by this project service')
        owned_run, owned_matches = owned[1], owned[2]
        if prepared.project_id != self.project.id or prepared.revision != self.project.revision:
            self._prepared.pop(prepared.run.id, None)
            raise ValueError('PT-SCHEMA: project changed during import; prepare the import again')
        path = safe_path(self.root, owned_run.raw_path)
        if self.store.file_fingerprint(path) != prepared.fingerprint:
            raise ValueError('PT-STORAGE: prepared raw output changed before commit')
        candidate = self.project.model_copy(deep=True)
        candidate.runs = [item for item in candidate.runs if item.id != owned_run.id] + [owned_run]
        self._invalidate(candidate)
        candidate.matches = list(owned_matches)
        self.store.remember_verified(path, owned_run.raw_sha256, prepared.fingerprint)
        self._commit(candidate)
        self._prepared.pop(prepared.run.id, None)

    def discard_import(self, prepared: PreparedImport) -> None:
        owned = self._prepared.get(prepared.run.id)
        if owned is not None and owned[0] is prepared:
            self._prepared.pop(prepared.run.id, None)

    def record_terminal_run(self, run: AnalysisRun) -> None:
        if run.status not in {'failed', 'cancelled', 'identical'}:
            raise ValueError('PT-SCHEMA: terminal-run record must be failed, cancelled or identical')
        if run.status == 'identical' and len({a.sha256 for a in self.project.artifacts}) != 1:
            raise ValueError('PT-SCHEMA: identical status requires identical input hashes')
        candidate = self.project.model_copy(deep=True)
        existing = next((item for item in candidate.runs if item.id == run.id), None)
        if existing is not None and existing.status not in {'queued', 'running'}:
            raise ValueError('PT-SCHEMA: terminal run cannot be overwritten')
        candidate.runs = [item for item in candidate.runs if item.id != run.id] + [run.model_copy(deep=True)]
        self._commit(candidate)

    def add_interpretation(self, run: InterpretationRun) -> None:
        candidate = self.project.model_copy(deep=True)
        if run.id in {item.id for item in candidate.interpretations}:
            raise ValueError('PT-SCHEMA: interpretation already belongs to project')
        owned = run.model_copy(deep=True)
        if owned.context.project_id != candidate.id:
            raise ValueError('PT-SCHEMA: interpretation belongs to another project')
        if owned.context.revision != candidate.revision:
            owned.context.stale = True
            for finding in owned.findings:
                finding.stale = True
        candidate.interpretations.append(owned)
        self._commit(candidate)

    def review_match(self, match_id: str, status: str) -> None:
        candidate = self.project.model_copy(deep=True)
        match = next((item for item in candidate.matches if item.id == match_id), None)
        if match is None:
            raise ValueError('PT-SCHEMA: match does not belong to project')
        match.review = status
        self._commit(candidate)

    def review_finding(self, finding_id: str, status: str, conclusion: str = '') -> None:
        candidate = self.project.model_copy(deep=True)
        finding = next((item for run in candidate.interpretations for item in run.findings
                        if item.id == finding_id), None)
        if finding is None:
            raise ValueError('PT-SCHEMA: finding does not belong to project')
        finding.review, finding.analyst_conclusion = status, conclusion
        self._commit(candidate)

    def annotate(self, target_id: str, text: str, kind: str = 'note') -> None:
        if kind == 'match-override':
            raise ValueError('PT-SCHEMA: match-override records are created only by manual correction')
        candidate = self.project.model_copy(deep=True)
        candidate.annotations.append(AnalystAnnotation(target_id=target_id, kind=kind, text=text))
        self._commit(candidate)

    def correct_match(self, match_id: str, older_ids: list[str], newer_ids: list[str],
                      category: str, reason: str) -> None:
        if not reason.strip():
            raise ValueError('PT-SCHEMA: manual correction requires an analyst reason')
        if len(older_ids + newer_ids) != len(set(older_ids + newer_ids)):
            raise ValueError('PT-SCHEMA: correction has duplicate selected function IDs')
        candidate = self.project.model_copy(deep=True)
        target = next((item for item in candidate.matches if item.id == match_id), None)
        if target is None:
            raise ValueError('PT-SCHEMA: match does not belong to project')
        old = {func.id: func for match in candidate.matches if match.run_id == target.run_id for func in match.older}
        new = {func.id: func for match in candidate.matches if match.run_id == target.run_id for func in match.newer}
        if not set(older_ids) <= old.keys() or not set(newer_ids) <= new.keys():
            raise ValueError('PT-SCHEMA: selected functions belong to another side or analysis run')
        corrected = FunctionMatch(id=target.id, run_id=target.run_id,
                                  older=[old[item] for item in older_ids], newer=[new[item] for item in newer_ids],
                                  category=category, manual=True, reason=reason, quality='analyst override',
                                  match_types=['manual'])
        consumed = set(older_ids + newer_ids)
        matches = []
        previous = []
        for match in candidate.matches:
            funcs = match.older + match.newer
            if match.id == match_id or consumed.intersection(func.id for func in funcs):
                previous.append(match.model_dump(mode='json'))
                for side in ('older', 'newer'):
                    remaining = [func for func in getattr(match, side) if func.id not in consumed]
                    if remaining:
                        matches.append(FunctionMatch(run_id=match.run_id, category='unmatched',
                                                     **{side: remaining}, quality='manual correction remainder'))
            else:
                matches.append(match)
        candidate.matches = matches + [corrected]
        self._invalidate(candidate)
        record = {'previous_matches': previous, 'older_ids': older_ids, 'newer_ids': newer_ids,
                  'category': category, 'reason': reason}
        candidate.annotations.append(AnalystAnnotation(target_id=match_id, kind='match-override',
                                                       text=json.dumps(record, ensure_ascii=False, sort_keys=True)))
        self._commit(candidate)

    def restore_match_override(self, annotation_id: str) -> None:
        candidate = self.project.model_copy(deep=True)
        annotation = next((item for item in candidate.annotations if item.id == annotation_id), None)
        if annotation is None or annotation.kind != 'match-override' or annotation.stale:
            raise ValueError('PT-SCHEMA: correction is absent or superseded; only an active override can be restored')
        record = strict_json(annotation.text)
        if not isinstance(record, dict) or set(record) != {
                'previous_matches', 'older_ids', 'newer_ids', 'category', 'reason'}:
            raise ValueError('PT-SCHEMA: correction provenance is malformed')
        original = [FunctionMatch.model_validate(item) for item in record['previous_matches']]
        current = next((match for match in candidate.matches if match.id == annotation.target_id), None)
        if (current is None or not current.manual or current.category != record['category']
                or current.reason != record['reason'] or {f.id for f in current.older} != set(record['older_ids'])
                or {f.id for f in current.newer} != set(record['newer_ids'])):
            raise ValueError('PT-SCHEMA: correction no longer describes the active match')
        if not original or annotation.target_id not in {match.id for match in original}:
            raise ValueError('PT-SCHEMA: correction provenance lacks its original relation')
        functions = {func.id: func for match in candidate.matches for func in match.older + match.newer}
        original_ids = set()
        for match in original:
            if match.run_id != current.run_id:
                raise ValueError('PT-SCHEMA: correction provenance crosses analysis runs')
            for side in ('older', 'newer'):
                for func in getattr(match, side):
                    if func.id in original_ids or functions.get(func.id) != func:
                        raise ValueError('PT-SCHEMA: original function ownership/content is no longer current')
                    artifact = next(a for a in candidate.artifacts if a.id == func.artifact_id)
                    if artifact.side != side:
                        raise ValueError('PT-SCHEMA: original function orientation is no longer current')
                    original_ids.add(func.id)
        affected = [match for match in candidate.matches
                    if original_ids.intersection(func.id for func in match.older + match.newer)]
        if {func.id for match in affected for func in match.older + match.newer} != original_ids:
            raise ValueError('PT-SCHEMA: correction intersects another active relation')
        affected_ids = {match.id for match in affected}
        retained = [match for match in candidate.matches if match.id not in affected_ids]
        if {match.id for match in retained}.intersection(match.id for match in original):
            raise ValueError('PT-SCHEMA: restored match identities conflict with current relations')
        self._invalidate(candidate)
        candidate.matches = retained + original
        candidate.annotations.append(AnalystAnnotation(
            target_id=annotation.target_id, kind='validation',
            text=json.dumps({'action': 'restore-match-override', 'annotation_id': annotation_id,
                             'reason': 'Analyst restored the recorded relations before the manual correction'},
                            ensure_ascii=False, sort_keys=True)))
        self._commit(candidate)

    def swap_orientation(self) -> None:
        candidate = self.project.model_copy(deep=True)
        self._invalidate(candidate)
        for artifact in candidate.artifacts:
            artifact.side = 'newer' if artifact.side == 'older' else 'older'
        categories = {'added': 'removed', 'removed': 'added', 'split': 'merged', 'merged': 'split'}
        # Replace each validated relation as a whole: assignment-validation cannot observe a half-swapped match.
        candidate.matches = [match.model_copy(update={'older': match.newer, 'newer': match.older,
                                                     'category': categories.get(match.category, match.category)})
                             for match in candidate.matches]
        self._commit(candidate)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
