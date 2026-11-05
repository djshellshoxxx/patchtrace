"""Local-only desktop investigation operations. No Qt, sockets or target execution.

Each request contains plain values. Workspace/project stores are opened and closed by
the existing service on this worker's thread; no connection is returned to the GUI.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from ..models import Artifact
from ..persistence import creation_directory_available
from .components import normalise_name
from .sources.cvrf import SourceError, load_json
from .store import KbcStoreError, WorkspaceStore


@dataclass(frozen=True, slots=True)
class CurrentProjectInputs:
    project_id: str
    revision: int
    root: Path
    older_json: str
    newer_json: str


@dataclass(frozen=True, slots=True)
class InvestigationRequest:
    operation: Literal['import', 'search', 'preview', 'create', 'current_inputs']
    workspace: Path
    source: Path | None = None
    lead: str = ''
    investigation_id: str | None = None
    scope_id: str | None = None
    older: Path | None = None
    newer: Path | None = None
    destination: Path | None = None
    name: str = ''
    expected_pair_id: str | None = None
    expected_revision: int | None = None
    current_project: Path | None = None
    confirm_same_component: bool = False
    current_inputs: CurrentProjectInputs | None = None


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    operation: str
    text: str
    data: dict = field(default_factory=dict)
    project_path: Path | None = None
    success: bool = True
    error_code: str | None = None


def _checkpoint(cancel) -> None:
    if cancel.is_set():
        raise KbcStoreError('PT-KBC-CANCEL', 'The local operation was cancelled before its next commit.')


def _required(value, label):
    if value is None or value == '':
        raise KbcStoreError('PT-KBC-INPUT', f'Choose {label} before continuing.')
    return value


def _new_destination(request: InvestigationRequest) -> Path:
    path = Path(_required(request.destination, 'a new project directory')).expanduser()
    if path.is_symlink():
        raise KbcStoreError('PT-KBC-INPUT', 'Choose a new project directory, not a symbolic link.')
    resolved = path.resolve()
    if request.current_project is not None and resolved.is_relative_to(request.current_project.resolve()):
        raise KbcStoreError('PT-KBC-INPUT', 'Choose a new directory outside the currently open project.')
    if not creation_directory_available(path):
        raise KbcStoreError('PT-KBC-INPUT', 'The project destination must be new or empty; existing data is retained.')
    return resolved


def _verified_current(snapshot: CurrentProjectInputs, cancel) -> tuple[tuple[Path, Path], dict]:
    artifacts, hints = [], []
    root = snapshot.root.resolve()
    for side, raw in (('older', snapshot.older_json), ('newer', snapshot.newer_json)):
        _checkpoint(cancel)
        if len(raw) > 16384:
            raise KbcStoreError('PT-KBC-INPUT', 'The captured artifact record exceeds the local input limit.')
        encoded = raw.encode('utf-8')
        if len(encoded) > 16384:
            raise KbcStoreError('PT-KBC-INPUT', 'The captured artifact record exceeds the local input limit.')
        artifact = Artifact.model_validate(load_json(encoded))
        if artifact.side != side or artifact.relative_path != f'artifacts/{artifact.sha256}.bin':
            raise KbcStoreError('PT-KBC-INPUT', 'The captured artifact does not match its project input side/path.')
        try:
            with VerifiedArtifactReader.open_artifact(artifact, root, cancel=cancel.is_set):
                pass
        except ArtifactBytesError as exc:
            raise KbcStoreError('PT-KBC-VERIFY',
                                f'The current project {side} input could not be verified ({exc.code}).') from None
        try:
            hints.append(normalise_name(artifact.name))
        except ValueError:
            raise KbcStoreError('PT-KBC-UNSUPPORTED', 'The current project has unsupported original input names. '
                                'This route requires original .sys, .dll or .exe basenames.') from None
        artifacts.append(artifact)
    older, newer = artifacts
    if older.id == newer.id:
        raise KbcStoreError('PT-KBC-INPUT', 'The captured project inputs must have distinct artifact records.')
    paths = (root / older.relative_path, root / newer.relative_path)
    if paths[0] == paths[1] and hints[0] != hints[1]:
        raise KbcStoreError('PT-KBC-UNSUPPORTED', 'The same stored input has conflicting original component names. '
                            'This route cannot choose one role label implicitly.')
    origin = {'project_id': snapshot.project_id, 'revision': snapshot.revision,
              'older_artifact_id': older.id, 'newer_artifact_id': newer.id,
              'older_name': older.name, 'newer_name': newer.name,
              'older_sha256': older.sha256, 'newer_sha256': newer.sha256,
              'older_size': older.size, 'newer_size': newer.size,
              'status': 'Preview-only input origin; original names are manual hints, not PE OriginalFilename authority. '
                        'Source annotations and CVE linkage are not carried over.'}
    return paths, origin


def _execute(request: InvestigationRequest, cancel, service_factory) -> InvestigationResult:
    _checkpoint(cancel)
    origin = None
    if request.current_inputs is not None:
        paths, origin = _verified_current(request.current_inputs, cancel)
        if request.operation == 'current_inputs':
            return InvestigationResult('current_inputs', 'Current project copies verified. '
                                       'Choose advisory scope and preview the pair before creating a project.',
                                       {'older': str(paths[0]), 'newer': str(paths[1]), 'input_origin': origin})
        if request.operation in {'preview', 'create'} and (request.older is None or request.newer is None or
                (request.older.resolve(), request.newer.resolve()) != paths):
            raise KbcStoreError('PT-KBC-STALE', 'The selected inputs differ from the captured current project.')
    elif request.operation == 'current_inputs':
        raise KbcStoreError('PT-KBC-INPUT', 'Open a project before using its input copies.')
    if origin is not None and request.operation in {'preview', 'create'} and not request.confirm_same_component:
        raise KbcStoreError('PT-KBC-INPUT', 'Explicitly confirm the current inputs are the same component before preview.')
    if service_factory is None:
        from .wiring import build_service
        service_factory = build_service
    service = service_factory(Path(request.workspace))
    if request.operation == 'create':
        from .service import KbService
        from .wiring import new_project_factory

        service = KbService(service.root, replace(service.env, project=new_project_factory))
    if origin is not None:
        from .service import KbService
        from .wiring import inspect_local_file

        expected = {path: (origin[f'{side}_sha256'], origin[f'{side}_size'], normalise_name(origin[f'{side}_name']))
                    for side, path in zip(('older', 'newer'), paths, strict=True)}
        # Re-read the exact bound paths. Do not let verification/inspection changes become a new pair.
        def inspect_current(path):
            _checkpoint(cancel)
            resolved = Path(path).resolve()
            if resolved not in expected:
                raise KbcStoreError('PT-KBC-STALE', 'The inspected path is outside the captured current pair.')
            expected_sha, expected_size, name = expected[resolved]
            observed = inspect_local_file(path, basename=name)
            if (observed.sha256, observed.size) != (expected_sha, expected_size):
                raise KbcStoreError('PT-KBC-STALE', 'The current input changed before pair inspection.')
            return observed

        service = KbService(service.root, replace(service.env, inspect=inspect_current))
    if request.operation == 'import':
        from .cli_index import plain_bytes, read_input_file
        from .sources.importer import import_bytes

        source = Path(_required(request.source, 'a local advisory file'))
        raw = plain_bytes(read_input_file(source))
        doc = import_bytes(raw, now=service.ports.now(), advisory=service.ports.advisory)
        _checkpoint(cancel)
        with WorkspaceStore(service.root, clock=service.env.clock) as store:
            added = store.add_document(doc, raw)
        return InvestigationResult('import', 'Local advisory imported.' if added else 'Local advisory already stored.',
                                   {'document': doc.summary(), 'already_present': not added})
    if request.operation == 'search':
        outcome = service.search(_required(request.lead.strip(), 'a KB or CVE identifier'),
                                 product=request.scope_id, investigation=request.investigation_id)
    elif request.operation in {'preview', 'create'}:
        inv = _required(request.investigation_id, 'a search result')
        scope = _required(request.scope_id, 'an explicit product')
        with WorkspaceStore(service.root, create=False, clock=service.env.clock) as store:
            revision = store.current_revision(inv)
            if revision is not None and revision.state in {
                    'PROJECT_CREATED', 'CONTEXT_PENDING', 'CONTEXT_ATTACHED', 'COMPARISON_PENDING',
                    'ANALYZED', 'CORRELATED', 'CORRELATED_PARTIAL'}:
                raise KbcStoreError('PT-KBC-STATE', 'This investigation already has a project. '
                                    'Use Search locally to start a new investigation before choosing another pair.')
        selected = service.products(inv).result.get('selected_scope_id')
        if selected != scope:
            raise KbcStoreError('PT-KBC-STALE', 'The selected product changed; search and select it again.')
        old = str(_required(request.older, 'the older local binary'))
        new = str(_required(request.newer, 'the newer local binary'))
        destination = _new_destination(request) if request.operation == 'create' else request.destination or Path('.')
        if request.operation == 'create':
            _required(request.expected_pair_id, 'a current pair preview')
            _required(request.expected_revision, 'a current investigation revision')
        _checkpoint(cancel)
        try:
            outcome = service.import_pair(inv, old, new, str(destination), name=request.name or None,
                                          confirm_same_component=request.confirm_same_component,
                                          dry_run=request.operation == 'preview',
                                          expected_pair_id=request.expected_pair_id,
                                          **({'expected_revision': request.expected_revision}
                                             if request.operation == 'create' else {}))
            if origin is not None:
                pair = outcome.result.get('pair', {})
                if (pair.get('older_sha256'), pair.get('newer_sha256')) != (
                        origin['older_sha256'], origin['newer_sha256']):
                    raise KbcStoreError('PT-KBC-STALE', 'The inspected pair differs from the current project snapshot.')
                outcome.result['input_origin'] = origin
        except Exception as exc:
            if request.operation == 'create' and (destination / 'project.sqlite3').is_file():
                return InvestigationResult('create', 'Local creation stopped after project files were written. '
                                           'The directory is retained; inspect it before retrying.',
                                           project_path=destination, success=False,
                                           error_code=getattr(exc, 'code', 'PT-KBC-STORAGE'))
            raise
        # Once the service starts a local commit, cancellation cannot undo it. Return
        # any created path so the controller can retain/report it instead of adopting.
        if request.operation == 'create' and outcome.result.get('project'):
            return InvestigationResult('create', outcome.text, outcome.result, Path(destination),
                                       success=outcome.exit == 0,
                                       error_code=None if outcome.exit == 0 else 'PT-KBC-PARTIAL')
    else:
        raise KbcStoreError('PT-KBC-INPUT', 'Unknown local investigation operation.')
    return InvestigationResult(request.operation, outcome.text, outcome.result,
                               success=outcome.exit in {0, 3, 4} if request.operation == 'search' else outcome.exit == 0,
                               error_code=None if outcome.exit in {0, 3, 4} else 'PT-KBC-INPUT')


def execute_request(request: InvestigationRequest, cancel, *, service_factory=None) -> InvestigationResult:
    """Run one offline operation; domain errors are plain result data for the GUI."""
    try:
        return _execute(request, cancel, service_factory)
    except (KbcStoreError, SourceError) as exc:
        return InvestigationResult(request.operation, exc.message, success=False, error_code=exc.code)
    except (OSError, ValueError) as exc:
        # Fixed failures remain actionable without exposing arbitrary parser text.
        code = getattr(exc, 'code', 'PT-KBC-INPUT')
        message = getattr(exc, 'message', 'The local input could not be read or validated; previous results remain.')
        return InvestigationResult(request.operation, message, success=False, error_code=code)
