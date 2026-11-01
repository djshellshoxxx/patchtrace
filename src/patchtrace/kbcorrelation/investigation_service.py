"""Local-only desktop investigation operations. No Qt, sockets or target execution.

Each request contains plain values. Workspace/project stores are opened and closed by
the existing service on this worker's thread; no connection is returned to the GUI.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from .sources.cvrf import SourceError
from .store import KbcStoreError, WorkspaceStore


@dataclass(frozen=True, slots=True)
class InvestigationRequest:
    operation: Literal['import', 'search', 'preview', 'create']
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
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise KbcStoreError('PT-KBC-INPUT', 'The project destination must be new or empty; existing data is retained.')
    return resolved


def _execute(request: InvestigationRequest, cancel, service_factory) -> InvestigationResult:
    _checkpoint(cancel)
    if service_factory is None:
        from .wiring import build_service
        service_factory = build_service
    service = service_factory(Path(request.workspace))
    if request.operation == 'create':
        from .service import KbService
        from .wiring import new_project_factory

        service = KbService(service.root, replace(service.env, project=new_project_factory))
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
                                          cancel=cancel.is_set,
                                          **({'expected_revision': request.expected_revision}
                                             if request.operation == 'create' else {}))
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
