"""Desktop investigation orchestration. No Qt, direct sockets or target execution.

Each request contains plain values. Workspace/project stores are opened and closed by
the existing service on this worker's thread; no connection is returned to the GUI.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Literal

from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from ..models import Artifact
from ..persistence import creation_directory_available
from .components import normalise_name
from .contracts import ProductScope
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
    operation: Literal['import', 'search', 'preview', 'create', 'current_inputs', 'plan_sources', 'sync_sources',
                       'candidate_pairs', 'candidate_preview', 'plan_metadata', 'refresh_metadata', 'browse_products']
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
    manual_pair_start: bool = False
    source_months: str = ''
    source_plan_json: str | None = None
    consent_hosts: tuple[str, ...] = ()
    consent_plan: str = ''
    component_name: str = ''
    candidate_pair_id: str | None = None
    expected_candidates_digest: str | None = None
    product_start: bool = False
    product_query: str = ''
    product_scope_json: str | None = None
    product_source_snapshot: tuple[str, ...] | None = None


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


def _source_plan(request: InvestigationRequest, service):
    from .service import parse_lead
    from .sources.net_plan import build_plan

    if request.manual_pair_start:
        raise KbcStoreError('PT-KBC-INPUT', 'Advisory sync requires an explicit KB/CVE starting point.')
    parse_lead(_required(request.lead.strip(), 'a KB or CVE identifier'))
    raw = request.source_months
    if not isinstance(raw, str):
        raise KbcStoreError('PT-KBC-INPUT', 'The advisory month scope must be text.')
    if len(raw) > 4096:
        raise KbcStoreError('PT-KBC-LIMIT', 'The advisory month scope exceeds its limit.')
    _required(raw.strip(), 'advisory months to preview')
    return build_plan([month.strip() for month in raw.split(',') if month.strip()],
                      now_release=service.ports.now()[:7])


def _source_operation(request: InvestigationRequest, cancel, service, source_fetcher) -> InvestigationResult:
    from .sources.cvrf_fetch import fetch_months, to_imported
    from .sources.net_plan import IndexPlan, render_plan, verify_consent

    plan = _source_plan(request, service)
    if request.operation == 'plan_sources':
        text = ('Advisory metadata only. No request has been made.\nHeader: User-Agent: PatchTrace\n'
                + render_plan(plan) + '\n\nExact plan JSON:\n' + plan.model_dump_json(indent=2))
        return InvestigationResult('plan_sources', text, {'plan_json': plan.model_dump_json(),
                                    'plan_sha': plan.plan_sha, 'hosts': plan.hosts})
    raw = _required(request.source_plan_json, 'a current advisory download preview')
    if not isinstance(raw, str):
        raise KbcStoreError('PT-KBC-INPUT', 'The captured advisory plan must be JSON text.')
    if len(raw) > 65536 or len(raw.encode('utf-8')) > 65536:
        raise KbcStoreError('PT-KBC-LIMIT', 'The captured advisory plan exceeds its limit.')
    load_json(raw.encode('utf-8'))  # Reject duplicate keys/non-finite constants before Pydantic's JSON decoder.
    captured = IndexPlan.model_validate_json(raw)
    if captured != plan:
        raise KbcStoreError('PT-KBC-STALE', 'The advisory plan changed; preview it again before consent.')
    verify_consent(plan, consent_hosts=request.consent_hosts, consent_plan=request.consent_plan)
    fetcher = source_fetcher if source_fetcher is not None else fetch_months
    rows, cancelled = [], False
    try:
        for fetched in fetcher(plan, consent_hosts=request.consent_hosts,
                               consent_plan=request.consent_plan, cancel=cancel):
            _checkpoint(cancel)
            row = {'month': fetched.month, 'state': fetched.state}
            if fetched.document is None:
                if fetched.error is not None:
                    row.update(code=fetched.error.code, message=fetched.error.message)
                rows.append(row)
                continue
            try:
                doc = to_imported(fetched.document)
            except SourceError as exc:
                rows.append({'month': fetched.month, 'state': 'failed', 'code': exc.code, 'message': exc.message})
                continue
            _checkpoint(cancel)
            with WorkspaceStore(service.root, clock=service.env.clock) as store:
                added = store.add_document(doc, fetched.document.raw)
            rows.append({'month': fetched.month, 'state': 'added' if added else 'already-present',
                         'sha256': doc.source.sha256, 'document': doc.summary()})
    except (SourceError, KbcStoreError) as exc:
        if exc.code != 'PT-KBC-CANCEL':
            raise
        cancelled = True
    summary = '\n'.join(f'{row["month"]}: {row["state"]}' +
                        (f' ({row["message"]})' if row.get('message') else '') for row in rows)
    data = {'source_months': rows, 'plan_sha': plan.plan_sha, 'requested_months': list(plan.months)}
    if cancelled:
        return InvestigationResult('sync_sources', summary + '\nCancelled. Completed advisory sources are retained.',
                                   data, success=False, error_code='PT-KBC-CANCEL')
    _checkpoint(cancel)
    outcome = service.search(request.lead.strip())
    partial = any(row['state'] not in {'added', 'already-present'} for row in rows)
    text = (summary + ('\nPartial advisory sync; valid stored sources remain available.' if partial else
                       '\nAdvisory sync completed for the displayed months.') + '\n' + outcome.text)
    return InvestigationResult('sync_sources', text, {**outcome.result, **data, 'source_partial': partial},
                               success=outcome.exit in {0, 3, 4},
                               error_code=None if outcome.exit in {0, 3, 4} else 'PT-KBC-INPUT')


class _CandidateFileIndex:
    """One selected-scope operation: keep immutable validated rows for each name the domain resolver reads."""

    def __init__(self, port):
        self._port = port
        self._available = port.available()
        self._captured = {}

    def available(self):
        return self._available

    def rows(self, file_name, version_key):
        if file_name not in self._captured:
            rows, skipped = self._port.rows(file_name, version_key)
            self._captured[file_name] = (version_key, tuple(rows), skipped)
        _, rows, skipped = self._captured[file_name]
        return rows, skipped

    def rows_for(self, file_name, version_key):
        raise KbcStoreError('PT-KBC-UNSUPPORTED', 'A read-only candidate snapshot cannot acquire binaries.')

    def unchanged(self):
        try:
            if self._port.available() != self._available:
                return False
            for name, (key, rows, skipped) in self._captured.items():
                current, current_skipped = self._port.rows(name, key)
                if tuple(current) != rows or current_skipped != skipped:
                    return False
        except (KbcStoreError, OSError, ValueError):
            return False
        return True


def _candidate_owner(service, investigation):
    with WorkspaceStore(service.root, create=False, clock=service.env.clock) as store:
        revision = store.current_revision(investigation)
        if revision is None:
            raise KbcStoreError('PT-KBC-INPUT', 'Search an advisory before inspecting index candidates.')
        return {'revision': revision.revision, 'scope_id': revision.selected_scope_id,
                'lead': {'kind': revision.lead.kind, 'value': revision.lead.value},
                'sources': [source.model_dump(mode='json') for source in store.sources()]}


def _index_claims(rows, sha, version_keys):
    matching = [row for row in rows if row.sha256 == sha and row.build.version_key in version_keys]
    return {'architectures': sorted({row.machine for row in matching}),
            'sizes': sorted({row.size for row in matching}),
            'file_versions': sorted({row.file_version for row in matching if row.file_version}),
            'observed_builds': sorted({row.build.release_version for row in matching if row.build.release_version}),
            'record_sha256': sorted({row.build.record_sha256 for row in matching}),
            'version_keys': sorted({row.build.version_key for row in matching})}


def _candidate_snapshot(request, cancel, service):
    from .contracts import domain_id
    from .service import KbService, parse_lead

    if request.manual_pair_start:
        raise KbcStoreError('PT-KBC-INPUT', 'Saved-index pairing requires an explicit advisory product.')
    investigation = _required(request.investigation_id, 'an advisory search result')
    scope_id = _required(request.scope_id, 'an explicit product')
    name = normalise_name(_required(request.component_name.strip(), 'a component basename'))
    owner = _candidate_owner(service, investigation)
    if parse_lead(request.lead) != (owner['lead']['kind'], owner['lead']['value']):
        raise KbcStoreError('PT-KBC-STALE', 'The identifier differs from the stored advisory investigation.')
    products = service.products(investigation).result
    if products.get('selected_scope_id') != scope_id or owner['scope_id'] != scope_id:
        raise KbcStoreError('PT-KBC-STALE', 'The selected product changed; search and select it again.')
    scope = next((item for item in products['products'] if item['scope_id'] == scope_id), None)
    if scope is None:
        raise KbcStoreError('PT-KBC-STALE', 'The selected product mapping is unavailable; repeat the search.')
    _checkpoint(cancel)
    original_index = service.env.file_index(service.root) if service.env.file_index is not None else None
    snapshot = _CandidateFileIndex(original_index) if original_index is not None else None
    resolver_service = (KbService(service.root, replace(service.env, file_index=lambda _: snapshot))
                        if snapshot is not None else service)
    outcome = resolver_service.pairs(investigation, product=scope_id, files=(name,))
    candidates = [dict(pair) for pair in outcome.result.get('pairs', ()) if pair.get('file_name') == name]
    resolutions = [dict(row) for row in outcome.result.get('resolutions', ()) if row.get('file_name') == name]
    versions = {row['version_key'] for row in resolutions if row.get('version_key')}
    rows = ()
    if candidates and snapshot is not None:
        rows, _ = snapshot.rows(name, '')
    for pair in candidates:
        pair['older_index'] = _index_claims(rows, pair['older_sha256'], versions)
        pair['newer_index'] = _index_claims(rows, pair['newer_sha256'], versions)
    _checkpoint(cancel)
    if snapshot is not None and not snapshot.unchanged():
        raise KbcStoreError('PT-KBC-STALE', 'The saved index changed during candidate inspection; inspect it again.')
    if _candidate_owner(service, investigation) != owner:
        raise KbcStoreError('PT-KBC-STALE', 'The advisory investigation changed during candidate inspection.')
    data = {**outcome.result, 'pairs': candidates, 'resolutions': resolutions,
            'scope': scope, 'component_name': name, 'investigation_revision': owner['revision'],
            'files_without_record': [item for item in outcome.result.get('files_without_record', ()) if item == name],
            'warnings': list(outcome.warnings), 'source': 'Saved Winbindex index claims; bytes unverified.'}
    data['candidates_digest'] = domain_id('kbc.desktop-candidates', 1, {'owner': owner, 'result': data})
    return outcome, data, resolver_service


def _candidate_operation(request, cancel, service):
    outcome, data, resolver_service = _candidate_snapshot(request, cancel, service)
    if request.operation == 'candidate_pairs':
        lines = [f'{pair["grade"]}/{pair["tier"]}  {pair["file_name"]}  {pair["kb"]}  '
                 f'older {pair["older_sha256"][:12]} -> newer {pair["newer_sha256"][:12]}  '
                 f'[{", ".join(pair["reason_codes"]) or "no flags"}]  {pair["pair_id"][:12]}'
                 for pair in data['pairs']]
        lines += [f'{row["file_name"]}  {row["kb"]}: {row["note"]}'
                  for row in data['resolutions'] if row.get('note')]
        lines += [f'{name}: no Winbindex record is saved in this workspace.' for name in data['files_without_record']]
        if not lines:
            lines.append(outcome.text)
        text = ('Saved-index claims only; candidate bytes and architecture are unverified until local inspection.\n'
                'No network request is made. Choose a candidate explicitly; ranking is not proof of a CVE fix.\n'
                + '\n'.join(lines))
        if outcome.warnings:
            text += '\nInvestigation file-index warnings:\n' + '\n'.join(outcome.warnings)
        return InvestigationResult('candidate_pairs', text, data, success=outcome.exit in {0, 3, 4})
    if (request.expected_revision != data['investigation_revision'] or
            request.expected_candidates_digest != data['candidates_digest']):
        raise KbcStoreError('PT-KBC-STALE', 'The candidate sources changed; inspect and select the pair again.')
    pair_id = _required(request.candidate_pair_id, 'an explicit index pair')
    selected = next((pair for pair in data['pairs'] if pair['pair_id'] == pair_id), None)
    if selected is None:
        raise KbcStoreError('PT-KBC-STALE', 'The selected full pair id is not in the current candidate list.')
    preview = resolver_service.plan(request.investigation_id, pair_id=pair_id, product=request.scope_id,
                           files=(data['component_name'],))
    _checkpoint(cancel)
    _, current, _ = _candidate_snapshot(request, cancel, service)
    if current['candidates_digest'] != data['candidates_digest']:
        raise KbcStoreError('PT-KBC-STALE', 'The candidate sources changed during preview; inspect them again.')
    pair = preview.result.get('pair')
    if pair is None or any(pair.get(key) != selected[key] for key in ('pair_id', 'older_sha256', 'newer_sha256')):
        raise KbcStoreError('PT-KBC-STALE', 'The selected index pair changed during preview.')
    text = ('Saved-index claims; candidate bytes and architecture remain unverified.\n'
            'Metadata-only preview. No download consent is granted and no project can be created from this preview.\n'
            + preview.text + '\n\nSelected advisory product scope:\n' + json.dumps(data['scope'], indent=2)
            + '\n\nSelected candidate and source claims:\n' + json.dumps(selected, indent=2))
    return InvestigationResult('candidate_preview', text, {**data, **preview.result, 'selected_candidate': selected},
                               success=preview.exit == 0, error_code=None if preview.exit == 0 else 'PT-KBC-INPUT')


def _metadata_operation(request, cancel, metadata_refresher):
    from .sources.winbindex_fetch import RefreshRequest, build_plan, refresh, render_plan

    if request.manual_pair_start:
        raise KbcStoreError('PT-KBC-INPUT', 'Switch from binary-only mode before requesting index metadata.')
    name = normalise_name(_required(request.component_name, 'a public component basename'))
    if request.operation == 'plan_metadata':
        plan = build_plan(name)
        return InvestigationResult('plan_metadata', render_plan(plan),
                                   {'plan_json': plan.to_json(), 'plan_sha': plan.plan_sha,
                                    'hosts': plan.hosts, 'file_name': plan.file_name})
    asked = RefreshRequest(Path(request.workspace), name,
                           _required(request.source_plan_json, 'a current metadata request preview'),
                           request.consent_hosts, request.consent_plan)
    refresher = metadata_refresher if metadata_refresher is not None else refresh
    receipt = asdict(refresher(asked, cancel))
    text = ('Saved third-party Winbindex metadata. No binary was downloaded or executed.\n'
            'TLS origin and raw SHA-256 do not establish Microsoft authorship or a CVE fix.\n'
            + json.dumps(receipt, indent=2) +
            '\nSelect the advisory product, then inspect saved index candidates explicitly.')
    # The refresher retains a completed publication even if cancellation arrives after its commit.
    return InvestigationResult('refresh_metadata', text, {'metadata': receipt, 'file_name': name})


def _product_selection(request: InvestigationRequest) -> ProductScope:
    raw = _required(request.product_scope_json, 'a product from the current local listing')
    if not isinstance(raw, str) or len(raw) > 65536 or len(raw.encode('utf-8')) > 65536:
        raise KbcStoreError('PT-KBC-INPUT', 'The captured product record exceeds its input limit.')
    load_json(raw.encode('utf-8'))
    product = ProductScope.model_validate_json(raw)
    if product.scope_id != _required(request.scope_id, 'an explicit product'):
        raise KbcStoreError('PT-KBC-STALE', 'The chosen product differs from the captured product record.')
    snapshot = request.product_source_snapshot
    if type(snapshot) is not tuple or not snapshot or not all(isinstance(source, str) for source in snapshot):
        raise KbcStoreError('PT-KBC-INPUT', 'List local products again to capture their source records.')
    return product


def _check_start_mode(request: InvestigationRequest) -> None:
    if request.product_start:
        if (request.manual_pair_start or request.investigation_id is not None or request.expected_revision is not None
                or request.operation not in {'import', 'browse_products', 'preview', 'create', 'current_inputs'}):
            raise KbcStoreError('PT-KBC-INPUT', 'Product-only mode uses a fresh local pair without KB/CVE or download requests.')
    elif (request.operation == 'browse_products' or request.product_scope_json is not None
          or request.product_source_snapshot is not None):
        raise KbcStoreError('PT-KBC-INPUT', 'A captured product listing belongs only to an explicit product start.')


def _execute(request: InvestigationRequest, cancel, service_factory, source_fetcher, metadata_refresher) -> InvestigationResult:
    _checkpoint(cancel)
    _check_start_mode(request)
    if request.operation in {'plan_metadata', 'refresh_metadata'}:
        return _metadata_operation(request, cancel, metadata_refresher)
    if request.manual_pair_start and (request.investigation_id is not None or request.scope_id is not None
                                      or request.expected_revision is not None):
        raise KbcStoreError('PT-KBC-INPUT', 'A binary-only start cannot reuse an advisory investigation or product.')
    origin = None
    if request.current_inputs is not None:
        paths, origin = _verified_current(request.current_inputs, cancel)
        if request.operation == 'current_inputs':
            next_step = ('Preview the binary-only pair before creating a project.' if request.manual_pair_start else
                         'Choose a stored product and preview the pair before creating a project.' if request.product_start else
                         'Choose advisory scope and preview the pair before creating a project.')
            return InvestigationResult('current_inputs', 'Current project copies verified. ' + next_step,
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
    if request.operation == 'browse_products':
        outcome = service.product_catalogue(request.product_query, cancel=cancel)
        _checkpoint(cancel)
        return InvestigationResult('browse_products', outcome.text, outcome.result)
    if request.operation in {'candidate_pairs', 'candidate_preview'}:
        return _candidate_operation(request, cancel, service)
    if request.operation in {'plan_sources', 'sync_sources'}:
        return _source_operation(request, cancel, service, source_fetcher)
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
        selected_product = _product_selection(request) if request.product_start else None
        if request.manual_pair_start or request.product_start:
            inv = 'new'
        else:
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
            if not request.manual_pair_start and not request.product_start:
                _required(request.expected_revision, 'a current investigation revision')
        _checkpoint(cancel)
        try:
            outcome = service.import_pair(inv, old, new, str(destination), name=request.name or None,
                                          confirm_same_component=request.confirm_same_component,
                                          dry_run=request.operation == 'preview',
                                          expected_pair_id=request.expected_pair_id,
                                          **({'selected_product': selected_product,
                                              'expected_source_snapshot': request.product_source_snapshot}
                                             if selected_product is not None else {}),
                                          **({'expected_revision': request.expected_revision}
                                             if request.operation == 'create' else {}))
            if selected_product is not None:
                outcome.text = ('Analyst-selected product scope; binary membership remains unverified and '
                                'no KB/CVE attribution is inferred.\n' + outcome.text)
                if request.operation == 'preview':
                    outcome.text += '\n\nSelected product and source identities:\n' + selected_product.model_dump_json(indent=2)
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


def execute_request(request: InvestigationRequest, cancel, *, service_factory=None, source_fetcher=None,
                    metadata_refresher=None) -> InvestigationResult:
    """Run one explicit operation; source transport remains outside the UI and domain errors are plain data."""
    try:
        return _execute(request, cancel, service_factory, source_fetcher, metadata_refresher)
    except (KbcStoreError, SourceError) as exc:
        return InvestigationResult(request.operation, exc.message, success=False, error_code=exc.code)
    except (OSError, ValueError) as exc:
        # Fixed failures remain actionable without exposing arbitrary parser text.
        code = getattr(exc, 'code', 'PT-KBC-INPUT')
        message = getattr(exc, 'message', 'The local input could not be read or validated; previous results remain.')
        return InvestigationResult(request.operation, message, success=False, error_code=code)
