"""Composition root of the KB-CVE correlator (KB-integration-plan section 9; slice K3).

The only ``kbcorrelation`` module that imports sibling packages (``intelligence``, ``service``, ``enrichment``). It binds
the Protocol ports of ``ports.py`` and ``context.py`` and builds the :class:`~.service.KbService`. No Qt.

``RealProjectPort`` is the production ``ProjectPort``. Resume depends on two of its properties: ``create_project``
returns the *existing* project when the directory already holds one (the attachment then compares the bytes), and a
project id resolves to its directory through a registry (in memory, backed by the workspace journal) so a repair in a
new process can still write rows.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .card_provenance import FIELDS, CardFactRef
from .components import normalise_name
from .contracts import Arch, CveCard
from .lineage import IndexRow, index_rows
from .pairs import LocalFile
from .service import Env, KbService
from .store import Fault, KbcStoreError, SystemClock, WorkspaceStore

INDEX_DIR = 'winbindex'
INDEX_RECORD = re.compile(r'(?P<name>[a-z0-9._-]+)@(?P<date>\d{4}-\d{2}-\d{2})\.json(?P<gz>\.gz)?')
MACHINES: dict[int, Arch] = {0x8664: 'amd64', 0xAA64: 'arm64', 0x14C: 'x86'}
HEADER_BYTES = 4096


class WorkspaceFileIndex:
    """``IndexPort`` over Winbindex records saved in the offline workspace as ``winbindex/<name>@YYYY-MM-DD.json[.gz]``
    (the date is the record's data date; the newest record of a name wins). Never fetches."""

    def __init__(self, root: Path):
        self.directory = Path(root) / INDEX_DIR
        self._skipped: dict[str, int] = {}

    def _record(self, file_name: str) -> tuple[Path, str, bool] | None:
        found = []
        if self.directory.is_dir():
            for path in self.directory.iterdir():
                match = INDEX_RECORD.fullmatch(path.name)
                if match and match['name'] == file_name and path.is_file():
                    found.append((match['date'], path, bool(match['gz'])))
        if not found:
            return None
        date, path, gz = max(found, key=lambda f: f[0])
        return path, date, gz

    def available(self) -> bool:
        return self.directory.is_dir() and any(INDEX_RECORD.fullmatch(p.name) for p in self.directory.iterdir())

    def rows_for(self, file_name: str, winbindex_key: str) -> list[dict]:
        """Every row of the file's record; ``winbindex_key`` is applied later by ``lineage.timeline`` because shared
        rows are copied between keys. A missing record is no rows."""
        from ..acquisition.contracts import AcquisitionError
        from ..acquisition.winbindex import MAX_COMPRESSED, parse_rows
        found = self._record(file_name)
        if found is None:
            return []
        path, date, compressed = found
        try:
            if path.stat().st_size > MAX_COMPRESSED:
                raise KbcStoreError('PT-KBC-LIMIT', 'a Winbindex record in the workspace exceeds its size limit')
            parsed = parse_rows(path.read_bytes(), file_name, date, compressed=compressed)
        except OSError:
            raise KbcStoreError('PT-KBC-INPUT', 'a Winbindex record in the workspace cannot be read') from None
        except AcquisitionError as exc:
            raise KbcStoreError('PT-KBC-SOURCE', f'a Winbindex record in the workspace is unusable: {exc.message}'
                                ) from None
        self._skipped[file_name] = parsed.skipped
        return [row.as_mapping() for row in parsed.rows]

    def has_record(self, file_name: str) -> bool:
        return self._record(file_name) is not None

    def rows(self, file_name: str, winbindex_key: str) -> tuple[tuple[IndexRow, ...], int]:
        """Index rows and the number of index entries that could not become rows (a gap in coverage)."""
        mappings = self.rows_for(file_name, winbindex_key)
        rows, rejected = index_rows(mappings, file_name=file_name)
        return rows, self._skipped.get(file_name, 0) + rejected


def save_winbindex_record(root: Path, source: Path, file_name: str, data_date: str) -> dict:
    """Validate one Winbindex record file and store it as ``winbindex/<name>@<date>.json[.gz]`` for the file index.

    Nothing is written unless ``parse_rows`` accepts it within its size bounds; a record of the same name and date is
    replaced (the same record or a corrected one). The file is data and is never executed.
    """
    from ..acquisition.contracts import AcquisitionError
    from ..acquisition.winbindex import MAX_COMPRESSED, parse_rows
    name = normalise_file(file_name)
    try:
        with open(source, 'rb') as handle:
            raw = handle.read(MAX_COMPRESSED + 1)
    except OSError:
        raise KbcStoreError('PT-KBC-INPUT', 'the Winbindex record cannot be read') from None
    if len(raw) > MAX_COMPRESSED:
        raise KbcStoreError('PT-KBC-LIMIT', 'the Winbindex record exceeds its size limit')
    gz = raw[:2] == b'\x1f\x8b'
    try:
        parsed = parse_rows(raw, name, data_date, compressed=gz)
    except AcquisitionError as exc:
        code = 'PT-KBC-LIMIT' if exc.code == 'PT-ACQ-LIMIT' else 'PT-KBC-INPUT'
        raise KbcStoreError(code, f'the file is not a usable Winbindex record: {exc.message}') from None
    if not parsed.rows:
        raise KbcStoreError('PT-KBC-INPUT', 'the Winbindex record has no usable build rows')
    target = Path(root) / INDEX_DIR / f'{name}@{data_date}.json{".gz" if gz else ""}'
    other = target.with_name(target.name[:-3] if gz else target.name + '.gz')
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        replaced = target.is_file() or other.is_file()
        staging = target.with_name(target.name + '.tmp')
        staging.write_bytes(raw)
        staging.replace(target)
        other.unlink(missing_ok=True)  # one record per name and date, in either form
    except OSError:
        raise KbcStoreError('PT-KBC-STORAGE', 'the workspace cannot be written') from None
    return {'file_name': name, 'data_date': data_date, 'stored_as': f'{INDEX_DIR}/{target.name}',
            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'rows': len(parsed.rows),
            'skipped': parsed.skipped, 'warnings': list(parsed.warnings), 'replaced': replaced}


class IntelligenceAdvisory:
    """``AdvisoryPort`` over the offline CSAF validator and normaliser of ``intelligence``."""

    def parse_csaf(self, raw: bytes, *, source_sha256: str) -> Mapping[str, Any]:
        from ..intelligence.csaf.normalize import normalize
        from ..intelligence.csaf.validate import load_document
        document, report = load_document(raw)
        return normalize(document, report, source_sha256).model_dump(mode='json')

    def report_for(self, cve, facts, older_sha256, newer_sha256) -> Mapping[str, Any]:
        raise KbcStoreError('PT-KBC-UNSUPPORTED', 'a CSAF applicability report is not built by this slice')


class IntelligenceRules:
    """Vendor-stated CWE -> curated hypothesis, through the reused ``intelligence`` lexicon and rules."""

    def __init__(self) -> None:
        from ..intelligence import hypotheses, lexicon
        self.rules_digest = hypotheses.rules_digest()
        self.lexicon_digest = lexicon.lexicon_digest()

    def interpret(self, card: CveCard, facts: tuple[CardFactRef, ...]):
        """Classify each agreeing source on its own; the bundle maps every output pointer to its raw source."""
        from ..intelligence.contracts import CVEFact, CweRef, Note
        from ..intelligence.hypotheses import hypotheses_for
        from ..intelligence.lexicon import classify
        grouped: dict[str, list[CardFactRef]] = {}
        for ref in facts:
            if ref.cve != card.cve or ref.source_kind != card.source_kind or ref.value != getattr(card, ref.field):
                raise ValueError('interpretation field does not match its card')
            grouped.setdefault(ref.doc_id, []).append(ref)
        profiles = []
        for _, refs in sorted(grouped.items()):
            by_field = {field: sorted((r for r in refs if r.field == field), key=lambda r: r.pointer)
                        for field in FIELDS}
            if len({r.source_sha256 for r in refs}) != 1 or any(
                    getattr(card, field) is not None and not by_field[field] for field in FIELDS):
                raise ValueError('each interpreted source needs every displayed field')
            cve_ref = by_field['cve'][0]
            cwe_refs = by_field['stated_cwe']
            cwe = CweRef(id=card.stated_cwe, name=card.stated_cwe, pointer=cwe_refs[0].pointer) if cwe_refs else None
            # The classifier's title convenience field invents a lowercase /title suffix. An explicitly
            # located description carries identical text semantics while preserving native JSON casing.
            notes = tuple(Note(category='description', text=r.value, pointer=r.pointer) for r in by_field['title'])
            fact = CVEFact(source_id=cve_ref.source_sha256, cve=card.cve,
                           pointer=cve_ref.pointer.rsplit('/', 1)[0], notes=notes, cwe=cwe)
            profile = classify(fact, explicit_basis=('explicit-csaf-cwe' if card.source_kind == 'csaf'
                                                    else 'explicit-advisory-cwe'))
            if cwe_refs:
                profile = profile.model_copy(update={'classifications': tuple(
                    item.model_copy(update={'pointers': tuple(sorted(set(item.pointers) |
                                                                 {r.pointer for r in cwe_refs}))})
                    if item.basis.startswith('explicit-') else item for item in profile.classifications)})
            profiles.append(profile)
        if not profiles:
            raise ValueError('interpretation requires source-bound card fields')
        profile = _merge_profiles(profiles)
        return profile, hypotheses_for(profile)


def _merge_profiles(profiles):
    """All values agreed before classification; combine references without counting sources as votes."""
    groups = {}
    for profile in profiles:
        for item in profile.classifications:
            key = item.cwe_id, item.family, item.basis, item.confidence, item.assessment
            groups.setdefault(key, []).append(item)
    def hits(items):
        return tuple(sorted(set(items), key=lambda h: (h.pointer, h.term_id, h.phrase, h.excerpt, h.negated)))
    classifications = [items[0].model_copy(update={
        'pointers': tuple(sorted({p for item in items for p in item.pointers})),
        'hits': hits(h for item in items for h in item.hits)}) for items in groups.values()]
    return profiles[0].model_copy(update={
        'classifications': tuple(sorted(classifications,
                                        key=lambda c: (('explicit', 'phrase-match', 'weak').index(c.confidence), c.cwe_id))),
        'negated_hits': hits(h for p in profiles for h in p.negated_hits),
        'effect_hits': hits(h for p in profiles for h in p.effect_hits),
        'disagreements': tuple(sorted({d for p in profiles for d in p.disagreements})),
        'limitations': tuple(sorted({d for p in profiles for d in p.limitations}))})


def inspect_local_file(path: str, *, basename: str | None = None) -> LocalFile:
    """Inspect bytes, using an explicit captured Artifact name only as a manual basename hint.

    The optional name is not PE OriginalFilename authority; ordinary local/CLI callers use the path name.
    """
    target = Path(path)
    digest = hashlib.sha256()
    head = b''
    size = 0
    try:
        with open(target, 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                if not head:
                    head = block[:HEADER_BYTES]
                digest.update(block)
                size += len(block)
    except OSError:
        raise KbcStoreError('PT-KBC-INPUT', 'an input file cannot be read') from None
    return LocalFile(sha256=digest.hexdigest(), size=size, basename=normalise_file(target.name if basename is None else basename),
                     machine=_machine(head))


def normalise_file(name: str) -> str:
    try:
        return normalise_name(name)
    except ValueError as exc:
        raise KbcStoreError('PT-KBC-INPUT', str(exc)) from None


def _machine(head: bytes) -> Arch:
    if head[:2] != b'MZ' or len(head) < 0x40:
        raise KbcStoreError('PT-KBC-INPUT', 'an input file is not a PE file')
    offset = struct.unpack_from('<I', head, 0x3C)[0]
    if offset + 6 > len(head) or head[offset:offset + 4] != b'PE\0\0':
        raise KbcStoreError('PT-KBC-INPUT', 'an input file is not a PE file')
    return MACHINES.get(struct.unpack_from('<H', head, offset + 4)[0], 'unknown')


class RealProjectPort:
    """``ProjectPort`` over ``ProjectService`` and ``EnrichmentStore`` (the project store stays single-owner: every
    call opens, uses and closes it)."""

    def __init__(self, workspace: WorkspaceStore | None = None, name: str = 'KB comparison', *,
                 reuse_existing: bool = True):
        self.name = name
        self.reuse_existing = reuse_existing
        self._dirs: dict[str, Path] = {}
        self._workspace = workspace

    def _directory(self, project_id: str) -> Path:
        found = self._dirs.get(project_id)
        if found is None and self._workspace is not None:
            found = next((Path(b['directory']) for _, _, b in self._workspace.journal_ops()
                          if b.get('project_id') == project_id), None)
        if found is None:
            raise KbcStoreError('PT-KBC-STATE', 'the project directory for this project id is not known')
        return found

    def create_project(self, older_path: str, newer_path: str, *, directory: str) -> Mapping[str, Any]:
        from ..service import ProjectService
        root = Path(directory)
        if self.reuse_existing and (root / 'project.sqlite3').is_file():
            service = ProjectService.open(root, maintenance=False)
        else:
            service = ProjectService.create(Path(older_path), Path(newer_path), self.name, root)
        try:
            side = {a.side: a.sha256 for a in service.project.artifacts}
            project_id = service.store.project_id
            self._dirs[project_id] = root
            return {'project_id': project_id, 'revision': service.project.revision,
                    'older_sha256': side['older'], 'newer_sha256': side['newer']}
        finally:
            service.close()

    def open_project(self, directory: str) -> str:
        from ..service import ProjectService
        try:
            service = ProjectService.open(Path(directory), maintenance=False)
        except Exception:
            raise KbcStoreError('PT-KBC-STORAGE', 'the project cannot be opened') from None
        try:
            project_id = service.store.project_id
            self._dirs[project_id] = Path(directory)
            return project_id
        finally:
            service.close()

    def put_row(self, project_id: str, kind: str, key: str, body: bytes) -> None:
        from ..enrichment.storage import EnrichmentStore, Guard
        from ..service import ProjectService
        service = ProjectService.open(self._directory(project_id), maintenance=False)
        try:
            guard = Guard(project_id, 'kb', hashlib.sha256(body).hexdigest(), f'{kind}:{key}')
            EnrichmentStore(service.store).publish(kind, guard, guard, service.project.revision, 'ok',
                                                   json.loads(body), f'{kind}:{key}')
        finally:
            service.close()

    def list_rows(self, project_id: str, kind: str) -> dict[str, bytes]:
        from ..enrichment.storage import EnrichmentStore
        from ..service import ProjectService
        service = ProjectService.open(self._directory(project_id), maintenance=False)
        try:
            prefix = f'{kind}:'
            return {e.id[len(prefix):]: json.dumps(e.body, sort_keys=True).encode()
                    for e in EnrichmentStore(service.store).entries(kind) if e.id.startswith(prefix)}
        finally:
            service.close()

    def get_row(self, project_id: str, kind: str, key: str) -> bytes | None:
        return self.list_rows(project_id, kind).get(key)


def escape_markdown(text: str) -> str:
    from ..intelligence.reports import escape_md
    return escape_md(text)


def _project_factory(workspace: WorkspaceStore | None, name: str) -> RealProjectPort:
    return RealProjectPort(workspace, name)


def new_project_factory(workspace: WorkspaceStore | None, name: str) -> RealProjectPort:
    """Desktop create-only route; ProjectService.create refuses a concurrently existing database.

    The normal CLI factory retains its journal-resume behavior.
    """
    return RealProjectPort(workspace, name, reuse_existing=False)


def build_env(*, clock=None, fault: Fault | None = None, advisory=None, acquirer=None) -> Env:
    """The production ports; ``clock``, ``fault`` (a crash-point seam) and ``acquirer`` (a fake transport) exist for
    tests. The default ``Acquirer`` opens a socket only inside a consented ``kb acquire``."""
    from ..acquisition.workflow import Acquirer
    return Env(advisory=advisory or IntelligenceAdvisory(), clock=clock or SystemClock(), rules=IntelligenceRules(),
               inspect=inspect_local_file, escape=escape_markdown, project=_project_factory, fault=fault,
               file_index=WorkspaceFileIndex,
               acquirer=acquirer or Acquirer(), winbindex_import=save_winbindex_record)


def build_service(workspace: Path, **options) -> KbService:
    return KbService(Path(workspace), build_env(**options))
