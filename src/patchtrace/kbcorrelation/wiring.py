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
import struct
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .components import normalise_name
from .contracts import Arch, CveCard
from .pairs import LocalFile
from .service import Env, KbService
from .store import Fault, KbcStoreError, SystemClock, WorkspaceStore

MACHINES: dict[int, Arch] = {0x8664: 'amd64', 0xAA64: 'arm64', 0x14C: 'x86'}
HEADER_BYTES = 4096


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

    def interpret(self, card: CveCard, pointer: str, source_sha256: str):
        from ..intelligence.contracts import CVEFact, CweRef
        from ..intelligence.hypotheses import hypotheses_for
        from ..intelligence.lexicon import classify
        cwe = CweRef(id=card.stated_cwe, name=card.stated_cwe, pointer=f'{pointer}/cwe') if card.stated_cwe else None
        fact = CVEFact(source_id=source_sha256, cve=card.cve, pointer=pointer, title=card.title, cwe=cwe)
        profile = classify(fact)
        return profile, hypotheses_for(profile)


def inspect_local_file(path: str) -> LocalFile:
    """Hash a file and read its PE machine from the header bytes; the file is never executed or loaded."""
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
    return LocalFile(sha256=digest.hexdigest(), size=size, basename=normalise_file(target.name),
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

    def __init__(self, workspace: WorkspaceStore | None = None, name: str = 'KB comparison'):
        self.name = name
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
        if (root / 'project.sqlite3').is_file():
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


def build_env(*, clock=None, fault: Fault | None = None, advisory=None) -> Env:
    """The production ports; ``clock`` and ``fault`` (a crash-point seam) exist for tests."""
    return Env(advisory=advisory or IntelligenceAdvisory(), clock=clock or SystemClock(), rules=IntelligenceRules(),
               inspect=inspect_local_file, escape=escape_markdown, project=_project_factory, fault=fault)


def build_service(workspace: Path, **options) -> KbService:
    return KbService(Path(workspace), build_env(**options))
