"""Group `pe:<side>`: imports, exports and build facts of one verified artifact copy (WB1 section 7).

Everything read from the file is untrusted text: it is escaped by the segment builder, and the COFF timestamp is
labelled untrusted because the build can forge or randomise it.
"""
from __future__ import annotations

import threading
from collections.abc import Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.models import Artifact
from patchtrace.pe_overview.inspect import inspect_pe
from patchtrace.pe_overview.models import PeOverview
from patchtrace.search.errors import SearchError
from patchtrace.search.segment import SegmentDoc
from patchtrace.search.sources.base import SourceSpec, name_fields

KINDS = ('import', 'export', 'build')
TABLE_SETS = ('name', 'text')
PE_INPUTS_VERSION = 1


class PeLoader:
    """Parses each side's artifact at most once per build request; a failure reads as None (unknown)."""

    def __init__(self, root: Path, artifacts: dict[str, Artifact]):
        self._root, self._artifacts = Path(root), dict(artifacts)
        self._lock = threading.Lock()
        self._done: dict[str, PeOverview | None] = {}

    def overview(self, side: str) -> PeOverview | None:
        with self._lock:
            if side not in self._done:
                self._done[side] = self._inspect(self._artifacts[side])
            return self._done[side]

    def _inspect(self, artifact: Artifact) -> PeOverview | None:
        try:
            with VerifiedArtifactReader.open_artifact(artifact, self._root) as reader:
                overview = inspect_pe(reader)
        except (ArtifactBytesError, OSError):
            return None
        return overview if overview.status != 'not_pe' else None

    def image_base(self, side: str) -> int | None:
        overview = self.overview(side)
        return overview.image_base if overview else None


def _basename(path: str) -> str:
    return PureWindowsPath(path).name or PurePosixPath(path).name or path


def _facts(overview: PeOverview) -> Iterable[tuple[str, str]]:
    for section in overview.sections or ():
        yield 'Section', section.name
    if overview.machine:
        yield 'Machine', overview.machine.name
    if overview.subsystem:
        yield 'Subsystem', overview.subsystem.name
    if overview.coff_timestamp and overview.coff_timestamp.iso_utc:
        yield 'COFF timestamp (untrusted)', overview.coff_timestamp.iso_utc
    if overview.codeview:
        yield 'PDB', _basename(overview.codeview.pdb_path)
    for hint in overview.packer_hints:
        yield 'Packer hint', f'{hint.name} ({hint.confidence})'


def _entries(overview: PeOverview) -> list[tuple[str, str, str]]:
    """(kind, label, dll) rows, sorted: the order does not depend on the file's table order."""
    rows = [('build', f'{title}: {value}', title) for title, value in _facts(overview)]
    for dll in overview.imports.dlls if overview.imports else ():
        rows.extend(('import', f'{dll.name}!{name}', dll.name) for name in dll.functions)
    rows.extend(('export', name, '') for name in (overview.exports.names if overview.exports else ()))
    return sorted(set(rows))


def _documents(loader: PeLoader, side: str) -> Iterable[SegmentDoc]:
    overview = loader.overview(side)
    if overview is None:
        raise SearchError('PT-SEARCH-SOURCE', 'the PE file could not be read for the search index', recoverable=True)
    for ref, (kind, label, owner) in enumerate(_entries(overview)):
        if kind == 'build':
            yield SegmentDoc(kind, side, owner[:64], label, ref, text_title=owner, text_body=label.split(': ', 1)[1])
        else:
            function = label.split('!', 1)[1] if kind == 'import' else label
            yield SegmentDoc(kind, side, (owner or 'export')[:64], label, ref, **name_fields(label, function, owner))


def pe_spec(side: str, artifact: Artifact, loader: PeLoader) -> SourceSpec:
    return SourceSpec(f'pe:{side}', KINDS, TABLE_SETS, side,
                      {'artifact_sha256': artifact.sha256, 'inputs': PE_INPUTS_VERSION},
                      lambda: _documents(loader, side))

