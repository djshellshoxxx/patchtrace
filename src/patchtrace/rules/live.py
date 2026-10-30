"""Proposing rules for the match selected in the panel: the live evidence behind `candidates.propose` (panel spec R6b).

Two steps along the thread rule. `prepare` runs on the GUI thread and only reads the in-memory project: it checks the
match is one the analyst accepted and freezes what a worker needs (ids, hashes, the match record, the local paths).
`run_proposal` runs on a worker: it opens both builds as verified data, reads function sizes from their exception data,
builds the pair and asks `candidates.propose`, whose compile and separation checks run in the hidden rules worker. No
build is executed, nothing is stored here (the caller appends the candidates) and nothing is accepted.

Channels. Imports (the PE import tables) and bytes (verified function extent, iced-x86 masks) are live. The string and
capability channels need stored FLOSS and capa evidence and are not wired here: they are reported `unavailable`, which is
unknown, never "none found". Materiality is not read from the project: it is `unknown` until the analyst confirms the
change is material, and the candidates then carry `unvetted`.
"""
from __future__ import annotations

import importlib.util
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ..gui.text import sanitize_text
from ..models import FunctionMatch
from . import candidates as cd
from .contracts import FunctionRef, PairSource
from .errors import RuleError

SIDES = ('older', 'newer')
ONE_TO_ONE = {'modified': (1, 1), 'added': (0, 1), 'removed': (1, 0)}


@dataclass(frozen=True)
class ProposeRequest:
    """Everything a worker may know: immutable ids and paths, no service, no connection."""
    project_id: str
    revision: int
    run_id: str
    match: FunctionMatch
    builds: Mapping[str, Path]
    hashes: Mapping[str, str]
    confirm_material: bool = False


def mask_available() -> bool:
    return importlib.util.find_spec('iced_x86') is not None


def prepare(project, paths: tuple[Path, Path, str, str], match_id: str, *, run_id: str | None = None,
            confirm_material: bool = False) -> ProposeRequest:
    """GUI thread, no I/O. `paths` is `ProjectPort.artifact_paths()`. Only an accepted match one-to-one can seed rules."""
    match = next((m for m in project.matches if m.id == match_id), None)
    if match is None:
        raise RuleError('PT-RULE-INPUT', 'No such match in the project', reason='no-such-match')
    if match.review != 'accepted':
        raise RuleError('PT-RULE-INPUT', 'Rules are only proposed for a pair you have accepted', reason='not-accepted')
    if (len(match.older), len(match.newer)) != ONE_TO_ONE.get(match.category):
        raise RuleError('PT-RULE-INPUT', 'Rules need one changed function per build', reason='not-one-to-one')
    older, newer, older_sha, newer_sha = paths
    return ProposeRequest(project.id, project.revision, run_id or match.run_id, match.model_copy(),
                          {'older': Path(older), 'newer': Path(newer)}, {'older': older_sha, 'newer': newer_sha},
                          confirm_material)


def _function(record, tables, base: int) -> FunctionRef:
    from ..intelligence.tools.normalize import _record_rva
    rva = _record_rva(record, base, tables.size_of_image) if base is not None else None
    if rva is None:
        raise RuleError('PT-RULE-INPUT', 'The function has no address in this build', reason='no-address')
    try:
        size = tables.function_extent(rva)
    except ValueError:
        size = None
    name = sanitize_text(record.name, 256) or None
    try:
        return FunctionRef(name=name, rva=rva, size=size, extent='pdata' if size else 'unknown')
    except ValidationError:
        raise RuleError('PT-RULE-INPUT', 'The function record is not valid', reason='bad-function') from None


def run_proposal(request: ProposeRequest, cancel: threading.Event | None = None, *,
                 checker: Callable | None = None, mask_source=None) -> cd.Proposal:
    """Worker thread. `checker` and `mask_source` are seams for tests; production uses the hidden rules worker and iced-x86."""
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..pe_overview.tables import PeTableError, PeTables
    from .adapters.pe_imports import PeImports
    from .window import BytesWindows
    readers, tables = {}, {}
    try:
        for side in SIDES:
            try:
                readers[side] = VerifiedArtifactReader.open_path(request.builds[side], request.hashes[side])
                tables[side] = PeTables.open(readers[side])
            except (ArtifactBytesError, PeTableError, OSError):
                raise RuleError('PT-RULE-STALE', 'A build of the pair cannot be read as a PE image',
                                reason='build-missing') from None
        match = request.match
        refs = {side: _function(getattr(match, side)[0], tables[side], tables[side].overview.image_base)
                for side in SIDES if getattr(match, side)}
        try:
            pair = PairSource(project_id=request.project_id, revision=request.revision, run_id=request.run_id,
                              older_sha256=request.hashes['older'], newer_sha256=request.hashes['newer'],
                              match_id=match.id, category=match.category, review='accepted', materiality='unknown',
                              analyst_confirmed_material=request.confirm_material, older=refs.get('older'),
                              newer=refs.get('newer'))
        except ValidationError:
            raise RuleError('PT-RULE-INPUT', 'The match cannot seed a rule', reason='bad-pair') from None
        imports = PeImports({side: tables[side].overview for side in SIDES})
        mask = mask_source if mask_source is not None else (_iced() if mask_available() else None)
        sources = cd.Sources(imports=imports, bytes=BytesWindows(mask, tables) if mask is not None else None)
        check = checker or cd.RunnerChecker({side: request.builds[side] for side in SIDES}, cancel=cancel)
        return cd.propose(pair, sources, check=check)
    finally:
        for reader in readers.values():
            reader.close()


def _iced():
    from .adapters.mask_iced import IcedMaskSource  # the only place the decoder extension enters this process
    return IcedMaskSource()
