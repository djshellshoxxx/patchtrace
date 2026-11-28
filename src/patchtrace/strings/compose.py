"""One offline strings comparison for the CLI and dock (WB3 composition).

Callers capture project/store state before entering a worker. This module reads only explicitly supplied
files and source values; it never runs an extractor, opens a store, or changes a project.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .pairing import Image

MAX_ANCHOR_FILE = 4 * 1024 * 1024


@dataclass
class Computed:
    delta: object
    tables: dict
    sources: dict[str, str]
    notes: list[str] = field(default_factory=list)
    pairing_reason: str | None = None


def table_from_source(result):
    """The columnar table of one source; the basis retains its extraction and provenance."""
    from . import contracts as c
    from .limits import NONE_U32
    from .table import CONFIDENCE, ENCODINGS, FLAG_SECRET, StringRow, StringTable
    from .table import TYPES as TABLE_TYPES
    part = result.part
    types = tuple(t for t in part.types if t in TABLE_TYPES)
    basis = c.StringBasis(
        artifact_sha256=result.artifact_sha256, side=result.side, min_length=result.min_length or 4,
        language=c.LanguageInfo(selected=result.language), rows_seen=max(result.rows_seen, len(result.rows)),
        rows_kept=len(result.rows),
        stages={name: c.StageState(state=s.state, detail=s.detail[:200]) for name, s in result.stages.items()},
        parts=(c.BasisPart(
            source=part.source, semantics_id=part.semantics_id, source_version=part.source_version or '',
            executable_sha256=part.executable_sha256, run_id=part.run_id, raw_sha256=part.raw_sha256,
            types=types, config_digest=part.config_digest, consent_sha256=part.consent_sha256),))

    def u32(value: int | None) -> int:
        return NONE_U32 if value is None else value
    return StringTable.from_rows(basis, (StringRow(
        value_sha256=r.value_sha256, type=TABLE_TYPES.index(r.type), encoding=ENCODINGS.index(r.encoding),
        length=r.length, offset=u32(r.offset), rva=u32(r.rva), fn_rva=u32(r.fn_rva), site=u32(r.site_rva),
        confidence=CONFIDENCE.index(r.confidence), flags=FLAG_SECRET if r.secret_kind else 0, display=r.display)
        for r in result.rows))


def check_cancelled(cancel) -> None:
    from .contracts import StringsError
    if cancel.is_set():
        raise StringsError('PT-STR-CANCEL', 'the scan was cancelled')


def load_anchors(path: Path | None):
    """Read only an explicitly selected bounded strict-JSON AnchorSet; no automatic advisory selection."""
    from ..intelligence.contracts import AnchorSet
    from ..persistence import strict_json
    from .contracts import StringsError
    if path is None:
        return None
    try:
        with path.open('rb') as stream:
            raw = stream.read(MAX_ANCHOR_FILE + 1)
        if len(raw) > MAX_ANCHOR_FILE:
            raise StringsError('PT-STR-INPUT', 'the anchors file is too large')
        strict_json(raw)
        return AnchorSet.model_validate_json(raw)
    except OSError:
        raise StringsError('PT-STR-INPUT', 'the anchors file cannot be read') from None
    except (ValueError, RecursionError):
        raise StringsError('PT-STR-INPUT', 'the anchors file is not a valid AnchorSet') from None


def builtin_source(path: Path, sha256: str, side: str, min_length: int, image: Image, cancel):
    from .scan import BuiltinScanSource
    pe = image.pe
    return BuiltinScanSource(path, artifact_sha256=sha256, side=side, min_length=min_length,
                             offset_to_rva=(lambda off: pe.offset_to_rva(off)[0]) if pe else None,
                             cancel=cancel.is_set)


def stored_sources(choice: str, captured) -> dict:
    """Select each side from captured values; no store or sidecar reads occur here."""
    from ..intelligence.tools.common import ToolError
    from .contracts import StringsError
    from .sources import FlossEvidenceSource
    if choice not in ('auto', 'floss', 'builtin'):
        raise StringsError('PT-STR-INPUT', 'unknown strings source choice')
    selected = {'older': None, 'newer': None}
    if choice == 'builtin':
        return selected
    if captured is not None:
        try:
            captured.require_capture()
        except ToolError as exc:
            raise StringsError('PT-STR-SOURCE', exc.message) from None
        for side in selected:
            try:
                found = captured.admitted('floss', side)
            except ToolError:
                continue  # the existing auto policy falls back only this refused side
            if found is None or not found.evidence_run.raw_sidecar:
                continue
            run = found.evidence_run
            selected[side] = FlossEvidenceSource(
                found.evidence, executable_sha256=run.manifest.executable_sha256, source_version=run.manifest.version,
                consent_sha256=run.options.get('emulation_consent_sha256'), raw_sha256=run.stdout_digest)
    if choice == 'floss':
        missing = next((side for side, source in selected.items() if source is None), None)
        if missing is not None:
            raise StringsError('PT-STR-INPUT',
                f'no stored FLOSS evidence for the {missing} artifact: run `intel-tools run` first')
    return selected


def _imports(image: Image) -> tuple[frozenset[str], frozenset[str]]:
    overview = image.overview
    imports = overview.imports.dlls if overview and overview.imports else ()
    exports = overview.exports.names if overview and overview.exports else ()
    return frozenset(name for dll in imports for name in dll.functions), frozenset(exports)


def compare(sources: Mapping[str, tuple[object, str]], images: Mapping[str, Image], root: Path | None, project,
            anchors, cancel, *, progress: Callable[[str, int, int], None] | None = None) -> Computed:
    """Compare captured sources using the existing pairing, basis, cue, region, ranking and anchor rules."""
    from .anchors import attach_anchors, terms
    from .cues import CueContext
    from .delta import compute_delta
    from .pairing import project_links
    tables, labels, notes = {}, {}, []
    for n, side in enumerate(('older', 'newer'), 1):
        check_cancelled(cancel)
        if progress is not None:
            progress(side, n, 2)
        source, labels[side] = sources[side]
        tables[side] = table_from_source(source.load())
        check_cancelled(cancel)
    found = project_links(root, project, tables, images, notes)
    check_cancelled(cancel)
    hints = terms(anchors)
    contexts = {}
    for side, other in (('older', 'newer'), ('newer', 'older')):
        imports, exports = _imports(images[side])
        contexts[side] = CueContext(imports=imports, exports=exports, other_side_imports=_imports(images[other])[0],
                                    api_hints=hints.api_hints, advisory_phrases=hints.advisory_phrases)
    sections = {side: image.overview.sections for side, image in images.items()
                if image.overview and image.overview.sections}
    check_cancelled(cancel)
    delta = compute_delta(tables['older'], tables['newer'], pairing=found.pairing, links=found.linked,
                          contexts=contexts, sections=sections)
    check_cancelled(cancel)
    delta = attach_anchors(delta, anchors)
    check_cancelled(cancel)
    return Computed(delta, tables, labels, notes, found.reason)
