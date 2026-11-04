"""The one string comparison of a project (WB3 s7.1, s8): shared by `patchtrace strings list|delta|explain|export`
and the Strings dock, so both give the same changes, cues and review order for the same sources.

Qt-free and offline. Choosing a side's source reads the project store, so it runs on the thread that owns the store
(`stored_sources`); the comparison itself (`compare`) only reads the two verified files and immutable sources, so it
may run on a worker. Nothing here runs a target or a tool. Importing it is cheap: heavy imports are in the functions.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .pairing import Image
    from .sources import FlossEvidenceSource

NO_FLOSS = 'no stored FLOSS evidence for the {side} artifact: run `intel-tools run` first'


@dataclass
class Computed:
    delta: object
    tables: dict
    sources: dict[str, str]
    notes: list[str] = field(default_factory=list)
    pairing_reason: str | None = None  # why every function is unknown (None: links were computed)


def stored_floss(store, artifact) -> FlossEvidenceSource | None:
    """The newest stored FLOSS evidence of one artifact as a source, or None when it has none."""
    from .sources import FlossEvidenceSource
    found = store.latest('floss', artifact.side)
    if found is None or found[1] is None or not found[0].raw_sidecar:
        return None
    run, evidence = found
    raw_sha = run.raw_sidecar.rsplit('-', 1)[-1].removesuffix('.json')
    return FlossEvidenceSource(
        evidence, executable_sha256=run.manifest.executable_sha256, source_version=run.manifest.version,
        consent_sha256=run.options.get('emulation_consent_sha256'), raw_sha256=raw_sha)


def stored_sources(choice: str, store, artifacts: Mapping) -> dict[str, FlossEvidenceSource | None]:
    """The `--source` rule per side: `builtin` never reads the store; `auto` and `floss` take a side's stored FLOSS
    evidence when it has some. None means that side is read with the built-in scan (`floss` refuses it, see
    `missing_floss`)."""
    return {side: None if choice == 'builtin' else stored_floss(store, artifact)
            for side, artifact in artifacts.items()}


def missing_floss(choice: str, found: Mapping[str, object]) -> str | None:
    """The first side that `floss` requires stored evidence for and that has none."""
    return next((side for side, source in found.items() if source is None), None) if choice == 'floss' else None


def builtin_source(path: Path, sha256: str, side: str, min_length: int, image: Image, cancel):
    """The built-in scan of one verified file; `image` maps file offsets to RVAs when it parsed as PE."""
    from .scan import BuiltinScanSource
    pe = image.pe
    return BuiltinScanSource(path, artifact_sha256=sha256, side=side, min_length=min_length,
                             offset_to_rva=(lambda off: pe.offset_to_rva(off)[0]) if pe else None,
                             cancel=cancel.is_set)


def _imports(image: Image) -> tuple[frozenset[str], frozenset[str]]:
    overview = image.overview
    imports = overview.imports.dlls if overview and overview.imports else ()
    exports = overview.exports.names if overview and overview.exports else ()
    return frozenset(n for dll in imports for n in dll.functions), frozenset(exports)


def _cancelled(cancel) -> None:
    from .contracts import StringsError
    if cancel.is_set():
        raise StringsError('PT-STR-CANCEL', 'the scan was cancelled')  # the scan's own words


def compare(sources: Mapping[str, tuple[object, str]], images: Mapping[str, Image], root: Path | None, project,
            anchors, cancel, *, progress: Callable[[str, int, int], None] | None = None) -> Computed:
    """Load each side's `(source, label)` in the given order, link the strings to the project's function pairing
    (none without a completed analysis), give the cues each build's imports, exports and the anchors' terms, and
    attach the anchor hits. `cancel` is checked before every stage."""
    from .anchors import attach_anchors, terms
    from .cli import table_from_source
    from .cues import CueContext
    from .delta import compute_delta
    from .pairing import project_links
    tables, labels, notes = {}, {}, []
    for n, (side, (source, label)) in enumerate(sources.items(), 1):
        _cancelled(cancel)
        if progress is not None:
            progress(side, n, len(sources))
        labels[side] = label
        tables[side] = table_from_source(source.load())
    _cancelled(cancel)
    found = project_links(root, project, tables, images, notes)
    hints = terms(anchors)
    contexts = {}
    for side, other in (('older', 'newer'), ('newer', 'older')):
        imports, exports = _imports(images[side])
        contexts[side] = CueContext(imports=imports, exports=exports, other_side_imports=_imports(images[other])[0],
                                    api_hints=hints.api_hints, advisory_phrases=hints.advisory_phrases)
    sections = {side: image.overview.sections for side, image in images.items()
                if image.overview and image.overview.sections}
    delta = compute_delta(tables['older'], tables['newer'], pairing=found.pairing, links=found.linked,
                          contexts=contexts, sections=sections)
    return Computed(attach_anchors(delta, anchors), tables, labels, notes, found.reason)
