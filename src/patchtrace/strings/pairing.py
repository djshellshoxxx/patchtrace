"""Function pairing for strings: which function of the accepted pairing uses a string, from data the project already holds.

Shared by `strings list|delta|explain` and the Strings panel. Pure orchestration over `links` (L1, L4, L5): this module
reads the two verified images and the project's function matches and asks `links.link_strings`; it adds no rule of its
own. A string is linked only by the evidence tiers of `links` (never by name similarity or by proximity), and a pairing
that cannot be built is reported with its reason, so a caller shows the function as unknown instead of guessing. No
target is executed; nothing is fetched.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .contracts import StringsError

NO_ANALYSIS = 'the project has no completed analysis with matched functions'
NO_IMAGE = 'a build could not be parsed as a PE image'


@dataclass
class Image:
    """One verified artifact: its PE layout (None when unparsable) and its overview."""
    pe: object | None = None
    overview: object | None = None


@dataclass(frozen=True)
class LinkOutcome:
    """`reason` is None when links were computed (a string may still have none); else why every function is unknown."""
    pairing: object
    linked: object | None
    reason: str | None = None


def inspect_image(path: Path, sha256: str) -> Image:
    """PE layout and import names of one verified artifact; an unparsable image just has no RVAs. Data reads only."""
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..intelligence.tools.common import ToolError
    from ..intelligence.tools.normalize import PeMap
    from ..pe_overview import inspect_pe
    try:
        reader = VerifiedArtifactReader.open_path(path, sha256)
    except ArtifactBytesError as exc:
        raise StringsError('PT-STR-INPUT', f'the artifact cannot be read ({exc.code})') from None
    try:
        overview = inspect_pe(reader)
        try:
            return Image(PeMap.from_reader(reader), overview)
        except ToolError:
            return Image(None, overview)
    finally:
        reader.close()


def project_links(root: Path, project, tables: Mapping, images: Mapping[str, Image], notes: list[str]) -> LinkOutcome:
    """Pairing and function links when `project` has a completed analysis and both images parse, else none with the reason."""
    from ..intelligence.tools.normalize import FunctionPairing
    from ..nway.contracts import NwayError
    from ..nway.series import current_run_id, read_raw_matches
    from .links import SideFunctions, link_strings
    empty = FunctionPairing.empty()
    run_id = current_run_id(project) if project is not None else None
    if project is None or not project.matches or run_id is None:
        return LinkOutcome(empty, None, NO_ANALYSIS)
    if any(images[s].pe is None for s in tables):
        return LinkOutcome(empty, None, NO_IMAGE)
    try:
        raw, raw_notes = read_raw_matches(root, project)
    except NwayError as exc:
        notes.append(f'function pairing unavailable: {exc}')
        return LinkOutcome(empty, None, 'the stored analysis output could not be read')
    pes = {side: images[side].pe for side in tables}
    pairing = FunctionPairing.from_project(
        project.matches, raw, older_base=pes['older'].image_base, newer_base=pes['newer'].image_base,
        older_size=pes['older'].size_of_image, newer_size=pes['newer'].size_of_image, notes=raw_notes)
    functions = {side: SideFunctions.from_matches(project.matches, side, pes[side].image_base,
                                                  pes[side].size_of_image) for side in tables}
    try:
        return LinkOutcome(pairing, link_strings(tables, pairing=pairing, functions=functions,
                                                 ghidra_group=f'ghidra:{run_id}'))
    except StringsError as exc:
        notes.append(f'function links unavailable: {exc.message}')
        return LinkOutcome(pairing, None, 'the function links could not be built')
