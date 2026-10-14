"""Project-level orchestration of preliminary artifact inspection (SPEC-26 D, alpha).

Responsibility: for both oriented project artifacts, open a verified reader,
run the bounded PE inspector, and compare the two overviews. Pure Python, no
Qt: the desktop runs :func:`inspect_project_artifacts` on a worker thread and
only reads the immutable result on the GUI thread.

Error contract: never raises for per-side failures. A side that cannot be
verified or read records ``error_code`` (an ``ArtifactBytesError`` code, or
``inspection_failed`` for an unexpected parser defect) and ``error``; the other
side is still inspected. Cancellation yields ``cancelled=True``. Successfully
opened readers stay open in the result for raw byte views; the owner must call
:meth:`ProjectInspection.close`.

Nothing here mutates the project, executes artifacts or touches the network.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from .ingestion import safe_path
from .models import Artifact
from .pe_overview import FieldComparison, PeOverview, compare_overviews, inspect_pe
from .pe_overview.authenticode import TrustResult, verify_authenticode

SIDES = ('older', 'newer')


@dataclass(frozen=True, slots=True)
class SideInspection:
    side: str
    artifact_sha256: str
    overview: PeOverview | None = None
    error_code: str | None = None
    error: str | None = None
    trust: TrustResult | None = None


@dataclass(slots=True)
class ProjectInspection:
    project_id: str
    sides: dict[str, SideInspection]
    comparisons: tuple[FieldComparison, ...] = ()
    cancelled: bool = False
    readers: dict[str, VerifiedArtifactReader] = field(default_factory=dict)

    def reader(self, side: str) -> VerifiedArtifactReader | None:
        return self.readers.get(side)

    def close(self) -> None:
        for reader in self.readers.values():
            reader.close()
        self.readers.clear()


def inspect_project_artifacts(project_id: str, artifacts: Iterable[Artifact], root: Path,
                              cancel: Callable[[], bool] | None = None,
                              verify_trust: Callable[[Path], TrustResult] = verify_authenticode,
                              ) -> ProjectInspection:
    """Inspect both sides. ``verify_trust`` is the platform Authenticode probe (Windows only,
    embedded signatures, no revocation, no network); it runs only on hash-verified copies."""
    by_side = {artifact.side: artifact for artifact in artifacts}
    missing = [side for side in SIDES if side not in by_side]
    if missing:
        raise ValueError(f'project is missing oriented artifact(s): {", ".join(missing)}')
    sides: dict[str, SideInspection] = {}
    readers: dict[str, VerifiedArtifactReader] = {}
    cancelled = False
    for side in SIDES:
        artifact = by_side[side]
        if cancel is not None and cancel():
            cancelled = True
            sides[side] = SideInspection(side, artifact.sha256, error_code='cancelled', error='Inspection cancelled')
            continue
        try:
            reader = VerifiedArtifactReader.open_artifact(artifact, root, cancel)
        except ArtifactBytesError as exc:
            cancelled = cancelled or exc.code == 'cancelled'
            sides[side] = SideInspection(side, artifact.sha256, error_code=exc.code, error=str(exc))
            continue
        readers[side] = reader
        try:
            overview = inspect_pe(reader, cancel=cancel)
        except ArtifactBytesError as exc:
            sides[side] = SideInspection(side, artifact.sha256, error_code=exc.code, error=str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 - a parser defect must not hide the other side
            sides[side] = SideInspection(side, artifact.sha256, error_code='inspection_failed',
                                         error=f'{type(exc).__name__}: {exc}')
            continue
        cancelled = cancelled or overview.status == 'cancelled'
        trust = None
        if not cancelled and overview.status != 'not_pe':
            try:
                trust = verify_trust(safe_path(Path(root), artifact.relative_path))
            except Exception as exc:  # noqa: BLE001 - trust probe failure is reported, never fatal
                trust = TrustResult('unavailable', None, f'Authenticode probe failed: {type(exc).__name__}')
        sides[side] = SideInspection(side, artifact.sha256, overview=overview, trust=trust)
    older, newer = sides['older'].overview, sides['newer'].overview
    comparisons = compare_overviews(older, newer) if older is not None and newer is not None else ()
    return ProjectInspection(project_id, sides, comparisons, cancelled, readers)
