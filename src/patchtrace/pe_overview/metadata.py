"""Version, manifest and signature records of one PE in a single bounded call (SPEC-51 D2-1 to D2-3).

Pure aggregation over the existing readers; it parses the resource tree once and shares it. Never raises for file
content: a failing stage becomes the warning `internal_error_<stage>` and the other stages still run.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from patchtrace.artifact_bytes import VerifiedArtifactReader

from ._common import Cancelled, Ctx
from .manifest import ManifestObservation, parse_manifests
from .models import Limits, PeOverview, PeWarning, SignatureInfo
from .resources import ResourceInventory, parse_resources
from .signature import verify_embedded
from .version_info import VersionInfoSet, parse_version_info

DEFAULT_LIMITS = Limits()


@dataclass(frozen=True, slots=True)
class PeMetadata:
    status: str  # ok | partial | not_pe | cancelled
    resources: ResourceInventory | None = None
    version: VersionInfoSet | None = None
    manifests: tuple[ManifestObservation, ...] = ()
    signatures: tuple[SignatureInfo, ...] = ()
    warnings: tuple[PeWarning, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def inspect_metadata(reader: VerifiedArtifactReader, overview: PeOverview,
                     cancel: Callable[[], bool] | None = None, limits: Limits = DEFAULT_LIMITS) -> PeMetadata:
    if overview.status == 'not_pe':
        return PeMetadata('not_pe')
    ctx = Ctx(reader, cancel, limits)
    found: dict[str, Any] = {}
    try:
        _run(ctx, overview, found, limits)
    except Cancelled:
        return PeMetadata('cancelled', warnings=tuple(ctx.warnings), **found)
    if cancel is not None and cancel():
        return PeMetadata('cancelled', warnings=tuple(ctx.warnings), **found)
    return PeMetadata('partial' if ctx.warnings else 'ok', warnings=tuple(ctx.warnings), **found)


def _stage(ctx: Ctx, name: str, fn: Callable[[], Any], default: Any = None) -> Any:
    ctx.check()
    try:
        return fn()
    except Cancelled:
        raise
    except Exception as exc:  # noqa: BLE001 - hostile input must not escape; one stage failing keeps the others
        ctx.warn(f'internal_error_{name}', f'{name} stage failed: {type(exc).__name__}')
        return default


def _run(ctx: Ctx, overview: PeOverview, found: dict[str, Any], limits: Limits) -> None:
    resource = overview.directory('Resource')
    smap = overview.section_map()
    if resource is not None and resource.present:
        inventory = _stage(ctx, 'resources', lambda: parse_resources(ctx, smap, resource.rva, resource.size))
        found['resources'] = inventory
        if inventory is not None:
            found['version'] = _stage(ctx, 'version', lambda: parse_version_info(ctx, smap, inventory))
            found['manifests'] = _stage(ctx, 'manifest', lambda: parse_manifests(ctx, smap, inventory), ())
    found['signatures'] = _stage(
        ctx, 'signature', lambda: verify_embedded(ctx.reader, overview, ctx.cancel, limits), ())
