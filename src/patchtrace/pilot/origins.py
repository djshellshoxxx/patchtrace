"""Shared-origin components: evidence derived from the same upstream data counts once (s4, s7 tier step 3).

The origin tags, the evidence-source table and the connected-components calculus are the fabric's (`fabric/origins.py`,
FAB-3): this module re-exports them, so "shared origin counts once" has one implementation and one table. What stays
PIL's is its error type (an unknown source raises `PT-PILOT-INPUT`), the `Lead.components` summary and its identity
domain: `digest()` hashes the fabric's table payload under `pilot-origins`, so a PIL id never equals a fabric id for the
same table and `keys.DOMAINS` is unchanged. Locality never counts here.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..enrichment.identity import domain_id
from ..fabric.limits import FabricError
from ..fabric.origins import ORIGINS_VERSION, SOURCE_TAGS, TAGS, components  # noqa: F401 - re-exported
from ..fabric.origins import DefaultOriginRegistry as FabricOriginRegistry
from .contracts import LeadComponents
from .limits import PilotError

DOMAIN = 'pilot-origins'


def lead_components(origin_sets: Iterable[Iterable[str]]) -> LeadComponents:
    """`Lead.components`: the component count and the smallest tag of each component."""
    found = components(origin_sets)
    return LeadComponents(count=len(found), tags=tuple(component[0] for component in found))


class DefaultOriginRegistry(FabricOriginRegistry):
    """The fabric's origin table and calculus under PIL's error type and identity domain; its digest is part of every
    result identity (`PilotInputs.origins_digest`)."""

    def tags_for(self, source: str) -> tuple[str, ...]:
        try:
            return super().tags_for(source)
        except FabricError:
            raise PilotError('PT-PILOT-INPUT', 'Unknown evidence source for origin tags',
                             reason='unknown-origin-source') from None

    def digest(self) -> str:
        return domain_id(DOMAIN, 1, self.payload())


def digest() -> str:
    """Digest of the default registry (`PilotInputs.origins_digest`)."""
    return DefaultOriginRegistry().digest()
