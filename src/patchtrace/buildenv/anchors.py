"""Build facts offered to other tracks as per-side anchors (DIE plan s4). An anchor is context, never a vote."""
from __future__ import annotations

from ..enrichment.identity import domain_id
from .contracts import BuildFactAnchor, BuildFingerprint, FactKey

# Descriptive version fields, entropy and overlay size stay card-only: they are not stable named facts.
ANCHOR_KEYS: frozenset[FactKey] = frozenset({
    'compiler', 'linker', 'build_tool', 'runtime_family', 'language', 'target_os', 'packer', 'protector',
    'installer', 'obfuscator', 'managed', 'gs_cookie', 'cfg', 'aslr', 'repro', 'rich_signature',
    'debug_entry_types'})


def anchors_for(fingerprint: BuildFingerprint) -> tuple[BuildFactAnchor, ...]:
    """Distinct anchors of one side in a stable order; heuristic facts are anchors too, labelled by `certainty`."""
    found: dict[str, BuildFactAnchor] = {}
    for fact in fingerprint.facts:
        if fact.key not in ANCHOR_KEYS or fact.certainty == 'unknown':
            continue
        anchor_id = domain_id('build-fact', 1, {'artifact_sha256': fingerprint.artifact_sha256, 'key': fact.key,
                                                'value': fact.value, 'source': fact.source})
        found.setdefault(anchor_id, BuildFactAnchor(
            anchor_id=anchor_id, key=fact.key, value=fact.value, side=fingerprint.side,
            artifact_sha256=fingerprint.artifact_sha256, source=fact.source, certainty=fact.certainty))
    return tuple(sorted(found.values(), key=lambda a: (a.key, a.value, a.source)))
