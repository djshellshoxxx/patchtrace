"""Composition root of the `graph` verbs: project input, the injected raw-matches reader, API hints, entries.
The only module of the package that reaches into other features (nway's verified raw reader, patch rules,
PE overview); the kernel stays free of those imports."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

from ..models import ComparisonProject
from .apis import HintRule, RuleHints
from .delta import DeltaContext, diff_types_by_match
from .limits import GraphError
from .noise import DEFAULT_HUBS
from .project_input import ProjectInput, read_project_input
from .snapshot import CallSnapshot, SnapshotOptions, build_snapshot
from .text import one_line

ENTRY_LABEL = 'entry'


def read_project(path: Path) -> ComparisonProject:
    """Read-only copy of a project (no maintenance, no migration); the handle is closed before returning."""
    from ..service import ProjectService
    try:
        service = ProjectService.open(Path(path), maintenance=False)
    except (ValueError, sqlite3.Error, OSError) as exc:
        raise GraphError('PT-GRAPH-INPUT', f'cannot open project {Path(path).name}: {exc}') from None
    try:
        return service.project.model_copy(deep=True)
    finally:
        service.close()


def project_input(path: Path, project: ComparisonProject) -> ProjectInput:
    from ..nway.series import read_raw_matches
    return read_project_input(project, Path(path), read_raw_matches)


def rule_hints() -> RuleHints:
    from ..intelligence.hypotheses import RULES
    return RuleHints(HintRule(rule.id, str(rule.revision), rule.family, rule.api_hints) for rule in RULES)


def snapshot_options() -> SnapshotOptions:
    from ..intelligence.hypotheses import RULES_VERSION, rules_digest
    return SnapshotOptions(hub_registry_version=DEFAULT_HUBS.version, patch_rules=(RULES_VERSION, rules_digest()))


class PeEntries:
    """`EntryPort`: the function labelled `entry`, the one at the PE entry point, and the export names."""

    def __init__(self, labels: dict[str, tuple[str, ...]]) -> None:
        self._labels = labels

    def entries(self, side: str) -> tuple[str, ...]:
        return self._labels.get(side, ())


def _pe_names(project: ComparisonProject, root: Path, side: str) -> tuple[int | None, tuple[str, ...]]:
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..pe_overview import inspect_pe
    artifact = next((a for a in project.artifacts if a.side == side), None)
    if artifact is None:
        return None, ()
    try:
        overview = inspect_pe(VerifiedArtifactReader.open_artifact(artifact, root))
    except (ArtifactBytesError, OSError, ValueError):
        return None, ()  # an unreadable image only means fewer known entries
    names = overview.exports.names if overview.exports is not None else ()
    return overview.entrypoint_va, tuple(names)


def entry_port(project: ComparisonProject, root: Path, data: ProjectInput) -> PeEntries:
    labels: dict[str, tuple[str, ...]] = {}
    for side in ('older', 'newer'):
        entry_va, exports = _pe_names(project, root, side)
        at_entry = tuple(e.label for e in data.side_entries(side)
                         if entry_va is not None and e.address == entry_va)
        labels[side] = tuple(dict.fromkeys((ENTRY_LABEL, *at_entry, *exports)))
    return PeEntries(labels)


class Analysis:
    """Everything one verb needs, built once: the project, its snapshot and the delta context."""

    def __init__(self, path: Path, cancel: Callable[[], bool] | None = None) -> None:
        self.path = Path(path)
        self.project = read_project(self.path)
        self.data = project_input(self.path, self.project)
        self.snapshot: CallSnapshot = build_snapshot(self.data, options=snapshot_options(), cancel=cancel)
        self.context = DeltaContext(hints=rule_hints(), registry=DEFAULT_HUBS,
                                    diff_types=diff_types_by_match(self.project))
        self.entries = entry_port(self.project, self.path, self.data)


def _pair_calls(root: Path, ref, warnings: list[str]):
    """PairCalls of one adjacent pair project, opened read-only and closed; None (unknown) when unusable."""
    from ..ingestion import safe_path
    from .pair_calls import PairCalls
    try:
        path = safe_path(root, ref.path)
        return PairCalls(project_input(path, read_project(path)))
    except (GraphError, ValueError, OSError) as exc:
        warnings.append(f'pair {ref.from_ordinal}->{ref.to_ordinal}: {one_line(getattr(exc, "message", exc), 200)}; '
                        'its callees are unknown')
        return None


def evolution_for_chain(root: Path, chain_id: str, cancel: Callable[[], bool] | None = None):
    """A7 evolution of one chain of `root/series.json`; returns (evolution, warnings)."""
    from ..nway import series as store
    from ..nway.contracts import NwayError
    from .evolution import build_evolution
    root = Path(root)
    file = root / store.SERIES_FILE
    if not file.is_file():
        raise GraphError('PT-GRAPH-INPUT', f'{store.SERIES_FILE} not found in {root.name}')
    try:
        series = store.load(file)
    except NwayError as exc:
        raise GraphError('PT-GRAPH-SOURCE', str(exc)) from None
    found = [c for c in series.chains
             if c.chain_id == chain_id or (len(chain_id) >= 8 and c.chain_id.startswith(chain_id))]
    if len(found) != 1:
        raise GraphError('PT-GRAPH-INPUT', f'{len(found)} chains match {one_line(chain_id, 40)!r}; '
                         'give the chain id from `series chains`')
    names = {node.ordinal: node.name for node in found[0].nodes}
    refs = {(r.from_ordinal, r.to_ordinal): r for r in series.pair_projects}
    warnings: list[str] = []
    pairs = []
    for k in range(len(series.builds) - 1):
        ref = refs.get((k, k + 1))
        if ref is None:
            warnings.append(f'pair {k}->{k + 1}: no pair project; its callees are unknown')
        pairs.append(None if ref is None else _pair_calls(root, ref, warnings))
    count = len(series.builds)
    evolution = build_evolution(series.series_id, found[0].chain_id, [b.label for b in series.builds],
                                [names.get(i) for i in range(count)], pairs, cancel)
    return evolution, warnings
