"""Shared builders for the call-graph input, pairing, snapshot and query tests (WB2 G2)."""
from __future__ import annotations

import copy

from callgraph_fixtures import build_fixture, project_for_fixtures

from patchtrace.callgraph.project_input import ProjectInput, read_project_input
from patchtrace.callgraph.snapshot import CallSnapshot, SnapshotOptions, build_snapshot
from patchtrace.models import ComparisonProject
from patchtrace.normalization import normalize_ghidriff


def project_and_raw(name: str, mutate=None) -> tuple[ComparisonProject, dict]:
    raw = copy.deepcopy(build_fixture(name))
    if mutate is not None:
        mutate(raw)
    project, run_id = project_for_fixtures()
    project.runs[0].id, project.id = 'run-1', 'project-1'  # stable ids so keys compare across builds
    run_id = 'run-1'
    project.matches = normalize_ghidriff(raw, project, run_id)
    return project, raw


def reader_for(raw: dict):
    return lambda _root, _project: (raw.get('matches'), ())


def graph_input(name: str, mutate=None, with_raw: bool = True) -> ProjectInput:
    project, raw = project_and_raw(name, mutate)
    return read_project_input(project, None, reader_for(raw) if with_raw else None)


def snapshot(name: str, mutate=None, with_raw: bool = True, options: SnapshotOptions | None = None,
             **kwargs) -> CallSnapshot:
    return build_snapshot(graph_input(name, mutate, with_raw), options=options, **kwargs)


def labels(view) -> list[str]:
    return [node.label for node in view.nodes]


def edge_labels(view) -> list[tuple[str, str]]:
    names = {node.id: node.label for node in view.nodes}
    return [(names[e.src], names[e.dst]) for e in view.edges]
