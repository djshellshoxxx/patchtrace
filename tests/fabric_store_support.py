"""Project and store builders for the enrichment-backed fabric tests (FAB-1, FAB-4).

A project database whose snapshot is written by hand, so its older and newer hashes are the ones `fabric_support`
builds anchors for (a real project needs real artifact files). Only what the fabric reads is in the snapshot: id,
revision and the artifacts' sides and hashes. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import fabric_support as fs

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.fabric.pins import EnrichmentPinStore
from patchtrace.fabric.store import KIND, EnrichmentAnchorStore
from patchtrace.persistence import ProjectStore

PROJECT = 'proj-1'


def snapshot_text(project_id: str = PROJECT, older: str = fs.OLDER, newer: str = fs.NEWER, revision: int = 3) -> str:
    return json.dumps({'id': project_id, 'revision': revision, 'artifacts': [
        {'side': 'older', 'sha256': older}, {'side': 'newer', 'sha256': newer}]})


def write_snapshot(project: ProjectStore, text: str) -> None:
    project.connection.execute(
        'INSERT INTO current_snapshot(singleton,payload,sha256) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET '
        'payload=excluded.payload, sha256=excluded.sha256', (text, hashlib.sha256(text.encode()).hexdigest()))
    project.connection.commit()


def make_project(root: Path, *, snapshot: bool = True, **fields) -> ProjectStore:
    """A project database; `snapshot=False` is one that was never saved (no snapshot row)."""
    project = ProjectStore(Path(root) / 'project', create=True)
    if snapshot:
        write_snapshot(project, snapshot_text(**fields))
    return project


def make_store(project: ProjectStore, **kwargs) -> EnrichmentAnchorStore:
    return EnrichmentAnchorStore(EnrichmentStore(project), **kwargs)


def make_pins(project: ProjectStore, **kwargs) -> EnrichmentPinStore:
    return EnrichmentPinStore(EnrichmentStore(project), **kwargs)


def has_table(project: ProjectStore) -> bool:
    found = project.connection.execute("SELECT 1 FROM sqlite_master WHERE name='enrichment_entries'").fetchone()
    return found is not None


def rows(project: ProjectStore, kind: str = KIND) -> dict[str, dict]:
    """The stored rows of a kind by id: parsed body and the guard columns, straight from SQLite."""
    if not has_table(project):
        return {}
    found = project.connection.execute(
        'SELECT id, body, stale, project_id, run_id, raw_sha256, input_digest, project_revision, body_sha256, status '
        'FROM enrichment_entries WHERE kind=?', (kind,)).fetchall()
    return {row[0]: {'body': json.loads(row[1]), 'stale': bool(row[2]), 'guard': tuple(row[3:7]), 'revision': row[7],
                     'body_sha256': row[8], 'status': row[9]} for row in found}


def row_ids(project: ProjectStore, kind: str = KIND) -> set[str]:
    return set(rows(project, kind))
