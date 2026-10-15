"""Paired neighbourhood export of one match (JSON contract and the shared, safe file writer)."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Literal

from .contracts import GraphView, Model, Side
from .delta import lookup
from .limits import CancelCheck, GraphError
from .query import find_node, neighbourhood, partner
from .snapshot import CallSnapshot

MAX_EXPORT_NODES = 2_000  # GL-10: per file, both sides together
MAX_EXPORT_EDGES = 2_000
MAX_EXPORT_BYTES = 2 * 1024 * 1024
_PER_SIDE_NODES, _PER_SIDE_EDGES = 500, 1_000  # two sides stay within the file caps
_REPLACE_ATTEMPTS = 5


class GraphExport(Model):
    contract: Literal['workbench-graph-export/1'] = 'workbench-graph-export/1'
    project_id: str
    run_id: str
    match_id: str
    older_sha256: str
    newer_sha256: str
    older: GraphView | None = None
    newer: GraphView | None = None
    # (older node id, newer node id) pairs from the pairing; never calls.
    correspondence: tuple[tuple[str, str], ...] = ()
    truncated: bool = False
    limitations: tuple[str, ...] = ()


def _focus(snap: CallSnapshot, match_id: str, side: Side) -> str | None:
    labels = [e.label for e in snap.data.side_entries(side) if e.match_id == match_id]
    return find_node(snap, side, labels[0]).id if labels else None


def _correspondence(snap: CallSnapshot, older: GraphView, newer: GraphView) -> tuple[tuple[str, str], ...]:
    shown = {n.id for n in newer.nodes}
    pairs = []
    for node in older.nodes:
        pairing = partner(snap, 'older', node.id)
        if pairing.kind != 'one':
            continue
        found = lookup(snap, 'newer', pairing.partners[0])
        if found is not None and found[1].id in shown:
            pairs.append((node.id, found[1].id))
    return tuple(sorted(pairs))


def build_export(snap: CallSnapshot, match_id: str, depth: int = 1, cancel: CancelCheck = None) -> GraphExport:
    focus = {side: _focus(snap, match_id, side) for side in ('older', 'newer')}
    if not any(focus.values()):
        raise GraphError('PT-GRAPH-INPUT', 'function-not-indexed: the match has no function in the stored change set')
    views = {side: neighbourhood(snap, side, [node_id], 'both', depth, _PER_SIDE_NODES, _PER_SIDE_EDGES, cancel)
             if node_id else None for side, node_id in focus.items()}
    older, newer = views['older'], views['newer']
    data = snap.data
    return GraphExport(
        project_id=data.project_id, run_id=data.run_id, match_id=match_id, older_sha256=data.older_sha256,
        newer_sha256=data.newer_sha256, older=older, newer=newer,
        correspondence=_correspondence(snap, older, newer) if older and newer else (),
        truncated=any(v.truncated for v in views.values() if v), limitations=snap.limitations)


def check_size(text: str) -> str:
    if len(text.encode('utf-8')) > MAX_EXPORT_BYTES:
        raise GraphError('PT-GRAPH-EXPORT', f'the export exceeds {MAX_EXPORT_BYTES // (1024 * 1024)} MiB; '
                         'narrow the depth')
    return text


def to_json(export: GraphExport) -> str:
    return check_size(json.dumps(export.model_dump(mode='json'), indent=2, sort_keys=True, ensure_ascii=True,
                                 allow_nan=False) + '\n')


def default_name(text: str, suffix: str) -> str:
    """`callgraph-<sha12>.<suffix>`: derived from the content, never from function names."""
    return f'callgraph-{hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]}.{suffix}'


def write_export(target: Path, text: str, suffix: str, overwrite: bool = False) -> Path:
    """Write UTF-8/LF text through a temp file in the target directory and `os.replace` it into place.
    A directory target gets the default name; an existing file is refused unless `overwrite`."""
    target = Path(target)
    if target.is_dir():
        target = target / default_name(text, suffix)
    if target.exists() and not overwrite:
        raise GraphError('PT-GRAPH-INPUT', f'{target.name} exists; pass --overwrite to replace it')
    stage = target.with_name(f'.{target.name}.{os.getpid()}.tmp')
    try:
        with open(stage, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        _replace(stage, target)
    except OSError as exc:
        raise GraphError('PT-GRAPH-EXPORT', f'cannot write {target.name}: {exc.strerror or exc}') from None
    finally:
        stage.unlink(missing_ok=True)
    return target


def _replace(stage: Path, target: Path) -> None:
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(stage, target)
            return
        except PermissionError:  # Windows: an indexer or viewer may hold the target briefly
            if attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(0.05 * (attempt + 1))
