"""LBL-31: transfer only verified Tier R label/engine JSON from shard scratch to Actions.

The shard's aggregate JSON remains free of per-function information. This independent
artifact set is checked against the actual report pair digests and label digests.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from collections.abc import Iterable

from ..common import canonical_json
from . import contracts as C
from . import output_store as OS
from . import report_schemas as RS

MAX_LABEL_BYTES = C.MAX_LABEL_BYTES


class ArtifactError(ValueError):
    """Absent, conflicting, oversized or tampered training data; fail the shard/merge."""


def expected_from_reports(reports: Iterable[dict]) -> tuple[dict[str, str], dict[str, str]]:
    """Return label and output digest maps. Reject inconsistent report references."""
    labels: dict[str, str] = {}
    outputs: dict[str, str] = {}
    for report in reports:
        C.load_report(canonical_json(report))
        for entry in report['inputs']:
            name = f"{entry['pair_id']}.json"
            prior = labels.setdefault(name, entry['labels_digest'])
            if prior != entry['labels_digest']:
                raise ArtifactError(f'conflicting labels digest for {name}')
        for pair in report['pairs']:
            if pair['status'] != 'ok':
                continue
            name = OS.output_file_name(pair['pair_id'], pair['engine'])
            sha = pair['output_sha256']
            if sha is None:
                raise ArtifactError(f'completed engine output {name} has no digest')
            prior = outputs.setdefault(name, sha)
            if prior != sha:
                raise ArtifactError(f'conflicting engine output digests for {name}')
    return labels, outputs


def _checked_label(raw: bytes, name: str, expected: str) -> None:
    if len(raw) > MAX_LABEL_BYTES:
        raise ArtifactError(f'{name}: labels exceed {MAX_LABEL_BYTES} bytes')
    try:
        doc = C.load_labels(raw)
    except C.ContractError as exc:
        raise ArtifactError(f'{name}: invalid labels: {str(exc)[:180]}') from None
    if name != f'{doc.pair_id}.json' or doc.digest_sha256 != expected:
        raise ArtifactError(f'{name}: label identity/digest does not match report')


def _checked_output(raw: bytes, name: str, expected: str) -> None:
    if len(raw) > OS.MAX_ENGINE_OUTPUT_BYTES:
        raise ArtifactError(f'{name}: engine output exceeds {OS.MAX_ENGINE_OUTPUT_BYTES} bytes')
    try:
        doc = RS.load_engine_output(raw)
    except C.ContractError as exc:
        raise ArtifactError(f'{name}: invalid engine output: {str(exc)[:180]}') from None
    if OS.output_file_name(name.rsplit('.', 2)[0], doc.engine) != name:
        raise ArtifactError(f'{name}: engine identity mismatch')
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ArtifactError(f'{name}: engine output SHA-256 mismatch')


def _read_capped(path: Path, cap: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > cap:
        raise ArtifactError(f'{path.name}: missing, linked or oversized artifact')
    return path.read_bytes()


def _paths(root: Path, expected: dict[str, str], kind: str) -> dict[str, Path]:
    folder = root / kind
    if folder.is_symlink():
        raise ArtifactError(f'{kind}: linked folder is refused')
    found = {p.name: p for p in folder.glob('*.json')} if folder.is_dir() else {}
    if set(found) != set(expected):
        raise ArtifactError(f'{kind}: expected and actual artifact names differ (missing or unexpected files)')
    return found


def verify_training_artifacts(reports: Iterable[dict], root: Path) -> dict[str, int]:
    """Confirm there are exactly the expected files and no missing/altered successful engine runs."""
    labels, outputs = expected_from_reports(reports)
    root = Path(root)
    label_paths, output_paths = _paths(root, labels, 'labels'), _paths(root, outputs, 'outputs')
    for name, sha in sorted(labels.items()):
        _checked_label(_read_capped(label_paths[name], MAX_LABEL_BYTES), name, sha)
    for name, sha in sorted(outputs.items()):
        _checked_output(_read_capped(output_paths[name], OS.MAX_ENGINE_OUTPUT_BYTES), name, sha)
    return {'labels': len(labels), 'outputs': len(outputs)}


def export_training_artifacts(reports: Iterable[dict], store: Path, dest: Path) -> dict[str, int]:
    """Copy only report-referenced, validated JSON from shard scratch to an empty artifact destination."""
    reports = list(reports)
    labels, outputs = expected_from_reports(reports)
    store, dest = Path(store), Path(dest)
    if dest.exists():
        if dest.is_symlink() or not dest.is_dir() or any(dest.iterdir()):
            raise ArtifactError('training artifacts destination is linked or nonempty')
    else:
        dest.mkdir(parents=True)
    (dest / 'labels').mkdir()
    (dest / 'outputs').mkdir()
    for name, sha in sorted(labels.items()):
        source = store / 'labels' / name
        raw = _read_capped(source, MAX_LABEL_BYTES)
        _checked_label(raw, name, sha)
        (dest / 'labels' / name).write_bytes(raw)
    for name, sha in sorted(outputs.items()):
        engine = name.rsplit('.', 2)[-2]
        source = store / 'outputs' / engine / name
        raw = _read_capped(source, OS.MAX_ENGINE_OUTPUT_BYTES)
        _checked_output(raw, name, sha)
        (dest / 'outputs' / name).write_bytes(raw)
    return verify_training_artifacts(reports, dest)
