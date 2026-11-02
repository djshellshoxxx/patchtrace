"""Exact, manifest-last Tier R shard transfer; no directory discovery earns credit.

The preserved PR #78 supplies the transfer intent (repository MIT license).
This implementation consumes the current managed report-credit API instead.
"""
from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..common import canonical_json, digest, strict_json
from . import contracts as C
from . import output_store as OS

CONTRACT = 'tier-r-training/1'
MANIFEST = 'manifest.json'
MAX_MANIFEST = 8 * 1024 * 1024


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class TransferCase(_Strict):
    id: str = Field(min_length=1, max_length=512)
    status: Literal['ok', 'findings', 'failed', 'timeout', 'blocked', 'skipped']
    reason: str | None = Field(max_length=1000)
    digest: C.Sha256 | None


class ShardOwner(_Strict):
    plan_sha256: C.Sha256
    shard_sha256: C.Sha256
    shard: int = Field(ge=0, le=255)
    of: int = Field(ge=1, le=256)
    seed: int
    subset: Literal['smoke', 'suites', 'cards', 'mutations', 'noise', 'full']
    cases: tuple[TransferCase, ...] = Field(max_length=10000)
    pair_cases: dict[C.Ident, str] = Field(max_length=200000)


class MergeOwner(_Strict):
    plan_sha256: C.Sha256
    shards: tuple[ShardOwner, ...] = Field(min_length=1, max_length=256)


class PairOwner(_Strict):
    shard: int = Field(ge=0, le=255)
    case: str = Field(min_length=1, max_length=512)


class TrainingManifest(_Strict):
    contract: Literal['tier-r-training/1']
    owner: ShardOwner | MergeOwner
    pair_cases: dict[C.Ident, str | PairOwner] = Field(max_length=200000)
    reports: tuple[C.Sha256, ...] = Field(min_length=1, max_length=10000)
    files: dict[str, C.Sha256] = Field(max_length=400000)
    manifest_sha256: C.Sha256


def schema_text() -> str:
    schema = TrainingManifest.model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/{CONTRACT}/TrainingManifest.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    return json.dumps(schema, indent=2, sort_keys=True) + '\n'


def write_schema(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / 'TrainingManifest.json'
    path.write_text(schema_text(), encoding='utf-8', newline='\n')
    return path


class ArtifactError(ValueError):
    """An incomplete, foreign, linked or inconsistent transfer cannot be credited."""


def _json(raw: bytes):
    try:
        return strict_json(raw)
    except (ValueError, RecursionError) as exc:
        raise ArtifactError(f'invalid training JSON: {type(exc).__name__}') from None


def checked_path(path: Path, *, missing: bool = False) -> tuple:
    """Inspect every lexical component, including parents with Windows reparse attributes."""
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    # Preserve '..' until all preceding components have been inspected: abspath
    # would hide a link before '..', while subsequent IO still follows that link.
    if any(part.lower() in ('tier-w', 'tier_w') for part in path.parts):
        raise ArtifactError('Tier W is forbidden in training transfers')
    identities = []
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise ArtifactError('missing training artifact or parent') from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ArtifactError('linked/reparse training artifact or parent')
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise ArtifactError('non-directory training parent')
        identities.append((str(item), info.st_dev, info.st_ino))
    return tuple(identities)


def read_bytes(path: Path, cap: int = C.MAX_LABEL_BYTES) -> bytes:
    before = checked_path(path)
    raw = OS.read_output_bytes(path, cap)
    if checked_path(path) != before:
        raise ArtifactError('training artifact parent ownership changed')
    return raw


def publish_bytes(path: Path, raw: bytes) -> None:
    checked_path(path, missing=True)
    before = checked_path(path.parent)
    OS.publish_bytes(path, raw)
    if checked_path(path.parent) != before:
        raise ArtifactError('training destination parent ownership changed')
    if read_bytes(path, max(len(raw), 1)) != raw:
        raise ArtifactError('training destination bytes changed')


def _fresh(folder: Path) -> None:
    checked_path(folder, missing=True)
    folder.parent.mkdir(parents=True, exist_ok=True)
    before = checked_path(folder.parent)
    folder.mkdir(mode=0o700, exist_ok=False)
    if checked_path(folder.parent) != before:
        raise ArtifactError('training destination parent ownership changed')
    checked_path(folder)


def inside(scratch: Path, path: str | Path) -> Path:
    """Check lexical ownership before canonicalizing nonlinked filesystem aliases."""
    scratch, path = Path(scratch), Path(path)
    original_scratch, original_path = checked_path(scratch), checked_path(path)
    canonical_scratch, canonical_path = scratch.resolve(strict=True), path.resolve(strict=True)
    final_scratch, final_path = checked_path(canonical_scratch), checked_path(canonical_path)
    if (original_scratch[-1][1:] != final_scratch[-1][1:]
            or original_path[-1][1:] != final_path[-1][1:]
            or checked_path(scratch) != original_scratch or checked_path(path) != original_path):
        raise ArtifactError('producer artifact ownership changed during path normalization')
    if not canonical_scratch.is_dir():
        raise ArtifactError('shard scratch is not a directory')
    try:
        canonical_path.relative_to(canonical_scratch)
    except ValueError:
        raise ArtifactError('producer artifact is outside its shard scratch') from None
    return canonical_path


def pair_name(pair: str) -> str:
    OS.output_file_name(pair, 'rz-diff')  # shared validated identifier alphabet
    return f'{pair}.json'


def shard_owner(doc: dict) -> dict:
    if 'pair_cases' not in doc:
        raise ArtifactError('shard lacks verified builder case ownership')
    return {key: doc[key] for key in ('plan_sha256', 'shard_sha256', 'shard', 'of', 'seed', 'subset', 'cases',
                                    'pair_cases')}


def _case_ownership(owner: dict, pair_cases: dict, pairs: set[str]) -> None:
    shards = [owner] if 'cases' in owner else owner['shards']
    expected, indices = {}, set()
    for shard in shards:
        if shard['shard'] in indices or shard['plan_sha256'] != owner['plan_sha256']:
            raise ArtifactError('duplicate or foreign shard ownership')
        indices.add(shard['shard'])
        allowed = {c['id'] for c in shard['cases'] if c['status'] in ('ok', 'findings')
                   and not c['id'].startswith(('evaluate:', 'transfer:'))}
        for pair, case in shard['pair_cases'].items():
            if not isinstance(case, str) or case not in allowed or pair in expected:
                raise ArtifactError('duplicate, foreign or incomplete producing case')
            expected[pair] = case if 'cases' in owner else {'shard': shard['shard'], 'case': case}
    if set(expected) != pairs or pair_cases != expected:
        raise ArtifactError('manifest case ownership differs from diagnostic shard')


def _managed_outputs(folder: Path) -> list[tuple]:
    before = checked_path(folder)
    records = OS.read_credited_outputs(folder)
    if records is None:
        raise ArtifactError('source output run has no managed credit')
    for path, raw, _model, _sha in records:
        if read_bytes(path) != raw:
            raise ArtifactError('credited output changed during transfer verification')
    if checked_path(folder) != before:
        raise ArtifactError('managed output parent ownership changed')
    return records


def _references(reports: Sequence[dict]) -> dict[str, tuple[str, str]]:
    labels, seen, report_ids = {}, set(), set()
    for report in reports:
        model = C.load_report(canonical_json(report))
        if model.report_sha256 in report_ids:
            raise ArtifactError('duplicate training report')
        report_ids.add(model.report_sha256)
        inputs = {row.pair_id: (row.labels_digest, row.stratum) for row in model.inputs}
        engines = {row.engine for row in model.engines}
        if len(inputs) != len(model.inputs) or len(engines) != len(model.engines):
            raise ArtifactError('ambiguous report input/provider ownership')
        for pair, ref in inputs.items():
            pair_name(pair)
            if labels.setdefault(pair, ref) != ref:
                raise ArtifactError('conflicting training label reference')
        for row in model.pairs:
            key = row.pair_id, row.engine
            if key in seen or row.pair_id not in inputs or row.engine not in engines:
                raise ArtifactError('duplicate or foreign report pair/provider ownership')
            seen.add(key)
            if row.stratum != inputs[row.pair_id][1]:
                raise ArtifactError('report pair stratum differs from label reference')
            if row.status == 'ok' and (row.output_sha256 is None or row.metrics is None):
                raise ArtifactError('successful report reference lacks credit')
            if row.status != 'ok' and (row.output_sha256 is not None or row.metrics is not None):
                raise ArtifactError('failed report reference carries credit')
    return labels


def _validate(reports: list[dict], labels: dict[str, bytes], outputs: list[tuple]) -> None:
    from .shard import refuse_microsoft

    refs = _references(reports)
    if set(labels) != set(refs):
        raise ArtifactError('labels do not exactly cover report inputs')
    models = {}
    for pair, raw in labels.items():
        refuse_microsoft(raw.decode('utf-8'))
        model = C.load_labels(raw)
        if (model.pair_id, model.digest_sha256, model.stratum) != (pair, *refs[pair]):
            raise ArtifactError('label identity/digest/stratum differs from report')
        models[pair] = model
    expected = {(r['pair_id'], r['engine']): (r['output_sha256'], report['symbols'])
                for report in reports for r in report['pairs'] if r['status'] == 'ok'}
    found = set()
    for name, raw, model, sha in outputs:
        refuse_microsoft(raw.decode('utf-8'))
        pair = Path(name).name.rsplit('.', 2)[0]
        key = pair, model.engine
        if key in found or key not in expected or (sha, model.symbols) != expected[key]:
            raise ArtifactError('duplicate or foreign credited output')
        if Path(name).name != OS.output_file_name(*key) or hashlib.sha256(raw).hexdigest() != sha:
            raise ArtifactError('output filename or exact digest differs')
        label = models[pair]
        hashes = ((label.older.sha256, label.newer.sha256) if model.symbols == 'hidden'
                  else (label.older.debug_sha256, label.newer.debug_sha256))
        if (model.older_sha256, model.newer_sha256) != hashes:
            raise ArtifactError('output ordered image ownership differs from label')
        found.add(key)
    if found != expected.keys():
        raise ArtifactError('successful report references are incomplete')


def _inventory(root: Path, files: set[str]) -> None:
    """Check fixed directories only; extras are rejected, never adopted."""
    expected = {MANIFEST, 'labels', 'outputs', 'reports'}
    checked_path(root)
    if {p.name for p in root.iterdir()} != expected:
        raise ArtifactError('unexpected or missing training bundle entry')
    for kind in ('labels', 'outputs', 'reports'):
        folder = root / kind
        checked_path(folder)
        if not folder.is_dir() or {p.name for p in folder.iterdir()} != {
                name.split('/')[1] for name in files if name.startswith(kind + '/')}:
            raise ArtifactError('unexpected or missing training file')


def _write_bundle(root: Path, owner: dict, pair_cases: dict, report_bytes: list[bytes],
                  labels: dict[str, bytes], outputs: list[tuple]) -> dict:
    reports = [_json(raw) for raw in report_bytes]
    _validate(reports, labels, outputs)
    _case_ownership(owner, pair_cases, set(labels))
    OS.preflight_credit_manifest(reports, [
        {'pair_id': Path(name).name.rsplit('.', 2)[0], 'engine': model.engine, 'output_sha256': sha,
         'older_sha256': model.older_sha256, 'newer_sha256': model.newer_sha256,
         'symbols': model.symbols, 'version': model.version}
        for name, _raw, model, sha in outputs])
    _fresh(root)
    for kind in ('labels', 'reports'):
        (root / kind).mkdir()
    checked_path(root / 'outputs', missing=True)
    store = OS.OutputStore(root / 'outputs')
    for pair, raw in sorted(labels.items()):
        publish_bytes(root / 'labels' / pair_name(pair), raw)
    for raw, report in zip(report_bytes, reports, strict=True):
        publish_bytes(root / 'reports' / (report['report_sha256'] + '.json'), raw)
    for name, raw, model, _sha in outputs:
        checked_path(store.folder)
        store.write_raw(Path(name).name.rsplit('.', 2)[0], model.engine, raw)
    checked_path(store.folder)
    store.finalize(reports)
    paths = ([f'labels/{pair_name(pair)}' for pair in labels]
             + [f'reports/{r["report_sha256"]}.json' for r in reports]
             + [f'outputs/{Path(row[0]).name}' for row in outputs]
             + [f'outputs/{name}' for name in OS.MANAGED_FILES])
    files = {name: hashlib.sha256(read_bytes(root / name)).hexdigest() for name in sorted(paths)}
    manifest = {'contract': CONTRACT, 'owner': owner, 'pair_cases': pair_cases,
                'reports': [r['report_sha256'] for r in reports], 'files': files}
    manifest['manifest_sha256'] = digest(manifest, 'manifest_sha256')
    raw_manifest = canonical_json(manifest)
    if len(raw_manifest) > MAX_MANIFEST:
        raise ArtifactError('training manifest exceeds its byte limit')
    TrainingManifest.model_validate_json(raw_manifest)
    publish_bytes(root / MANIFEST, raw_manifest)
    verify_bundle(root, owner=owner, expected_reports=reports)
    return manifest


def export_training_artifacts(doc: dict, scratch: Path, destination: Path, sources: list[tuple],
                              pair_cases: dict[str, str]) -> dict:
    """Explicit (provider, report path, managed run) sources; no scratch glob adoption."""
    reports, raw_reports, outputs = [], [], []
    for engine, report_path, output_path in sources:
        raw = read_bytes(inside(scratch, report_path))
        report = _json(raw)
        C.load_report(raw)
        if [row['engine'] for row in report['engines']] != [engine] or engine not in doc['engines']:
            raise ArtifactError('report differs from requested provider ownership')
        folder = inside(scratch, output_path)
        records = _managed_outputs(folder)
        credits = _json(read_bytes(folder / OS.CREDIT_FILE))
        if credits['reports'] != [report]:
            raise ArtifactError('source managed report differs from evaluator report')
        for path, *_rest in records:
            checked_path(path)
        raw_reports.append(raw)
        reports.append(report)
        outputs.extend(records)
    if reports != doc['reports'] or not reports:
        raise ArtifactError('diagnostic shard and explicit evaluator reports differ or are absent')
    refs = _references(reports)
    if set(pair_cases) != set(refs):
        raise ArtifactError('report labels lack exact builder case ownership')
    allowed = {c['id'] for c in doc['cases'] if c['status'] in ('ok', 'findings')
               and not c['id'].startswith('evaluate:')}
    if any(case not in allowed for case in pair_cases.values()):
        raise ArtifactError('label producing case was not completed')
    labels = {pair: read_bytes(inside(scratch, scratch / 'known-answer' / 'labels' / pair_name(pair)))
              for pair in refs}
    return _write_bundle(destination, shard_owner(doc), pair_cases, raw_reports, labels, outputs)


def verify_bundle(root: Path, *, owner: dict, expected_reports: list[dict]) -> tuple:
    raw = read_bytes(root / MANIFEST, MAX_MANIFEST)
    manifest = _json(raw)
    TrainingManifest.model_validate_json(raw)
    if canonical_json(manifest) != raw:
        raise ArtifactError('training manifest bytes are not canonical')
    if (not isinstance(manifest, dict) or set(manifest) != {
            'contract', 'owner', 'pair_cases', 'reports', 'files', 'manifest_sha256'}
            or manifest['contract'] != CONTRACT or manifest['owner'] != owner
            or digest(manifest, 'manifest_sha256') != manifest['manifest_sha256']):
        raise ArtifactError('training manifest ownership/digest mismatch')
    refs = _references(expected_reports)
    reports = [r['report_sha256'] for r in expected_reports]
    if manifest['reports'] != reports or set(manifest['pair_cases']) != set(refs):
        raise ArtifactError('manifest report or case ownership differs')
    _case_ownership(owner, manifest['pair_cases'], set(refs))
    paths = ({f'labels/{pair_name(pair)}' for pair in refs}
             | {f'reports/{sha}.json' for sha in reports}
             | {f'outputs/{name}' for name in OS.MANAGED_FILES}
             | {f'outputs/{OS.output_file_name(row["pair_id"], row["engine"])}'
                for report in expected_reports for row in report['pairs'] if row['status'] == 'ok'})
    if set(manifest['files']) != paths:
        raise ArtifactError('manifest file set differs from successful references')
    _inventory(root, paths)
    blobs = {name: read_bytes(root / name) for name in sorted(paths)}
    if any(hashlib.sha256(raw).hexdigest() != manifest['files'][name] for name, raw in blobs.items()):
        raise ArtifactError('training exact byte digest mismatch')
    raw_reports = [blobs[f'reports/{sha}.json'] for sha in reports]
    if [_json(raw) for raw in raw_reports] != expected_reports:
        raise ArtifactError('transferred reports differ from shard diagnostics')
    credits = _json(blobs[f'outputs/{OS.CREDIT_FILE}'])
    if credits['reports'] != expected_reports:
        raise ArtifactError('managed credit differs from transferred reports')
    outputs = _managed_outputs(root / 'outputs')
    labels = {pair: blobs[f'labels/{pair_name(pair)}'] for pair in refs}
    _validate(expected_reports, labels, outputs)
    if read_bytes(root / MANIFEST, MAX_MANIFEST) != raw:
        raise ArtifactError('training manifest changed during verification')
    return raw_reports, labels, outputs, manifest['pair_cases']


def merge_training_artifacts(docs: list[dict], source: Path, destination: Path) -> dict:
    reports, labels, outputs, cases = [], {}, [], {}
    for doc in docs:
        # Check the training parent too; checking only shard-N misses Windows junctions.
        checked_path(source)
        raw_reports, shard_labels, shard_outputs, owners = verify_bundle(
            source / f'shard-{doc["shard"]}', owner=shard_owner(doc), expected_reports=doc['reports'])
        if labels.keys() & shard_labels.keys():
            raise ArtifactError('duplicate pair ownership across shards')
        reports.extend(raw_reports)
        labels.update(shard_labels)
        outputs.extend(shard_outputs)
        cases.update({pair: {'shard': doc['shard'], 'case': case} for pair, case in owners.items()})
    owner = {'plan_sha256': docs[0]['plan_sha256'], 'shards': [shard_owner(doc) for doc in docs]}
    return _write_bundle(destination, owner, cases, reports, labels, outputs)
