"""Bounded Tier R training transport; preserve exact bytes and existing managed credit.

No images, source trees, target execution, legacy adoption or final-evaluation lock.
See LBL-DATA-integration-plan section 2.0. Artifact manifests are published last.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from patchtrace import owned_publication as owned

from ..common import canonical_json, digest, strict_json
from . import contracts as C
from . import output_store as OS
from . import report_schemas as RS

CONTRACT = 'tier-r-training-artifacts/1'
MANIFEST = 'training-artifacts.json'
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILES = 10_000
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_BATCH_BYTES = 2 * 1024 * 1024 * 1024


class ArtifactError(ValueError):
    """The complete transport set cannot be credited; source evidence is unchanged."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ShardOwner(_Strict):
    shard: int = Field(ge=0, lt=256)
    of: int = Field(ge=1, le=256)
    plan_sha256: C.Sha256
    shard_sha256: C.Sha256
    reports: tuple[C.Sha256, ...] = Field(min_length=1, max_length=10_000)


class ArtifactFile(_Strict):
    path: str = Field(min_length=1, max_length=160)
    size: int = Field(ge=0, le=RS.MAX_OUTPUT_BYTES)
    sha256: C.Sha256


class TrainingArtifacts(_Strict):
    contract: Literal['tier-r-training-artifacts/1']
    shards: tuple[ShardOwner, ...] = Field(min_length=1, max_length=256)
    files: tuple[ArtifactFile, ...] = Field(max_length=MAX_FILES)
    aggregate_sha256: C.Sha256 | None = None
    merge_sha256: C.Sha256 | None = None
    manifest_sha256: C.Sha256


class _SmokeSummary(_Strict):
    command: Literal['run']
    status: Literal['ok', 'halted']
    train_key: C.Sha256
    report_sha256: C.Sha256
    gates: dict[Literal['G0', 'G1', 'G2', 'G3'], Literal['pass', 'fail', 'insufficient-data']]
    halt: tuple[str, ...] = Field(default=(), max_length=10)
    report: str = Field(min_length=1, max_length=4096)


def _public(function):
    @wraps(function)
    def call(*args, **kwargs):
        from .shard import ShardError
        try:
            return function(*args, **kwargs)
        except ArtifactError:
            raise
        except (C.ContractError, OS.OutputError, owned.OwnedPublicationError, ValidationError, ShardError,
                OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise ArtifactError(f'training artifact refused: {str(exc)[:300]}') from None
    return call


def _refuse(*texts: str) -> None:
    from .shard import ShardError, refuse_microsoft
    try:
        refuse_microsoft(*texts)
    except ShardError as exc:
        raise ArtifactError(str(exc)[:300]) from None


def _path(path: Path) -> Path:
    result = Path(os.path.abspath(path))  # Preserve links for the owned reader to refuse.
    _refuse(result.as_posix())
    return result


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(path: Path, cap: int, anchor: owned.DirectoryAnchor) -> bytes:
    raw = owned.read_bytes(path, maximum=cap, anchor=anchor)
    _refuse(raw.decode('utf-8'))
    return raw


def _scan(folder: Path) -> tuple[owned.DirectoryAnchor, dict[str, int]]:
    """Bound immediate regular JSON members before any file body is materialized."""
    anchor = owned.directory_anchor(folder)
    found = {}
    with os.scandir(folder) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
                    or not entry.name.endswith('.json') or info.st_size > RS.MAX_OUTPUT_BYTES):
                raise ArtifactError('nonregular, linked, non-JSON or oversized training artifact')
            found[entry.name] = info.st_size
            if len(found) > MAX_FILES:
                raise ArtifactError('training artifact file-count limit exceeded')
    if owned.directory_anchor(folder) != anchor:
        raise ArtifactError('training artifact directory changed during enumeration')
    return anchor, found


def _budget(sizes, maximum=MAX_ARTIFACT_BYTES, *, max_files=MAX_FILES) -> None:
    sizes = list(sizes)
    if len(sizes) > max_files or sum(sizes) > maximum:
        raise ArtifactError('training artifact aggregate byte/file limit exceeded')


def _owner(shard: dict) -> dict:
    if (shard.get('contract') != 'tier-r-shard/1'
            or digest(shard, 'shard_sha256') != shard.get('shard_sha256')):
        raise ArtifactError('invalid originating shard identity')
    if any(case.get('status') not in ('ok', 'findings', 'skipped') for case in shard['cases']):
        raise ArtifactError('failed or blocked shard cannot authorize training artifacts')
    requested = shard['engines']
    covered = {engine['engine'] for report in shard['reports'] for engine in report['engines']}
    if not requested or len(set(requested)) != len(requested) or set(requested) != covered:
        raise ArtifactError('originating reports do not cover the exact requested engines')
    owner = {key: shard[key] for key in ('shard', 'of', 'plan_sha256', 'shard_sha256')}
    owner['reports'] = sorted(report['report_sha256'] for report in shard['reports'])
    model = ShardOwner.model_validate_json(canonical_json(owner))
    if model.shard >= model.of or len(set(model.reports)) != len(model.reports):
        raise ArtifactError('ambiguous shard or report ownership')
    return owner


def _references(reports: list[dict]) -> tuple[dict, dict]:
    labels, outputs, seen_reports, seen_pairs = {}, {}, set(), set()
    for raw in reports:
        report = C.load_report(canonical_json(raw))
        _refuse(canonical_json(raw).decode())
        if report.symbols != 'hidden' or report.report_sha256 in seen_reports:
            raise ArtifactError('visible symbols or duplicate report ownership')
        seen_reports.add(report.report_sha256)
        inputs = {}
        for item in report.inputs:
            expected = item.labels_digest, item.stratum
            if item.pair_id in inputs or labels.setdefault(item.pair_id, expected) != expected:
                raise ArtifactError('duplicate or conflicting label ownership')
            inputs[item.pair_id] = expected
        for pair in report.pairs:
            key = pair.pair_id, pair.engine
            if key in seen_pairs or pair.pair_id not in inputs:
                raise ArtifactError('duplicate or foreign pair/engine ownership')
            seen_pairs.add(key)
            if pair.status == 'ok':
                if pair.output_sha256 is None or pair.metrics is None:
                    raise ArtifactError('successful report reference lacks retained evidence')
                outputs[OS.output_file_name(*key)] = (pair.pair_id, pair.engine, pair.output_sha256)
    return labels, outputs


def _label(raw: bytes, pair: str, expected: tuple) -> C.KnownAnswerLabels:
    doc = C.load_labels(raw)
    if (doc.pair_id != pair or (doc.digest_sha256, doc.stratum) != expected
            or any(side.source.license_spdx not in C.PERMISSIVE_SPDX for side in (doc.older, doc.newer))):
        raise ArtifactError('label identity, report digest, stratum or permissive licence differs')
    return doc


@dataclass
class _Dataset:
    reports: list[dict]
    labels: dict[str, tuple[bytes, C.KnownAnswerLabels]]
    outputs: dict[str, tuple[bytes, RS.EngineOutputDoc]]

    def records(self) -> list[dict]:
        return [{'pair_id': name.rsplit('.', 2)[0], 'engine': output.engine,
                 'output_sha256': _hash(raw), 'older_sha256': output.older_sha256,
                 'newer_sha256': output.newer_sha256, 'symbols': output.symbols,
                 'version': output.version} for name, (raw, output) in sorted(self.outputs.items())]


def _bound(raw: bytes, relative: str, expected_files: dict | None) -> bytes:
    if expected_files is not None:
        expected = expected_files.get(relative)
        if expected is None or (len(raw), _hash(raw)) != (expected['size'], expected['sha256']):
            raise ArtifactError('training artifact exact bytes differ from its manifest')
    return raw


def _admit(reports: list[dict], labels_dir: Path, output_dirs: list[Path], *, expected_files: dict | None = None,
           maximum: int | None = None) -> _Dataset:
    expected_labels, expected_outputs = _references(reports)
    labels_dir = _path(labels_dir)
    labels_anchor, label_sizes = _scan(labels_dir)
    folders = [_path(folder) for folder in output_dirs]
    if len(set(folders)) != len(folders) or not folders:
        raise ArtifactError('duplicate or missing managed output run')
    scans = [(folder, *_scan(folder)) for folder in folders]
    if expected_files is not None:
        actual = {f'labels/{name}' for name in label_sizes}
        actual.update(f'outputs/{name}' for _folder, _anchor, files in scans for name in files)
        if len(folders) != 1 or actual != expected_files.keys():
            raise ArtifactError('training artifact members changed during admission')
    sizes = [label_sizes.get(f'{pair}.json', 0) for pair in expected_labels]
    sizes += [size for _folder, _anchor, files in scans for size in files.values()]
    _budget(sizes, MAX_ARTIFACT_BYTES if maximum is None else maximum)
    labels = {pair: (raw, _label(raw, pair, expected)) for pair, expected in sorted(expected_labels.items())
              for raw in [_bound(_read(labels_dir / f'{pair}.json', C.MAX_LABEL_BYTES, labels_anchor),
                                 f'labels/{pair}.json', expected_files)]}
    if expected_files is not None and {f'{pair}.json' for pair in labels} != label_sizes.keys():
        raise ArtifactError('training artifact contains unowned labels')
    outputs, received_reports = {}, {}
    for folder, anchor, _files in scans:
        managed = {name: _bound(_read(folder / name, RS.MAX_CREDIT_BYTES, anchor),
                               f'outputs/{name}', expected_files) for name in OS.MANAGED_FILES}
        credit = strict_json(managed[OS.CREDIT_FILE])
        rows = OS.read_credited_outputs(folder)
        if rows is None:
            raise ArtifactError('legacy output directories cannot acquire transfer credit')
        for report in credit['reports']:
            sha = report['report_sha256']
            if sha in received_reports:
                raise ArtifactError('duplicate managed report ownership')
            received_reports[sha] = report
        for path, raw, model, sha in rows:
            _refuse(raw.decode())
            _bound(raw, f'outputs/{path.name}', expected_files)
            expected = expected_outputs.get(path.name)
            if expected is None or path.name in outputs or sha != expected[2]:
                raise ArtifactError('foreign, duplicate or mismatching credited output')
            label = labels[expected[0]][1]
            if (model.engine != expected[1] or model.symbols != 'hidden'
                    or (model.older_sha256, model.newer_sha256) != (label.older.sha256, label.newer.sha256)):
                raise ArtifactError('output image/engine/symbol identity differs from its labels')
            outputs[path.name] = raw, model
        if (owned.directory_anchor(folder) != anchor
                or any(_read(folder / name, RS.MAX_CREDIT_BYTES, anchor) != raw for name, raw in managed.items())):
            raise ArtifactError('managed source changed during transfer admission')
    if received_reports != {report['report_sha256']: report for report in reports}:
        raise ArtifactError('managed runs do not cover the exact originating reports')
    if outputs.keys() != expected_outputs.keys():
        raise ArtifactError('missing successful output evidence')
    dataset = _Dataset(reports, labels, outputs)
    OS.preflight_credit_manifest(dataset.reports, dataset.records())
    return dataset


def _allowed(path: str) -> bool:
    parts = path.split('/')
    if len(parts) != 2 or parts[0] not in ('labels', 'outputs'):
        return False
    name = parts[1]
    if parts[0] == 'outputs' and name in OS.MANAGED_FILES:
        return True
    if not name.endswith('.json'):
        return False
    try:
        if parts[0] == 'outputs':
            pair, engine, _suffix = name.rsplit('.', 2)
            return OS.output_file_name(pair, engine) == name
        OS.output_file_name(name[:-5], 'rz-diff')
        return True
    except (OS.OutputError, ValueError):
        return False


def _manifest(raw: bytes) -> dict:
    document = strict_json(raw)
    model = TrainingArtifacts.model_validate_json(raw)
    if digest(document, 'manifest_sha256') != model.manifest_sha256:
        raise ArtifactError('training manifest digest differs')
    names = [item.path for item in model.files]
    if names != sorted(set(names)) or not all(_allowed(name) for name in names):
        raise ArtifactError('training manifest filenames are duplicate, unordered or forbidden')
    owners = [owner.shard for owner in model.shards]
    if owners != sorted(set(owners)) or any(owner.shard >= owner.of for owner in model.shards):
        raise ArtifactError('training manifest shard ownership is ambiguous')
    return document


def _manifest_preflight(owners: list[dict], names, aggregate, provenance) -> None:
    # Every eventual size/digest fits these widths. This bounds transport metadata
    # before destination creation; the actual exact bytes are checked again below.
    if len(names) > MAX_FILES:
        raise ArtifactError('training artifact file-count limit exceeded')
    document = {'contract': CONTRACT, 'shards': owners,
                'files': [{'path': name, 'size': RS.MAX_OUTPUT_BYTES, 'sha256': '0' * 64}
                          for name in sorted(names)],
                'aggregate_sha256': aggregate, 'merge_sha256': provenance, 'manifest_sha256': '0' * 64}
    if len(canonical_json(document)) > MAX_MANIFEST_BYTES:
        raise ArtifactError('training transport manifest byte limit exceeded')


def _write(dataset: _Dataset, destination: Path, owners: list[dict], *, aggregate=None, provenance=None) -> dict:
    destination = _path(destination)
    OS.preflight_credit_manifest(dataset.reports, dataset.records())
    expected = {f'labels/{pair}.json': raw for pair, (raw, _model) in dataset.labels.items()}
    expected.update({f'outputs/{name}': raw for name, (raw, _model) in dataset.outputs.items()})
    metadata = {f'outputs/{name}' for name in OS.MANAGED_FILES}
    _manifest_preflight(owners, {*expected, *metadata}, aggregate, provenance)
    existing = destination.parent
    while True:
        try:
            existing.lstat()
            break
        except FileNotFoundError:
            if existing == existing.parent:
                raise
            existing = existing.parent
    parent_anchor = owned.directory_anchor(existing)  # Refuse existing links before mkdir can follow them.
    destination.mkdir(parents=True)  # Exclusive; no failed creation acquires cleanup authority.
    owned.verify_anchor(parent_anchor)
    anchor = owned.directory_anchor(destination)
    (destination / 'labels').mkdir()
    outputs = OS.OutputStore(destination / 'outputs')
    for pair, (raw, _model) in sorted(dataset.labels.items()):
        owned.publish_bytes(destination / 'labels' / f'{pair}.json', raw, anchor=anchor)
    for name, (raw, model) in sorted(dataset.outputs.items()):
        outputs.write_raw(name.rsplit('.', 2)[0], model.engine, raw)
    outputs.finalize(dataset.reports)
    managed = {f'outputs/{name}': _read(destination / 'outputs' / name, RS.MAX_CREDIT_BYTES, anchor)
               for name in OS.MANAGED_FILES}
    if strict_json(managed[f'outputs/{OS.CREDIT_FILE}'])['reports'] != dataset.reports:
        raise ArtifactError('published managed credit belongs to other originating reports')
    OS.read_credited_outputs(destination / 'outputs')
    expected.update(managed)
    entries = []
    for kind in ('labels', 'outputs'):
        _folder_anchor, found = _scan(destination / kind)
        for name, size in sorted(found.items()):
            raw = _read(destination / kind / name, RS.MAX_OUTPUT_BYTES, anchor)
            relative = f'{kind}/{name}'
            if expected.get(relative) != raw:
                raise ArtifactError('published training evidence differs from its admitted source bytes')
            entries.append({'path': relative, 'size': size, 'sha256': _hash(raw)})
    if {item['path'] for item in entries} != {*expected, *metadata}:
        raise ArtifactError('published training artifact file set changed')
    _budget((item['size'] for item in entries), MAX_BATCH_BYTES if len(owners) > 1 else MAX_ARTIFACT_BYTES)
    document = {'contract': CONTRACT, 'shards': owners, 'files': entries,
                'aggregate_sha256': aggregate, 'merge_sha256': provenance}
    document['manifest_sha256'] = digest(document, 'manifest_sha256')
    raw = canonical_json(document)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ArtifactError('training transport manifest byte limit exceeded')
    _manifest(raw)
    owned.publish_bytes(destination / MANIFEST, raw, anchor=anchor)
    return document


@_public
def export_training_artifacts(shard: dict, labels_dir: Path, output_dirs: list[Path], destination: Path) -> dict:
    """Export the exact successful evidence owned by one complete shard, before scratch cleanup."""
    owner = _owner(shard)
    dataset = _admit(shard['reports'], labels_dir, output_dirs)
    return _write(dataset, destination, [owner])


def _artifact_metadata(root: Path, *, maximum: int | None = None) -> tuple[dict, owned.DirectoryAnchor]:
    root = _path(root)
    anchor = owned.directory_anchor(root)
    names = set()
    with os.scandir(root) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > 3:
                raise ArtifactError('unexpected training artifact root members')
    if names != {MANIFEST, 'labels', 'outputs'}:
        raise ArtifactError('unexpected or missing training artifact root members')
    raw = _read(root / MANIFEST, MAX_MANIFEST_BYTES, anchor)
    document = _manifest(raw)
    actual = {}
    for kind in ('labels', 'outputs'):
        _folder_anchor, sizes = _scan(root / kind)
        actual.update({f'{kind}/{name}': size for name, size in sizes.items()})
    expected = {item['path']: item for item in document['files']}
    if actual.keys() != expected.keys() or any(actual[name] != item['size'] for name, item in expected.items()):
        raise ArtifactError('training artifact file set or lengths differ from its manifest')
    _budget(actual.values(), MAX_ARTIFACT_BYTES if maximum is None else maximum)
    if owned.directory_anchor(root) != anchor:
        raise ArtifactError('training artifact root changed during verification')
    return document, anchor


def _artifact_dataset(root: Path, document: dict, anchor: owned.DirectoryAnchor, reports: list[dict], *,
                      maximum: int | None = None) -> _Dataset:
    root = _path(root)
    dataset = _admit(reports, root / 'labels', [root / 'outputs'],
                     expected_files={item['path']: item for item in document['files']}, maximum=maximum)
    if (owned.directory_anchor(root) != anchor
            or _manifest(_read(root / MANIFEST, MAX_MANIFEST_BYTES, anchor)) != document):
        raise ArtifactError('training artifact ownership changed during admission')
    return dataset


@_public
def verify_training_artifacts(shard: dict, root: Path) -> dict:
    """Verify complete shard/report ownership and every exact byte; never use legacy loading."""
    document, anchor = _artifact_metadata(root)
    if (document['shards'] != [_owner(shard)] or document['aggregate_sha256'] is not None
            or document['merge_sha256'] is not None):
        raise ArtifactError('training artifact belongs to another shard or merge')
    _artifact_dataset(root, document, anchor, shard['reports'])
    return document


def _complete_shards(shards: list[dict]) -> tuple[list[dict], list[dict]]:
    from . import shard as S
    if not isinstance(shards, list) or not 1 <= len(shards) <= S.MAX_SHARDS:
        raise ArtifactError('missing or oversized originating shard set')
    owners = [_owner(shard) for shard in shards]
    ordered = sorted(zip(shards, owners, strict=True), key=lambda pair: pair[1]['shard'])
    docs, owners = [pair[0] for pair in ordered], [pair[1] for pair in ordered]
    first = docs[0]
    if ([owner['shard'] for owner in owners] != list(range(first['of']))
            or any((doc['of'], doc['plan_sha256'], doc['seed'], doc['subset']) !=
                   (first['of'], first['plan_sha256'], first['seed'], first['subset']) for doc in docs)
            or type(first['seed']) is not int or first['subset'] not in S.SUBSETS):
        raise ArtifactError('originating shard set is incomplete, duplicate or foreign')
    return docs, owners


@_public
def merge_training_artifacts(shards: list[dict], root: Path, destination: Path,
                             aggregate: dict, provenance: dict) -> dict:
    """Verify every separate shard root, then publish fresh credit for the original reports."""
    from . import shard as S
    docs, owners = _complete_shards(shards)
    if S.merge(docs) != (aggregate, provenance) or provenance['failing_cases']:
        raise ArtifactError('aggregate or merge provenance does not belong to this successful shard set')
    root = _path(root)
    anchor = owned.directory_anchor(root)
    actual = set()
    with os.scandir(root) as entries:
        for entry in entries:
            actual.add(entry.name)
            if len(actual) > len(docs):
                raise ArtifactError('unexpected training shard roots')
    if actual != {f'tier-r-training-{owner["shard"]}' for owner in owners}:
        raise ArtifactError('missing or unexpected training shard roots')
    admitted = []
    for doc, owner in zip(docs, owners, strict=True):
        folder = root / f'tier-r-training-{owner["shard"]}'
        manifest, child_anchor = _artifact_metadata(folder)
        if (manifest['shards'] != [owner] or manifest['aggregate_sha256'] is not None
                or manifest['merge_sha256'] is not None):
            raise ArtifactError('training artifact belongs to another shard or merge')
        admitted.append((doc, folder, manifest, child_anchor))
    _budget((item['size'] for _doc, _folder, manifest, _anchor in admitted for item in manifest['files']),
            MAX_BATCH_BYTES, max_files=MAX_FILES * len(docs))
    combined = _Dataset([], {}, {})
    for doc, folder, manifest, child_anchor in admitted:
        dataset = _artifact_dataset(folder, manifest, child_anchor, doc['reports'])
        combined.reports.extend(dataset.reports)
        for pair, label in dataset.labels.items():
            if pair in combined.labels and combined.labels[pair][0] != label[0]:
                raise ArtifactError('conflicting exact label bytes across shards')
            combined.labels[pair] = label
        if combined.outputs.keys() & dataset.outputs.keys():
            raise ArtifactError('duplicate output ownership across shards')
        combined.outputs.update(dataset.outputs)
    _references(combined.reports)
    if owned.directory_anchor(root) != anchor:
        raise ArtifactError('training shard collection changed during admission')
    return _write(combined, destination, owners, aggregate=aggregate['report_sha256'],
                  provenance=provenance['merge_sha256'])


@_public
def verify_merged_artifacts(root: Path, aggregate: dict, provenance: dict) -> dict:
    """Recheck exact transport, complete original report ownership and reconstructed aggregate."""
    from . import shard as S
    report = C.load_report(canonical_json(aggregate))
    if (provenance.get('contract') != S.MERGE_CONTRACT
            or digest(provenance, 'merge_sha256') != provenance.get('merge_sha256')
            or provenance.get('report_sha256') != report.report_sha256
            or provenance.get('failing_cases') != []
            or any(case['status'] not in ('ok', 'findings', 'skipped') for case in provenance['cases'])
            or type(provenance['seed']) is not int or provenance['subset'] not in S.SUBSETS):
        raise ArtifactError('invalid or unsuccessful training merge provenance')
    _refuse(canonical_json(provenance).decode())
    document, anchor = _artifact_metadata(root, maximum=MAX_BATCH_BYTES)
    owners = document['shards']
    if (document['aggregate_sha256'] != report.report_sha256
            or document['merge_sha256'] != provenance['merge_sha256']
            or [owner['shard'] for owner in owners] != list(range(len(owners)))
            or any(owner['of'] != len(owners) or owner['plan_sha256'] != provenance['plan_sha256'] for owner in owners)
            or [{'shard': owner['shard'], 'shard_sha256': owner['shard_sha256']} for owner in owners] !=
               [{key: item[key] for key in ('shard', 'shard_sha256')} for item in provenance['shards']]
            or any(type(item['cases']) is not int or item['cases'] < 0 for item in provenance['shards'])
            or sum(item['cases'] for item in provenance['shards']) != len(provenance['cases'])):
        raise ArtifactError('consolidated training ownership differs from merge provenance')
    root = _path(root)
    credit_raw = _read(root / 'outputs' / OS.CREDIT_FILE, RS.MAX_CREDIT_BYTES, anchor)
    _bound(credit_raw, f'outputs/{OS.CREDIT_FILE}', {item['path']: item for item in document['files']})
    reports = strict_json(credit_raw)['reports']
    by_sha = {item['report_sha256']: item for item in reports}
    expected = [sha for owner in owners for sha in owner['reports']]
    if len(expected) != len(set(expected)) or len(by_sha) != len(reports) or set(expected) != by_sha.keys():
        raise ArtifactError('consolidated managed reports have missing, duplicate or foreign shard owners')
    _artifact_dataset(root, document, anchor, reports, maximum=MAX_BATCH_BYTES)
    reconstructed = []
    for owner in owners:
        original = [by_sha[sha] for sha in owner['reports']]
        reconstructed.append({'reports': original, 'engines': sorted({e['engine'] for r in original for e in r['engines']}),
                              'cases': [], 'labels': [], 'features': [], 'shard': owner['shard'],
                              'shard_sha256': owner['shard_sha256'], 'seed': provenance['seed'],
                              'subset': provenance['subset'], 'plan_sha256': provenance['plan_sha256']})
    if S.merge(reconstructed)[0] != aggregate:
        raise ArtifactError('aggregate does not reproduce the credited original reports')
    return document


@_public
def read_document(path: Path, *, maximum: int = C.MAX_LABEL_BYTES) -> dict:
    """Read one explicit CLI report/provenance through the same bounded strict JSON boundary."""
    path = _path(path)
    document = strict_json(_read(path, maximum, owned.directory_anchor(path.parent)))
    if not isinstance(document, dict):
        raise ArtifactError('expected a JSON document')
    return document


@_public
def verify_smoke_result(summary: dict, report: dict, exit_code: int) -> dict:
    """Accept a verified unlocked result; only the existing lineage floor may explain exit 1."""
    from .. import report as R
    from .. import train as T
    from ..contracts import CalibrationReport
    model = _SmokeSummary.model_validate_json(canonical_json(summary))
    CalibrationReport.model_validate_json(canonical_json(report))
    R.verify_tier_r_report(report)
    cfg = T.TrainConfig.smoke_config()
    dataset = report['dataset']
    count = dataset.get('n_lineages_natural')
    if (type(exit_code) is not int or exit_code not in (0, 1)
            or report['prereg_sha256'] is not None or dataset.get('preregistered') is not False
            or dataset.get('origin') != 'labels+outputs' or dataset.get('config') != cfg.as_dict()
            or dataset.get('config_digest') != cfg.digest()
            or model.train_key != dataset.get('train_key') or model.report_sha256 != report['report_sha256']
            or model.gates != {key: value['status'] for key, value in report['gates'].items()}
            or type(count) is not int or not 0 <= count <= MAX_FILES):
        raise ArtifactError('training result is not the same verified unlocked smoke run')
    expected_halt = T.lineage_guard([str(index) for index in range(count)], {}, cfg)
    if (exit_code != bool(expected_halt) or list(model.halt) != expected_halt
            or model.status != ('halted' if expected_halt else 'ok')
            or expected_halt and set(model.gates.values()) != {'insufficient-data'}):
        raise ArtifactError('training exit or halt is not explained solely by the minimum-lineage guard')
    return {'status': 'insufficient-data' if expected_halt else 'ok', 'exit_code': exit_code,
            'train_key': model.train_key, 'report_sha256': model.report_sha256, 'gates': model.gates,
            'unlocked': True, 'smoke': True}


@_public
def verify_smoke_result_files(summary: Path, report: Path, exit_code: int) -> dict:
    # Calibration reports contain the fixed "Tier W rung: not-run" scope copy.
    # Their strict report validator, rather than the data-artifact token scanner,
    # admits that copy; paths and reads retain the same owned/bounded boundary.
    def read(path: Path, maximum: int):
        path = _path(path)
        return strict_json(owned.read_bytes(path, maximum=maximum, anchor=owned.directory_anchor(path.parent)))
    return verify_smoke_result(read(summary, 1024 * 1024), read(report, C.MAX_LABEL_BYTES), exit_code)
