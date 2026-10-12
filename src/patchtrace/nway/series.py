"""series.json persistence, pair-project discovery/validation and stale detection (SPEC-09).

Pair projects are ordinary two-artifact projects opened through ProjectService, which holds
the single-writer lock; each is opened only long enough to copy its snapshot. Discovery
identifies projects by their ordered artifact hashes, never by directory name, so the
result does not depend on how directories happen to be named or listed.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..models import ComparisonProject
from ..persistence import strict_json
from .contracts import MAX_BUILDS, BuildRef, Chain, NwayError, PairRef, Series
from .graph import extract_chains, series_id, validate_builds, validate_pair

SERIES_FILE = 'series.json'
MAX_SERIES_BYTES = 256 * 1024 * 1024
PROJECT_FILE = 'project.sqlite3'


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open('rb') as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                digest.update(chunk)
    except OSError as exc:
        raise NwayError('PT-NWAY-INPUT', f'cannot read build {Path(path).name}: {exc.strerror or exc}') from None
    return digest.hexdigest()


def read_project(path: Path) -> ComparisonProject:
    from ..service import ProjectService
    try:
        service = ProjectService.open(path)
    except ValueError as exc:
        raise NwayError('PT-NWAY-PAIR', f'cannot open pair project {Path(path).name}: {exc}') from None
    try:
        return service.project.model_copy(deep=True)
    finally:
        service.close()


def current_run_id(project: ComparisonProject) -> str | None:
    completed = [run.id for run in project.runs if run.status in {'completed', 'identical'}]
    return completed[-1] if completed else None


def pair_ref(root: Path, path: Path, project: ComparisonProject, from_ordinal: int, to_ordinal: int) -> PairRef:
    return PairRef(from_ordinal=from_ordinal, to_ordinal=to_ordinal,
                   path=Path(path).resolve().relative_to(Path(root).resolve()).as_posix(),
                   project_id=project.id, revision=project.revision, run_id=current_run_id(project))


def discover_pairs(root: Path, wanted: dict[tuple[str, str], tuple[int, int]]) -> dict[tuple[int, int], Path]:
    """Map wanted ordered hash pairs to the unique project directory below root holding each."""
    found: dict[tuple[int, int], list[Path]] = {}
    root = Path(root)
    if not root.is_dir():
        return {}
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if child.is_symlink() or not child.is_dir() or not (child / PROJECT_FILE).is_file():
            continue
        project = read_project(child)
        sides = {a.side: a.sha256 for a in project.artifacts}
        ordinals = wanted.get((sides['older'], sides['newer']))
        if ordinals is not None:
            found.setdefault(ordinals, []).append(child)
    duplicates = {k: v for k, v in found.items() if len(v) > 1}
    if duplicates:
        (i, j), paths = sorted(duplicates.items())[0]
        raise NwayError('PT-NWAY-PAIR', f'builds {i}→{j} have several pair projects '
                        f'({", ".join(p.name for p in paths)}); keep exactly one')
    return {k: v[0] for k, v in found.items()}


@dataclass
class SeriesPlan:
    root: Path
    hashes: list[str]
    labels: list[str]
    pair_paths: list[Path]
    direct_path: Path | None = None
    created: list[Path] = field(default_factory=list)


def prepare(files: list[Path], root: Path, labels: list[str] | None = None, direct: bool = False) -> SeriesPlan:
    """Validate builds, then reuse or create one pair project per adjacent pair (and first→last if asked)."""
    from ..service import ProjectService
    if not 3 <= len(files) <= MAX_BUILDS:
        raise NwayError('PT-NWAY-INPUT', f'a series needs 3–{MAX_BUILDS} builds, got {len(files)}')
    if labels is not None and len(labels) != len(files):
        raise NwayError('PT-NWAY-INPUT', '--labels must give one label per build')
    labels = list(labels) if labels is not None else [Path(f).name[:64] for f in files]
    if any(not label.strip() or len(label) > 64 for label in labels):
        raise NwayError('PT-NWAY-INPUT', 'build labels must be 1–64 characters')
    hashes = [sha256_file(f) for f in files]
    validate_builds(hashes)
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    wanted = {(hashes[i], hashes[i + 1]): (i, i + 1) for i in range(len(hashes) - 1)}
    if direct:
        wanted[(hashes[0], hashes[-1])] = (0, len(hashes) - 1)
    existing = discover_pairs(root, wanted)
    plan = SeriesPlan(root, hashes, labels, [])
    for (older, newer), (i, j) in wanted.items():
        path = existing.get((i, j))
        if path is None:
            path = root / f'pair-{i}-{j}-{older[:12]}-{newer[:12]}'
            if path.exists():
                raise NwayError('PT-NWAY-PAIR', f'{path.name} exists but does not hold builds {i}→{j}')
            try:
                service = ProjectService.create(files[i], files[j], f'{labels[i]} → {labels[j]}', path)
            except ValueError as exc:
                raise NwayError('PT-NWAY-INPUT', f'cannot create pair project {i}→{j}: {exc}') from None
            service.close()
            plan.created.append(path)
        if (i, j) == (0, len(hashes) - 1) and direct:
            plan.direct_path = path
        else:
            plan.pair_paths.append(path)
    return plan


def compute(plan: SeriesPlan) -> Series:
    pairs = [read_project(p) for p in plan.pair_paths]
    direct = read_project(plan.direct_path) if plan.direct_path is not None else None
    chains, node_count = extract_chains(plan.hashes, pairs, direct)
    return Series(
        series_id=series_id(plan.hashes),
        builds=tuple(BuildRef(ordinal=i, label=label, artifact_sha256=sha)
                     for i, (label, sha) in enumerate(zip(plan.labels, plan.hashes, strict=True))),
        pair_projects=tuple(pair_ref(plan.root, path, project, i, i + 1)
                            for i, (path, project) in enumerate(zip(plan.pair_paths, pairs, strict=True))),
        direct_project=None if direct is None else pair_ref(plan.root, plan.direct_path, direct, 0,
                                                            len(plan.hashes) - 1),
        node_count=node_count, chains=tuple(chains))


def dumps(series: Series) -> str:
    # No timestamps or absolute paths: identical inputs must give byte-identical files.
    return json.dumps(series.model_dump(mode='json', by_alias=True), sort_keys=True, indent=2,
                      ensure_ascii=False, allow_nan=False) + '\n'


def save(series: Series, path: Path) -> None:
    path = Path(path)
    if path.exists():
        previous = load(path)
        if previous.series_id != series.series_id:
            raise NwayError('PT-NWAY-STORAGE', f'{path.name} belongs to another series; use a different --root')
    fd, temporary = tempfile.mkstemp(prefix='.series-', dir=path.parent)
    stage = Path(temporary)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(dumps(series))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(stage, path)
    finally:
        stage.unlink(missing_ok=True)


def load(path: Path) -> Series:
    path = Path(path)
    try:
        if path.stat().st_size > MAX_SERIES_BYTES:
            raise NwayError('PT-NWAY-LIMIT', f'{path.name} exceeds {MAX_SERIES_BYTES} bytes')
        text = path.read_text(encoding='utf-8')
        strict_json(text)  # rejects duplicate keys and non-finite constants before validation
        return Series.model_validate_json(text)
    except NwayError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise NwayError('PT-NWAY-STORAGE', f'{path.name} is not a valid nway/1 series: {exc}') from None


@dataclass(frozen=True)
class Staleness:
    pairs: frozenset[int]  # from_ordinal of each adjacent pair whose project changed
    direct: bool
    reasons: tuple[str, ...]

    def chain_stale(self, chain: Chain, last: int) -> bool:
        if any(edge.from_node.ordinal in self.pairs for edge in chain.edges):
            return True
        return self.direct and chain.nodes[0].ordinal == 0 and chain.nodes[-1].ordinal == last


def staleness(series: Series, series_path: Path) -> Staleness:
    root = Path(series_path).resolve().parent
    hashes = [b.artifact_sha256 for b in series.builds]
    stale, direct, reasons = set(), False, []
    refs = [*series.pair_projects, *([series.direct_project] if series.direct_project else [])]
    for ref in refs:
        label = f'pair {ref.from_ordinal}→{ref.to_ordinal}'
        target = (root / ref.path).resolve()
        reason = None
        if not target.is_relative_to(root) or not (target / PROJECT_FILE).is_file():
            reason = f'{label}: project {ref.path} is missing'
        else:
            try:
                project = read_project(target)
                validate_pair(project, hashes[ref.from_ordinal], hashes[ref.to_ordinal])
                if project.id != ref.project_id:
                    reason = f'{label}: a different project now occupies {ref.path}'
                elif (project.revision, current_run_id(project)) != (ref.revision, ref.run_id):
                    reason = f'{label}: project changed (revision {ref.revision}→{project.revision})'
            except NwayError as exc:
                reason = f'{label}: {exc}'
        if reason:
            reasons.append(reason)
            if series.direct_project is ref:
                direct = True
            else:
                stale.add(ref.from_ordinal)
    return Staleness(frozenset(stale), direct, tuple(reasons))
