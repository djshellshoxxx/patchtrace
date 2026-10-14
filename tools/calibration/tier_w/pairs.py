"""Pair builder and `calibration-corpus/1` manifest writer for Tier W (SPEC-33 s3.4-3.8). Pure: no network.

Adjacent pairs = consecutive builds of one OS build line (monthly cumulative updates, with KB annotations);
cross-version pairs = consecutive selected lines (feature updates), the 'large rewrite' stratum.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from ..common import canonical_json
from ..contracts import ContractError, load_manifest
from ..lineage import assign_roles
from .catalogue import CLASSES, version_tuple
from .contracts import Catalogue, CatalogueBuild, Coverage, KbLine, PairBinary, PairEntry, PairsDoc
from .paths import TIER, TierWError, check_corpus_id, stem

X64 = 34404
MIN_FILES = 6
SALT = 'c9-v1'


@dataclass(frozen=True)
class PairParams:
    lines: tuple[str, ...] | None = None
    recent_lines: int = 2
    max_adjacent: int = 4
    since: str | None = None
    cross: bool = True
    security_only: bool = False

    def __post_init__(self):
        if self.recent_lines < 1 or self.max_adjacent < 0 or self.max_adjacent > 1000:
            raise TierWError('PT-TIERW-INPUT', 'recent_lines must be >= 1 and max_adjacent 0..1000')

    def as_dict(self) -> dict:
        return {'lines': self.lines, 'recent_lines': self.recent_lines, 'max_adjacent': self.max_adjacent,
                'since': self.since, 'cross': self.cross, 'security_only': self.security_only}


def binary_id(sha256: str) -> str:
    return f'w-{sha256[:16]}'


def pair_id(file_name: str, older_sha: str, newer_sha: str) -> str:
    return f'tw.{stem(file_name)}.{hashlib.sha256(f"{older_sha}|{newer_sha}".encode()).hexdigest()[:10]}'


def lineage_id(file_name: str) -> str:
    return f'L-w-{stem(file_name, 58)}'


@dataclass(frozen=True)
class Placed:
    date: str
    version: tuple[int, ...]
    build: CatalogueBuild
    kbs: tuple[KbLine, ...]

    @property
    def key(self):
        return (self.date, self.version, self.build.sha256)


def first_in_line(build: CatalogueBuild, line: str, security_only: bool) -> tuple[str, tuple[KbLine, ...]] | None:
    kbs = [k for k in build.lines.get(line, ()) if k.date and (not security_only or k.kind in ('monthly', 'base'))]
    if not kbs:
        return None
    first = min(k.date for k in kbs)
    return first, tuple(k for k in kbs if k.date == first)


def line_number(builds: Sequence[CatalogueBuild], line: str) -> int | None:
    """Most common major of releaseVersion among the line's KBs (ties: the smaller)."""
    majors = Counter(int(k.release.split('.')[0]) for b in builds for k in b.lines.get(line, ()) if k.release)
    if not majors:
        return None
    top = max(majors.values())
    return min(m for m, c in majors.items() if c == top)


@dataclass
class FilePlan:
    pairs: list[dict]
    used: dict[str, CatalogueBuild]
    exclusions: Counter
    lines: tuple[str, ...]


def plan_file(cat: Catalogue, params: PairParams) -> FilePlan:
    exclusions: Counter = Counter()
    eligible = []
    for b in cat.builds:
        if b.machine != X64:
            exclusions['non-x64'] += 1
        elif not b.size_of_image:
            exclusions[f'download-{b.download}'] += 1
        else:
            eligible.append(b)
    by_line: dict[str, list[Placed]] = {}
    for b in eligible:
        dated = False
        for line in b.lines:
            first = first_in_line(b, line, params.security_only)
            if first is not None:
                by_line.setdefault(line, []).append(Placed(first[0], version_tuple(b.version), b, first[1]))
                dated = True
        if not dated:
            exclusions['undated'] += 1
    for placed in by_line.values():
        placed.sort(key=lambda p: p.key)
    numbers = {line: line_number(eligible, line) for line in by_line}
    if params.lines is not None:
        selected = [line for line in params.lines if line in by_line]
        exclusions['line-not-present'] += len(params.lines) - len(selected)
    else:
        ranked = sorted((line for line in by_line if len(by_line[line]) >= 2 and numbers[line] is not None),
                        key=lambda line: (numbers[line], line), reverse=True)
        selected = ranked[:params.recent_lines]
    selected = sorted(selected, key=lambda line: (numbers.get(line) if numbers.get(line) is not None else -1, line))
    found: dict[tuple[str, str], dict] = {}

    def add(older: Placed, newer: Placed, kind: str, line_tag: str, lines: tuple[str, ...]):
        if older.build.sha256 == newer.build.sha256:
            return
        key = (older.build.sha256, newer.build.sha256)
        stratum = 'stratum:monthly' if kind == 'adjacent-patch' else 'stratum:large-rewrite'
        if key in found:
            entry = found[key]
            entry['lines'] = tuple(sorted(set(entry['lines']) | set(lines)))
            entry['tags'] = tuple(sorted(set(entry['tags']) | {line_tag, stratum}))
            return
        found[key] = {'id': pair_id(cat.file_name, *key), 'older': older.build, 'newer': newer.build, 'kind': kind,
                      'lines': tuple(sorted(lines)), 'older_kbs': older.kbs, 'newer_kbs': newer.kbs,
                      'older_date': older.date, 'newer_date': newer.date,
                      'tags': tuple(sorted({cat.family, f'file:{cat.file_name}', line_tag, stratum}))}

    for line in selected:
        placed = by_line[line]
        adjacent = [(placed[i], placed[i + 1]) for i in range(len(placed) - 1)
                    if params.since is None or placed[i + 1].date >= params.since]
        for older, newer in adjacent[-params.max_adjacent:] if params.max_adjacent else []:
            add(older, newer, 'adjacent-patch', f'line:{line}', (line,))
    if params.cross:
        for a, b in zip(selected, selected[1:], strict=False):
            in_a = {p.build.sha256 for p in by_line[a]}
            in_b = {p.build.sha256 for p in by_line[b]}
            newer = next((p for p in by_line[b] if p.build.sha256 not in in_a), None)
            olders = [p for p in by_line[a] if p.build.sha256 not in in_b]
            if newer is None or not olders:
                exclusions['cross-version-missing-side'] += 1
                continue
            before = [p for p in olders if p.date <= newer.date]
            add((before or olders)[-1], newer, 'cross-version', f'line:{a}->{b}', (a, b))
    pairs = sorted(found.values(), key=lambda e: (e['newer_date'] or '', e['id']))
    used = {}
    for e in pairs:
        used[e['older'].sha256] = e['older']
        used[e['newer'].sha256] = e['newer']
    return FilePlan(pairs, used, exclusions, tuple(selected))


def coverage(plans: dict[str, tuple[Catalogue, FilePlan]], allow_incomplete: bool) -> Coverage:
    with_pairs = sorted(name for name, (_c, plan) in plans.items() if plan.pairs)
    classes = sorted({plans[name][0].family for name in with_pairs})
    missing = [f'class:{c}' for c in CLASSES if c not in classes]
    if len(with_pairs) < MIN_FILES:
        missing.append(f'files:{len(with_pairs)}<{MIN_FILES}')
    return Coverage(classes=tuple(classes), files_with_pairs=tuple(with_pairs), complete=not missing,
                    allow_incomplete=allow_incomplete, missing=tuple(missing))


def build_corpus(catalogues: Sequence[Catalogue], params: PairParams, *, corpus_id: str, created: str,
                 tool_git: str = 'unknown', allow_incomplete: bool = False,
                 shift_test: Sequence[str] = ()) -> tuple[dict, PairsDoc]:
    """Return (calibration-corpus/1 manifest dict, tier-w-pairs/1 sidecar). Raises when coverage fails."""
    check_corpus_id(corpus_id)
    names = [c.file_name for c in catalogues]
    if len(set(names)) != len(names):
        raise TierWError('PT-TIERW-INPUT', 'one catalogue per file name')
    plans = {c.file_name: (c, plan_file(c, params)) for c in sorted(catalogues, key=lambda c: c.file_name)}
    cov = coverage(plans, allow_incomplete)
    if not cov.complete and not allow_incomplete:
        raise TierWError('PT-TIERW-INPUT', 'coverage below the C9 G0 minimum (>= 6 files spanning kernel, '
                                           f'driver and user-mode DLL): {", ".join(cov.missing)}; '
                                           'add families or pass --allow-incomplete')
    lineage_ids = [lineage_id(name) for name, (_c, plan) in plans.items() if plan.pairs]
    roles = assign_roles(lineage_ids, SALT, shift_test)
    binaries, pair_rows, lineages, side_binaries, side_pairs = [], [], [], [], []
    exclusions: Counter = Counter()
    for name, (cat, plan) in plans.items():
        exclusions.update({f'{name}:{k}': v for k, v in plan.exclusions.items()})
        if not plan.pairs:
            continue
        lid = lineage_id(name)
        members = []
        for sha, b in sorted(plan.used.items()):
            bid = binary_id(sha)
            members.append(bid)
            kbs = sorted({k.kb for kb_line in b.lines.values() for k in kb_line})
            binaries.append({'id': bid, 'tier': 'W', 'file_name': name, 'arch': 'x64', 'sha256': sha,
                             'size': b.size,
                             'winbindex': {'timestamp': b.timestamp, 'virtual_size': b.size_of_image,
                                           'version': b.version, 'kb': kbs[:64]},
                             'pdb': {'guid_age': None, 'name': None, 'used_for': 'labels-only'},
                             'toolchain': 'msvc-unknown', 'redistribution': 'none'})
            side_binaries.append(PairBinary(id=bid, file_name=name, sha256=sha, record_sha256=b.record_sha256,
                                            family=cat.family, version=b.version))
        evidence = hashlib.sha256(canonical_json({'rule': 'file-name', 'file': name, 'members': members})).hexdigest()
        lineages.append({'id': lid, 'members': members, 'cluster_rule': 'file-name',
                         'cluster_evidence_sha256': evidence, 'family': cat.family})
        for e in plan.pairs:
            pair_rows.append({'id': e['id'], 'older': binary_id(e['older'].sha256),
                              'newer': binary_id(e['newer'].sha256), 'kind': e['kind'], 'lineage': lid,
                              'family_tags': list(e['tags']), 'role': roles[lid]})
            side_pairs.append(PairEntry(id=e['id'], older=binary_id(e['older'].sha256),
                                        newer=binary_id(e['newer'].sha256), kind=e['kind'], file_name=name,
                                        lines=e['lines'], older_kbs=e['older_kbs'], newer_kbs=e['newer_kbs'],
                                        older_date=e['older_date'], newer_date=e['newer_date'], tags=e['tags']))
    manifest = {'contract': 'calibration-corpus/1', 'corpus_id': corpus_id, 'created': created, 'tool_git': tool_git,
                'binaries': binaries, 'pairs': pair_rows, 'lineages': lineages,
                'split': {'salt': SALT, 'method': 'sha256(lineage_id|salt) -> u; <.60 dev, <.85 locked-test, '
                                                  'else shift-test', 'shift_test_lineages': list(shift_test)}}
    try:
        load_manifest(json.dumps(manifest).encode())
    except ContractError as exc:
        raise TierWError('PT-TIERW-INPUT', f'generated manifest failed validation: {exc}') from None
    sidecar = PairsDoc(contract='tier-w-pairs/1', tier=TIER, corpus_id=corpus_id, created=created,
                       params={k: (tuple(v) if isinstance(v, tuple | list) else v)
                               for k, v in params.as_dict().items()},
                       binaries=tuple(side_binaries), pairs=tuple(side_pairs),
                       exclusions=dict(sorted(exclusions.items())), coverage=cov)
    return manifest, sidecar
