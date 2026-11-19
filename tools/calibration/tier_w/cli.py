"""SPEC-33 s11 CLI: `PYTHONPATH=src python -m tools.calibration.tier_w <cmd> --corpus-id tier-w-<name>`. Dev-only, Qt-free.

Wired offline stages: `catalogue --from-file`, `pairs`, `fetch-plan`, `symbols` (stdlib MSF producer), `labels`,
`evaluate`, `status` and `guard`. Every other stage exits explicitly, never silently: the network stages (`catalogue`
without `--from-file`, `resolve`, `fetch`) refuse without consent naming the host they contact (exit 2) and are
otherwise BLOCKED (exit 3, transport not wired here); `audit`, `review`, `audit-report` and `run` are BLOCKED too.
`labels` skips a pair whose export table cannot be read on either side (binary gone or unreadable): the export status
is unknown, so it is never recorded as `exported: false` (the non-exported headline stratum). Each command prints
exactly one strict-JSON summary line on stdout. Everything is read from and written under the corpus root
(PATCHTRACE_CALIB_ROOT, refused inside the work tree; decision O1). Nothing is uploaded or executed.
Exit codes: 0 ok, 1 partial, 2 configuration/consent/input, 3 BLOCKED, 5 cancelled (the CANCEL file or Ctrl-C).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from pydantic import ValidationError

from patchtrace.acquisition import winbindex
from patchtrace.artifact_bytes import ArtifactBytesError

from .. import corpus
from ..contracts import ContractError, CorpusManifest, load_manifest
from . import aggregate as AG
from . import catalogue as CAT
from . import evaluate as EV
from . import fetch as FE
from . import labels as LB
from . import msf
from . import pairs as PA
from .audit import AuditReport
from .contracts import (
    CATALOGUE_LIMIT,
    DOC_LIMIT,
    SYMBOL_MAP_LIMIT,
    Catalogue,
    LabelDetail,
    MatchLine,
    PairBinary,
    PairsDoc,
    SymbolMap,
    load_catalogue,
    load_jsonl,
    load_pairs,
    load_symbol_map,
)
from .paths import (
    BLOCKED,
    CANCELLED,
    CONFIG,
    ERROR_EXIT,
    OK,
    PARTIAL,
    REPO_ROOT,
    Layout,
    TierWError,
    atomic_write,
    calib_root,
    check_corpus_id,
    check_root,
    dumps,
    read_bytes,
    write_json,
    write_jsonl,
)
from .pe_tables import PeTableError, PeView
from .run_local import ALLOWED_HOSTS
from .symbols import export_msf
from .transport import pdb_cap_bytes

STATUS = {OK: 'ok', PARTIAL: 'partial', CONFIG: 'failed', BLOCKED: 'blocked', CANCELLED: 'cancelled'}
NETWORK_HOST = {'catalogue': 'winbindex.m417z.com', 'resolve': 'msdl.microsoft.com', 'fetch': 'msdl.microsoft.com'}
NOT_WIRED = {
    'catalogue': 'catalogue download: network stage not wired in this CLI yet; save <name>.json.gz from Winbindex and '
                 'run catalogue --from-file',
    'resolve': 'resolve: network stage not wired in this CLI yet; builds without SizeOfImage stay ineligible',
    'fetch': 'fetch: network stage not wired in this CLI yet; nothing was downloaded (fetch-plan lists what it needs)',
    'audit': 'audit: not wired in this CLI yet (library tier_w/audit.py); nothing was sampled',
    'review': 'review: not wired in this CLI yet; nothing was reviewed',
    'audit-report': 'audit-report: not wired in this CLI yet; no audit report was written',
    'run': 'runner not built (LBL-23): no engine was run; evaluate needs runs/<corpus>/matches.jsonl',
}
PRODUCERS = ('msf', 'ghidra', 'llvm-pdbutil')
SYMBOL_OUTCOMES = ('exported', 'missing_binaries', 'mismatched', 'no_codeview', 'missing_pdbs', 'rejected_pdbs',
                   'failed')
NO_CANCEL = frozenset({'status', 'guard'})
GZIP_MAGIC = b'\x1f\x8b'
MATCHES_LIMIT = 1 << 30
MESSAGE_MAX = 600
_DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
Handler = Callable[[argparse.Namespace, Layout, str], tuple[int, dict]]


class _Parser(argparse.ArgumentParser):
    """Usage errors become a TierWError, so they too end in one JSON line and exit 2."""

    def error(self, message: str):
        raise TierWError('PT-TIERW-INPUT', f'{self.prog}: {message}')


def _ratio_min(value: str) -> float:
    try:
        ratio = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('expected a number in (0, 1]') from None
    if not 0 < ratio <= 1:  # also refuses nan and inf
        raise argparse.ArgumentTypeError('expected a number in (0, 1]')
    return ratio


def _date(value: str) -> str:
    if not _DATE.fullmatch(value):
        raise argparse.ArgumentTypeError('expected YYYY-MM-DD')
    return value


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def _check_cancel(layout: Layout) -> None:
    if FE.cancelled(layout):
        raise TierWError('PT-TIERW-CANCEL', 'cancelled: the CANCEL file exists under the corpus root (delete it to resume)')


def _binary(root: Path, binary: PairBinary) -> Path:
    return root / 'binaries' / binary.sha256 / binary.file_name


def _sidecar(layout: Layout, corpus_id: str) -> PairsDoc:
    path = layout.pairs(corpus_id)
    if not path.is_file():
        raise TierWError('PT-TIERW-INPUT', 'no pairs document for this corpus id; run pairs first')
    return load_pairs(read_bytes(path, DOC_LIMIT))


def _manifest(layout: Layout, corpus_id: str) -> tuple[CorpusManifest, dict]:
    data = read_bytes(layout.manifest(corpus_id), DOC_LIMIT)
    try:
        return load_manifest(data), json.loads(data)
    except ContractError as exc:
        raise TierWError('PT-TIERW-INPUT', f'corpus manifest invalid: {str(exc)[:300]}') from None


def _matches(layout: Layout, corpus_id: str) -> list[MatchLine]:
    path = layout.matches(corpus_id)
    return load_jsonl(MatchLine, read_bytes(path, MATCHES_LIMIT), 'matches') if path.is_file() else []


# ---- network stages: consent first, then an explicit BLOCKED ----------------------------------------------------------

def _network(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    host = NETWORK_HOST[args.command]
    hosts = {h.strip() for h in args.consent_hosts.split(',') if h.strip()}
    if not hosts:
        raise TierWError('PT-TIERW-CONFIG', f'{args.command} contacts {host}: pass --consent-hosts {host}')
    if hosts - ALLOWED_HOSTS:
        raise TierWError('PT-TIERW-CONFIG', 'consent names a host outside the allow-list; allowed hosts are '
                                            + ', '.join(sorted(ALLOWED_HOSTS)))
    if host not in hosts:
        raise TierWError('PT-TIERW-CONFIG', f'{args.command} contacts {host}; --consent-hosts must name it')
    raise TierWError('PT-TIERW-BLOCKED', NOT_WIRED[args.command])


def _blocked(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    raise TierWError('PT-TIERW-BLOCKED', NOT_WIRED[args.command])


# ---- catalogue --from-file and pairs (s3) -----------------------------------------------------------------------------

def _families(values: Sequence[str]) -> dict[str, str]:
    out = {}
    for value in values:
        name, _, family = value.partition('=')
        if family not in CAT.CLASSES:
            raise TierWError('PT-TIERW-INPUT', '--family takes name=' + '|'.join(CAT.CLASSES))
        out[name] = family
    return out


def _name_from(path: Path) -> str:
    name = path.name
    for suffix in ('.json.gz', '.json', '.gz'):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _catalogue(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    if not args.from_file:
        return _network(args, layout, corpus_id)
    if args.names and len(args.names) != len(args.from_file):
        raise TierWError('PT-TIERW-INPUT', 'give one NAME per --from-file, or none (names come from the file names)')
    overrides = _families(args.family)
    built: list[Catalogue] = []
    for index, path in enumerate(args.from_file):
        name = args.names[index] if args.names else _name_from(path)
        data = read_bytes(path, winbindex.MAX_DECOMPRESSED)
        date = args.data_date or dt.datetime.fromtimestamp(path.stat().st_mtime, dt.UTC).strftime('%Y-%m-%d')
        cat = CAT.build_catalogue(data, name, date, compressed=data[:2] == GZIP_MAGIC,
                                  family=CAT.family_of(name, overrides))
        write_json(layout.catalogue(cat.file_name), cat.model_dump(mode='json'))
        built.append(cat)
    return OK, {'catalogues': len(built), 'builds': sum(len(c.builds) for c in built),
                'eligible': sum(1 for c in built for b in c.builds if b.size_of_image),
                'skipped': sum(c.skipped for c in built), 'non_x64': sum(c.non_x64 for c in built),
                'dropped_kbs': sum(c.dropped_kbs for c in built)}


def _catalogues(layout: Layout) -> list[Catalogue]:
    folder = layout.base / 'catalogue'
    paths = sorted(folder.glob('*.json')) if folder.is_dir() else []
    if not paths:
        raise TierWError('PT-TIERW-INPUT', 'no catalogue under the corpus root; run catalogue first')
    return [load_catalogue(read_bytes(p, CATALOGUE_LIMIT)) for p in paths]


def _pairs(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    catalogues = _catalogues(layout)
    params = PA.PairParams(lines=tuple(args.lines.split(',')) if args.lines else None, recent_lines=args.recent_lines,
                           max_adjacent=args.max_adjacent, since=args.since, security_only=args.security_only)
    manifest, sidecar = PA.build_corpus(catalogues, params, corpus_id=corpus_id, created=_now(),
                                        allow_incomplete=args.allow_incomplete, shift_test=tuple(args.shift_test))
    atomic_write(layout.manifest(corpus_id), dumps(manifest))
    write_json(layout.pairs(corpus_id), sidecar.model_dump(mode='json'))
    cov = sidecar.coverage
    return OK, {'catalogues': len(catalogues), 'pairs': len(sidecar.pairs), 'binaries': len(sidecar.binaries),
                'lineages': len(manifest['lineages']), 'classes': len(cov.classes), 'complete': cov.complete,
                'missing': list(cov.missing), 'excluded_builds': sum(sidecar.exclusions.values())}


# ---- fetch-plan (s4.1, offline) -------------------------------------------------------------------------------------

def _fetch_plan(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    sidecar = _sidecar(layout, corpus_id)
    planned = FE.plan_binaries(sidecar, _manifest(layout, corpus_id)[1])
    names = {b.sha256: b for b in sidecar.binaries}
    missing = [p for p in planned if not _verified(_binary(layout.root, names[p.sha256]), p.sha256)]
    sizes = [p.size for p in missing]
    return OK, {'planned': len(planned), 'present': len(planned) - len(missing), 'missing': len(missing),
                'bytes': sum(p.size for p in planned), 'missing_bytes': sum(sizes),
                'disk_needed': FE.disk_needed(sizes, pdb_cap_bytes()), 'urls': [p.url for p in missing]}


def _verified(path: Path, sha256: str) -> bool:
    return path.is_file() and FE.sha256_file(path) == sha256


# ---- symbols (s5, stdlib MSF producer) --------------------------------------------------------------------------------

def _export_one(layout: Layout, binary: PairBinary) -> str:
    pe = _binary(layout.root, binary)
    if not pe.is_file():
        return 'missing_binaries'
    if FE.sha256_file(pe) != binary.sha256:
        return 'mismatched'
    try:
        name, guid, age = FE.pdb_request(pe)
    except (TierWError, ArtifactBytesError):
        return 'no_codeview'
    pdb = layout.pdb(name, FE.guid_age(guid, age))
    if not pdb.is_file():
        return 'missing_pdbs'
    if FE._identity_mismatch(pdb, guid, age):
        return 'rejected_pdbs'
    try:
        export_msf(pe, pdb, layout)
    except (TierWError, msf.MsfError, PeTableError, ArtifactBytesError):
        return 'failed'
    return 'exported'


def _symbols(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    if args.producer != 'msf':
        raise TierWError('PT-TIERW-BLOCKED', f'symbols --producer {args.producer} is not wired in this CLI yet; '
                                             'use --producer msf')
    sidecar = _sidecar(layout, corpus_id)
    outcomes: Counter = Counter()
    for binary in sidecar.binaries:
        _check_cancel(layout)
        outcomes[_export_one(layout, binary)] += 1
    code = OK if outcomes['exported'] == len(sidecar.binaries) else PARTIAL
    return code, {'producer': 'msf', 'binaries': len(sidecar.binaries), **{k: outcomes[k] for k in SYMBOL_OUTCOMES}}


# ---- labels (s6) ------------------------------------------------------------------------------------------------------

def _symbol_map(layout: Layout, binary: PairBinary, producer: str) -> SymbolMap | None:
    path = layout.symbols(binary.sha256, producer)
    return load_symbol_map(read_bytes(path, SYMBOL_MAP_LIMIT)) if path.is_file() else None


def _exports(root: Path, binary: PairBinary) -> frozenset[int] | None:
    pe = _binary(root, binary)
    if not pe.is_file():
        return None
    try:
        with PeView(pe, expected_sha256=binary.sha256) as view:
            return view.export_rvas()
    except (PeTableError, ArtifactBytesError):
        return None


def _labels(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    sidecar = _sidecar(layout, corpus_id)
    binaries = {b.id: b for b in sidecar.binaries}
    by_pair: dict[str, list[MatchLine]] = defaultdict(list)
    for match in _matches(layout, corpus_id):
        by_pair[match.pair].append(match)
    folder = layout.labels_dir(corpus_id)
    counts: Counter = Counter()
    excluded: Counter = Counter()
    answers: Counter = Counter()
    for pair in sidecar.pairs:
        _check_cancel(layout)
        sides = (binaries[pair.older], binaries[pair.newer])
        older, newer = (_symbol_map(layout, b, args.producer) for b in sides)
        if older is None or newer is None:
            counts['missing_maps'] += 1
            continue
        older_exports, newer_exports = (_exports(layout.root, b) for b in sides)
        if older_exports is None or newer_exports is None:
            counts['exports_unknown'] += 1  # unknown is not "not exported": leave the pair unlabelled
            continue
        truth, exclusions = LB.derive_truth(older, newer, args.ratio_min)
        candidates = LB.label_candidates(truth, by_pair.get(pair.id, ()))
        write_jsonl(folder / f'{pair.id}.truth.jsonl', [r.model_dump() for r in LB.truth_records(pair.id, truth)])
        write_jsonl(folder / f'{pair.id}.candidates.jsonl', LB.candidate_records(pair.id, candidates))
        details = LB.detail_records(pair.id, truth, exclusions, candidates, older, newer, older_exports, newer_exports)
        write_jsonl(folder / f'{pair.id}.detail.jsonl', [d.model_dump(mode='json') for d in details])
        counts['labelled'] += 1
        counts['truth'] += len(truth)
        excluded.update(e.reason for e in exclusions)
        answers.update(c.answer or 'unlabelled' for c in candidates)
    code = OK if counts['labelled'] == len(sidecar.pairs) else PARTIAL
    return code, {'producer': args.producer, 'pairs': len(sidecar.pairs), 'labelled': counts['labelled'],
                  'truth': counts['truth'], 'excluded': {r: excluded[r] for r in LB.EXCLUSIONS},
                  'candidates': {a: answers[a] for a in ('same', 'different', 'unlabelled')},
                  'missing_maps': counts['missing_maps'], 'exports_unknown': counts['exports_unknown']}


# ---- evaluate (s10) and the aggregate export (LBL s8.2) -------------------------------------------------------------

def _truth_labels(layout: Layout, corpus_id: str, sidecar: PairsDoc) -> tuple[list[EV.TruthLabel], dict[str, int], int]:
    """(`same` truth labels with side tags plus the pair's `stratum:*` tags, labelled candidates per pair, pairs
    without labels). Only `stratum:*` pair tags are kept: `file:` and `line:` tags would carry names."""
    folder = layout.labels_dir(corpus_id)
    labels: list[EV.TruthLabel] = []
    candidates: Counter = Counter()
    unlabelled = 0
    for pair in sidecar.pairs:
        path = folder / f'{pair.id}.detail.jsonl'
        if not path.is_file():
            unlabelled += 1
            continue
        strata = {t for t in pair.tags if t.startswith('stratum:')}
        for row in load_jsonl(LabelDetail, read_bytes(path, SYMBOL_MAP_LIMIT), 'label detail'):
            if row.pair != pair.id:
                continue
            if row.kind == 'truth' and row.A == 'same':
                tags = tuple(sorted({*row.older.tags, *row.newer.tags, *strata}))
                labels.append(EV.TruthLabel(pair.id, row.older.rva, row.newer.rva, 'same', LB.SOURCE, tags))
            elif row.kind == 'candidate' and row.A:
                candidates[pair.id] += 1
    return labels, dict(candidates), unlabelled


def _audit_report(layout: Layout, corpus_id: str) -> AuditReport | None:
    path = layout.review_dir(corpus_id) / 'audit-report.json'
    if not path.is_file():
        return None
    try:
        return AuditReport.model_validate_json(read_bytes(path, DOC_LIMIT))
    except ValidationError:
        raise TierWError('PT-TIERW-INPUT', 'audit-report.json is not a valid tier-w-audit-report/1') from None


def _evaluate(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    sidecar = _sidecar(layout, corpus_id)
    matches = _matches(layout, corpus_id)
    known = {p.id for p in sidecar.pairs}
    scored = [m for m in matches if m.pair in known]
    if not scored:  # nothing to score: keep any earlier report and the shared aggregate as they are
        return PARTIAL, {'matches': 0, 'foreign_matches': len(matches),
                         'reason': 'no engine matches for this corpus\'s pairs (runs/<corpus>/matches.jsonl); '
                                   'run the run stage first'}
    labels, candidates, unlabelled = _truth_labels(layout, corpus_id, sidecar)
    if not labels:
        return PARTIAL, {'matches': len(scored), 'reason': 'no symbol-derived labels for this corpus; run labels first'}
    lineage_of = {p.id: p.lineage for p in _manifest(layout, corpus_id)[0].pairs}
    evaluation = EV.evaluate(labels, scored, lineage_of)
    write_json(layout.report(corpus_id), evaluation)
    doc = AG.aggregate(evaluation, classes=AG.class_counts(sidecar, candidates), audit=_audit_report(layout, corpus_id))
    export = layout.base / 'export'
    atomic_write(export / 'aggregate.json', AG.to_json(doc))
    atomic_write(export / 'aggregate.md', AG.render_markdown(doc).encode('utf-8'))
    cells = Counter('scored' if c['status'] == 'scored' else 'circular'
                    for conditions in evaluation['cells'].values() for c in conditions.values())
    return OK, {'matches': len(scored), 'foreign_matches': len(matches) - len(scored), 'truth': len(labels),
                'pairs': len(sidecar.pairs), 'unlabelled_pairs': unlabelled, 'engines': len(evaluation['cells']),
                'cells': {'scored': cells['scored'], 'circular': cells['circular']},
                'suppressed_cells': doc.suppressed_cells, 'audit': doc.audit.status,
                'metrics': doc.model_dump(mode='json')['metrics']}


# ---- status and guard -------------------------------------------------------------------------------------------------

def _status(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    folder = layout.base / 'catalogue'
    out = {'catalogues': len(list(folder.glob('*.json'))) if folder.is_dir() else 0,
           'manifest': layout.manifest(corpus_id).is_file(), 'pairs': 0, 'binaries': {'planned': 0, 'present': 0},
           'maps': 0, 'labelled': 0, 'matches': layout.matches(corpus_id).is_file(),
           'report': layout.report(corpus_id).is_file(), 'aggregate': (layout.base / 'export' / 'aggregate.json').is_file(),
           'cancel': FE.cancelled(layout)}
    if layout.pairs(corpus_id).is_file():
        sidecar = _sidecar(layout, corpus_id)
        labels = layout.labels_dir(corpus_id)
        out.update(pairs=len(sidecar.pairs),
                   binaries={'planned': len(sidecar.binaries),
                             'present': sum(_binary(layout.root, b).is_file() for b in sidecar.binaries)},
                   maps=sum(any(layout.symbols(b.sha256, p).is_file() for p in PRODUCERS) for b in sidecar.binaries),
                   labelled=sum((labels / f'{p.id}.detail.jsonl').is_file() for p in sidecar.pairs))
    return OK, out


def _guard(args, layout: Layout, corpus_id: str) -> tuple[int, dict]:
    manifest = _manifest(layout, corpus_id)[0] if layout.manifest(corpus_id).is_file() else None
    problems = corpus.guard(REPO_ROOT, manifest)
    return (PARTIAL if problems else OK), {'findings': len(problems), 'problems': [p[:300] for p in problems[:200]]}


HANDLERS: dict[str, Handler] = {
    'catalogue': _catalogue, 'resolve': _network, 'pairs': _pairs, 'fetch-plan': _fetch_plan, 'fetch': _network,
    'symbols': _symbols, 'labels': _labels, 'audit': _blocked, 'review': _blocked, 'audit-report': _blocked,
    'run': _blocked, 'evaluate': _evaluate, 'status': _status, 'guard': _guard}


def build_parser() -> argparse.ArgumentParser:
    ap = _Parser(prog='tier_w', description='Tier W local-only calibration corpus (SPEC-33 s11). One JSON line out.')
    sub = ap.add_subparsers(dest='command', required=True, parser_class=_Parser)
    commands = {}
    for name in HANDLERS:
        p = sub.add_parser(name)
        p.add_argument('--corpus-id', required=True, help='tier-w-<letters, digits, . _ ->')
        if name in NETWORK_HOST:
            p.add_argument('--consent-hosts', default='', help='comma list; must name the host this stage contacts')
        commands[name] = p
    cat = commands['catalogue']
    cat.add_argument('names', nargs='*', help='file names (default: taken from each --from-file name)')
    cat.add_argument('--from-file', action='append', type=Path, default=[], help='local <name>.json[.gz] (offline)')
    cat.add_argument('--data-date', type=_date, help='Winbindex data date (default: the file modification date)')
    cat.add_argument('--family', action='append', default=[], help='name=kernel|driver|usermode-dll')
    pairs = commands['pairs']
    pairs.add_argument('--allow-incomplete', action='store_true', help='record a coverage shortfall instead of failing')
    pairs.add_argument('--shift-test', action='append', default=[], help='lineage id held out as shift-test')
    pairs.add_argument('--lines', default='', help='comma list of Winbindex line keys (default: --recent-lines)')
    pairs.add_argument('--recent-lines', type=int, default=2)
    pairs.add_argument('--max-adjacent', type=int, default=4)
    pairs.add_argument('--since', type=_date)
    pairs.add_argument('--security-only', action='store_true')
    commands['symbols'].add_argument('--producer', choices=PRODUCERS, default='msf')
    commands['labels'].add_argument('--producer', choices=PRODUCERS, default='msf', help='symbol maps to read')
    commands['labels'].add_argument('--ratio-min', type=_ratio_min, default=LB.RATIO_MIN, help='in (0, 1]')
    run = commands['run']
    run.add_argument('--python', default='')
    run.add_argument('--ghidra-dir', default='')
    run.add_argument('--timeout', type=int, default=3600)
    return ap


def _emit(command: str | None, code: int, body: Mapping) -> None:
    doc = {**body, 'tier_w': command, 'status': STATUS.get(code, 'failed'), 'exit': code}
    print(json.dumps(doc, sort_keys=True, allow_nan=False))


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    command = None
    try:
        args = build_parser().parse_args(argv)
        command = args.command
        corpus_id = check_corpus_id(args.corpus_id)
        layout = Layout(check_root(calib_root(environ)))
        if command not in NO_CANCEL:
            _check_cancel(layout)
        code, body = HANDLERS[command](args, layout, corpus_id)
        body = {'corpus_id': corpus_id, **body}
    except TierWError as exc:
        code, body = ERROR_EXIT.get(exc.code, CONFIG), {'code': exc.code, 'message': exc.message[:MESSAGE_MAX]}
    except KeyboardInterrupt:
        code, body = CANCELLED, {'code': 'PT-TIERW-CANCEL', 'message': 'interrupted'}
    except OSError as exc:
        code, body = CONFIG, {'code': 'PT-TIERW-CONFIG', 'message': f'file system error: {exc.strerror or exc}'[:MESSAGE_MAX]}
    _emit(command, code, body)
    return code
