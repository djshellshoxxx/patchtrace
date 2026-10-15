"""`patchtrace build-env show|delta|timeline` (DIE plan s8). Own dispatcher; `cli.py` only registers and routes.

Envelope `enrichment-cli/1`, exit codes 0/2/3/4/5, no Qt, no network. The CLI never spawns a tool and never writes to
the project: PE header facts are read from the hash-checked project copies and Detect It Easy results come from
stored `tool-evidence` rows (written by `intel-tools run --engines diec`); without them the output says
`"die": "not-run"`. Output shows basenames only, no stderr excerpts and no paths; `--technical` adds raw Rich entries,
the database digest and the argv version. Importing this module is cheap because the parser is built on every call.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

SIDES = ('older', 'newer')
VERBS = ('show', 'delta', 'timeline')
SERIES_FILE = 'series.json'


def register(sub, common, handlers) -> None:
    parser = sub.add_parser('build-env', help='build environment of the older and newer file (headers, Rich header, '
                            'stored Detect It Easy results; reads only, never runs a tool)')
    actions = parser.add_subparsers(dest='action', required=True, parser_class=type(parser))
    show = common(actions.add_parser('show', help='facts read from one or both files'))
    show.add_argument('project', type=Path)
    show.add_argument('--side', choices=('older', 'newer', 'both'), default='both')
    show.add_argument('--technical', action='store_true', help='add raw Rich entries, database digest, argv version')
    delta = common(actions.add_parser('delta', help='what changed between the older and the newer build environment'))
    delta.add_argument('project', type=Path)
    timeline = common(actions.add_parser('timeline', help='toolchain change per adjacent build of a series'))
    timeline.add_argument('series_dir', type=Path)
    handlers['build-env'] = dispatch


def dispatch(args, cancel: threading.Event) -> int:
    return {'show': _show, 'delta': _delta, 'timeline': _timeline}[args.action](args, cancel)


def _t(value: object, limit: int = 200) -> str:
    from ..intelligence.tools.common import display_text
    return display_text(str('' if value is None else value), limit)


@dataclass(slots=True)
class SideResult:
    side: str
    name: str
    sha256: str
    fingerprint: object | None = None   # BuildFingerprint
    error: str | None = None            # PT-BUILD-* code when the side could not be read
    stale: bool = False                 # stored Detect It Easy evidence of another file was ignored
    cancelled: bool = False


def _fingerprint(artifact, root: Path, tools, cancel: threading.Event) -> SideResult:
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..pe_overview import inspect_pe
    from ..pe_overview.build_facts import collect_build_facts
    from .adapters import die_summary_from, pe_facts_from
    from .contracts import BuildEnvError
    from .fingerprint import build_fingerprint
    result = SideResult(artifact.side, Path(artifact.name).name, artifact.sha256)
    try:
        with VerifiedArtifactReader.open_artifact(artifact, root, cancel.is_set) as reader:
            overview = inspect_pe(reader, cancel=cancel.is_set)
            if overview.status == 'cancelled' or cancel.is_set():
                result.cancelled = True
                return result
            if overview.status == 'not_pe':
                result.error = 'PT-BUILD-INPUT'
                return result
            pe = pe_facts_from(collect_build_facts(reader, overview, cancel=cancel.is_set))
    except ArtifactBytesError:
        result.cancelled = cancel.is_set()
        result.error = None if result.cancelled else 'PT-BUILD-INPUT'
        return result
    found = tools.latest('diec', artifact.side)
    run, evidence = found if found else (None, None)
    if run is not None and (run.input_artifact_hash != artifact.sha256 or evidence is None):
        run, evidence, result.stale = None, None, True
    try:
        result.fingerprint = build_fingerprint(artifact.sha256, artifact.side, pe=pe, hints=overview.packer_hints,
                                               die=die_summary_from(run), evidence=evidence)
    except BuildEnvError:
        result.stale = True
        result.fingerprint = build_fingerprint(artifact.sha256, artifact.side, pe=pe, hints=overview.packer_hints)
    return result


def _read_sides(service, sides: tuple[str, ...], cancel: threading.Event) -> list[SideResult]:
    from ..cli import ENVIRONMENT, CliError
    from ..enrichment.storage import EnrichmentStore
    from ..intelligence.tools.store import ToolStore
    project = service.project
    by_side = {a.side: a for a in project.artifacts}
    missing = [side for side in sides if side not in by_side]
    if missing:
        raise CliError(ENVIRONMENT, f'the project has no {" or ".join(missing)} artifact')
    tools = ToolStore(EnrichmentStore(service.store), service.root, project.id, project.revision)
    out = []
    for side in sides:
        out.append(_fingerprint(by_side[side], service.root, tools, cancel))
        if out[-1].cancelled:
            break
    return out


# --- show -----------------------------------------------------------------------------------------------------------

def _die_status(fp) -> str:
    return fp.die.status if fp.die else 'not-run'


def _side_json(result: SideResult, technical: bool) -> dict:
    row: dict = {'side': result.side, 'name': _t(result.name), 'sha256': result.sha256,
                 'status': 'read' if result.fingerprint else 'unreadable', 'error': result.error,
                 'stale_evidence_ignored': result.stale}
    fp = result.fingerprint
    if fp is None:
        return row
    row |= {'die': _die_status(fp), 'anomalies': list(fp.anomalies),
            'facts': [{'key': f.key, 'value': _t(f.value), 'version': _t(f.version), 'source': f.source,
                       'certainty': f.certainty} for f in fp.facts]}
    if technical:
        rich = fp.pe.rich if fp.pe else None
        row['technical'] = {
            'rich': [{'product_id': e.product_id, 'build': e.build, 'count': e.count} for e in (rich.entries if rich else ())],
            'die_database_sha256': fp.die.db_sha256 if fp.die else None,
            'die_argv_version': fp.die.argv_version if fp.die else None}
    return row


def _side_text(row: dict) -> list[str]:
    from .copy import FACT_LABELS
    head = f'{row["side"].upper()} {row["name"]} sha256 {row["sha256"][:16]}'
    if row['status'] != 'read':
        return [f'{head}: could not be read ({row["error"]})']
    lines = [f'{head}: Detect It Easy {row["die"]}']
    lines += [f'  {FACT_LABELS[f["key"]]}: {f["value"]} {f["version"]}'.rstrip() + f' ({f["source"]}, {f["certainty"]})'
              for f in row['facts']]
    lines += [f'  anomaly {name}' for name in row['anomalies']]
    for name, value in (row.get('technical') or {}).items():
        lines += [f'  {name}: {value}']
    return lines


def _show(args, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, OK, RUNTIME, _emit, _open
    from .copy import DISCLAIMER
    sides = SIDES if args.side == 'both' else (args.side,)
    service = _open(args.project)
    try:
        results = _read_sides(service, sides, cancel)
    finally:
        service.close()
    if any(r.cancelled for r in results):
        _emit(args, 'build-env show', 'cancelled', None, [], '')
        return CANCELLED
    rows = [_side_json(r, args.technical) for r in results]
    warnings = [f'{r.side}: stored Detect It Easy results belong to another file and were ignored'
                for r in results if r.stale]
    read = [r for r in rows if r['status'] == 'read']
    code, status = (OK, 'complete') if len(read) == len(rows) else (RUNTIME, 'partial') if read else (
        ENVIRONMENT, 'failed')
    text = '\n'.join([line for row in rows for line in _side_text(row)] + [DISCLAIMER])
    _emit(args, 'build-env show', status, {'contract': 'build-environment/1', 'sides': rows}, warnings, text)
    return code


# --- delta ----------------------------------------------------------------------------------------------------------

_PARTIAL_REASONS = frozenset({'die-one-side', 'die-versions-differ'})


def _delta_json(older, newer, delta, view) -> dict:
    return {
        'contract': delta.contract, 'delta_id': delta.delta_id, 'orientation': delta.orientation,
        'older_sha256': delta.older_sha256, 'newer_sha256': delta.newer_sha256, 'comparable': delta.comparable,
        'toolchain': delta.toolchain, 'toolchain_corroborated': delta.toolchain_corroborated,
        'state': view.state, 'state_text': view.state_text, 'reasons': list(delta.reasons),
        'options_changed': list(delta.options_changed), 'counts': delta.counts,
        'die': {'older': _die_status(older), 'newer': _die_status(newer)},
        'changes': [{'key': r.key, 'label': r.label, 'older': r.older, 'newer': r.newer, 'status': r.status,
                     'basis': r.basis} for r in view.rows],
        'preflight': [{'code': w.code, 'side': w.side, 'severity': w.severity, 'summary': _t(w.summary, 160),
                       'detail': _t(w.detail, 400), 'teach_id': w.teach_id} for w in delta.preflight],
        'noise': [{'code': n.code, 'classes': list(n.classes), 'effect': n.effect} for n in delta.noise]}


def _delta_text(view) -> str:
    lines = [view.state_text]
    lines += [f'{b.glyph} {b.side}: {b.text}' for b in view.banners]
    lines += [f'  {r.label}: {r.older} -> {r.newer} [{r.status}; {r.basis}]' for r in view.rows]
    lines.append(view.provenance)
    return '\n'.join(lines)


def _delta_exit(delta, stale: bool) -> tuple[int, str]:
    from ..cli import NO_RESULTS, OK, RUNTIME
    if stale or _PARTIAL_REASONS & set(delta.reasons):
        return RUNTIME, 'partial'
    found = (delta.toolchain == 'differs' or delta.options_changed
             or any(w.severity == 'caution' for w in delta.preflight))
    return (OK, 'complete') if found else (NO_RESULTS, 'complete')


def _delta(args, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, RUNTIME, _emit, _open
    from .delta import compute_delta
    from .view_model import build_view
    service = _open(args.project)
    try:
        results = _read_sides(service, SIDES, cancel)
    finally:
        service.close()
    if any(r.cancelled for r in results):
        _emit(args, 'build-env delta', 'cancelled', None, [], '')
        return CANCELLED
    older, newer = results
    warnings = [f'{r.side}: stored Detect It Easy results belong to another file and were ignored'
                for r in (older, newer) if r.stale]
    if older.fingerprint is None or newer.fingerprint is None:
        unreadable = [r.side for r in (older, newer) if r.fingerprint is None]
        result = {'contract': 'build-environment/1', 'delta': None, 'unreadable': unreadable}
        text = 'Build environment could not be compared: ' + ', '.join(unreadable) + ' could not be read.'
        _emit(args, 'build-env delta', 'partial' if len(unreadable) == 1 else 'failed', result, warnings, text)
        return RUNTIME if len(unreadable) == 1 else ENVIRONMENT
    delta = compute_delta(older.fingerprint, newer.fingerprint)
    view = build_view(older.fingerprint, newer.fingerprint, delta)
    document = _delta_json(older.fingerprint, newer.fingerprint, delta, view)
    code, status = _delta_exit(delta, older.stale or newer.stale)
    _emit(args, 'build-env delta', status, document, warnings, _delta_text(view))
    return code


# --- timeline -------------------------------------------------------------------------------------------------------

def _hop(series, pair, root: Path, cancel: threading.Event) -> dict:
    from ..service import ProjectService
    labels = {b.ordinal: b.label for b in series.builds}
    hop = {'from': pair.from_ordinal, 'to': pair.to_ordinal, 'from_label': _t(labels[pair.from_ordinal], 64),
           'to_label': _t(labels[pair.to_ordinal], 64), 'toolchain': 'unknown', 'status': 'unreadable'}
    path = (root / pair.path).resolve()
    if root not in path.parents:
        return hop
    try:
        service = ProjectService.open(path, maintenance=False)
    except (ValueError, OSError):
        return hop
    try:
        sides = _read_sides(service, SIDES, cancel)
    finally:
        service.close()
    if any(r.cancelled for r in sides):
        hop['status'] = 'cancelled'
    elif all(r.fingerprint is not None for r in sides):
        from .delta import compute_delta
        delta = compute_delta(sides[0].fingerprint, sides[1].fingerprint)
        ran = [r.fingerprint.die is not None and r.fingerprint.die.produced() for r in sides]
        hop |= {'toolchain': delta.toolchain, 'status': 'complete' if all(ran) else 'not-run',
                'reasons': list(delta.reasons)}
    return hop


def _timeline(args, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, OK, RUNTIME, CliError, _emit
    from ..nway import series as store
    from ..nway.contracts import NwayError
    root = Path(args.series_dir).resolve()
    try:
        series = store.load(root / SERIES_FILE)
    except NwayError as exc:
        raise CliError(ENVIRONMENT, f'{exc.code}: not a usable series folder') from None
    hops = []
    for pair in series.pair_projects:  # adjacent builds only; non-adjacent builds are never compared
        hops.append(_hop(series, pair, root, cancel))
        if hops[-1]['status'] == 'cancelled':
            _emit(args, 'build-env timeline', 'cancelled', None, [], '')
            return CANCELLED
    complete = all(h['status'] == 'complete' for h in hops)
    lines = [f'{h["from_label"]} -> {h["to_label"]}: toolchain {h["toolchain"]} ({h["status"]})' for h in hops]
    result = {'contract': 'build-environment/1', 'series_id': series.series_id, 'hops': hops}
    _emit(args, 'build-env timeline', 'complete' if complete else 'partial', result, [], '\n'.join(lines))
    return OK if complete else RUNTIME
