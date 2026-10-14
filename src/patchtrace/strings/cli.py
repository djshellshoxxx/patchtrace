"""`patchtrace strings list|delta|explain|scan|export` (spec WB3 s8, WB3-S6). Own dispatcher; `cli.py` only routes.

Envelope `enrichment-cli/1`, exits 0 results / 2 invalid input or nothing readable / 3 rejected or partial (basis,
truncation, failed source) / 4 complete without results / 5 cancelled. Offline, no Qt, no process: FLOSS is run only
by `intel-tools run`; here its stored evidence is read and the built-in scan runs in this process. Secret-looking
strings are redacted unless `--show-secrets`. Importing this module is cheap (the heavy imports are inside the
handlers) because the parser is built on every CLI call.
"""
from __future__ import annotations

import argparse
import threading
from dataclasses import dataclass, field
from pathlib import Path

ACTIONS = ('list', 'delta', 'explain', 'scan', 'export')
SOURCES = ('auto', 'floss', 'builtin')
CHANGES = ('only-newer', 'only-older', 'edited', 'changed', 'all')
TYPES = ('static', 'stack', 'tight', 'decoded', 'language')
GLYPH = {'only-newer': '+', 'only-older': '-', 'edited': '~', 'both': '=', 'representation-changed': '~',
         'not-compared': '?', 'indeterminate': '?'}
MAX_ANCHOR_FILE = 4 * 1024 * 1024
DEFAULT_LIMIT = 200


def _bounded(low: int, high: int):
    def parse(value: str) -> int:
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f'must be {low}..{high}')
        return number
    return parse


def _project_options(p, *, anchors: bool = True) -> None:
    p.add_argument('project', type=Path)
    p.add_argument('--source', choices=SOURCES, default='auto',
                   help='auto = the stored FLOSS evidence of a side when it has some, else the built-in scan')
    p.add_argument('--min-length', type=_bounded(1, 4096), default=4, metavar='N', help='built-in scan minimum')
    if anchors:
        p.add_argument('--anchors', type=Path, metavar='FILE', help='an intelligence AnchorSet JSON file')
    p.add_argument('--show-secrets', action='store_true')


def register(sub, common, handlers: dict | None = None) -> None:
    if handlers is not None:
        handlers['strings'] = dispatch
    parser = sub.add_parser('strings', help='string changes between the two builds (static; never executes them)')
    act = parser.add_subparsers(dest='action', required=True, parser_class=type(parser))
    ls = common(act.add_parser('list', help='changed strings in review order'))
    _project_options(ls)
    ls.add_argument('--side', choices=('older', 'newer', 'both'), default='both')
    ls.add_argument('--change', choices=CHANGES, default='changed')
    ls.add_argument('--type', nargs='+', choices=TYPES, default=None, dest='types')
    ls.add_argument('--function', metavar='ID', help='a project function id, match id or function name')
    ls.add_argument('--cue', nargs='+', default=None, metavar='K')
    ls.add_argument('--limit', type=_bounded(1, 50_000), default=DEFAULT_LIMIT, metavar='N')
    delta = common(act.add_parser('delta', help='the whole strings-delta/1 document'))
    _project_options(delta)
    explain = common(act.add_parser('explain', help='links, reasons and provenance of one changed string'))
    _project_options(explain)
    explain.add_argument('--id', required=True, dest='string_id', metavar='STRING_ID')
    scan = common(act.add_parser('scan', help='built-in scan of both artifacts (no FLOSS)'))
    scan.add_argument('project', type=Path)
    scan.add_argument('--builtin', action='store_true', help='required: the in-process scan')
    scan.add_argument('--min-length', type=_bounded(1, 4096), default=4, metavar='N')
    export = common(act.add_parser('export', help='write the delta to a JSON or CSV file (redacted by default)'))
    _project_options(export)
    export.add_argument('--out', type=Path, required=True, metavar='FILE')
    export.add_argument('--format', choices=('json', 'csv'), required=True, dest='fmt')
    export.add_argument('--scope', choices=('changed', 'all'), default='changed')
    export.add_argument('--force', action='store_true', help='replace an existing file')


@dataclass
class Computed:
    delta: object
    tables: dict
    sources: dict[str, str]
    notes: list[str] = field(default_factory=list)


def table_from_source(result):
    """The columnar table of one `SourceResult`: the basis records what the rows were extracted with."""
    from . import contracts as c
    from .limits import NONE_U32
    from .table import CONFIDENCE, ENCODINGS, FLAG_SECRET, StringRow, StringTable
    from .table import TYPES as TABLE_TYPES
    part = result.part
    types = tuple(t for t in part.types if t in TABLE_TYPES)
    basis = c.StringBasis(
        artifact_sha256=result.artifact_sha256, side=result.side, min_length=result.min_length or 4,
        language=c.LanguageInfo(selected=result.language), rows_seen=max(result.rows_seen, len(result.rows)),
        rows_kept=len(result.rows),
        stages={name: c.StageState(state=s.state, detail=s.detail[:200]) for name, s in result.stages.items()},
        parts=(c.BasisPart(
            source=part.source, semantics_id=part.semantics_id, source_version=part.source_version or '',
            executable_sha256=part.executable_sha256, run_id=part.run_id, raw_sha256=part.raw_sha256,
            types=types, config_digest=part.config_digest, consent_sha256=part.consent_sha256),))

    def u32(value: int | None) -> int:
        return NONE_U32 if value is None else value
    return StringTable.from_rows(basis, (StringRow(
        value_sha256=r.value_sha256, type=TABLE_TYPES.index(r.type), encoding=ENCODINGS.index(r.encoding),
        length=r.length, offset=u32(r.offset), rva=u32(r.rva), fn_rva=u32(r.fn_rva), site=u32(r.site_rva),
        confidence=CONFIDENCE.index(r.confidence), flags=FLAG_SECRET if r.secret_kind else 0, display=r.display)
        for r in result.rows))


def _fail(message: str, code: str = 'PT-STR-INPUT'):
    from .contracts import StringsError
    return StringsError(code, message)


def _artifacts(service) -> dict:
    found = {a.side: a for a in service.project.artifacts}
    if set(found) != {'older', 'newer'}:
        raise _fail('the project needs an older and a newer artifact')
    return found


@dataclass
class _Image:
    pe: object | None = None
    overview: object | None = None


def _inspect(path: Path, sha256: str) -> _Image:
    """PE layout and import names of one verified artifact; an unparsable image just has no RVAs."""
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..intelligence.tools.common import ToolError
    from ..intelligence.tools.normalize import PeMap
    from ..pe_overview import inspect_pe
    try:
        reader = VerifiedArtifactReader.open_path(path, sha256)
    except ArtifactBytesError as exc:
        raise _fail(f'the artifact cannot be read ({exc.code})') from None
    try:
        overview = inspect_pe(reader)
        try:
            return _Image(PeMap.from_reader(reader), overview)
        except ToolError:
            return _Image(None, overview)
    finally:
        reader.close()


def _floss_source(store, artifact):
    from .sources import FlossEvidenceSource
    found = store.latest('floss', artifact.side)
    if found is None or found[1] is None or not found[0].raw_sidecar:
        return None
    run, evidence = found
    raw_sha = run.raw_sidecar.rsplit('-', 1)[-1].removesuffix('.json')
    return FlossEvidenceSource(
        evidence, executable_sha256=run.manifest.executable_sha256, source_version=run.manifest.version,
        consent_sha256=run.options.get('emulation_consent_sha256'), raw_sha256=raw_sha)


def _source(args, service, store, artifact, image: _Image, cancel: threading.Event):
    from .scan import BuiltinScanSource
    if args.source != 'builtin':
        floss = _floss_source(store, artifact)
        if floss is not None:
            return floss, 'floss'
        if args.source == 'floss':
            raise _fail(f'no stored FLOSS evidence for the {artifact.side} artifact: run `intel-tools run` first')
    pe = image.pe
    return BuiltinScanSource(
        service.root / artifact.relative_path, artifact_sha256=artifact.sha256, side=artifact.side,
        min_length=args.min_length, offset_to_rva=(lambda off: pe.offset_to_rva(off)[0]) if pe else None,
        cancel=cancel.is_set), 'builtin-scan'


def _imports(image: _Image) -> tuple[frozenset[str], frozenset[str]]:
    overview = image.overview
    imports = overview.imports.dlls if overview and overview.imports else ()
    exports = overview.exports.names if overview and overview.exports else ()
    return frozenset(n for dll in imports for n in dll.functions), frozenset(exports)


def _load_anchors(path: Path | None):
    from pydantic import ValidationError

    from ..intelligence.contracts import AnchorSet
    if path is None:
        return None
    try:
        if path.stat().st_size > MAX_ANCHOR_FILE:
            raise _fail('the anchors file is too large')
        return AnchorSet.model_validate_json(path.read_bytes())
    except OSError:
        raise _fail('the anchors file cannot be read') from None
    except ValidationError:
        raise _fail('the anchors file is not a valid AnchorSet') from None


def _links(service, tables: dict, images: dict, notes: list[str]):
    """Pairing and function links when the project has a completed analysis and parsable images, else none."""
    from ..intelligence.tools.normalize import FunctionPairing
    from ..nway.contracts import NwayError
    from ..nway.series import current_run_id, read_raw_matches
    from .contracts import StringsError
    from .links import SideFunctions, link_strings
    project = service.project
    run_id = current_run_id(project)
    if not project.matches or run_id is None or any(images[s].pe is None for s in tables):
        return FunctionPairing.empty(), None
    try:
        raw, raw_notes = read_raw_matches(service.root, project)
    except NwayError as exc:
        notes.append(f'function pairing unavailable: {exc}')
        return FunctionPairing.empty(), None
    pes = {side: images[side].pe for side in tables}
    pairing = FunctionPairing.from_project(
        project.matches, raw, older_base=pes['older'].image_base, newer_base=pes['newer'].image_base,
        older_size=pes['older'].size_of_image, newer_size=pes['newer'].size_of_image, notes=raw_notes)
    functions = {side: SideFunctions.from_matches(project.matches, side, pes[side].image_base,
                                                  pes[side].size_of_image) for side in tables}
    try:
        return pairing, link_strings(tables, pairing=pairing, functions=functions, ghidra_group=f'ghidra:{run_id}')
    except StringsError as exc:
        notes.append(f'function links unavailable: {exc.message}')
        return pairing, None


def compute(args, service, cancel: threading.Event) -> Computed:
    from ..enrichment.storage import EnrichmentStore
    from ..intelligence.tools.store import ToolStore
    from .anchors import attach_anchors, terms
    from .cues import CueContext
    from .delta import compute_delta
    artifacts = _artifacts(service)
    anchors = _load_anchors(args.anchors)
    store = ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)
    images = {side: _inspect(service.root / a.relative_path, a.sha256) for side, a in artifacts.items()}
    tables, sources, notes = {}, {}, []
    for side, artifact in artifacts.items():
        source, sources[side] = _source(args, service, store, artifact, images[side], cancel)
        tables[side] = table_from_source(source.load())
    pairing, linked = _links(service, tables, images, notes)
    hints = terms(anchors)
    contexts = {}
    for side, other in (('older', 'newer'), ('newer', 'older')):
        imports, exports = _imports(images[side])
        contexts[side] = CueContext(imports=imports, exports=exports, other_side_imports=_imports(images[other])[0],
                                    api_hints=hints.api_hints, advisory_phrases=hints.advisory_phrases)
    sections = {side: image.overview.sections for side, image in images.items()
                if image.overview and image.overview.sections}
    delta = compute_delta(tables['older'], tables['newer'], pairing=pairing, links=linked, contexts=contexts,
                          sections=sections)
    return Computed(attach_anchors(delta, anchors), tables, sources, notes)


def reveal_map(tables: dict) -> dict[str, str]:
    """value hash -> escaped text of the secret-looking strings, only ever built for `--show-secrets`."""
    from .table import FLAG_SECRET
    return {row.value_sha256.hex(): row.display for table in tables.values() for row in table
            if row.flags & FLAG_SECRET}


def _dump(change, reveal: dict[str, str] | None) -> dict:
    row = change.model_dump(mode='json')
    if reveal and change.value_sha256 in reveal:
        row['display'] = reveal[change.value_sha256]
    return row


def _functions(change) -> set[str]:
    return {x for link in change.links for x in (link.function.project_function_id, link.function.match_id,
                                                 link.function.name) if x}


def _keep(change, args) -> bool:
    observed = [o for o in ((change.older if args.side != 'newer' else None),
                            (change.newer if args.side != 'older' else None)) if o]
    wanted = {'changed': lambda s: s != 'both', 'all': lambda s: True}.get(args.change, lambda s: s == args.change)
    return (bool(observed) and wanted(change.status)
            and (not args.types or any(t in args.types for o in observed for t in o.types))
            and (not args.function or args.function in _functions(change))
            and (not args.cue or any(c in args.cue for c in change.cues)))


def _line(row: dict) -> str:
    return f'R{row["review_tier"]} {GLYPH[row["status"]]} {row["status"]:<22} {row["display"]}'


def _exit(delta, *, results: bool = True) -> tuple[int, str]:
    from ..cli import NO_RESULTS, OK, RUNTIME
    if not delta.comparable:
        return RUNTIME, 'failed'
    if delta.truncated:
        return RUNTIME, 'partial'
    return (OK, 'complete') if results else (NO_RESULTS, 'complete')


def _summary(computed: Computed) -> dict:
    delta = computed.delta
    return {'comparable': delta.comparable, 'basis_notes': list(delta.basis_notes), 'sources': computed.sources,
            'notes': computed.notes}


def _list(args, service, cancel) -> int:
    from ..cli import _emit
    computed = compute(args, service, cancel)
    reveal = reveal_map(computed.tables) if args.show_secrets else None
    rows = [_dump(c, reveal) for c in computed.delta.changes if _keep(c, args)]
    result = {**_summary(computed), 'counts': computed.delta.counts, 'total': len(rows), 'changes': rows[:args.limit]}
    code, status = _exit(computed.delta, results=bool(rows))
    _emit(args, 'strings list', status, result, computed.notes,
          '\n'.join([*computed.delta.basis_notes, *(_line(r) for r in result['changes'])]))
    return code


def _delta(args, service, cancel) -> int:
    from ..cli import _emit
    computed = compute(args, service, cancel)
    delta = computed.delta
    code, status = _exit(delta, results=bool(delta.changes))
    result = {**delta.model_dump(mode='json'), 'sources': computed.sources}
    text = (f'{len(delta.changes)} changed strings ' + ' '.join(f'{k} {v}' for k, v in delta.counts.items())
            if delta.comparable else 'not comparable: ' + '; '.join(delta.basis_notes))
    _emit(args, 'strings delta', status, result, computed.notes, text)
    return code


def _explain(args, service, cancel) -> int:
    from ..cli import ENVIRONMENT, _emit
    computed = compute(args, service, cancel)
    found = next((c for c in computed.delta.changes if args.string_id in (c.id, c.value_sha256)), None)
    if found is None:
        _emit(args, 'strings explain', 'failed', {'string_id': args.string_id, **_summary(computed)}, computed.notes,
              'No changed string has that id.')
        return ENVIRONMENT
    reveal = reveal_map(computed.tables) if args.show_secrets else None
    provenance = {side: [p.model_dump(mode='json') for p in table.basis.parts]
                  for side, table in computed.tables.items()}
    hits = [h.model_dump(mode='json') for h in computed.delta.anchors.hits if h.string_id == found.value_sha256]
    result = {'change': _dump(found, reveal), 'provenance': provenance, 'anchor_hits': hits, **_summary(computed)}
    _emit(args, 'strings explain', 'complete', result, computed.notes,
          '\n'.join([_line(result['change']), *(f'reason: {r}' for r in found.reasons),
                     *(f'link {k.tier} {k.pair_status} {k.function.name or k.function.rva}' for k in found.links)]))
    return 0


def _scan(args, service, cancel) -> int:
    from ..cli import NO_RESULTS, OK, RUNTIME, _emit
    if not args.builtin:
        raise _fail('only the built-in scan runs here: pass --builtin (FLOSS is run by `intel-tools run`)')
    args.source, args.anchors = 'builtin', None
    rows = []
    for side, artifact in _artifacts(service).items():
        image = _inspect(service.root / artifact.relative_path, artifact.sha256)
        source, _label = _source(args, service, None, artifact, image, cancel)
        table = table_from_source(source.load())
        basis = table.basis
        rows.append({'side': side, 'artifact_sha256': artifact.sha256, 'min_length': basis.min_length,
                     'rows_seen': basis.rows_seen, 'rows_kept': basis.rows_kept, 'basis_digest': basis.digest(),
                     'stages': {k: v.model_dump(mode='json') for k, v in basis.stages.items()}})
    truncated = any(s['state'] == 'truncated' for r in rows for s in r['stages'].values())
    code, status = (RUNTIME, 'partial') if truncated else (OK, 'complete') if any(
        r['rows_kept'] for r in rows) else (NO_RESULTS, 'complete')
    _emit(args, 'strings scan', status, {'source': 'builtin-scan', 'sides': rows}, [],
          '\n'.join(f'{r["side"]}: {r["rows_kept"]} of {r["rows_seen"]} strings' for r in rows))
    return code


def _export(args, service, cancel) -> int:
    from ..cli import _emit
    from .export import export_delta
    computed = compute(args, service, cancel)
    reveal = reveal_map(computed.tables) if args.show_secrets else None
    result = export_delta(computed.delta, args.out, fmt=args.fmt, scope=args.scope, reveal=reveal, force=args.force)
    code, status = _exit(computed.delta, results=bool(result.rows))
    _emit(args, 'strings export', status, {'file': result.file, 'format': result.format, 'scope': result.scope,
                                           'rows': result.rows, 'sha256': result.sha256,
                                           'redacted': result.redacted, **_summary(computed)}, computed.notes,
          f'wrote {result.rows} rows to {result.file}')
    return code


def _exit_for(code: str) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, RUNTIME
    if code == 'PT-STR-CANCEL':
        return CANCELLED
    return ENVIRONMENT if code in ('PT-STR-INPUT', 'PT-STR-EXPORT', 'PT-STR-CONSENT', 'PT-STR-SOURCE') else RUNTIME


def dispatch(args, cancel: threading.Event) -> int:
    from ..cli import CliError, _open
    from ..intelligence.tools.common import ToolError
    from .contracts import StringsError
    from .scan import ScanError
    service = _open(args.project)
    try:
        return {'list': _list, 'delta': _delta, 'explain': _explain, 'scan': _scan,
                'export': _export}[args.action](args, service, cancel)
    except StringsError as exc:
        raise CliError(_exit_for(exc.code), str(exc)) from None
    except ScanError as exc:
        raise CliError(_exit_for(exc.code), str(exc)) from None
    except ToolError as exc:
        raise CliError(_exit_for('PT-STR-SOURCE'), str(exc)) from None
    finally:
        service.close()
