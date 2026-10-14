"""``patchtrace intelligence import|fetch|explain`` (SPEC-28 sections J and L). Headless: never imports Qt.

Output is the ``enrichment-cli/1`` envelope: with ``--json`` stdout carries exactly one document; diagnostics and
the announcement of every network request go to stderr. Exit codes: 0 success; 2 invalid arguments, consent or
input file (a malformed local file included); 3 runtime, network, provider, integrity or partial result; 4
legitimate no result (no index entry names the CVE, or no stored advisory lists it); 5 cancelled.

The parser is built on every CLI call, so only the standard library is imported at module level; everything that
needs pydantic is imported inside the actions. ``ACTIONS`` maps an action name to its parser registration and its
runner: a later track adds actions with ``ACTIONS.update`` and needs no further change in ``cli.py``.

Network use is consent-gated and goes through ``csaf.transport`` only: ``fetch`` needs ``--consent-hosts
msrc.microsoft.com``, or ``--offline`` with ``--cache-dir`` (the cache is the only source and no socket is
opened). HTTPS allowlist, size/redirect/time bounds and cancellation are the transport's; nothing about the
project, a binary or the analyst is sent. ``explain`` is offline. Advisory text is untrusted: everything printed
to a terminal passes ``reports.plain_text`` (controls and bidi marks become ``\\uXXXX``).
"""
from __future__ import annotations

import argparse
import contextlib
import functools
import hashlib
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

MAX_IMPORT_BYTES = 16 * 1024 * 1024  # equals csaf.transport.CAPS['document'] (a test pins it)
MAX_CVE_CHARS = 24  # the contract's CveId bound
MAX_ASSERTED = 64  # ArtifactIdentity.asserted_product_ids
MAX_PRODUCT_CHARS = 1000
MAX_FINDINGS_SHOWN = 5
MAX_WARNINGS = 20
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')
_LOCAL_INPUT = frozenset({'PT-INTEL-FORMAT', 'PT-INTEL-LIMIT', 'PT-INTEL-VALIDATE', 'PT-INTEL-UNSUPPORTED'})


@dataclass(frozen=True)
class Action:
    """One ``intelligence`` action: ``register(actions, common)`` adds its sub-parser, ``run(args, cancel)`` -> exit."""
    name: str
    register: Callable
    run: Callable


# ---------------------------------------------------------------------------------------------- shared helpers

def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _cve(value: str) -> str:
    text = value.strip().upper()
    if not text.isascii() or len(text) > MAX_CVE_CHARS or _CVE.fullmatch(text) is None:
        raise argparse.ArgumentTypeError('must look like CVE-YYYY-NNNN')
    return text


def _product(value: str) -> str:
    if not value or len(value) > MAX_PRODUCT_CHARS or not value.isprintable():
        raise argparse.ArgumentTypeError(f'a product ID is 1 to {MAX_PRODUCT_CHARS} printable characters')
    return value


def _cli():
    from .. import cli
    return cli


def _exit_code(exc, *, local: bool) -> int:
    cli = _cli()
    if exc.code == 'PT-INTEL-CANCEL':
        return cli.CANCELLED
    if exc.code in ('PT-INTEL-INPUT', 'PT-INTEL-CONFIG') or (local and exc.code in _LOCAL_INPUT):
        return cli.ENVIRONMENT
    return cli.RUNTIME


def _handled(command: str, *, local: bool = False):
    """Map ``IntelError`` to the CLI contract: cancellation emits a ``cancelled`` envelope (exit 5); everything
    else becomes a ``CliError`` whose message is terminal-safe. ``local`` marks input read from a local file, where
    a malformed document is the analyst's input problem (exit 2) rather than a runtime failure."""
    def wrap(run):
        @functools.wraps(run)
        def inner(args, cancel):
            from .contracts import IntelError
            from .reports import plain_text
            cli = _cli()
            try:
                return run(args, cancel)
            except IntelError as exc:
                if exc.code == 'PT-INTEL-CANCEL':
                    cli._emit(args, command, 'cancelled', None, [], '')
                    return cli.CANCELLED
                raise cli.CliError(_exit_code(exc, local=local), plain_text(str(exc), 600)) from None
        return inner
    return wrap


def _say(args, command: str, status: str, result, warnings, text: str) -> None:
    """Emit the envelope. Text mode prints warnings to a terminal, so they are sanitised first; JSON keeps the
    data and lets ``json.dumps`` escape it."""
    if not getattr(args, 'json', False):
        from .reports import plain_text
        warnings = [plain_text(w, 500) for w in warnings]
    _cli()._emit(args, command, status, result, list(warnings), text)


@contextlib.contextmanager
def _project(path: Path):
    from ..enrichment.storage import EnrichmentStore
    from .storage import AdvisoryStore
    service = _cli()._open(path)
    try:
        yield service, AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                                     service.project.revision)
    finally:
        service.close()


def _stored_row(stored) -> dict:
    return {'source': stored.source.model_dump(mode='json'), 'facts_id': stored.facts.facts_id,
            'cves': list(stored.facts.cves()), 'superseded': stored.superseded, 'retrievals': stored.retrievals,
            'validation_warnings': len(stored.facts.validation.warnings)}


def _describe(stored) -> str:
    from .reports import plain_text
    source = stored.source
    return (f'{plain_text(source.tracking_id, 80)} revision {plain_text(source.revision, 20)} '
            f'({source.sha256[:12]}): {len(stored.facts.cves())} CVE(s), '
            f'{"superseded" if stored.superseded else "current"}, {stored.retrievals} retrieval(s), '
            f'{source.authenticity_state}')


def _more_findings(findings) -> None:
    """The validation errors after the first (the first is in the error message), at most a few, on stderr."""
    from .reports import plain_text
    for item in findings[1:1 + MAX_FINDINGS_SHOWN]:
        print(f'  also [{plain_text(item.test, 20)}] {plain_text(item.pointer or "/", 120)}: '
              f'{plain_text(item.message, 200)}', file=sys.stderr)
    if len(findings) > 1 + MAX_FINDINGS_SHOWN:
        print(f'  ... and {len(findings) - 1 - MAX_FINDINGS_SHOWN} more finding(s)', file=sys.stderr)


# ---------------------------------------------------------------------------------------------- import

def _register_import(actions, common) -> None:
    p = common(actions.add_parser(
        'import', help='store a local CSAF 2.0 JSON file as an advisory source',
        description='Validates a CSAF 2.0 document (strict JSON, schema, mandatory tests) and stores its exact '
                    'bytes and normalized facts in the project, append-only. The document must list the CVE. '
                    'Nothing is sent anywhere; local paths are never stored.'))
    p.add_argument('project', type=Path)
    p.add_argument('file', type=Path, help='CSAF 2.0 JSON file')
    p.add_argument('--cve', required=True, type=_cve, metavar='CVE-YYYY-NNNN', help='a CVE the document must list')


def _read_bounded(path: Path) -> bytes:
    from .reports import plain_text
    cli = _cli()
    name = plain_text(path.name, 120)
    if not path.is_file():
        raise cli.CliError(cli.ENVIRONMENT, f'{name} is not a readable file')
    try:
        with path.open('rb') as handle:
            data = handle.read(MAX_IMPORT_BYTES + 1)
    except OSError as exc:
        raise cli.CliError(cli.ENVIRONMENT, f'cannot read {name}: {plain_text(exc.strerror or exc, 120)}') from None
    if len(data) > MAX_IMPORT_BYTES:
        raise cli.CliError(cli.ENVIRONMENT, f'{name} is larger than {MAX_IMPORT_BYTES} bytes')
    return data


@_handled('intelligence import', local=True)
def _run_import(args, cancel) -> int:
    from .csaf.validate import ValidationFailed, load_document
    from .reports import plain_text
    cli = _cli()
    raw = _read_bounded(args.file)
    try:
        document, _report = load_document(raw, cancel=cancel)
    except ValidationFailed as exc:
        _more_findings(exc.report.errors)
        raise
    if not any(item.get('cve') == args.cve for item in document.get('vulnerabilities') or ()):
        raise cli.CliError(cli.ENVIRONMENT, f'{plain_text(args.file.name, 120)} does not list {args.cve}')
    with _project(args.project) as (_service, store):
        stored = store.add(raw, origin='local-import', uri=None, file_name=args.file.name, retrieved_at=_now(),
                           cancel=cancel)
    warnings = [f'{w.test} {w.pointer or "/"}: {w.message}' for w in stored.facts.validation.warnings[:MAX_WARNINGS]]
    _say(args, 'intelligence import', 'complete', {'cve': args.cve, **_stored_row(stored)}, warnings,
         f'imported {_describe(stored)}')
    return cli.OK


# ---------------------------------------------------------------------------------------------- fetch

def _register_fetch(actions, common) -> None:
    p = common(actions.add_parser(
        'fetch', help='download a CSAF advisory from msrc.microsoft.com (needs consent) or replay a cache',
        description='Reads the provider metadata and the directory index, selects index entries whose file name '
                    'contains the CVE ID, downloads them, checks the .sha256 file when present and validates the '
                    'document. HTTPS to msrc.microsoft.com only, bounded and cancellable. Nothing about the '
                    'project or any binary is sent. --offline reads only the cache and opens no socket.'))
    p.add_argument('project', type=Path)
    p.add_argument('--cve', required=True, type=_cve, metavar='CVE-YYYY-NNNN')
    p.add_argument('--consent-hosts', default='', metavar='HOSTS',
                   help='must be exactly msrc.microsoft.com (not needed with --offline)')
    p.add_argument('--provider-metadata', metavar='URL',
                   help='provider-metadata.json URL inside the same allowlist (the default location is unverified)')
    p.add_argument('--cache-dir', type=Path, help='opt-in content-addressed cache of every response')
    p.add_argument('--offline', action='store_true', help='use only --cache-dir; no network, no consent needed')


def _make_transport(consent, *, cancel, cache, offline, announce):
    # Seam for tests to inject a fake opener; production always uses the hardened default (urllib_open).
    from .csaf.transport import CsafTransport
    return CsafTransport(consent, cancel=cancel, cache=cache, offline=offline, announce=announce)


def _announce(message: str) -> None:
    print(f'request: {message}', file=sys.stderr)


@_handled('intelligence fetch')
def _run_fetch(args, cancel) -> int:
    from .contracts import IntelError
    from .csaf import discovery
    from .csaf.transport import CsafConsent, OfflineCache
    cli = _cli()
    command = 'intelligence fetch'
    if args.cache_dir is not None and args.cache_dir.exists() and not args.cache_dir.is_dir():
        raise cli.CliError(cli.ENVIRONMENT, '--cache-dir is not a directory')
    if args.offline:
        if args.cache_dir is None or not args.cache_dir.is_dir():
            raise cli.CliError(cli.ENVIRONMENT, '--offline needs --cache-dir naming an existing cache directory')
        consent = None
    elif not args.consent_hosts.strip():
        raise cli.CliError(cli.ENVIRONMENT, 'fetch contacts msrc.microsoft.com only with your consent: pass '
                                            '--consent-hosts msrc.microsoft.com (or use --offline with --cache-dir)')
    else:
        consent = CsafConsent.for_hosts(args.consent_hosts.split(','))
    provider = discovery.provider_url_ok(args.provider_metadata or discovery.DEFAULT_PROVIDER_METADATA)
    cache = OfflineCache(args.cache_dir) if args.cache_dir is not None else None
    with _project(args.project) as (_service, store):
        transport = _make_transport(consent, cancel=cancel, cache=cache, offline=args.offline, announce=_announce)
        try:
            found = discovery.discover(transport, args.cve, provider)
        except IntelError as exc:
            if exc.code in ('PT-INTEL-NOTFOUND', 'PT-INTEL-PROVIDER') and not args.offline \
                    and args.provider_metadata is None:
                raise IntelError(exc.code, f'{exc.message} (the Microsoft provider-metadata location is unverified; '
                                           'use --provider-metadata to name it)', recoverable=exc.recoverable) from None
            raise
        warnings = list(found.warnings)
        result = {'cve': args.cve, 'provider': provider, 'offline': bool(args.offline),
                  'directories': list(found.directories), 'candidates': [e.url for e in found.candidates],
                  'skipped_index_lines': found.skipped_lines, 'requests': [], 'stored': []}
        if not found.candidates:
            result['requests'] = list(transport.requests)
            _say(args, command, 'complete', result, warnings,
                 f'No index entry names {args.cve}. File names are only hints: import the advisory document with '
                 '`intelligence import` if you have it.')
            return cli.NO_RESULTS
        documents, more = discovery.fetch_documents(transport, found, args.cve, cancel)
        warnings += more
        rows = []
        for document in documents:
            rows.append(store.add(document.raw, origin='https-fetch', uri=document.url, file_name=document.file_name,
                                  retrieved_at=document.retrieved_at, authenticity_state=document.authenticity_state,
                                  cancel=cancel))
    result['requests'] = list(transport.requests)
    result['stored'] = [_stored_row(stored) for stored in rows]
    if not rows:
        _say(args, command, 'failed', result, warnings,
             f'{len(found.candidates)} candidate file(s) were checked, but none is an acceptable advisory that '
             f'lists {args.cve}; see the warnings.')
        return cli.RUNTIME
    where = 'the offline cache' if args.offline else 'msrc.microsoft.com'
    lines = [f'{"read" if args.offline else "fetched"} {len(rows)} document(s) for {args.cve} from {where} '
             f'({len(transport.requests)} request(s))', *(f'  {_describe(stored)}' for stored in rows)]
    if not args.offline:
        lines.append('Nothing about the project or any binary was sent.')
    _say(args, command, 'complete', result, warnings, '\n'.join(lines))
    return cli.OK


# ---------------------------------------------------------------------------------------------- explain

def _register_explain(actions, common) -> None:
    p = common(actions.add_parser(
        'explain', help='explain a CVE for the older/newer artifacts from stored advisories (offline)',
        description='Joins the stored advisories that list the CVE with the project\'s two artifacts: product '
                    'applicability (verified identity only; a file name never maps), the CWE profile, rule '
                    'hypotheses and search anchors, with explicit unknowns. It restates vendor claims; it does not '
                    'show that any function contains or fixes the CVE. Never uses the network.'))
    p.add_argument('project', type=Path)
    p.add_argument('--cve', required=True, type=_cve, metavar='CVE-YYYY-NNNN')
    p.add_argument('--older-product', action='append', type=_product, metavar='PID',
                   help='analyst assertion: this advisory product ID describes the older artifact (repeatable)')
    p.add_argument('--newer-product', action='append', type=_product, metavar='PID',
                   help='analyst assertion for the newer artifact (repeatable)')
    p.add_argument('--export', type=Path, metavar='FILE',
                   help='also write the report; the suffix chooses the format (.json or .md, escaped, LF)')


def _asserted(values) -> tuple[str, ...]:
    unique = tuple(sorted(set(values or ())))
    if len(unique) > MAX_ASSERTED:
        cli = _cli()
        raise cli.CliError(cli.ENVIRONMENT, f'at most {MAX_ASSERTED} product IDs can be asserted per side')
    return unique


def _export_target(path: Path | None):
    """(path, format) after checking the target; the checks run before any work."""
    if path is None:
        return None
    from .reports import format_for
    cli = _cli()
    fmt = format_for(path)
    if not path.parent.is_dir():
        raise cli.CliError(cli.ENVIRONMENT, 'the directory of --export does not exist')
    if path.is_dir():
        raise cli.CliError(cli.ENVIRONMENT, '--export names a directory')
    return path, fmt


@_handled('intelligence explain')
def _run_explain(args, cancel) -> int:
    from .csaf.identity import project_identities
    from .explain import build_report
    from .reports import plain_text, render, summary, write_export
    cli = _cli()
    command = 'intelligence explain'
    target = _export_target(args.export)
    asserted = {'older': _asserted(args.older_product), 'newer': _asserted(args.newer_product)}
    with _project(args.project) as (service, store):
        advisories, warnings = store.for_cve(args.cve)
        if not advisories:
            none = {'cve': args.cve, 'report': None, 'export': None}
            if warnings:  # a damaged source may be the one that lists the CVE: not a clean "none"
                _say(args, command, 'partial', none, warnings, f'No usable stored advisory lists {args.cve}; some '
                                                               'stored sources were skipped (see the warnings).')
                return cli.RUNTIME
            _say(args, command, 'complete', none, [], f'no stored advisory lists {args.cve}; run '
                                                     '`intelligence import` or `intelligence fetch` first')
            return cli.NO_RESULTS
        older, newer = project_identities(service.project.artifacts, service.root, asserted, cancel)
        report = build_report(args.cve, advisories, older, newer, cancel=cancel)
    export = None
    lines = [summary(report)]
    if target is not None:
        path, fmt = target
        data = render(report, fmt)
        write_export(path, data)
        export = {'format': fmt, 'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        lines.append(f'exported the {fmt} report to {plain_text(path, 300)} ({len(data)} bytes)')
    _say(args, command, 'partial' if warnings else 'complete',
         {'cve': args.cve, 'report': report.model_dump(mode='json'), 'export': export}, warnings, '\n'.join(lines))
    return cli.RUNTIME if warnings else cli.OK


# ---------------------------------------------------------------------------------------------- the command

ACTIONS: dict[str, Action] = {a.name: a for a in (Action('import', _register_import, _run_import),
                                                  Action('fetch', _register_fetch, _run_fetch),
                                                  Action('explain', _register_explain, _run_explain))}


def register(sub, common) -> None:
    """Add the ``intelligence`` command (called from ``cli._parser``)."""
    parser = sub.add_parser('intelligence', help='advisory (CSAF) intelligence: import, fetch, explain',
                            description='Advisory facts are vendor claims with provenance; rule hypotheses are '
                                        'search guidance. Neither is verification of a vulnerability in a function.')
    actions = parser.add_subparsers(dest='action', required=True, parser_class=type(parser))
    for action in ACTIONS.values():
        action.register(actions, common)


def dispatch(args, cancel) -> int:
    return ACTIONS[args.action].run(args, cancel)
