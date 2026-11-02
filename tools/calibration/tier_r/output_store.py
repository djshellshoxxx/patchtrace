"""Retain normalized Tier R evidence with atomic, non-replacing publication.

Selectively adapts the intent of PR #78 (repository MIT license), not its
check-then-replace writer. There is no fallback when atomic hard links are absent.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from ..common import canonical_json, strict_json
from . import contracts as C
from . import report_schemas as RS

MAX_ENGINE_OUTPUT_BYTES = 64 * 1024 * 1024
MANAGED_MARKER = '.tier-r-output-run.json'
CREDIT_FILE = 'output-credits.json'
MANAGED_FILES = (MANAGED_MARKER, CREDIT_FILE)
COMPLETION_FILE = '.tier-r-output-incomplete.json'
FAILURE_FILE = 'evaluation-failure.json'
UNCREDITED_REPORT = 'uncredited-report.json'
_INCOMPLETE_FILES = (COMPLETION_FILE, FAILURE_FILE, UNCREDITED_REPORT)
_MARKER_BYTES = b'{"contract":"tier-r-output-run/1"}'
_COMPLETION_BYTES = b'{"contract":"tier-r-output-completion/1","status":"incomplete"}'
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z')
_ENGINES = frozenset(('rz-diff', 'bindiff', 'ghidriff', 'attention'))


class OutputError(ValueError):
    """Evidence could not be retained; it must not receive successful-run credit."""


def output_file_name(pair_id: str, engine: str) -> str:
    if not isinstance(pair_id, str) or not _NAME.fullmatch(pair_id):
        raise OutputError('invalid pair identifier for output filename')
    if engine not in _ENGINES:
        raise OutputError('engine has no normalized output storage contract')
    return f'{pair_id}.{engine}.json'


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _file_version(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def _canonical_bytes(document: dict, maximum: int) -> bytes:
    """Encode already validated values with an incremental total-byte cap."""
    stream = io.BytesIO()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    try:
        for chunk in encoder.iterencode(document):
            encoded = chunk.encode('utf-8')
            if stream.tell() + len(encoded) > maximum:
                raise OutputError(f'normalized output exceeds {maximum} bytes')
            stream.write(encoded)
    except (TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, OutputError):
            raise
        raise OutputError(f'normalized output is not canonical JSON: {type(exc).__name__}') from None
    return stream.getvalue()


def canonical_output_bytes(document: dict) -> bytes:
    """Validate scalar/array bounds before encoding the original document, without adding model defaults."""
    try:
        RS.validate_engine_output_document(document)
    except C.ContractError as exc:
        raise OutputError(str(exc)) from None
    return _canonical_bytes(document, MAX_ENGINE_OUTPUT_BYTES)


def read_output_bytes(path: Path, maximum: int = RS.MAX_OUTPUT_BYTES) -> bytes:
    """Read one bounded regular, unlinked file and reject observed identity/content-version changes."""
    path = Path(path)
    try:
        named = path.lstat()
        if _linked(named) or not stat.S_ISREG(named.st_mode) or named.st_size > maximum:
            raise OutputError('output metadata is linked, nonregular or exceeds its byte limit')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if _identity(before) != _identity(named) or not stat.S_ISREG(before.st_mode):
                raise OutputError('output identity changed while opening')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                raw = stream.read(maximum + 1)
            after, final = os.fstat(descriptor), path.lstat()
            if (len(raw) > maximum or _linked(final) or _file_version(before) != _file_version(after)
                    or _file_version(after) != _file_version(final)):
                raise OutputError('output bytes changed while reading or exceed their byte limit')
            return raw
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OutputError(f'output evidence unreadable: {type(exc).__name__}') from None


def _present(path: Path) -> bool:
    try:
        path.lstat()  # A broken symlink is present and must not select legacy mode.
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OutputError(f'managed metadata unreadable: {type(exc).__name__}') from None


def _directory_identity(folder: Path) -> tuple[int, int]:
    try:
        info = folder.lstat()
    except OSError as exc:
        raise OutputError(f'output directory unavailable: {type(exc).__name__}') from None
    if _linked(info) or not stat.S_ISDIR(info.st_mode):
        raise OutputError('output directory is linked or not a directory')
    return _identity(info)


def legacy_output_paths(folder: Path) -> list[Path]:
    """Preserve loose-file discovery, but never implicitly select nested managed runs."""
    paths = []

    def error(exc):
        raise OutputError(f'output directory unreadable: {type(exc).__name__}') from None

    for directory, children, files in os.walk(folder, followlinks=False, onerror=error):
        if set((*MANAGED_FILES, *_INCOMPLETE_FILES)) & set((*children, *files)):
            raise OutputError('select one managed output run; parent collections are ambiguous')
        paths.extend(Path(directory) / name for name in files if name.endswith('.json'))
    return sorted(paths)


def _report_references(reports: Sequence[dict]) -> dict[tuple[str, str], tuple[str, str, str]]:
    """Successful refs bound to validated report digest/symbols, with unique pair and engine ownership."""
    references, seen, report_ids = {}, set(), set()
    for raw in reports:
        try:
            report = C.load_report(canonical_json(raw))
        except (C.ContractError, ValueError) as exc:
            raise OutputError(f'invalid credit report: {str(exc)[:250]}') from None
        if report.report_sha256 in report_ids:
            raise OutputError('duplicate credit report')
        report_ids.add(report.report_sha256)
        inputs = {item.pair_id for item in report.inputs}
        engines = {item.engine for item in report.engines}
        if len(inputs) != len(report.inputs) or len(engines) != len(report.engines):
            raise OutputError('ambiguous report input or engine ownership')
        for pair in report.pairs:
            key = pair.pair_id, pair.engine
            if key in seen or pair.pair_id not in inputs or pair.engine not in engines:
                raise OutputError('duplicate or foreign report pair/engine reference')
            seen.add(key)
            if pair.status == 'ok':
                if pair.output_sha256 is None or pair.metrics is None:
                    raise OutputError('successful report reference lacks output digest or metrics')
                references[key] = report.report_sha256, pair.output_sha256, report.symbols
            elif pair.output_sha256 is not None or pair.metrics is not None:
                raise OutputError('failed report reference carries success credit')
    return references


def _validated_credits(document: dict) -> RS.OutputCredits:
    try:
        raw = _canonical_bytes(document, RS.MAX_CREDIT_BYTES)
        model = RS.OutputCredits.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise OutputError(f'invalid output credit manifest: {str(exc)[:250]}') from None
    references = _report_references(document['reports'])
    records = {(record.pair_id, record.engine): record for record in model.outputs}
    if len(records) != len(model.outputs) or records.keys() != references.keys():
        raise OutputError('credit records do not uniquely cover successful report references')
    for key, record in sorted(records.items()):
        if (record.report_sha256, record.output_sha256, record.symbols) != references[key]:
            raise OutputError('credit record differs from its successful report reference')
    return model


def _credit_document(reports: Sequence[dict], output_records: Sequence[dict]) -> dict:
    # Bound complete batches before validating/copying each potentially large report.
    try:
        _canonical_bytes({'reports': reports}, RS.MAX_CREDIT_BYTES)
    except OutputError as exc:
        raise OutputError(f'invalid output credit manifest: {exc}') from None
    references = _report_references(reports)
    records = {}
    for record in output_records:
        try:
            key = record['pair_id'], record['engine']
            if key in records:
                raise OutputError('duplicate retained output metadata')
            records[key] = record
        except (KeyError, TypeError) as exc:
            raise OutputError(f'invalid retained output metadata: {type(exc).__name__}') from None
    outputs = []
    for key, (report_sha, output_sha, symbols) in sorted(references.items()):
        record = records.get(key)
        if record is None or (record.get('output_sha256'), record.get('symbols')) != (output_sha, symbols):
            raise OutputError('successful report reference has no matching retained output')
        outputs.append({**record, 'report_sha256': report_sha})
    document = {'contract': RS.CREDITS_CONTRACT, 'reports': list(reports), 'outputs': outputs}
    _validated_credits(document)
    return document


def preflight_credit_manifest(reports: Sequence[dict], output_records: Sequence[dict]) -> None:
    """Check complete batches and the exact aggregate budget without creating files.

    Records contain write_raw metadata (without report_sha256). Retained records
    not referenced by a successful report remain uncredited, as in finalization.
    Actual retained bytes and directory ownership are rechecked by finalize.
    """
    _credit_document(reports, output_records)


def _verified_credits(folder: Path, document: dict) -> list[tuple[Path, bytes, RS.EngineOutputDoc, str]]:
    model = _validated_credits(document)
    result = []
    for record in sorted(model.outputs, key=lambda row: (row.pair_id, row.engine)):
        key = record.pair_id, record.engine
        path = folder / output_file_name(*key)
        raw = read_output_bytes(path)
        if hashlib.sha256(raw).hexdigest() != record.output_sha256:
            raise OutputError('credited output byte digest mismatch')
        try:
            parsed = RS.load_engine_output(raw)
        except C.ContractError as exc:
            raise OutputError(str(exc)) from None
        if (parsed.engine, parsed.older_sha256, parsed.newer_sha256, parsed.symbols, parsed.version) != (
                record.engine, record.older_sha256, record.newer_sha256, record.symbols, record.version):
            raise OutputError('credited output owner/image/symbol/version metadata mismatch')
        if _canonical_bytes(strict_json(raw), RS.MAX_OUTPUT_BYTES) != raw:
            raise OutputError('credited output bytes are not canonical')
        result.append((path, raw, parsed, record.output_sha256))
    return result


def read_credited_outputs(folder: Path) -> list[tuple[Path, bytes, RS.EngineOutputDoc, str]] | None:
    """Verify a completed managed run; None means explicitly unverified legacy compatibility, never credit."""
    folder = Path(folder)
    owner = _directory_identity(folder)
    if any(_present(folder / name) for name in _INCOMPLETE_FILES):
        raise OutputError('managed output run is incomplete or failed')
    marked = _present(folder / MANAGED_MARKER)
    if not marked:
        if _present(folder / CREDIT_FILE):
            raise OutputError('credit manifest lacks its managed run marker')
        legacy_output_paths(folder)  # Reject a parent collection before selecting legacy compatibility.
        return None
    result = _verify_completed_outputs(folder)
    if any(_present(folder / name) for name in _INCOMPLETE_FILES):
        raise OutputError('managed output run became incomplete or failed')
    if _directory_identity(folder) != owner:
        raise OutputError('output directory ownership changed during credit verification')
    return result


def _verify_completed_outputs(folder: Path) -> list[tuple[Path, bytes, RS.EngineOutputDoc, str]]:
    """Common exact-byte checks; the writer calls this while its sentinel still blocks readers."""
    owner = _directory_identity(folder)
    if read_output_bytes(folder / MANAGED_MARKER, 4096) != _MARKER_BYTES:
        raise OutputError('invalid managed output run marker')
    if not _present(folder / CREDIT_FILE):
        raise OutputError('managed output run has no completed credit manifest')
    try:
        document = strict_json(read_output_bytes(folder / CREDIT_FILE, RS.MAX_CREDIT_BYTES))
    except (ValueError, RecursionError) as exc:
        raise OutputError(f'invalid output credit manifest: {type(exc).__name__}') from None
    result = _verified_credits(folder, document)
    if _directory_identity(folder) != owner:
        raise OutputError('output directory ownership changed during credit verification')
    return result


def publish_bytes(path: Path, raw: bytes) -> str:
    """Publish verified bytes exclusively; return their exact digest."""
    return _publish_owned_bytes(path, raw)[0]


def _publish_owned_bytes(path: Path, raw: bytes) -> tuple[str, tuple[int, int]]:
    """Publish complete bytes without replacing any existing file, link or device.

    A flushed/fsynced private stage is hard-linked into place atomically. Verify
    the linked inode and its actual bytes before success. A failed final artifact
    is retained without credit; only the owned temporary name is cleaned up.
    """
    path = Path(path)
    expected = hashlib.sha256(raw).hexdigest()
    pending = None
    owned = None
    descriptor = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix='.pending-', suffix='.tmp', dir=path.parent)
        pending = Path(name)
        with os.fdopen(descriptor, 'w+b') as handle:
            descriptor = None
            owned = _identity(os.fstat(handle.fileno()))
            if handle.write(raw) != len(raw):
                raise OutputError('short evidence write')
            handle.flush()
            os.fsync(handle.fileno())
            stage = pending.lstat()
            if _linked(stage) or not stat.S_ISREG(stage.st_mode) or _identity(stage) != owned:
                raise OutputError('evidence stage identity changed')
            os.link(pending, path, follow_symlinks=False)
            published = path.lstat()
            if _linked(published) or _identity(published) != owned:
                raise OutputError('published evidence identity changed')
            before = os.fstat(handle.fileno())
            handle.seek(0)
            actual = hashlib.sha256()
            count = 0
            while chunk := handle.read(min(1024 * 1024, len(raw) + 1 - count)):
                count += len(chunk)
                actual.update(chunk)
                if count > len(raw):
                    break
            after = os.fstat(handle.fileno())
            if (count != len(raw) or actual.hexdigest() != expected or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
                raise OutputError('published evidence bytes changed')
            if _identity(path.lstat()) != owned:
                raise OutputError('published evidence identity changed')
        return expected, owned
    except (OSError, NotImplementedError) as exc:
        raise OutputError(f'evidence publication failed: {type(exc).__name__}') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if pending is not None:
            try:
                if owned is None or _identity(pending.lstat()) == owned:
                    pending.unlink()
            except OSError:
                # A leftover .tmp is not a successful normalized JSON artifact.
                # Never remove the published path or another completed output.
                pass


class OutputStore:
    """One exclusively created run directory; never adopt an existing empty one."""

    def __init__(self, folder: Path):
        self.folder = Path(folder)
        try:
            self.folder.mkdir(parents=True, mode=0o700, exist_ok=False)
            info = self.folder.lstat()
            if _linked(info) or not stat.S_ISDIR(info.st_mode):
                raise OutputError('output directory is linked or not a directory')
            self._owner = _identity(info)
        except OSError as exc:
            raise OutputError(f'a fresh output directory is required: {type(exc).__name__}') from None
        self._written: dict[tuple[str, str], dict] = {}
        self._finalized = False
        self._attempted = False
        publish_bytes(self.folder / MANAGED_MARKER, _MARKER_BYTES)
        self._check_owner()

    def _check_owner(self) -> None:
        try:
            info = self.folder.lstat()
        except OSError as exc:
            raise OutputError(f'output directory unavailable: {type(exc).__name__}') from None
        if _linked(info) or not stat.S_ISDIR(info.st_mode) or _identity(info) != self._owner:
            raise OutputError('output directory ownership changed')

    def write(self, pair_id: str, engine: str, document: dict) -> str:
        raw = canonical_output_bytes(document)
        return self.write_raw(pair_id, engine, raw)

    def write_raw(self, pair_id: str, engine: str, raw: bytes) -> str:
        """Retain exact validated canonical bytes, including transfer copies, without inferring report credit."""
        filename = output_file_name(pair_id, engine)
        self._check_owner()
        if self._finalized or self._attempted or _present(self.folder / CREDIT_FILE):
            raise OutputError('managed output run is already finalized')
        if type(raw) is not bytes or len(raw) > MAX_ENGINE_OUTPUT_BYTES:
            raise OutputError('normalized output must be bounded immutable bytes')
        try:
            parsed = RS.load_engine_output(raw)
        except C.ContractError as exc:
            raise OutputError(f'normalized output contract invalid: {str(exc)[:250]}') from None
        if parsed.engine != engine:
            raise OutputError('normalized output engine differs from its provider owner')
        if _canonical_bytes(strict_json(raw), MAX_ENGINE_OUTPUT_BYTES) != raw:
            raise OutputError('normalized output bytes must be canonical')
        digest = publish_bytes(self.folder / filename, raw)
        self._check_owner()
        self._written[(pair_id, engine)] = {
            'pair_id': pair_id, 'engine': engine, 'output_sha256': digest,
            'older_sha256': parsed.older_sha256, 'newer_sha256': parsed.newer_sha256,
            'symbols': parsed.symbols, 'version': parsed.version}
        return digest

    def finalize(self, reports: Sequence[dict]) -> None:
        """Publish credit only after report assembly and renewed exact-byte verification of every success."""
        self._check_owner()
        if self._finalized or self._attempted or _present(self.folder / CREDIT_FILE):
            raise OutputError('managed output run is already finalized')
        self._attempted = True
        if read_output_bytes(self.folder / MANAGED_MARKER, 4096) != _MARKER_BYTES:
            raise OutputError('managed output run marker changed')
        document = _credit_document(reports, list(self._written.values()))
        _verified_credits(self.folder, document)
        self._check_owner()
        sentinel = self.folder / COMPLETION_FILE
        _, owned = _publish_owned_bytes(sentinel, _COMPLETION_BYTES)
        self._check_owner()
        publish_bytes(self.folder / CREDIT_FILE, _canonical_bytes(document, RS.MAX_CREDIT_BYTES))
        _verify_completed_outputs(self.folder)
        self._check_owner()
        if any(_present(self.folder / name) for name in (FAILURE_FILE, UNCREDITED_REPORT)):
            raise OutputError('managed output run has failure diagnostics')
        try:
            if read_output_bytes(sentinel, 4096) != _COMPLETION_BYTES or _identity(sentinel.lstat()) != owned:
                raise OutputError('completion sentinel ownership or content changed')
            sentinel.unlink()  # Final success transition: no fallible validation after this point.
        except OSError as exc:
            raise OutputError(f'completion sentinel removal failed: {type(exc).__name__}') from None
        self._finalized = True

    def retain_failure(self, report: dict, error: Exception) -> dict:
        """Best-effort exclusive diagnostics; never change an already completed run."""
        if self._finalized or not self._attempted:
            raise OutputError('managed output run is finalized or finalization was not attempted')
        attempted = {'marker': (self.folder / FAILURE_FILE).as_posix(),
                     'report': (self.folder / UNCREDITED_REPORT).as_posix()}
        result = {'attempted': attempted, 'errors': {}}
        marker = {'contract': RS.FAILURE_CONTRACT, 'status': 'failed', 'credited': False,
                  'report_file': UNCREDITED_REPORT, 'report_sha256': report['report_sha256'],
                  'error': str(error)[:1000]}
        for kind, document, maximum in (('marker', marker, 8192), ('report', report, RS.MAX_OUTPUT_BYTES)):
            try:
                self._check_owner()
                publish_bytes(Path(attempted[kind]), _canonical_bytes(document, maximum))
                self._check_owner()
                result[kind] = attempted[kind]
            except (OutputError, OSError) as exc:
                result['errors'][kind] = str(exc)[:1000]
        return result
