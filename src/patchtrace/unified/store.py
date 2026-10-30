"""SPEC-31 result sidecars and pointer rows (02 s4, s7, s9). Never edits enrichment/storage.py.

Layout: `runs/<run_id>/unified/results/<result_id[:16]>/{manifest.json, rows.jsonl.gz, facts.jsonl.gz}`. Parts are
gzip JSON Lines; `Part.sha256/bytes/records` describe the DECOMPRESSED content (gzip bytes differ between zlib
builds). Writers stage a directory, the owner verifies it (every hash, and with `deep=True` every record and the
cross-checks between manifest, rows and facts: the staged directory comes from a worker process), renames it into
place and only then publishes the tiny pointer row (`unified-result`, KINDS only, never DERIVED_KINDS) through the
public EnrichmentStore API. Readers trust a directory only when the row exists, agrees with its manifest and every
hash matches; anything else is a cache miss. `backup_once`/`delete_own` live here (phase D coordination): they use
only public attributes (`EnrichmentStore.store.connection`, `.root`) and delete nothing but `unified-*` kinds after
a verified backup that holds the rows about to go. Part lines are parsed strictly (duplicate keys are an error,
LF framing only, a higher contract is `stale`, never `invalid`).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import time
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from ..ingestion import safe_path
from ..persistence import strict_json
from . import keys
from .contracts import (
    DECISIONS,
    MATERIALITIES,
    ChangeFacts,
    Counts,
    IrRef,
    Part,
    ResultKeyInputs,
    SourceRef,
    UnifiedMatch,
    UnifiedResultManifest,
    UnifiedResultPointer,
    UnifiedResultPointerV2,
    UnifiedRun,
    newer_contract,
    parse_pointer,
    safe_run_id,
)
from .limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits

RESULT_KIND = 'unified-result'
RUN_KIND = 'unified-run'
UNIFIED_KINDS = (RUN_KIND, RESULT_KIND)
RUN_KEEP = 8
BACKUP_LABEL = 'unified-retention'
MANIFEST = 'manifest.json'
ROWS, FACTS = 'rows.jsonl.gz', 'facts.jsonl.gz'
DECOMP = 'decomp.jsonl.gz'   # optional part of the on-demand decompile (S3b)
MANIFEST_MAX_BYTES = 1024 * 1024
LINE_MAX_BYTES = 4 * 1024 * 1024
ORPHAN_RESULT_S = 300  # 02 s4: a result directory without a row is an orphan after 5 minutes
ORPHAN_STAGING_S = DEFAULT_LIMITS.l34_timeout_max_s  # a staging directory older than any worker may live
WINDOWS_PATH_LIMIT = 240  # 01 s7.6
_RUN_DIR = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_RESULT_ID = re.compile(r'[0-9a-f]{64}')
_RESULT_DIR = re.compile(r'[0-9a-f]{16}')
_STAGING_DIR = re.compile(r'tmp-[0-9a-f]{16}')
_PREVIOUS_DIR = re.compile(r'prev-[0-9a-f]{16}-[0-9a-f]{16}')
_LONGEST_TAIL = len('tmp-') + len('/rows.jsonl.gz.part')  # below results/<16 hex>: a staging dir's part file


def _err(message: str, reason: str, code: str = 'PT-UNIFIED-STORE') -> UnifiedError:
    return UnifiedError(code, message, reason=reason)


# --- paths --------------------------------------------------------------------------------------------------------

def _valid_run_id(run_id) -> bool:
    if not isinstance(run_id, str) or not _RUN_DIR.fullmatch(run_id):  # fullmatch: `$` also matched before a newline
        return False
    try:
        safe_run_id(run_id)  # Windows device names and a trailing dot
    except ValueError:
        return False
    return True


def result_relative_dir(run_id: str, result_id: str) -> str:
    if not _valid_run_id(run_id) or not isinstance(result_id, str) or not _RESULT_ID.fullmatch(result_id):
        raise _err('Invalid run or result identity for a sidecar path', 'bad-identity', 'PT-UNIFIED-INPUT')
    return f'runs/{run_id}/unified/results/{result_id[:16]}'


def _check_path_length(root: Path, relative: str, *, windows: bool | None = None) -> None:
    """Windows MAX_PATH: the longest file below a result directory stays under 240 characters (01 s7.6). The
    relative part alone is up to 166 characters, so a long project path would fail obscurely deep inside a write."""
    if (os.name == 'nt' if windows is None else windows) and (
            len(str(root)) + 1 + len(relative) + _LONGEST_TAIL >= WINDOWS_PATH_LIMIT):
        raise _err('The project path is too long for unified sidecars', 'path-too-long', 'PT-UNIFIED-INPUT')


def result_dir(root: Path, run_id: str, result_id: str) -> Path:
    relative = result_relative_dir(run_id, result_id)
    _check_path_length(Path(root), relative)
    return safe_path(root, relative)


def new_staging_dir(root: Path, run_id: str) -> Path:
    """A private staging directory on the project volume (so the owner's rename stays atomic)."""
    relative = result_relative_dir(run_id, '0' * 64)
    _check_path_length(Path(root), relative)
    parent = safe_path(root, relative.rsplit('/', 1)[0])
    parent.mkdir(parents=True, exist_ok=True)
    path = parent / f'tmp-{secrets.token_hex(8)}'
    path.mkdir()
    return path


# --- writing (pure file I/O; worker side) -------------------------------------------------------------------------

def dump_line(record: BaseModel | dict) -> bytes:
    data = record.model_dump(mode='json') if isinstance(record, BaseModel) else record
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8') + b'\n'


def _replace(source: Path, target: Path) -> None:
    """os.replace with a bounded retry for antivirus/indexer locks on Windows (T-08: 5 x 200 ms)."""
    for attempt in range(5):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 4:
                raise _err('A unified sidecar could not be moved into place', 'replace-failed') from None
            time.sleep(0.2)


def write_part(directory: Path, name: str, records: Iterable[BaseModel | dict],
               limits: UnifiedLimits = DEFAULT_LIMITS) -> Part:
    digest, size, count = hashlib.sha256(), 0, 0
    part = directory / f'{name}.part'
    with open(part, 'wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=6) as gz:
        for record in records:
            line = dump_line(record)
            if len(line) > LINE_MAX_BYTES:  # the reader refuses it, so the producer is told now
                raise _err('A unified result line exceeds the line cap', 'line-too-long', 'PT-UNIFIED-LIMIT')
            size += len(line)
            if size > limits.l30_part_bytes:
                raise _err('A unified result part exceeds L-30', 'part-too-large', 'PT-UNIFIED-LIMIT')
            digest.update(line)
            gz.write(line)
            count += 1
    _replace(part, directory / name)
    return Part(name=name, sha256=digest.hexdigest(), bytes=size, records=count)


def write_result(directory: Path, *, older_sha256: str, newer_sha256: str, ghidriff_run_id: str,
                 ghidriff_raw_sha256: str, ir_older: IrRef | None, ir_newer: IrRef | None,
                 sources: Iterable[SourceRef], manual_digest: str, config_digest: str, status: str,
                 limitations: Iterable[str], rows: Iterable[UnifiedMatch], facts: Iterable[ChangeFacts],
                 created_utc: str | None = None, limits: UnifiedLimits = DEFAULT_LIMITS) -> UnifiedResultManifest:
    """Write parts and the manifest into an existing private directory; `result_id` is computed from the inputs."""
    directory = Path(directory)
    rows, facts = list(rows), list(facts)
    sources = tuple(sorted(sources, key=lambda s: (s.source, s.entry_id, s.file_sha256 or '', s.version)))
    inputs = ResultKeyInputs(older_sha256=older_sha256, newer_sha256=newer_sha256,
                             ghidriff_raw_sha256=ghidriff_raw_sha256,
                             ir_older_digest=ir_older.content_digest if ir_older else None,
                             ir_newer_digest=ir_newer.content_digest if ir_newer else None, sources=sources,
                             manual_digest=manual_digest, config_digest=config_digest)
    by_id: dict[str, UnifiedMatch] = {}
    for row in rows:
        expected = keys.row_id(older_sha256, newer_sha256, [s.rva for s in row.older], [s.rva for s in row.newer])
        if row.row_id != expected or row.row_id in by_id:
            raise _err('A unified row has a wrong or duplicate row id', 'row-id', 'PT-UNIFIED-INTERNAL')
        by_id[row.row_id] = row
    seen: set[str] = set()
    for fact in facts:
        row = by_id.get(fact.row_id)
        if row is None or fact.row_id in seen or row.materiality != fact.verdict:
            raise _err('Change facts do not match their row', 'facts-row', 'PT-UNIFIED-INTERNAL')
        seen.add(fact.row_id)
    parts = (write_part(directory, FACTS, facts, limits), write_part(directory, ROWS, rows, limits))
    manifest = UnifiedResultManifest(
        result_id=keys.result_key(inputs), older_sha256=older_sha256, newer_sha256=newer_sha256,
        orientation='older->newer', ghidriff_run_id=ghidriff_run_id, ghidriff_raw_sha256=ghidriff_raw_sha256,
        ir_older=ir_older, ir_newer=ir_newer, sources=sources, manual_digest=manual_digest,
        config_digest=config_digest, engine_version='ude/1', status=status, limitations=tuple(limitations),
        counts=Counts.of(rows), parts=parts,
        created_utc=created_utc or datetime.now(UTC).isoformat(timespec='seconds'))
    part = directory / f'{MANIFEST}.part'
    part.write_bytes(dump_line(manifest))
    _replace(part, directory / MANIFEST)
    return manifest


def add_limitations(directory: Path, notes: Iterable[str]) -> UnifiedResultManifest:
    """Add informational limitations to a staged result: the manifest is rewritten, no part is touched. They are not
    an input of the result key (02 s5) and the status stays as it is, so callers add only non-degrading notes."""
    manifest, _sha = read_manifest(directory)
    document = manifest.model_dump(mode='json')
    document['limitations'] = sorted({*manifest.limitations, *notes})
    updated = UnifiedResultManifest.model_validate_json(json.dumps(document))
    part = Path(directory) / f'{MANIFEST}.part'
    part.write_bytes(dump_line(updated))
    _replace(part, Path(directory) / MANIFEST)
    return updated


def add_part(directory: Path, part: Part) -> UnifiedResultManifest:
    """Add an optional part (`decomp.jsonl.gz`, S3b) to a staged result whose file `write_part` already wrote. The
    manifest is rewritten; the result key does not cover the parts, and readers that do not know the part ignore it."""
    manifest, _sha = read_manifest(directory)
    document = manifest.model_dump(mode='json')
    document['parts'] = sorted([*(p for p in document['parts'] if p['name'] != part.name), part.model_dump(mode='json')],
                               key=lambda p: p['name'])
    updated = UnifiedResultManifest.model_validate_json(json.dumps(document))
    target = Path(directory) / f'{MANIFEST}.part'
    target.write_bytes(dump_line(updated))
    _replace(target, Path(directory) / MANIFEST)
    return updated


# --- verification and reading (pure file I/O; any thread) ---------------------------------------------------------

def read_manifest(directory: Path) -> tuple[UnifiedResultManifest, str]:
    path = Path(directory) / MANIFEST
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MANIFEST_MAX_BYTES:
            raise _err('The unified result manifest is missing or too large', 'manifest-missing')
        data = path.read_bytes()
        doc = strict_json(data.decode('utf-8'))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        if isinstance(exc, UnifiedError):
            raise
        raise _err('The unified result manifest is unreadable', 'manifest-unreadable') from None
    if isinstance(doc, dict) and newer_contract(doc.get('contract'), 'unified-result/1'):
        raise _err('The unified result was produced by a newer PatchTrace', 'newer-contract', 'PT-UNIFIED-STALE')
    try:
        manifest = UnifiedResultManifest.model_validate_json(data)
    except ValidationError:
        raise _err('The unified result manifest failed validation', 'manifest-invalid') from None
    return manifest, hashlib.sha256(data).hexdigest()


def part_lines(path: Path, limits: UnifiedLimits = DEFAULT_LIMITS) -> Iterator[bytes]:
    """The LF-terminated lines of one gzip part, under the L-30 part cap and the line cap (the one reader every
    consumer shares: verification, `read_rows`, the read layer's lazy record access)."""
    try:
        with open(path, 'rb') as raw, gzip.GzipFile(fileobj=raw, mode='rb') as gz:
            total, buffer = 0, b''
            while chunk := gz.read(1 << 20):
                total += len(chunk)
                if total > limits.l30_part_bytes:
                    raise _err('A unified result part exceeds L-30', 'part-too-large')
                buffer += chunk
                *complete, buffer = buffer.split(b'\n')
                for line in complete:
                    if len(line) > LINE_MAX_BYTES:
                        raise _err('A unified result line is too long', 'line-too-long')
                    yield line + b'\n'
                if len(buffer) > LINE_MAX_BYTES:
                    raise _err('A unified result line is too long', 'line-too-long')
            if buffer:
                raise _err('A unified result part is truncated', 'part-truncated')
    except (OSError, EOFError, zlib.error) as exc:  # corrupt deflate data raises zlib.error, which is no OSError
        raise _err('A unified result part is unreadable', 'part-unreadable') from exc


def _no_duplicate_keys(pairs: list) -> dict:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise ValueError('duplicate JSON key')
    return out


def parse_line(line: bytes, model):
    """One part line -> a validated record. Strict where pydantic is not (`persistence.strict_json` is the repo's
    gate, but its per-number hooks cost as much as the validation itself): a duplicate key is an error, because
    last-wins would let a hostile writer hide a field; NaN, floats and oversized ints cannot validate (no model has
    a float field and every int is bounded). Lines are LF-framed. A higher `/N` contract is `stale`, not invalid."""
    if b'\r' in line:
        raise _err('A unified result line is not LF-framed', 'line-framing')
    try:
        doc = json.loads(line.decode('utf-8'), object_pairs_hook=_no_duplicate_keys)
        newer = isinstance(doc, dict) and newer_contract(doc.get('contract'), model.model_fields['contract'].default)
        record = None if newer else model.model_validate_json(line)  # ValidationError is a ValueError
    except (ValueError, RecursionError):
        raise _err('A unified result record failed validation', 'record-invalid') from None
    if newer:
        raise _err('A unified result record was produced by a newer PatchTrace', 'newer-contract',
                   'PT-UNIFIED-STALE')
    return record


def _row_id_ok(manifest: UnifiedResultManifest, row: UnifiedMatch) -> bool:
    return row.row_id == keys.row_id(manifest.older_sha256, manifest.newer_sha256, [s.rva for s in row.older],
                                     [s.rva for s in row.newer])


class _Deep:
    """Whole-part cross-checks of `verify_result_dir(deep=True)`, fed line by line while the part is hashed (rows
    first). A staged directory comes from a worker process: matching hashes prove integrity, not that the content
    is what the manifest claims."""

    def __init__(self, manifest: UnifiedResultManifest, limits: UnifiedLimits):
        self.manifest = manifest
        self.limits = limits
        self.check_decomp = any(p.name == DECOMP for p in manifest.parts)
        self.materiality: dict[str, str] = {}  # row_id -> materiality of every row seen
        self.facted: set[str] = set()
        self.row_rvas: set[tuple[str, int]] = set()
        self.decompiled: set[tuple[str, int]] = set()
        self.decisions = dict.fromkeys(DECISIONS, 0)
        self.materialities = dict.fromkeys(MATERIALITIES, 0)

    def feed(self, name: str):
        return {ROWS: self.row, FACTS: self.fact, DECOMP: self.decomp}.get(name)

    def row(self, line: bytes) -> None:
        row = parse_line(line, UnifiedMatch)
        if not _row_id_ok(self.manifest, row) or row.row_id in self.materiality:
            raise _err('A unified row id is wrong or repeated', 'row-id')
        self.materiality[row.row_id] = row.materiality
        if self.check_decomp:
            self.row_rvas.update(('older', side.rva) for side in row.older)
            self.row_rvas.update(('newer', side.rva) for side in row.newer)
        self.decisions[row.decision] += 1
        self.materialities[row.materiality] += 1

    def fact(self, line: bytes) -> None:
        fact = parse_line(line, ChangeFacts)
        if self.materiality.get(fact.row_id) != fact.verdict or fact.row_id in self.facted:
            raise _err('Change facts do not match their row', 'facts-row')
        self.facted.add(fact.row_id)

    def decomp(self, line: bytes) -> None:
        """Reject a rehashed but forged code part before its result pointer can be published."""
        try:
            doc = strict_json(line.decode('utf-8'))
        except (ValueError, RecursionError, UnicodeDecodeError):
            raise _err('A decompiled code record is invalid', 'decompile-invalid') from None
        if (type(doc) is not dict or set(doc) != {'side', 'rva', 'status', 'code'}
                or doc['side'] not in ('older', 'newer') or type(doc['rva']) is not int
                or doc['status'] not in ('ok', 'failed', 'timeout')
                or (doc['status'] == 'ok' and (type(doc['code']) is not str or not doc['code']))
                or (doc['status'] != 'ok' and doc['code'] is not None)):
            raise _err('A decompiled code record is invalid', 'decompile-invalid')
        if doc['code'] is not None:
            try:
                doc['code'].encode('utf-8')
            except UnicodeEncodeError:
                raise _err('A decompiled code record is invalid', 'decompile-invalid') from None
            if (len(doc['code']) > self.limits.l29_pseudo_chars
                    or doc['code'].count('\n') + 1 > self.limits.l29_pseudo_lines):
                raise _err('A decompiled code record exceeds its bounds', 'decompile-invalid')
        key = (doc['side'], doc['rva'])
        if key not in self.row_rvas or key in self.decompiled:
            raise _err('A decompiled code record has a foreign or repeated RVA', 'decompile-rva')
        self.decompiled.add(key)

    def finish(self) -> None:
        if Counts.of_tallies(self.decisions, self.materialities) != self.manifest.counts:
            raise _err('The unified result manifest counts do not match its rows', 'counts-mismatch')


def _verify(directory: Path, *, expected_result_id: str | None = None, expected_manifest_sha256: str | None = None,
            limits: UnifiedLimits = DEFAULT_LIMITS, deep: bool = True) -> tuple[UnifiedResultManifest, str]:
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise _err('The unified result directory is missing', 'dir-missing')
    manifest, manifest_sha = read_manifest(directory)
    if expected_manifest_sha256 is not None and manifest_sha != expected_manifest_sha256:
        raise _err('The unified result manifest changed', 'manifest-hash-mismatch')
    if expected_result_id is not None and manifest.result_id != expected_result_id:
        raise _err('The unified result belongs to another result id', 'result-id-mismatch')
    if keys.result_key(keys.result_key_inputs(manifest)) != manifest.result_id:
        raise _err('The unified result manifest does not certify its result id', 'result-id-inputs')
    names = {MANIFEST, *(p.name for p in manifest.parts)}
    if {p.name for p in directory.iterdir()} != names:
        raise _err('The unified result directory holds unexpected files', 'unexpected-files')
    checks = _Deep(manifest, limits) if deep else None
    for part in sorted(manifest.parts, key=lambda p: p.name != ROWS):  # rows before facts: facts link to rows
        path = directory / part.name
        if path.is_symlink() or not path.is_file():
            raise _err('A unified result part is missing', 'part-missing')
        feed = checks.feed(part.name) if checks else None
        digest, size, count = hashlib.sha256(), 0, 0
        for line in part_lines(path, limits):
            digest.update(line)
            size += len(line)
            count += 1
            if feed:
                feed(line)
        if (digest.hexdigest(), size, count) != (part.sha256, part.bytes, part.records):
            raise _err('A unified result part does not match its manifest', 'part-hash-mismatch')
    if checks:
        checks.finish()
    return manifest, manifest_sha


def verify_result_dir(directory: Path, *, expected_result_id: str | None = None,
                      expected_manifest_sha256: str | None = None, limits: UnifiedLimits = DEFAULT_LIMITS,
                      deep: bool = True) -> UnifiedResultManifest:
    """Re-hash every part; the manifest must certify its own result_id (02 s5). `deep` (the default, for a
    directory nobody has verified yet) also parses every row and fact strictly in the same pass and cross-checks
    them: row ids, unique rows, facts linked to rows with the row's materiality, counts recomputed against the
    manifest. Readers of a published result pass `deep=False`: its pointer row pins the manifest that publish
    verified deeply. Raises UnifiedError(STORE)."""
    return _verify(directory, expected_result_id=expected_result_id,
                   expected_manifest_sha256=expected_manifest_sha256, limits=limits, deep=deep)[0]


def _read(directory: Path, manifest: UnifiedResultManifest, name: str, model, limits: UnifiedLimits):
    part = next(p for p in manifest.parts if p.name == name)
    for line in part_lines(Path(directory) / part.name, limits):
        yield parse_line(line, model)


def read_rows(directory: Path, manifest: UnifiedResultManifest,
              limits: UnifiedLimits = DEFAULT_LIMITS) -> Iterator[UnifiedMatch]:
    for row in _read(directory, manifest, ROWS, UnifiedMatch, limits):
        if not _row_id_ok(manifest, row):
            raise _err('A unified row id does not match its pairing', 'row-id')
        yield row


def read_facts(directory: Path, manifest: UnifiedResultManifest,
               limits: UnifiedLimits = DEFAULT_LIMITS) -> Iterator[ChangeFacts]:
    yield from _read(directory, manifest, FACTS, ChangeFacts, limits)


# --- owner-thread operations --------------------------------------------------------------------------------------

def _require_owner(enrichment: EnrichmentStore) -> None:
    if enrichment.store.closed:
        raise _err('The project is closed', 'project-closed')
    try:
        enrichment.store.connection.execute('SELECT 1').fetchone()
    except sqlite3.ProgrammingError:
        raise _err('Unified rows are read and published only on the project owner thread', 'wrong-thread') from None
    enrichment.ensure()


def _body(model: BaseModel, limits: UnifiedLimits) -> dict:
    body = model.model_dump(mode='json')
    size = len(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    if size > limits.l31_pointer_body_bytes:
        raise _err('A unified pointer row exceeds L-31', 'pointer-row-cap', 'PT-UNIFIED-LIMIT')
    return body


def _rmtree(path: Path) -> None:
    def retry(function, target, _exc):
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        function(target)
    shutil.rmtree(path, onexc=retry)


def _live_project_id(enrichment: EnrichmentStore) -> str | None:
    row = enrichment.store.connection.execute(
        "SELECT json_extract(payload, '$.id') FROM current_snapshot WHERE singleton=1").fetchone()
    return row[0] if row and isinstance(row[0], str) else None


def _project_facts(enrichment: EnrichmentStore) -> tuple[str | None, dict[str, str | None], set[str]]:
    """(project id, {run id: raw sha256}, artifact hashes) of the saved project snapshot."""
    row = enrichment.store.connection.execute(
        "SELECT json_extract(payload, '$.id'), json_extract(payload, '$.runs'), "
        "json_extract(payload, '$.artifacts') FROM current_snapshot WHERE singleton=1").fetchone()
    if row is None or not isinstance(row[0], str):
        return None, {}, set()
    runs = {r.get('id'): r.get('raw_sha256') for r in json.loads(row[1] or '[]') if isinstance(r, dict)}
    shas = {a.get('sha256') for a in json.loads(row[2] or '[]') if isinstance(a, dict)}
    return row[0], runs, shas


def _require_owned(enrichment: EnrichmentStore, manifest: UnifiedResultManifest, guard: Guard) -> None:
    """AGENTS.md: validate artifact and run ownership. The guard project is the open project, the Ghidriff run
    exists in it with this raw hash, and the older/newer hashes are the project's two artifacts. Either
    orientation is accepted: a result computed before an orientation swap is stored stale, not refused."""
    project_id, runs, shas = _project_facts(enrichment)
    if project_id is None:
        raise _err('The project has no saved snapshot to own this result', 'project-unsaved', 'PT-UNIFIED-INPUT')
    if guard.project_id != project_id:
        raise _err('The result belongs to another project', 'foreign-project', 'PT-UNIFIED-INPUT')
    if manifest.ghidriff_run_id not in runs:
        raise _err('The result names a Ghidriff run that the project does not have', 'run-unknown',
                   'PT-UNIFIED-INPUT')
    if runs[manifest.ghidriff_run_id] != manifest.ghidriff_raw_sha256:
        raise _err('The result names another raw output than the Ghidriff run holds', 'raw-mismatch',
                   'PT-UNIFIED-INPUT')
    if {manifest.older_sha256, manifest.newer_sha256} != shas:
        raise _err('The result compares files that are not the project artifacts', 'artifact-foreign',
                   'PT-UNIFIED-INPUT')


@dataclass(frozen=True)
class PublishedResult:
    entry: Entry
    pointer: UnifiedResultPointer
    manifest: UnifiedResultManifest
    directory: Path
    deleted_rows: int


def _previous_path(final: Path, manifest_sha: str) -> Path:
    """Recoverable sibling selected by the committed pointer's full, verified manifest hash."""
    return final.with_name(f'prev-{final.name}-{manifest_sha[:16]}')


def publish_result(enrichment: EnrichmentStore, staged: Path, *, guard: Guard, current: Guard, revision: int,
                   limits: UnifiedLimits = DEFAULT_LIMITS, upgrade: bool = False) -> PublishedResult:
    """Verify a staged result (deeply: it comes from a worker), check that it belongs to this project, rename it
    into place, then publish its pointer row. Any failure before the row leaves the previous pointer row current;
    a crash after the rename leaves a directory without a row that the next publish sweeps. The same `result_id`
    with other content is refused (`result-drift`): ids bind the inputs, not the parts, so a changed payload under
    an old id means the engine is not deterministic, which must be seen, never silently discarded. `upgrade` is the
    one exception: the on-demand decompile (S3b) adds a second channel to rows of a result whose id it does not
    change, so a refresh that decompiled replaces the verified directory of the same id."""
    _require_owner(enrichment)
    if enrichment.read_only:
        raise _err('Project enrichment data was written by a newer PatchTrace', 'read-only-store',
                   'PT-UNIFIED-STALE')
    manifest, manifest_sha = _verify(staged, limits=limits)
    if (guard.input_digest, guard.run_id, guard.raw_sha256) != (manifest.result_id, manifest.ghidriff_run_id,
                                                               manifest.ghidriff_raw_sha256):
        raise _err('The result does not belong to this guard', 'guard-mismatch', 'PT-UNIFIED-INPUT')
    _require_owned(enrichment, manifest, guard)
    root = enrichment.store.root
    relative = result_relative_dir(manifest.ghidriff_run_id, manifest.result_id)
    _check_path_length(root, relative)
    final = safe_path(root, relative)
    staged = Path(staged)
    in_place = staged.resolve() == final.resolve()
    previous = None
    if final.exists() and not in_place:
        try:
            existing, existing_sha = _verify(final, limits=limits, deep=False)
        except UnifiedError:
            existing = None
        if existing is None:  # corrupt leftover: move aside, then replace
            trash = final.with_name(f'tmp-{secrets.token_hex(8)}')
            _replace(final, trash)
            _rmtree(trash)
        elif existing.result_id != manifest.result_id:
            raise _err('Another result already uses this sidecar directory', 'dir-collision')
        elif existing.model_copy(update={'created_utc': manifest.created_utc}) != manifest and upgrade:
            previous = _previous_path(final, existing_sha)
            _check_path_length(root, str(previous.relative_to(root)))
            if previous.exists():
                _verify(previous, expected_result_id=existing.result_id,
                        expected_manifest_sha256=existing_sha, limits=limits, deep=False)
                _rmtree(final)  # an interrupted earlier attempt already preserved this exact generation
            else:
                _replace(final, previous)
        elif existing.model_copy(update={'created_utc': manifest.created_utc}) != manifest:
            raise _err('The same result id was produced with different content', 'result-drift',
                       'PT-UNIFIED-INTERNAL')
        else:  # idempotent re-publish: the verified directory is already in place and is the one that counts
            manifest, manifest_sha = existing, existing_sha
    try:
        if not final.exists():
            final.parent.mkdir(parents=True, exist_ok=True)
            _replace(staged, final)
        elif not in_place:
            _rmtree(staged)
        if hashlib.sha256((final / MANIFEST).read_bytes()).hexdigest() != manifest_sha:
            raise _err('The unified result manifest changed while it was published', 'manifest-hash-mismatch')
        pointer = UnifiedResultPointerV2(
            result_id=manifest.result_id, relative_dir=relative, manifest_sha256=manifest_sha, status=manifest.status,
            counts=manifest.counts, config_digest=manifest.config_digest, older_sha256=manifest.older_sha256,
            newer_sha256=manifest.newer_sha256)
        try:
            entry = enrichment.publish(RESULT_KIND, guard, current, revision, manifest.status, _body(pointer, limits),
                                       manifest.result_id)
        except EnrichmentError as exc:
            raise _err('The unified pointer row could not be stored', 'enrichment-limit'
                       if exc.code == 'PT-ENRICH-LIMIT' else 'pointer-publish') from None
    except BaseException:
        if previous is not None:
            try:
                if final.exists():
                    _rmtree(final)
                _replace(previous, final)
            except (OSError, UnifiedError):
                pass  # readers can still recover the exact committed generation from `previous`
        raise
    if previous is not None:
        try:
            _rmtree(previous)
        except OSError:
            pass  # committed replacement is current; the orphan sweep can remove this later
    deleted = 0
    try:
        deleted = apply_unified_retention(enrichment, protect=(manifest.result_id,), limits=limits)
    except (UnifiedError, sqlite3.Error, OSError):
        pass  # best effort: retention never fails a publish
    try:
        sweep_orphans(enrichment, manifest.ghidriff_run_id)
    except (UnifiedError, sqlite3.Error, OSError, ValueError):
        pass  # best effort as well
    return PublishedResult(entry, pointer, manifest, final, deleted)


def publish_run(enrichment: EnrichmentStore, run: UnifiedRun, *, guard: Guard, current: Guard, revision: int,
                limits: UnifiedLimits = DEFAULT_LIMITS) -> Entry:
    _require_owner(enrichment)
    if enrichment.read_only:
        raise _err('Project enrichment data was written by a newer PatchTrace', 'read-only-store',
                   'PT-UNIFIED-STALE')
    if guard.project_id != _live_project_id(enrichment):
        raise _err('The run row belongs to another project', 'foreign-project', 'PT-UNIFIED-INPUT')
    try:
        return enrichment.publish(RUN_KIND, guard, current, revision, run.status, _body(run, limits), run.run_id)
    except EnrichmentError as exc:
        raise _err('The unified run row could not be stored', 'enrichment-limit'
                   if exc.code == 'PT-ENRICH-LIMIT' else 'run-publish') from None


def _pointers(enrichment: EnrichmentStore, current: Guard | None = None):
    """Valid pointer rows newest first (`/1` and `/2`, through the version-gated `parse_pointer`), the ids skipped
    as corrupt, invalid or newer, and the subset written by a newer PatchTrace: cache misses, never deleted here."""
    skipped: list[str] = []
    newer: list[str] = []
    out = []
    # `EnrichmentStore.entries` keeps the last of two equal keys, so the raw row text is checked here as well
    raw = dict(enrichment.store.connection.execute('SELECT id, body FROM enrichment_entries WHERE kind=?',
                                                   (RESULT_KIND,)).fetchall())
    for entry in enrichment.entries(RESULT_KIND, current, on_corrupt=skipped.append):
        try:
            json.loads(raw[entry.id], object_pairs_hook=_no_duplicate_keys)
            out.append((entry, parse_pointer(entry.body)))
        except UnifiedError:  # a higher /N
            newer.append(entry.id)
            skipped.append(entry.id)
        except (ValidationError, ValueError, RecursionError, KeyError):
            skipped.append(entry.id)
    return out, skipped, newer


@dataclass(frozen=True)
class LoadedResult:
    state: str                      # 'current' | 'stale' | 'none' | 'invalid'
    reason: str | None
    entry: Entry | None = None
    pointer: UnifiedResultPointer | None = None
    manifest: UnifiedResultManifest | None = None
    directory: Path | None = None
    skipped: tuple[str, ...] = ()


def _open(enrichment: EnrichmentStore, entry: Entry, pointer: UnifiedResultPointer,
          limits: UnifiedLimits) -> tuple[Path, UnifiedResultManifest]:
    """The directory and manifest a pointer row stands for. Hashes are verified (the row pins the manifest that
    publish verified deeply) and the row must agree with it: same run, raw output, pair, status, counts and
    config, and a directory inside its own run. Raises UnifiedError or ValueError (unsafe path)."""
    directory = safe_path(enrichment.store.root, pointer.relative_dir)
    try:
        manifest, _sha = _verify(directory, expected_result_id=pointer.result_id,
                                 expected_manifest_sha256=pointer.manifest_sha256, limits=limits, deep=False)
    except UnifiedError as original:
        previous = _previous_path(directory, pointer.manifest_sha256)
        try:
            manifest, _sha = _verify(previous, expected_result_id=pointer.result_id,
                                     expected_manifest_sha256=pointer.manifest_sha256, limits=limits, deep=False)
        except UnifiedError:
            raise original from None
        directory = previous
    pair = (getattr(pointer, 'older_sha256', manifest.older_sha256), getattr(pointer, 'newer_sha256',
                                                                           manifest.newer_sha256))
    if (pointer.relative_dir != result_relative_dir(manifest.ghidriff_run_id, manifest.result_id)
            or (entry.guard.run_id, entry.guard.raw_sha256, entry.guard.input_digest) != (
                manifest.ghidriff_run_id, manifest.ghidriff_raw_sha256, manifest.result_id)
            or (pointer.status, pointer.counts, pointer.config_digest) != (
                manifest.status, manifest.counts, manifest.config_digest)
            or pair != (manifest.older_sha256, manifest.newer_sha256)):
        raise _err('The unified pointer row disagrees with its manifest', 'pointer-mismatch')
    return directory, manifest


def load_result(enrichment: EnrichmentStore, current: Guard,
                limits: UnifiedLimits = DEFAULT_LIMITS) -> LoadedResult:
    """The current result if one verifies, else the newest stale one that does (shown for reference), never a
    crash. A corrupt current sidecar therefore never hides an intact older result; when nothing verifies, the
    failure of the first candidate is reported."""
    _require_owner(enrichment)
    rows, skipped, newer = _pointers(enrichment, current)
    if not rows:
        if newer:
            return LoadedResult('invalid', 'newer-contract', skipped=tuple(skipped))
        return LoadedResult('none', 'no-result', skipped=tuple(skipped))
    failure = None
    for entry, pointer in sorted(rows, key=lambda row: row[0].stale):  # current first; newest first within each
        try:
            directory, manifest = _open(enrichment, entry, pointer, limits)
        except (UnifiedError, ValueError) as exc:
            failure = failure or LoadedResult('invalid', getattr(exc, 'reason', None) or 'dir-invalid', entry,
                                              pointer, skipped=tuple(skipped))
            continue
        return LoadedResult('stale' if entry.stale else 'current', 'guard-moved' if entry.stale else None, entry,
                            pointer, manifest, directory, tuple(skipped))
    return failure


def cached_result(enrichment: EnrichmentStore, result_id: str,
                  limits: UnifiedLimits = DEFAULT_LIMITS) -> LoadedResult | None:
    """A verified result with this id, or None (corrupt rows and directories are cache misses). A row stored stale
    is reported as stale, not current."""
    _require_owner(enrichment)
    rows, _skipped, _newer = _pointers(enrichment)
    for entry, pointer in rows:
        if pointer.result_id == result_id:
            try:
                directory, manifest = _open(enrichment, entry, pointer, limits)
            except (UnifiedError, ValueError):
                return None
            return LoadedResult('stale' if entry.stale else 'current', 'guard-moved' if entry.stale else None, entry,
                                pointer, manifest, directory)
    return None


# --- backup and own deletion (A-04 wrappers, public API only) ---------------------------------------------------

def _snapshot(db: sqlite3.Connection) -> tuple:
    row = db.execute("SELECT sha256, json_extract(payload, '$.id') FROM current_snapshot WHERE singleton=1").fetchone()
    return tuple(row) if row else (None, None)


def _unified_rows(db: sqlite3.Connection) -> list[tuple]:
    return db.execute('SELECT id, body_sha256 FROM enrichment_entries WHERE kind IN (?, ?) ORDER BY id',
                      UNIFIED_KINDS).fetchall()


def _trusted(path: Path, project_id: str | None, must_contain: list[str]) -> bool:
    """A backup of this project that passes `quick_check` and holds every id in `must_contain`. Checked on every
    call: a cache keyed by (path, size, mtime) is unbounded, not thread-safe and fooled by FAT's 2 s mtime."""
    try:
        copy = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True, timeout=5)
        try:
            ok = copy.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            tables = {r[0] for r in copy.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            pid = _snapshot(copy)[1] if ok and 'enrichment_entries' in tables else None
            have = pid is not None and all(
                copy.execute(f'SELECT COUNT(*) FROM enrichment_entries WHERE id IN ({",".join("?" * len(chunk))})',
                             chunk).fetchone()[0] == len(chunk)
                for chunk in (must_contain[i:i + 400] for i in range(0, len(must_contain), 400)))
        finally:
            copy.close()
    except (sqlite3.Error, OSError, ValueError):
        return False
    return pid is not None and pid == project_id and have


def backup_once(enrichment: EnrichmentStore, label: str = BACKUP_LABEL, *,
                must_contain: Iterable[str] = ()) -> Path:
    """Reuse a trusted `backups/project-pre-<label>-*.sqlite3` of this project that holds every row id in
    `must_contain` (the rows about to be deleted), or write and verify a new one: `.part` copy through the SQLite
    backup API, closed, re-opened read-only, `integrity_check`, snapshot and unified rows compared with the live
    database, then renamed. Raises UnifiedError(STORE) on failure."""
    _require_owner(enrichment)
    if not label.replace('-', '').isalnum() or not label.islower() or len(label) > 32:
        raise _err('Invalid backup label', 'bad-label', 'PT-UNIFIED-INPUT')
    root, db = enrichment.store.root, enrichment.store.connection
    live_sha, project_id = _snapshot(db)
    wanted = sorted(set(must_contain))
    directory = safe_path(root, 'backups')
    directory.mkdir(exist_ok=True)
    for candidate in sorted(directory.glob(f'project-pre-{label}-*.sqlite3'), reverse=True):
        if not candidate.is_symlink() and _trusted(candidate, project_id, wanted):
            return candidate
    stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
    target = safe_path(root, f'backups/project-pre-{label}-{stamp}.sqlite3')
    part = safe_path(root, f'backups/project-pre-{label}-{stamp}.sqlite3.part')
    try:
        copy = sqlite3.connect(part)
        try:
            db.backup(copy)
        finally:
            copy.close()
        check = sqlite3.connect(f'{part.resolve().as_uri()}?mode=ro', uri=True, timeout=5)
        try:
            ok = (check.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                  and _snapshot(check) == (live_sha, project_id) and _unified_rows(check) == _unified_rows(db))
        finally:
            check.close()
        if not ok:
            raise _err('The pre-deletion backup failed verification', 'backup-failed')
        _replace(part, target)
    except (sqlite3.Error, OSError) as exc:
        part.unlink(missing_ok=True)
        raise _err('The pre-deletion backup could not be written', 'backup-failed') from exc
    except UnifiedError:
        part.unlink(missing_ok=True)
        raise
    return target


def delete_own(enrichment: EnrichmentStore, ids: Iterable[str], kinds: Iterable[str] = UNIFIED_KINDS) -> int:
    """Delete `unified-*` rows only, in one transaction, after a `backup_once` that holds them. Other kinds are
    refused."""
    kinds = tuple(sorted(set(kinds)))
    if not kinds or not set(kinds) <= set(UNIFIED_KINDS):
        raise _err('Only unified kinds can be deleted here', 'foreign-kind', 'PT-UNIFIED-INPUT')
    ids = sorted(set(ids))
    _require_owner(enrichment)
    if not ids or enrichment.read_only:
        return 0
    backup_once(enrichment, must_contain=ids)
    db = enrichment.store.connection
    if db.in_transaction:
        raise _err('Another transaction is open on the project database', 'transaction-open')
    deleted = 0
    db.execute('BEGIN IMMEDIATE')
    try:
        marks = ','.join('?' * len(kinds))
        for start in range(0, len(ids), 400):
            chunk = ids[start:start + 400]
            deleted += db.execute(f'DELETE FROM enrichment_entries WHERE id IN ({",".join("?" * len(chunk))}) '
                                  f'AND kind IN ({marks})', (*chunk, *kinds)).rowcount
    except BaseException:
        db.execute('ROLLBACK')
        raise
    db.execute('COMMIT')
    return deleted


def _pair_of(enrichment: EnrichmentStore, pointer: UnifiedResultPointer) -> tuple[str, str] | None:
    """The (older, newer) hashes a pointer belongs to: in the row from `/2`; read from the manifest for a `/1`
    row, whose pair is None when the manifest cannot say (such a row is never evicted)."""
    if isinstance(pointer, UnifiedResultPointerV2):
        return pointer.older_sha256, pointer.newer_sha256
    try:
        manifest, _sha = read_manifest(safe_path(enrichment.store.root, pointer.relative_dir))
    except (UnifiedError, ValueError):
        return None
    return manifest.older_sha256, manifest.newer_sha256


def apply_unified_retention(enrichment: EnrichmentStore, *, protect: Iterable[str] = (),
                            limits: UnifiedLimits = DEFAULT_LIMITS) -> int:
    """Keep the newest L-32 results per (older, newer, config_digest) (plus `protect`) and the newest RUN_KEEP run
    rows per Ghidriff run; delete the rest (rows first, then their directories). Another pair, orientation or run
    never evicts a result. Rows that do not validate are never deleted here."""
    _require_owner(enrichment)
    if enrichment.read_only:
        return 0
    rows, _skipped, _newer = _pointers(enrichment)
    keep = set(protect)
    per_group: dict[tuple, int] = {}
    doomed = []
    for entry, pointer in rows:  # newest first
        pair = _pair_of(enrichment, pointer)
        if pair is None:
            continue
        group = (*pair, pointer.config_digest)
        per_group[group] = per_group.get(group, 0) + 1
        if entry.id not in keep and per_group[group] > limits.l32_results_kept:
            doomed.append((entry.id, pointer.relative_dir))
    per_run: dict[str, int] = {}
    doomed_runs = []
    for run in enrichment.entries(RUN_KIND, on_corrupt=lambda _id: None):  # newest first
        per_run[run.guard.run_id] = per_run.get(run.guard.run_id, 0) + 1
        if per_run[run.guard.run_id] > RUN_KEEP:
            doomed_runs.append(run.id)
    if not doomed and not doomed_runs:
        return 0
    deleted = delete_own(enrichment, [i for i, _ in doomed] + doomed_runs)
    referenced = {p.relative_dir for e, p in _pointers(enrichment)[0]}
    for _id, relative in doomed:
        if relative not in referenced:
            path = safe_path(enrichment.store.root, relative)
            if path.is_dir() and not path.is_symlink():
                _rmtree(path)
    return deleted


def sweep_orphans(enrichment: EnrichmentStore, run_id: str) -> int:
    """Remove what a crash left beside the results of one run (02 s4): a result directory without a pointer row
    once it is 5 minutes old, and a `tmp-*` staging directory older than any worker may live (L-34 maximum). A
    directory named by a corrupt or invalid row is never swept. Returns the number removed."""
    _require_owner(enrichment)
    parent = safe_path(enrichment.store.root, result_relative_dir(run_id, '0' * 64).rsplit('/', 1)[0])
    if not parent.is_dir() or parent.is_symlink():
        return 0
    rows, skipped, _newer = _pointers(enrichment)
    stored = {p.relative_dir.rsplit('/', 1)[1] for _e, p in rows} | {i[:16] for i in skipped}
    preserved = {_previous_path(Path(p.relative_dir), p.manifest_sha256).name for _e, p in rows}
    now, removed = time.time(), 0
    for child in sorted(parent.iterdir()):
        staging = _STAGING_DIR.fullmatch(child.name) is not None
        previous = _PREVIOUS_DIR.fullmatch(child.name) is not None
        if previous and (skipped or child.name in preserved):
            continue
        if not staging and not previous and (not _RESULT_DIR.fullmatch(child.name) or child.name in stored):
            continue
        try:
            age = now - child.stat().st_mtime
            if child.is_symlink() or not child.is_dir() or age < (ORPHAN_STAGING_S if staging else ORPHAN_RESULT_S):
                continue
            _rmtree(child)
        except OSError:
            continue
        removed += 1
    return removed
