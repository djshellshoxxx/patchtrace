"""`IrReader`: the in-memory, read-only view of one `program-ir/1` sidecar (02 s4 "in-memory only").

`FunctionTable` keeps one `array('q')` per numeric column (INT64_MIN is the NULL sentinel, so 250k functions cost
about 60 MB) plus CSR adjacency over `fid`; blocks, calls, strings, constants, references and instruction records
are read on demand from the hardened read-only database. The reader never writes; opening verifies the manifest,
the SHA-256 of the file and the `meta` rows (a mismatch is `PT-UNIFIED-STORE`, a newer contract `PT-UNIFIED-STALE`).
`IrReader.from_columns` builds a reader without a database (unit-test builders for the ladder, S2).
"""
from __future__ import annotations

import hashlib
import json
from array import array
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from pydantic import ValidationError

from ..contracts import ProgramIrManifest
from ..limits import UnifiedError
from . import schema
from .features import NULL_KEY
from .ins import Insn, decode_instructions, decode_text

FN_COLUMNS = ('rva', 'size', 'kind', 'name_src', 'thunk_target', 'n_bb', 'n_edge', 'n_insn', 'n_call', 'loops', 'h0',
              'h1', 'h2', 'h3', 'hm', 'hms', 'md_td', 'md_bu', 'extent_src', 'flags')
EDGE_KIND_NAMES = tuple(sorted(schema.EDGE_KIND_CODES, key=schema.EDGE_KIND_CODES.get))


class BlockRow(NamedTuple):
    ord: int
    rva: int
    size: int
    n_insn: int
    h1: int | None
    hms: int | None
    succ: tuple[tuple[int, str], ...]


class CallRow(NamedTuple):
    site: int
    callee: int | None
    import_key: str | None
    kind: str


class StringRow(NamedTuple):
    site: int
    sha: str
    length: int
    prefix: str | None


class ConstRow(NamedTuple):
    site: int
    value: int
    ctx: int


class RefRow(NamedTuple):
    ord: int
    opi: int
    kind: str
    target: int | None
    import_key: str | None


def _store_error(message: str, reason: str) -> UnifiedError:
    return UnifiedError('PT-UNIFIED-STORE', message, reason=reason)


@dataclass
class FunctionTable:
    """Columnar function facts, indexed by fid (= rank by rva). NULL numeric cells hold `NULL_KEY`."""
    n: int
    columns: dict[str, array]
    name: list[str | None]
    aliases: list[tuple[str, ...]]
    import_key: list[str | None]
    eh: list[str | None]
    rva_to_fid: dict[int, int] = field(default_factory=dict)

    def __getattr__(self, name: str) -> array:
        columns = self.__dict__.get('columns')
        if columns is not None and name in columns:
            return columns[name]
        raise AttributeError(name)

    def get(self, column: str, fid: int) -> int | None:
        value = self.columns[column][fid]
        return None if value == NULL_KEY else value


def _csr(n: int, pairs: Sequence[tuple[int, int]]) -> tuple[array, array]:
    """Sorted unique neighbours per vertex as (indptr, indices)."""
    lists: list[set[int]] = [set() for _ in range(n)]
    for source, target in pairs:
        lists[source].add(target)
    indptr, indices = array('q', [0]), array('q')
    for neighbours in lists:
        indices.extend(sorted(neighbours))
        indptr.append(len(indices))
    return indptr, indices


@dataclass
class IrReader:
    manifest: ProgramIrManifest | None
    functions: FunctionTable
    call_indptr: array
    call_indices: array
    caller_indptr: array
    caller_indices: array
    directory: Path | None = None
    _db: object = None

    # --- construction -----------------------------------------------------------------------------------------
    @classmethod
    def open(cls, directory: Path, *, verify: bool = True) -> IrReader:
        directory = Path(directory)
        manifest = read_manifest(directory)
        db_path = directory / schema.DB_NAME
        if verify and _sha256_file(db_path) != manifest.file_sha256:
            raise _store_error('The IR database changed after it was published', 'ir-file-hash')
        db = schema.open_readonly(db_path)
        try:
            meta = dict(db.execute('SELECT key, value FROM meta'))
            if meta.get('contract') != schema.CONTRACT or meta.get('ir_key') != manifest.ir_key \
                    or meta.get('content_digest') != manifest.content_digest:
                raise _store_error('The IR database does not match its manifest', 'ir-meta-mismatch')
            functions = _load_functions(db)
            pairs = [(row[0], row[1]) for row in db.execute('SELECT fid, callee FROM call WHERE callee IS NOT NULL')]
        except Exception:
            db.close()
            raise
        call_indptr, call_indices = _csr(functions.n, pairs)
        caller_indptr, caller_indices = _csr(functions.n, [(callee, fid) for fid, callee in pairs])
        return cls(manifest, functions, call_indptr, call_indices, caller_indptr, caller_indices, directory, db)

    @classmethod
    def from_columns(cls, columns: dict[str, Sequence[int | None]], *, names: Sequence[str | None] | None = None,
                     calls: Sequence[tuple[int, int]] = ()) -> IrReader:
        """A database-less reader for tests: `columns` may omit any of FN_COLUMNS (cells default to NULL / 0)."""
        n = len(next(iter(columns.values()))) if columns else 0
        arrays: dict[str, array] = {}
        for column in FN_COLUMNS:
            cells = columns.get(column)
            default = 0 if column in ('size', 'kind', 'name_src', 'n_bb', 'n_edge', 'n_insn', 'n_call', 'loops',
                                      'extent_src', 'flags') else NULL_KEY
            arrays[column] = array('q', [default if v is None else v for v in cells] if cells is not None
                                   else [default] * n)
        table = FunctionTable(n, arrays, list(names) if names is not None else [None] * n, [()] * n, [None] * n,
                              [None] * n, {int(rva): fid for fid, rva in enumerate(arrays['rva'])
                                           if rva != NULL_KEY})
        call_indptr, call_indices = _csr(n, calls)
        caller_indptr, caller_indices = _csr(n, [(callee, fid) for fid, callee in calls])
        return cls(None, table, call_indptr, call_indices, caller_indptr, caller_indices)

    # --- adjacency --------------------------------------------------------------------------------------------
    def callees(self, fid: int) -> array:
        return self.call_indices[self.call_indptr[fid]:self.call_indptr[fid + 1]]

    def callers(self, fid: int) -> array:
        return self.caller_indices[self.caller_indptr[fid]:self.caller_indptr[fid + 1]]

    def call_edges(self) -> list[tuple[int, int]]:
        """Every resolved call row including duplicates (BinDiff counts multi-edges in its degrees)."""
        self._require_db()
        return [(a, b) for a, b in self._db.execute(
            'SELECT fid, callee FROM call WHERE callee IS NOT NULL ORDER BY fid, site, kind, callee')]

    # --- on-demand rows ---------------------------------------------------------------------------------------
    def _require_db(self) -> None:
        if self._db is None:
            raise _store_error('This reader has no database', 'no-database')

    def blocks(self, fid: int) -> list[BlockRow]:
        self._require_db()
        out = []
        for ord_, rva, size, n_insn, h1, hms, succ in self._db.execute(
                'SELECT ord, rva, size, n_insn, h1, hms, succ FROM bb WHERE fid=? ORDER BY ord', (fid,)):
            out.append(BlockRow(ord_, rva, size, n_insn, h1, hms,
                                tuple((target, EDGE_KIND_NAMES[kind]) for target, kind in json.loads(succ))))
        return out

    def calls(self, fid: int) -> list[CallRow]:
        self._require_db()
        return [CallRow(site, callee, key, 'jump' if kind else 'call') for site, callee, key, kind in self._db.execute(
            'SELECT site, callee, import_key, kind FROM call WHERE fid=? ORDER BY site, kind, callee, import_key',
            (fid,))]

    def strings(self, fid: int) -> list[StringRow]:
        self._require_db()
        return [StringRow(*row) for row in self._db.execute(
            'SELECT site, sha, len, prefix FROM str WHERE fid=? ORDER BY site, sha, len, prefix', (fid,))]

    def constants(self, fid: int) -> list[ConstRow]:
        self._require_db()
        return [ConstRow(*row) for row in self._db.execute(
            'SELECT site, value, ctx FROM cst WHERE fid=? ORDER BY site, value, ctx', (fid,))]

    def refs(self, fid: int) -> list[RefRow]:
        self._require_db()
        names = tuple(sorted(schema.REF_KIND_CODES, key=schema.REF_KIND_CODES.get))
        return [RefRow(ord_, opi, names[kind], target, key) for ord_, opi, kind, target, key in self._db.execute(
            'SELECT ord, opi, kind, target, import_key FROM ref WHERE fid=? ORDER BY ord, opi, kind, target, '
            'import_key', (fid,))]

    def instructions(self, fid: int) -> list[Insn]:
        self._require_db()
        row = self._db.execute('SELECT blob FROM ins WHERE fid=?', (fid,)).fetchone()
        return decode_instructions(row[0]) if row else []

    def texts(self, fid: int) -> list[str]:
        self._require_db()
        row = self._db.execute('SELECT txt FROM ins WHERE fid=?', (fid,)).fetchone()
        return decode_text(row[0]) if row and row[0] is not None else []

    def mnemonics(self) -> list[str]:
        self._require_db()
        return [text for (text,) in self._db.execute('SELECT text FROM mnem ORDER BY id')]

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None


def read_manifest(directory: Path) -> ProgramIrManifest:
    path = Path(directory) / schema.MANIFEST_NAME
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise _store_error('The IR manifest is missing or too large', 'manifest-missing')
        data = path.read_bytes()
        document = json.loads(data.decode('utf-8'))
    except (OSError, ValueError):
        raise _store_error('The IR manifest is unreadable', 'manifest-unreadable') from None
    contract = document.get('contract') if isinstance(document, dict) else None
    if isinstance(contract, str) and contract.startswith('program-ir/') and contract != schema.CONTRACT:
        raise UnifiedError('PT-UNIFIED-STALE', 'The IR was produced by a newer PatchTrace', reason='newer-contract')
    try:
        return ProgramIrManifest.model_validate_json(data)
    except ValidationError:
        raise _store_error('The IR manifest failed validation', 'manifest-invalid') from None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, 'rb') as stream:
            while chunk := stream.read(1 << 22):
                digest.update(chunk)
    except OSError:
        raise _store_error('The IR database is unreadable', 'ir-unreadable') from None
    return digest.hexdigest()


def _load_functions(db) -> FunctionTable:
    count = db.execute('SELECT COUNT(*) FROM fn').fetchone()[0]
    arrays = {column: array('q') for column in FN_COLUMNS}
    names: list[str | None] = []
    aliases: list[tuple[str, ...]] = []
    imports: list[str | None] = []
    eh: list[str | None] = []
    rva_to_fid: dict[int, int] = {}
    select = ', '.join(('fid', *FN_COLUMNS, 'name', 'aliases', 'import_key', 'eh'))
    expected = 0
    for row in db.execute(f'SELECT {select} FROM fn ORDER BY fid'):
        if row[0] != expected:
            raise _store_error('IR function ids are not contiguous', 'fid-gap')
        expected += 1
        for column, value in zip(FN_COLUMNS, row[1:1 + len(FN_COLUMNS)], strict=True):
            arrays[column].append(NULL_KEY if value is None else value)
        name, alias, key, signature = row[1 + len(FN_COLUMNS):]
        names.append(name)
        aliases.append(tuple(json.loads(alias)) if alias else ())
        imports.append(key)
        eh.append(signature)
        rva_to_fid[row[1]] = row[0]
    if expected != count:
        raise _store_error('IR function rows are inconsistent', 'fid-count')
    return FunctionTable(count, arrays, names, aliases, imports, eh, rva_to_fid)
