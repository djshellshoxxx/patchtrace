"""Ingest of the extractor's untrusted JSON Lines into the `program-ir/1` sidecar (03 s5, s12).

`ingest()` streams `ir.jsonl` once (strict validation per line), computes operand types, located address fields,
the normalised keys (`h0..h3`, `hm`, `hms`), block keys, loops, MD indices, PE-table facts, then writes one SQLite
file and a manifest into a private directory the caller owns. The result is deterministic: rows are ordered by
RVA/fid, nothing time- or path-dependent enters a table, and `content_digest` is computed from the rows.
Pure except for file I/O below `out_dir`; runs in the PatchTrace worker child, never in the GUI process.
"""
from __future__ import annotations

import hashlib
import json
import os
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .. import keys
from ..contracts import IrCounts, IrKeyInputs, IrProducer, ProgramIrManifest
from ..limits import DEFAULT_LIMITS, Budget, UnifiedError, UnifiedLimits
from . import schema
from .cfg import count_back_edges
from .features import (
    KeyStream,
    constant_context,
    h64,
    instruction_flags,
    is_direct_branch,
    is_nop,
    multiset_key,
    padding_start,
    sequence_key,
)
from .ins import encode_instructions, encode_text
from .mdindex import flow_graph_md, md_key
from .operands import (
    STATE_LOCATED,
    STATE_UNLOCATED,
    VK_ADDRESS,
    VK_REGISTER,
    VK_SCALAR,
    apply_instruction_mask,
    classify_operand,
    mask_instruction,
)
from .records import (
    FnRec,
    bad,
    check_instruction_layout,
    fail,
    parse_fn,
    parse_footer,
    parse_header,
    parse_json_line,
)

FLUSH_EVERY = 500
MAX_WARNINGS = 64


class PeView(Protocol):
    image_base: int
    size_of_image: int
    warnings: list[str]

    def reloc_in(self, low: int, high: int) -> bool: ...
    def is_executable(self, rva: int) -> bool: ...
    def extent(self, entry: int, ranges) -> int: ...
    def eh_for(self, entry: int) -> str | None: ...


@dataclass(frozen=True)
class ExpectedSide:
    """What the caller knows before ingesting: the project artifact, its PE tables and the producer it asked for."""
    side: str
    artifact_sha256: str
    pe: PeView
    mode: str = 'analyze'
    analysis_options_digest: str | None = None
    symbols: str | None = None
    script_sha256: str | None = None
    gzf_sha256: str | None = None
    other_sha256: str | None = None   # the other side's artifact hash (a swapped pair is ORIENTATION, not PAIR)


@dataclass(frozen=True)
class IrBuildResult:
    directory: Path
    manifest: ProgramIrManifest


def ir_key_inputs(header, limits: UnifiedLimits = DEFAULT_LIMITS) -> IrKeyInputs:
    """02 s5 payload of `ir_key`, from the validated header (the probed versions are authoritative)."""
    producer = header.producer
    return IrKeyInputs(artifact_sha256=header.artifact_sha256, producer_kind='ghidra', mode=producer.mode,
                       symbols=producer.symbols, ghidra=producer.ghidra, pyghidra=producer.pyghidra,
                       python=producer.python, script_sha256=producer.script_sha256,
                       analysis_options_digest=producer.analysis_options_digest,
                       ingest_limits_digest=keys.ingest_limits_digest(limits))


def _lines(path: Path, limits: UnifiedLimits) -> Iterator[bytes]:
    try:
        info = path.lstat()
    except OSError:
        raise fail('no-output') from None
    if path.is_symlink() or not path.is_file():
        raise fail('no-output')
    if info.st_size > limits.l05_output_bytes:
        raise UnifiedError('PT-UNIFIED-LIMIT', 'The extractor output exceeds L-05', reason='output-limit')
    cap = limits.l05_line_bytes
    with open(path, 'rb') as stream:
        while True:
            line = stream.readline(cap + 1)
            if not line:
                return
            if len(line) > cap and not line.endswith(b'\n'):
                raise UnifiedError('PT-UNIFIED-LIMIT', 'An extractor line exceeds L-05', reason='line-too-long')
            if not line.endswith(b'\n'):
                raise fail('truncated')
            yield line


class _Tables:
    """Buffered rows of one side; flushed to SQLite every FLUSH_EVERY functions."""

    def __init__(self, connection) -> None:
        self.db = connection
        self.fn: list[tuple] = []
        self.bb: list[tuple] = []
        self.str: list[tuple] = []
        self.cst: list[tuple] = []
        self.ref: list[tuple] = []
        self.ins: list[tuple] = []
        self.calls: list[tuple] = []        # (fid, site, target_rva, import_key, kind) until callees are resolved
        self.mnemonics: set[str] = set()
        self.rva_to_fid: dict[int, int] = {}
        self.counts = {'functions': 0, 'blocks': 0, 'instructions': 0, 'call_edges': 0, 'strings': 0, 'consts': 0,
                       'refs': 0, 'thunks': 0, 'imports': 0, 'pdata_confirmed': 0, 'mask_unlocated': 0}
        self.limits_hit: set[str] = set()
        self.l2_unlocated = 0
        self.sanitized = 0

    def flush(self) -> None:
        for table, rows in (('fn', self.fn), ('bb', self.bb), ('str', self.str), ('cst', self.cst),
                            ('ref', self.ref), ('ins', self.ins)):
            if rows:
                marks = ','.join('?' * len(rows[0]))
                self.db.executemany(f'INSERT INTO {table} VALUES ({marks})', rows)
                rows.clear()


def _import_key(imported: dict | None) -> str | None:
    if imported is None:
        return None
    name = imported['name'] if imported['name'] is not None else f'#{imported["ordinal"]}'
    return f'{imported["dll"].lower()}!{name}'


def _ref_rows(fid: int, ordinal: int, opi: int, refs, pe: PeView) -> list[tuple]:
    out = []
    for _kind, text in refs:
        if text.startswith('rva:'):
            target = int(text[4:])
            out.append((fid, ordinal, opi, 0 if pe.is_executable(target) else 1, target, None))
        elif text.startswith('stack:'):
            out.append((fid, ordinal, opi, 3, int(text[6:]), None))
        else:
            out.append((fid, ordinal, opi, 2, None, text[4:]))
    return out


def _process(record: FnRec, fid: int, pe: PeView, limits: UnifiedLimits, tables: _Tables) -> None:
    """Derive every column and child row of one function (03 s12.4, s12.5)."""
    flags = schema.FN_FLAGS['thunk'] if record.kind == 'thunk' else 0
    import_key = _import_key(record.imp)
    if import_key is not None:
        flags |= schema.FN_FLAGS['import']
    size = sum(length for _, length in record.ranges)
    h0 = h1 = h2 = h3 = hm = hms = md_td = md_bu = None
    n_bb = n_edge = loops = 0
    n_insn = len(record.insns)
    if record.raw is None:
        flags |= schema.FN_FLAGS['truncated' if record.truncated else 'oversize']
        tables.limits_hit.add('fn-truncated' if record.truncated else 'fn-oversize')
    else:
        h0, h1, h2, h3, hm, hms, n_bb, n_edge, loops, md_td, md_bu, flags = _keys_and_rows(
            record, fid, pe, limits, tables, flags)
    for site, target, key, kind in record.calls:
        tables.calls.append((fid, site, target, key, schema.CALL_KIND_CODES[kind]))
    for site, sha, length, prefix in record.strings:
        tables.str.append((fid, site, sha, length, prefix))
    tables.counts['strings'] += len(record.strings)
    extent = pe.extent(record.rva, record.ranges)
    if extent == 1:
        flags |= schema.FN_FLAGS['pdata-confirmed']
        tables.counts['pdata_confirmed'] += 1
    if flags & schema.FN_FLAGS['mask-unlocated']:
        tables.counts['mask_unlocated'] += 1
    if record.kind == 'thunk':
        tables.counts['thunks'] += 1
    if import_key is not None:
        tables.counts['imports'] += 1
    aliases = json.dumps(record.aliases, separators=(',', ':'), ensure_ascii=False) if record.aliases else None
    tables.fn.append((fid, record.rva, size, schema.KIND_CODES[record.kind], record.name,
                      schema.NAME_SRC_CODES[record.name_src], aliases, import_key, record.thunk_target,
                      n_bb, n_edge, n_insn, len(record.calls), loops, h0, h1, h2, h3, hm, hms, md_td, md_bu,
                      extent, flags, pe.eh_for(record.rva)))
    tables.counts['instructions'] += n_insn
    tables.counts['functions'] += 1
    tables.sanitized += record.sanitized
    tables.rva_to_fid[record.rva] = fid


def _keys_and_rows(record: FnRec, fid: int, pe: PeView, limits: UnifiedLimits, tables: _Tables, flags: int):
    raw = record.raw
    rvas = check_instruction_layout(record)
    mnemonics = [insn.mnem for insn in record.insns]
    padding = padding_start(mnemonics)
    tables.mnemonics.update(mnemonics)
    s1, s2, s3 = KeyStream(), KeyStream(), KeyStream()
    mask_missing = unlocated = False
    kept = 0
    l1_chunks: list[bytes | None] = []
    skipped: list[bool] = []
    ins_records, ref_seen = [], set()
    for index, insn in enumerate(record.insns):
        chunk = raw[insn.off:insn.off + insn.length]
        facts = []
        for opi, op in enumerate(insn.ops):
            fact = classify_operand(rvas[index], insn.length, chunk, insn.imask, op.optype, op.mask, op.objs, op.refs,
                                    pe)
            facts.append(fact)
            if fact.vkind != VK_REGISTER and op.mask is None:
                mask_missing = True
            if fact.state == STATE_UNLOCATED:
                if fact.vkind == VK_ADDRESS:
                    unlocated = True
                else:
                    tables.l2_unlocated += 1
            if fact.vkind == VK_SCALAR and isinstance(fact.value, int):
                tables.cst.append((fid, rvas[index], fact.value, constant_context(insn.mnem)))
                tables.counts['consts'] += 1
            for row in _ref_rows(fid, index, opi, op.refs, pe):
                if row not in ref_seen:
                    ref_seen.add(row)
                    tables.ref.append(row)
        if insn.imask is None:
            mask_missing = True
        nop = is_nop(insn.mnem) or index >= padding
        skipped.append(nop)
        l1 = mask_instruction(chunk, facts, 1)
        l1_chunks.append(l1)
        if not nop:
            kept += 1
            s1.add(l1)
            s2.add(mask_instruction(chunk, facts, 2))
            l3 = apply_instruction_mask(chunk, insn.imask)
            if l3 is None:
                mask_missing = True
            else:
                s3.add(l3)
        ins_records.append([rvas[index], chunk.hex(), insn.mnem, instruction_flags(insn.mnem, insn.flow) |
                            (32 if nop else 0), insn.flow,
                            [[f.vkind, op.optype, f.value, f.offset if f.state == STATE_LOCATED else None,
                              f.length if f.state == STATE_LOCATED else None, list(f.regs)]
                             for f, op in zip(facts, insn.ops, strict=True)]])
    tables.counts['refs'] += len(ref_seen)
    h0 = h64(raw)
    kept_mnemonics = [m for m, skip in zip(mnemonics, skipped, strict=True) if not skip]
    h1v, h2v = s1.value(), s2.value()
    h3v = None if mask_missing else s3.value()
    hmv, hmsv = sequence_key(kept_mnemonics), multiset_key(kept_mnemonics)
    if kept == 0:
        h1v = h2v = h3v = hmv = hmsv = None
    n_bb, n_edge, loops, md_td, md_bu = _blocks(record, fid, rvas, l1_chunks, skipped, tables, limits)
    if mask_missing:
        flags |= schema.FN_FLAGS['mask-missing']
    if unlocated:
        flags |= schema.FN_FLAGS['mask-unlocated']
    if kept <= limits.l10_tiny_instructions:
        flags |= schema.FN_FLAGS['tiny']
    if ins_records:
        tables.ins.append((fid, encode_instructions(ins_records), encode_text(record.texts)))
    return h0, h1v, h2v, h3v, hmv, hmsv, n_bb, n_edge, loops, md_td, md_bu, flags


def _blocks(record: FnRec, fid: int, rvas: list[int], l1_chunks, skipped, tables: _Tables, limits: UnifiedLimits):
    blocks = record.blocks
    if not blocks:
        return 0, 0, 0, None, None
    starts = [block.rva for block in blocks]
    members: list[list[int]] = [[] for _ in blocks]
    for index, rva in enumerate(rvas):
        position = bisect_right(starts, rva) - 1
        if position < 0:
            raise bad('blocks')
        members[position].append(index)
    ordinal = {start: i for i, start in enumerate(starts)}
    succ_lists: list[list[int]] = []
    edges: list[tuple[int, int]] = []
    for i, (block, indexes) in enumerate(zip(blocks, members, strict=True)):
        if len(indexes) != block.n_insn:
            raise bad('blocks')
        pairs = sorted(((ordinal[t], kind) for t, kind in zip(block.succ, block.kinds, strict=True)),
                       key=lambda item: (item[0], schema.EDGE_KIND_CODES[item[1]]))
        targets = [t for t, _ in pairs]
        succ_lists.append(targets)
        edges.extend((i, t) for t in targets)
        body = [k for k in indexes if not skipped[k]]
        if body and is_direct_branch(record.insns[body[-1]].flow):
            body = body[:-1]
        stream = KeyStream()
        for k in body:
            stream.add(l1_chunks[k])
        mnemonics = [record.insns[k].mnem for k in indexes if not skipped[k]]
        succ_json = json.dumps([[t, schema.EDGE_KIND_CODES[kind]] for t, kind in pairs], separators=(',', ':'))
        tables.bb.append((fid, i, block.rva, block.length, block.n_insn, stream.value() if body else None,
                          multiset_key(mnemonics) if mnemonics else None, succ_json))
    tables.counts['blocks'] += len(blocks)
    entry = max(0, bisect_right(starts, record.rva) - 1)
    loops = count_back_edges(len(blocks), succ_lists, entry)
    md_td = md_bu = None
    if len(blocks) >= limits.l11_md_min_blocks:
        top, bottom = flow_graph_md(len(blocks), edges)
        md_td, md_bu = md_key(top), md_key(bottom)
    return len(blocks), len(edges), loops, md_td, md_bu


def _check_header(header, expect: ExpectedSide) -> None:
    pe, producer = expect.pe, header.producer
    if header.image_base != pe.image_base:
        raise UnifiedError('PT-UNIFIED-IR', 'The extractor image base differs from the PE header',
                           reason='image-base-mismatch')
    if header.size_of_image != pe.size_of_image:
        raise UnifiedError('PT-UNIFIED-IR', 'The extractor image size differs from the PE header',
                           reason='size-of-image-mismatch')
    if not producer.analyzed:
        raise UnifiedError('PT-UNIFIED-EXTRACT', 'The extractor program was not analysed', reason='gzf-not-analyzed')
    for field, got, want in (('mode', producer.mode, expect.mode),
                             ('options-digest', producer.analysis_options_digest, expect.analysis_options_digest),
                             ('symbols', producer.symbols, expect.symbols),
                             ('script', producer.script_sha256, expect.script_sha256)):
        if want is not None and got != want:
            raise UnifiedError('PT-UNIFIED-IR', 'The extractor producer differs from the request',
                               reason=f'{field}-mismatch')


def ingest(jsonl: Path, expect: ExpectedSide, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
           *, out_dir: Path, created_utc: str | None = None) -> IrBuildResult:
    """Validate `jsonl` and build `out_dir/{ir.sqlite3, manifest.json}` (a private, existing, empty directory)."""
    budget = budget or Budget()
    out_dir = Path(out_dir)
    db_path = out_dir / schema.DB_NAME
    lines = _lines(Path(jsonl), limits)
    first = next(lines, None)
    if first is None:
        raise fail('no-output')
    header = parse_header(parse_json_line(first), expect.artifact_sha256, expect.other_sha256)
    _check_header(header, expect)
    connection = schema.create_database(db_path)
    try:
        connection.execute('BEGIN')
        tables = _Tables(connection)
        footer = None
        previous = -1
        size_of_image = header.size_of_image
        for line in lines:
            budget.tick()
            document = parse_json_line(line)
            if document.get('type') == 'footer':
                footer = parse_footer(document)
                if next(lines, None) is not None:
                    raise fail('trailing-data')
                break
            record = parse_fn(document, size_of_image, limits)
            if record.rva <= previous:
                raise UnifiedError('PT-UNIFIED-IR', 'Extractor functions are not in ascending RVA order',
                                   reason='fn-order')
            previous = record.rva
            if tables.counts['functions'] >= limits.l01_functions_per_side:
                raise UnifiedError('PT-UNIFIED-LIMIT', 'The image has more functions than L-01', reason='functions-cap')
            _process(record, tables.counts['functions'], expect.pe, limits, tables)
            budget.tick(len(record.insns))
            if tables.counts['instructions'] > limits.l02_instructions_per_side \
                    or tables.counts['blocks'] > limits.l02_instructions_per_side:
                raise UnifiedError('PT-UNIFIED-LIMIT', 'The image has more instructions than L-02',
                                   reason='instructions-cap')
            if tables.counts['functions'] % FLUSH_EVERY == 0:
                tables.flush()
        if footer is None:
            raise fail('no-footer')
        _check_footer(footer, tables)
        return _finish(connection, db_path, header, expect, tables, limits, footer, created_utc)
    finally:
        connection.close()


def _check_footer(footer, tables: _Tables) -> None:
    if footer.status != 'complete':
        reason = 'functions-cap' if any(w.startswith('functions-cap') for w in footer.warnings) else 'instructions-cap'
        raise UnifiedError('PT-UNIFIED-LIMIT', 'The extractor stopped at a cap', reason=reason)
    if footer.functions != tables.counts['functions'] or footer.instructions != tables.counts['instructions']:
        raise UnifiedError('PT-UNIFIED-IR', 'The extractor footer counts differ from the records',
                           reason='footer-mismatch')


def _finish(connection, db_path: Path, header, expect: ExpectedSide, tables: _Tables, limits: UnifiedLimits, footer,
            created_utc: str | None) -> IrBuildResult:
    tables.flush()
    resolved = []
    for fid, site, target, key, kind in tables.calls:
        callee = tables.rva_to_fid.get(target) if target is not None else None
        resolved.append((fid, site, callee, key, kind))
    connection.executemany('INSERT INTO call VALUES (?,?,?,?,?)', resolved)
    tables.counts['call_edges'] = sum(1 for row in resolved if row[2] is not None)
    connection.executemany('INSERT INTO mnem VALUES (?,?)', list(enumerate(sorted(tables.mnemonics))))
    inputs = ir_key_inputs(header, limits)
    key = keys.ir_key(inputs)
    connection.execute('COMMIT')
    digest = schema.content_digest(connection)
    for name, value in (('contract', schema.CONTRACT), ('ir_key', key), ('content_digest', digest),
                        ('ingest_version', schema.INGEST_VERSION), ('norm_version', schema.NORM_VERSION),
                        ('artifact_sha256', header.artifact_sha256), ('image_base', str(header.image_base)),
                        ('size_of_image', str(header.size_of_image))):
        connection.execute('INSERT INTO meta VALUES (?,?)', (name, value))
    connection.commit()
    connection.close()
    size = db_path.stat().st_size
    if size > limits.l07_ir_file_bytes:
        raise UnifiedError('PT-UNIFIED-LIMIT', 'The IR database exceeds L-07', reason='ir-too-large')
    file_sha = _sha256_file(db_path)
    producer = header.producer
    warnings = [*(f'extractor: {w}' for w in footer.warnings), *(f'pe: {w}' for w in expect.pe.warnings)]
    if tables.sanitized:
        warnings.append(f'sanitized-text-fields: {tables.sanitized}')
    if tables.l2_unlocated:
        warnings.append(f'l2-unlocated-operands: {tables.l2_unlocated}')
    manifest = ProgramIrManifest(
        ir_key=key, content_digest=digest, artifact_sha256=header.artifact_sha256,
        program_sha256=header.program_sha256, image_base=header.image_base, size_of_image=header.size_of_image,
        producer=IrProducer(kind='ghidra', mode=producer.mode, ghidra=producer.ghidra, pyghidra=producer.pyghidra,
                            java=producer.java, python=producer.python, script_sha256=producer.script_sha256,
                            analysis_options_digest=producer.analysis_options_digest,
                            gzf_sha256=expect.gzf_sha256, symbols=producer.symbols),
        ingest_version=schema.INGEST_VERSION, norm_version=schema.NORM_VERSION, counts=IrCounts(**tables.counts),
        limits_hit=tuple(sorted(tables.limits_hit)), warnings=tuple(w[:200] for w in warnings[:MAX_WARNINGS]),
        file_sha256=file_sha, created_utc=created_utc or datetime.now(UTC).isoformat(timespec='seconds'))
    text = json.dumps(manifest.model_dump(mode='json'), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    part = db_path.with_name(schema.MANIFEST_NAME + '.part')
    part.write_text(text + '\n', encoding='utf-8', newline='\n')
    os.replace(part, db_path.with_name(schema.MANIFEST_NAME))
    return IrBuildResult(db_path.parent, manifest)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1 << 22):
            digest.update(chunk)
    return digest.hexdigest()
