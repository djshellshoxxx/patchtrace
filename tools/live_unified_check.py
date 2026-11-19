"""SPEC-31 S1 live acceptance: the extractor on a REAL Ghidra (workflow `live-unified.yml`); never executes a DLL.

usage: python tools/live_unified_check.py --old OLD.dll --new NEW.dll --ghidra-dir DIR --out DIR [--tag NAME]
           [--python PY] [--other-results FILE] [--no-ghidriff] [--no-hashers] [--record FIXTURE_DIR NAME_OLD NAME_NEW]

Per side (each line prints PASS/FAIL, any FAIL exits 1; results go to OUT/live-unified-TAG-<os>.json):
  L1  `analyze` extraction runs twice from scratch and ingests to the SAME `content_digest` (determinism)
  L2  the analysed program the first run packed (`program.gzf`) re-imported in `gzf` mode gives the same
      `content_digest` and function records as the `analyze` run (the plan's gzf == analyze gate)
  L3  facts that must hold on a real image: functions > 0, pdata-confirmed extents (if it has .pdata), no `mask-unlocated`
      function, no limit hit, header image base equal to the PE header, ingest warnings listed
  L4  (unless --no-ghidriff) a real Ghidriff run with `BackendConfig.retain_gzf` retains exactly two GZFs under the
      run directory, and `gzf` extraction of each gives the `content_digest` of the own analysis (informational line
      if it differs: Ghidriff's analysis options are not under our control)
  L5  (unless --no-hashers) against Ghidra's own ExactBytes / ExactInstructions / ExactMnemonics hashers over the same
      analysed program (their classes are compared, never the hash values):
        h0 induces the same classes (both read every byte of the body);
        what the extractor exports (masked instruction bytes; mnemonics with operand counts) induces the same classes
        when read the way Ghidra reads it (every instruction, nothing skipped), and the bytes outside the exported
        instructions are exactly Ghidra's non-instruction code units;
        the stored h3 / hm never separate what Ghidra equates, and h3 equals Ghidra's classes on every function without
        a skipped NOP or INT3-padding instruction (those two keys skip them by design, 03 s12.5, so they are coarser
        on the other functions; hm also leaves out Ghidra's operand counts)
  L6  (with --other-results, the JSON of the other OS for the SAME DLL bytes) `content_digest` equal across OSes
The recorded test fixtures (tests/fixtures/unified/*.ir.jsonl, *.pe.json, PROVENANCE.json) are produced with
`--record`, so a maintainer can refresh them from the sources without scratch scripts.
"""
from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import io
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from patchtrace import backend as backend_module
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.backend import BackendConfig, run_comparison
from patchtrace.jobs import run_process
from patchtrace.service import ProjectService
from patchtrace.unified import extract
from patchtrace.unified.extract import runner
from patchtrace.unified.ir import schema
from patchtrace.unified.ir.features import is_nop, padding_start
from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.pe_tables import read_pe_tables

EXTRACT_TIMEOUT_S = 1200
DIAGNOSTIC_FILE_BYTES = 12 * 1024 ** 2
DIAGNOSTIC_PAIR_BYTES = 48 * 1024 ** 2
DIAGNOSTIC_ATTEMPTS = 4
DIAGNOSTIC_JSONL_BYTES = 4 * 1024 ** 2
DIAGNOSTIC_JSONL_RECORDS = 4098
DIAGNOSTIC_IR_BYTES = 4 * 1024 ** 2
DIAGNOSTIC_IR_ROWS = 32768
DIAGNOSTIC_FN_ROWS = 4096
DIAGNOSTIC_FN_BYTES = 512 * 1024
DIAGNOSTIC_ROW_BYTES = 16 * 1024
DIAGNOSTIC_META_BYTES = 128 * 1024
DIAGNOSTIC_SECONDS = 2
DIAGNOSTIC_SQL_STEPS = 2_000_000

# Runs inside the external Python (pyghidra + Ghidra); stdlib otherwise. Hashes every non-external function of a GZF with
# Ghidra's own function hashers and writes {rva: {name, bytes, insns, mnem}}.
HASHER_SCRIPT = r'''
import json, os, sys, tempfile
from pathlib import Path
gzf, out, ghidra = sys.argv[1], sys.argv[2], sys.argv[3]
from pyghidra.launcher import HeadlessPyGhidraLauncher
launcher = HeadlessPyGhidraLauncher(install_dir=Path(ghidra))
launcher.add_vmargs('-Xmx2048m')
launcher.start()
import java.io
from ghidra.app.plugin.match import (ExactBytesFunctionHasher, ExactInstructionsFunctionHasher,
                                     ExactMnemonicsFunctionHasher)
from ghidra.base.project import GhidraProject
from ghidra.util.task import TaskMonitor
work = tempfile.mkdtemp(prefix='pthash-')
project = GhidraProject.createProject(work, 'pt', True)
program = project.importProgram(java.io.File(gzf))
base = program.getImageBase().getOffset()
hashers = {'bytes': ExactBytesFunctionHasher.INSTANCE, 'insns': ExactInstructionsFunctionHasher.INSTANCE,
           'mnem': ExactMnemonicsFunctionHasher.INSTANCE}
listing = program.getListing()
result = {}
for function in program.getFunctionManager().getFunctions(True):
    if function.isExternal():
        continue
    row = {'name': str(function.getName())}
    for key, hasher in hashers.items():
        try:
            row[key] = int(hasher.hash(function, TaskMonitor.DUMMY))
        except Exception:
            row[key] = None
    # Ghidra's hashers walk getCodeUnits(): instructions AND data units of the body; `data` counts the latter
    body = function.getBody()
    row['data'] = sum(1 for _ in listing.getCodeUnits(body, True)) - sum(1 for _ in listing.getInstructions(body, True))
    result[str(int(function.getEntryPoint().getOffset() - base))] = row
Path(out).write_text(json.dumps(result), encoding='utf-8')
project.close()
'''


class Checks:
    """PASS/FAIL ledger; `info` lines never fail the run."""

    def __init__(self, emit: Callable[[str], None] = print) -> None:
        self.emit = emit
        self.failures: list[str] = []

    def check(self, label: str, ok: bool, detail: str = '') -> bool:
        self.emit(f'{"PASS" if ok else "FAIL"} {label}')
        if not ok:
            self.failures.append(f'{label}: {detail[-600:]}')
            self.emit(f'     {detail[-600:]}')
        return ok

    def info(self, label: str, detail: str = '') -> None:
        self.emit(f'INFO {label}' + (f': {detail}' if detail else ''))


def equivalence_classes(pairs: Sequence[tuple[int, int]]) -> set[tuple[int, ...]]:
    """Group function RVAs by key value; the set of groups is the equivalence relation."""
    groups: dict[int, list[int]] = collections.defaultdict(list)
    for rva, value in pairs:
        groups[value].append(rva)
    return {tuple(sorted(group)) for group in groups.values()}


def compare_hasher_classes(ghidra_rows: dict, ir_rows: dict[int, dict], ghidra_key: str, ir_key: str) -> dict:
    """Compare Ghidra's hasher classes with an IR key's classes over the functions both sides know."""
    left, right = [], []
    for rva_text, entry in ghidra_rows.items():
        rva = int(rva_text)
        if rva in ir_rows and entry.get(ghidra_key) is not None and ir_rows[rva].get(ir_key) is not None:
            left.append((rva, entry[ghidra_key]))
            right.append((rva, ir_rows[rva][ir_key]))
    a, b = equivalence_classes(left), equivalence_classes(right)
    return {'functions': len(left), 'classes_ghidra': len(a), 'classes_ir': len(b),
            'only_ghidra': sorted(a - b, key=lambda g: (len(g), g))[:5], 'only_ir': sorted(b - a, key=lambda g: (len(g), g))[:5],
            'equal': a == b}


def compare_refinement(ghidra_rows: dict, ir_rows: dict[int, dict], ghidra_key: str, ir_key: str) -> dict:
    """Does the IR key ever separate functions that Ghidra's hasher equates? `refines`: every Ghidra class lies inside
    one IR class (the IR key may be coarser, never finer)."""
    ir_value: dict[int, object] = {}
    left = []
    for rva_text, entry in ghidra_rows.items():
        rva = int(rva_text)
        if rva in ir_rows and entry.get(ghidra_key) is not None and ir_rows[rva].get(ir_key) is not None:
            left.append((rva, entry[ghidra_key]))
            ir_value[rva] = ir_rows[rva][ir_key]
    classes = equivalence_classes(left)
    straddling = sorted((group for group in classes if len({ir_value[rva] for rva in group}) > 1),
                        key=lambda g: (len(g), g))
    return {'functions': len(left), 'classes_ghidra': len(classes), 'classes_ir': len(set(ir_value.values())),
            'straddling': straddling[:5], 'refines': not straddling}


def exported_keys(records: Sequence[dict]) -> tuple[dict[int, dict], dict[int, dict]]:
    """(keys, facts) per function record of the extractor output, by function RVA.

    keys   what Ghidra's ExactInstructions / ExactMnemonics hashers read from the record: EVERY instruction, none skipped;
           `h3x` the instruction bytes under the SLEIGH mask (raw bytes when there is no mask), `hmx` the (mnemonic,
           operand count) sequence. Only for functions whose body is exactly its instructions: Ghidra also hashes the
           data units of a body and the record does not say where those end.
    facts  name, instruction count, `skipped` (instructions the stored h1..h3 / hm leave out: NOP and INT3 padding) and
           `gap` (body bytes outside the instructions): they explain every legitimate difference between the key families.
    """
    keys, facts = {}, {}
    for record in records:
        if record.get('type') != 'fn' or record.get('raw') is None:
            continue
        raw, insns = bytes.fromhex(record['raw']), record['insns']
        mnemonics = [item[2] for item in insns]
        padding = padding_start(mnemonics)
        covered = sum(item[1] for item in insns)
        facts[record['rva']] = {'name': record['name'], 'insns': len(insns), 'gap': len(raw) - covered,
                                'skipped': sum(1 for i, text in enumerate(mnemonics) if is_nop(text) or i >= padding)}
        if covered != len(raw):
            continue
        masked, counted = bytearray(), []
        for offset, length, mnemonic, imask, operands, _flow in insns:
            chunk = raw[offset:offset + length]
            if imask is not None:
                chunk = bytes(b & m for b, m in zip(chunk, bytes.fromhex(imask), strict=True))
            masked += chunk
            counted.append((mnemonic, len(operands)))
        keys[record['rva']] = {'h3x': bytes(masked), 'hmx': tuple(counted)}
    return keys, facts


def explain_groups(groups: Sequence[Sequence[int]], facts: dict[int, dict]) -> str:
    """The functions of the first mismatching groups with the facts that usually explain a difference."""
    parts = []
    for group in list(groups)[:4]:
        named = []
        for rva in list(group)[:3]:
            fact = facts.get(rva)
            named.append(f'{rva}:{fact["name"]}(insns={fact["insns"]},skipped={fact["skipped"]},gap={fact["gap"]})'
                         if fact else str(rva))
        parts.append('[' + ' '.join(named) + (' ...' if len(group) > 3 else '') + ']')
    return ' '.join(parts)


def l5_report(label: str, ghidra_rows: dict, rows: dict[int, dict], records: Sequence[dict], checks: Checks) -> dict:
    """The L5 checks of one side: `ghidra_rows` is the hasher child's output {rva text: {bytes, insns, mnem, data}},
    `rows` the stored `fn` rows by RVA, `records` the extractor's function lines."""
    exported, facts = exported_keys(records)

    def shape(compared: dict) -> dict:
        return {k: compared[k] for k in ('functions', 'classes_ghidra', 'classes_ir', 'equal')}

    def classes(compared: dict) -> str:
        return f'{compared["functions"]} functions, {compared["classes_ir"]} classes'

    def difference(compared: dict) -> str:
        return json.dumps({k: compared[k] for k in ('only_ghidra', 'only_ir')})

    report: dict = {}
    compared = compare_hasher_classes(ghidra_rows, rows, 'bytes', 'h0')
    checks.check(f'L5 {label}: h0 classes equal Ghidra ExactBytes classes ({classes(compared)})',
                 compared['equal'] and compared['functions'] > 0,
                 difference(compared))
    report['h0'] = shape(compared)
    for name, ghidra_key, key, what in (('ExactInstructions', 'insns', 'h3x', 'masked instruction bytes'),
                                        ('ExactMnemonics', 'mnem', 'hmx', 'mnemonics with operand counts')):
        compared = compare_hasher_classes(ghidra_rows, exported, ghidra_key, key)
        if not checks.check(f'L5 {label}: exported {what} induce Ghidra {name} classes ({classes(compared)})',
                            compared['equal'] and compared['functions'] > 0, difference(compared)):
            checks.info(f'L5 {label}: {name} groups', explain_groups(compared['only_ghidra'] + compared['only_ir'], facts))
        report[key] = shape(compared)
    outside = sorted(rva for rva, fact in facts.items()
                     if isinstance(ghidra_rows.get(str(rva), {}).get('data'), int)
                     and (fact['gap'] > 0) != (ghidra_rows[str(rva)]['data'] > 0))
    checks.check(f"L5 {label}: bytes outside the exported instructions are exactly Ghidra's data units", not outside,
                 explain_groups([outside], facts))
    skipping = sum(1 for fact in facts.values() if fact['skipped'])
    with_data = sum(1 for fact in facts.values() if fact['gap'])
    checks.info(f'L5 {label}: {skipping} of {len(facts)} functions contain NOP or INT3 padding instructions that h1..h3 '
                f'and hm skip, {with_data} contain bytes that are not instructions; the stored keys are coarser than '
                "Ghidra's there by design")
    clean = {rva for rva, fact in facts.items() if not fact['skipped'] and not fact['gap']}
    clean_rows = {rva: row for rva, row in rows.items() if rva in clean}
    for name, ghidra_key, key in (('ExactInstructions', 'insns', 'h3'), ('ExactMnemonics', 'mnem', 'hm')):
        refined = compare_refinement(ghidra_rows, rows, ghidra_key, key)
        on_clean = compare_hasher_classes(ghidra_rows, clean_rows, ghidra_key, key)
        detail = {'straddling': refined['straddling']}
        if key == 'h3':
            # h3 reads the same masked bytes as Ghidra: it must equal Ghidra's classes wherever nothing is skipped
            ok = refined['refines'] and on_clean['equal'] and refined['functions'] > 0
            detail.update(only_ghidra=on_clean['only_ghidra'], only_ir=on_clean['only_ir'])
            title = (f'{key} never separates what Ghidra {name} equates and equals it on the {on_clean["functions"]} '
                     'functions without skipped instructions')
        else:
            # hm leaves out Ghidra's operand counts, so it is coarser than Ghidra's even without skipped instructions
            ok = refined['refines'] and refined['functions'] > 0
            title = f'{key} never separates what Ghidra {name} equates ({refined["functions"]} functions)'
            checks.info(f'L5 {label}: {key} on the {on_clean["functions"]} functions without skipped instructions is '
                        f'{"equal to" if on_clean["equal"] else "coarser than"} Ghidra {name} ({on_clean["classes_ir"]} '
                        f'vs {on_clean["classes_ghidra"]} classes)')
        if not checks.check(f'L5 {label}: {title}', ok, json.dumps(detail)):
            checks.info(f'L5 {label}: {key} groups',
                        explain_groups(refined['straddling'] + on_clean['only_ghidra'] + on_clean['only_ir'], facts))
        report[key] = {**shape(on_clean), 'refines': refined['refines'], 'functions_all': refined['functions']}
    report.update(functions=len(facts), skipping=skipping, with_data=with_data)
    return report


def compare_with_other(own: dict, other: dict) -> list[str]:
    """Differences between this run's per-side digests and another OS's for the same DLL bytes (empty = equal)."""
    problems = []
    for side in ('older', 'newer'):
        mine, theirs = own['sides'].get(side), other.get('sides', {}).get(side)
        if theirs is None:
            problems.append(f'{side}: missing in the other results')
        elif mine['artifact_sha256'] != theirs['artifact_sha256']:
            problems.append(f'{side}: different DLL bytes ({mine["artifact_sha256"][:12]} vs '
                            f'{theirs["artifact_sha256"][:12]}); cross-OS equality needs the same file')
        elif mine['content_digest'] != theirs['content_digest']:
            problems.append(f'{side}: content_digest {mine["content_digest"][:16]} (here) != '
                            f'{theirs["content_digest"][:16]} ({other.get("os", "other")})')
    return problems


def pe_json(reader: VerifiedArtifactReader, pe) -> dict:
    """The PE view recorded next to a fixture's extractor output (what tests/test_unified_ir_ingest.py loads)."""
    return {'sha256': reader.sha256, 'image_base': pe.image_base, 'size_of_image': pe.size_of_image,
            'sections': [[s.name, s.start, s.end, s.executable] for s in pe.sections], 'relocs': list(pe.relocs),
            'primaries': {str(b): {'end': p.end, 'unwind': p.unwind, 'chunks': [list(c) for c in p.chunks],
                                   'eh': pe.eh_for(b)} for b, p in sorted(pe.primaries.items())},
            'warnings': pe.warnings}


def write_json(path: Path, document: object, *, sort: bool = True, indent: int | None = None) -> None:
    separators = (',', ':') if indent is None else (',', ': ')
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(document, handle, sort_keys=sort, indent=indent, separators=separators)
        handle.write('\n')


class _DiagnosticStop(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _diagnostic_report(reason: str, name: str = '', *, protect_primary: bool = False) -> None:
    """Ordinary sink failures are harmless; only an entry-time caller primary shields interrupts."""
    try:
        sys.stderr.write(f'INFO diagnostic {reason[:40]} {name[:120]}\n')
    except Exception:
        return
    except BaseException:
        if not protect_primary:
            raise


def _diagnostic_json(value, limit: int) -> bytes:
    result = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    for text in encoder.iterencode(value):
        remaining = limit - len(result)
        if len(text) > remaining:
            raise _DiagnosticStop('byte-cap')
        chunk = text.encode('utf-8')
        if len(chunk) > remaining:
            raise _DiagnosticStop('byte-cap')
        result.extend(chunk)
    return bytes(result)


def _diagnostic_read(path: Path, limit: int, check) -> bytes:
    check()
    if not stat.S_ISREG(path.lstat().st_mode):
        raise _DiagnosticStop('nonregular')
    result = bytearray()
    with path.open('rb') as stream:
        while True:
            check()
            chunk = stream.read(min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > limit:
                raise _DiagnosticStop('byte-cap')
    check()
    return bytes(result)


def _diagnostic_write(path: Path, data: bytes, check=None) -> None:
    with path.open('xb') as stream:
        for offset in range(0, len(data), 65536):
            if check is not None:
                check()
            chunk = data[offset:offset + 65536]
            if stream.write(chunk) != len(chunk):
                raise OSError('incomplete diagnostic write')


def _diagnostic_blob(raw: bytes) -> dict:
    return {'status': 'complete', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'encoding': 'base64', 'data_base64': base64.b64encode(raw).decode('ascii')}


def _diagnostic_refusal(reason: str, *, error: bool = False) -> dict:
    return {'status': 'error' if error else 'omitted', 'reason': reason}


class _RunDiagnostics:
    """Four nonretryable observation slots. No native calls or changes to Checks/acceptance."""

    def __init__(self, out: Path, work: Path, tag: str, *, clock=time.monotonic) -> None:
        self.out, self.work, self.tag, self.clock = out, work, tag, clock
        self.invocation = uuid.uuid4().hex
        self.attempts: set[tuple[str, int]] = set()
        self.remaining = DIAGNOSTIC_PAIR_BYTES

    def _metadata(self, side, result, check) -> dict:
        try:
            check()
            manifest = result['manifest']
            if manifest.artifact_sha256 != side.sha256 or manifest.producer.mode != 'analyze':
                return _diagnostic_refusal('artifact-identity', error=True)
            pair = ({'older': side.sha256, 'newer': side.other_sha256} if side.label == 'older'
                    else {'older': side.other_sha256, 'newer': side.sha256})
            sources = {}
            for name, path in [('tool', __file__), ('schema', schema.__file__), ('ingest', ingest.__code__.co_filename)]:
                sources[name + '_sha256'] = hashlib.sha256(
                    _diagnostic_read(Path(path), 256 * 1024, check)).hexdigest()
            metadata = {'status': 'complete', 'pair': pair, 'tag': self.tag, 'os': platform.system(),
                        'python': platform.python_version(), 'source': sources,
                        'script_sha256': manifest.producer.script_sha256,
                        'manifest': manifest.model_dump(mode='json')}
            _diagnostic_json(metadata, DIAGNOSTIC_META_BYTES)
            return metadata
        except _DiagnosticStop as exc:
            return _diagnostic_refusal('metadata-cap' if exc.reason == 'byte-cap' else exc.reason)
        except Exception:
            return _diagnostic_refusal('metadata-error', error=True)

    def _jsonl(self, result, check) -> dict:
        check()
        raw = result['jsonl']
        if type(raw) is not bytes:
            return _diagnostic_refusal('invalid-jsonl', error=True)
        if len(raw) > DIAGNOSTIC_JSONL_BYTES:
            return _diagnostic_refusal('byte-cap')
        count = 0
        for _line in io.BytesIO(raw):
            check()
            count += 1
            if count > DIAGNOSTIC_JSONL_RECORDS:
                return _diagnostic_refusal('record-cap')
        return {**_diagnostic_blob(raw), 'records': count}

    def _functions(self, connection, total: int, check) -> dict:
        projection = {'status': 'complete', 'columns': list(schema.COLUMNS['fn']), 'source_rows': total,
                      'retained_rows': 0, 'rows': []}
        # Reserve fixed status/reason/count growth; retained rows are accumulated only inside the remaining allowance.
        allowance = DIAGNOSTIC_FN_BYTES - len(_diagnostic_json(projection, DIAGNOSTIC_FN_BYTES)) - 128
        used, reason = 0, None
        for row in schema.table_rows(connection, 'fn'):
            check()
            if len(projection['rows']) >= DIAGNOSTIC_FN_ROWS:
                reason = 'row-cap'
                break
            try:
                encoded = _diagnostic_json(row, DIAGNOSTIC_ROW_BYTES)
            except _DiagnosticStop:
                reason = 'row-byte-cap'
                break
            cost = len(encoded) + int(bool(projection['rows']))
            if used + cost > allowance:
                reason = 'projection-byte-cap'
                break
            projection['rows'].append(row)
            used += cost
        projection['retained_rows'] = len(projection['rows'])
        if reason is not None:
            projection.update(status='prefix' if projection['rows'] else 'omitted', reason=reason)
        _diagnostic_json(projection, DIAGNOSTIC_FN_BYTES)
        return projection

    def _ir(self, side, ordinal: int, result, check, report) -> tuple[dict, dict]:
        connection = None
        progress_reason = None
        try:
            raw = _diagnostic_read(result['directory'] / schema.DB_NAME, DIAGNOSTIC_IR_BYTES, check)
            if hashlib.sha256(raw).hexdigest() != result['manifest'].file_sha256:
                raise _DiagnosticStop('hash-mismatch')
            snapshot = self.work / f'diagnostic-{self.invocation}-{side.label}-{ordinal}.sqlite3'
            _diagnostic_write(snapshot, raw, check)
            check()
            # Initial metadata SQL belongs to the unchanged helper; our progress scope starts only after it returns.
            connection = schema.open_readonly(snapshot)
            check()
            steps, quantum = 0, min(1000, max(1, DIAGNOSTIC_SQL_STEPS))

            def progress():
                nonlocal steps, progress_reason
                steps += quantum
                try:
                    check()
                except _DiagnosticStop:
                    progress_reason = 'deadline'
                if steps >= DIAGNOSTIC_SQL_STEPS:
                    progress_reason = progress_reason or 'query-cap'
                return int(progress_reason is not None)

            connection.set_progress_handler(progress, quantum)
            counts = {}
            total = 0
            for table in schema.TABLES:
                check()
                counts[table] = connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                total += counts[table]
                if total > DIAGNOSTIC_IR_ROWS:
                    raise _DiagnosticStop('row-cap')
            functions = self._functions(connection, counts['fn'], check)
            check()
            return {**_diagnostic_blob(raw), 'row_counts': counts}, functions
        except _DiagnosticStop as exc:
            error = exc.reason not in {'byte-cap', 'row-cap'}
            return _diagnostic_refusal(exc.reason, error=error), _diagnostic_refusal(exc.reason, error=error)
        except Exception:
            reason = progress_reason or 'snapshot-error'
            return _diagnostic_refusal(reason, error=True), _diagnostic_refusal(reason, error=True)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    report('snapshot-close-error')

    def capture(self, side, ordinal: int, result) -> None:
        protect_primary = sys.exception() is not None

        def report(reason: str, name: str = '') -> None:
            _diagnostic_report(reason, name, protect_primary=protect_primary)

        name = ''
        try:
            slot = (side.label, ordinal)
            if side.label not in {'older', 'newer'} or type(ordinal) is not int or ordinal not in {1, 2}:
                report('invalid-slot')
                return
            if slot in self.attempts or len(self.attempts) >= DIAGNOSTIC_ATTEMPTS:
                report('attempt-limit')
                return
            self.attempts.add(slot)
            if self.remaining < DIAGNOSTIC_FILE_BYTES:
                report('pair-byte-cap')
                return
            self.remaining -= DIAGNOSTIC_FILE_BYTES
            name = f'live-unified-diagnostics-{self.invocation}-{side.label}-analyze-{ordinal}.json'
            deadline = self.clock() + DIAGNOSTIC_SECONDS

            def check():
                if self.clock() >= deadline:
                    raise _DiagnosticStop('deadline')

            doc = {'contract': 'live-unified-diagnostics/1', 'invocation_id': self.invocation,
                   'side': side.label, 'analyze_ordinal': ordinal, 'complete': False}
            doc['metadata'] = self._metadata(side, result, check)
            try:
                doc['jsonl'] = self._jsonl(result, check)
            except _DiagnosticStop as exc:
                doc['jsonl'] = _diagnostic_refusal(exc.reason)
            doc['ir'], doc['functions'] = self._ir(side, ordinal, result, check, report)
            expired = self.clock() >= deadline
            if expired:
                # Once exhausted, attempt only a small failure envelope, never another payload/query/expansion.
                for key in ('jsonl', 'ir', 'functions'):
                    if doc[key]['status'] in {'complete', 'prefix'}:
                        doc[key] = _diagnostic_refusal('deadline')
            for key in ('jsonl', 'ir'):
                doc[key]['retained_bytes'] = doc[key].get('bytes', 0) if doc[key]['status'] == 'complete' else 0
            doc['jsonl']['retained_records'] = doc['jsonl'].get('records', 0)
            doc['ir']['retained_rows'] = sum(doc['ir'].get('row_counts', {}).values())
            doc['functions'].setdefault('retained_rows', 0)
            doc['functions'].setdefault('rows', [])
            metadata_view = {**doc, 'jsonl': {k: v for k, v in doc['jsonl'].items() if k != 'data_base64'},
                             'ir': {k: v for k, v in doc['ir'].items() if k != 'data_base64'},
                             'functions': {'status': doc['functions']['status']}}
            try:
                _diagnostic_json(metadata_view, DIAGNOSTIC_META_BYTES)
            except _DiagnosticStop:
                doc['metadata'] = _diagnostic_refusal('metadata-cap')
                metadata_view['metadata'] = doc['metadata']
                _diagnostic_json(metadata_view, DIAGNOSTIC_META_BYTES)
            doc['complete'] = all(doc[key]['status'] == 'complete' for key in ('metadata', 'jsonl', 'ir', 'functions'))
            data = _diagnostic_json(doc, DIAGNOSTIC_FILE_BYTES - 1) + b'\n'
            try:
                _diagnostic_write(self.out / name, data, None if expired else check)
            except FileExistsError:
                report('file-collision', name)
            except Exception:
                report('write-error', name)
            else:
                report('saved' if doc['complete'] else 'saved-incomplete', name)
        except _DiagnosticStop as exc:
            report(exc.reason, name)
        except Exception:
            report('capture-error', name)


class Side:
    """One DLL: verified bytes, PE tables, and the helpers that extract + ingest it."""

    def __init__(self, label: str, dll: Path, other_sha256: str, backend: BackendConfig, work: Path) -> None:
        self.label, self.dll, self.backend, self.work = label, dll, backend, work
        self.reader = VerifiedArtifactReader.open_path(dll)
        self.sha256 = self.reader.sha256
        self.other_sha256 = other_sha256
        self.pe = read_pe_tables(self.reader)
        self.counter = 0

    def close(self) -> None:
        self.reader.close()

    def run(self, mode: str, gzf: Path | None = None, gzf_sha256: str | None = None) -> dict:
        """Extract (real Ghidra) and ingest; returns digests, counts, the JSONL text and the packed program."""
        self.counter += 1
        job = runner.ExtractJob(side=self.label, artifact_path=self.dll, artifact_sha256=self.sha256, backend=self.backend,
                                mode=mode, gzf_path=gzf, gzf_sha256=gzf_sha256, timeout_seconds=EXTRACT_TIMEOUT_S)
        started = time.monotonic()
        output = runner.extract_side(job)
        extract_seconds = time.monotonic() - started
        try:
            text = output.jsonl.read_bytes()
            packed = None
            if output.gzf is not None:
                packed = self.work / f'{self.label}-{self.counter}.gzf'
                shutil.copy2(output.gzf, packed)
            built = self.work / f'{self.label}-{self.counter}-ir'
            built.mkdir()
            expected = ExpectedSide(self.label, self.sha256, self.pe, mode=mode,
                                    analysis_options_digest=output.analysis_options_digest,
                                    symbols=extract.SYMBOLS_BY_MODE[mode], script_sha256=extract.script_sha256(),
                                    gzf_sha256=gzf_sha256, other_sha256=self.other_sha256)
            started = time.monotonic()
            result = ingest(output.jsonl, expected, out_dir=built)
            ingest_seconds = time.monotonic() - started
            return {'mode': mode, 'manifest': result.manifest, 'directory': result.directory, 'jsonl': text,
                    'gzf': packed, 'probe': output.probe, 'extract_seconds': round(extract_seconds, 1),
                    'ingest_seconds': round(ingest_seconds, 1), 'stderr_tail': output.stderr_tail}
        finally:
            output.cleanup()

    def function_rows(self, directory: Path) -> dict[int, dict]:
        connection = schema.open_readonly(directory / schema.DB_NAME)
        try:
            return {rva: {'h0': h0, 'h3': h3, 'hm': hm, 'flags': flags, 'name': name} for rva, h0, h3, hm, flags, name in
                    connection.execute('SELECT rva, h0, h3, hm, flags, name FROM fn')}
        finally:
            connection.close()


def function_lines(jsonl: bytes) -> list[dict]:
    return [json.loads(line) for line in jsonl.decode('utf-8').splitlines()[1:-1]]


def check_side(side: Side, checks: Checks, args: argparse.Namespace, *, diagnostics=None) -> tuple[dict, dict]:
    """(public result for the JSON file, the first analyze run with its files for later steps)."""
    label = side.label
    first = side.run('analyze')
    if diagnostics is not None:
        diagnostics.capture(side, 1, first)
    second = side.run('analyze')
    if diagnostics is not None:
        diagnostics.capture(side, 2, second)
    manifest = first['manifest']
    checks.check(f'L1 {label}: two analyze runs give the same content_digest',
                 manifest.content_digest == second['manifest'].content_digest,
                 f'{manifest.content_digest} vs {second["manifest"].content_digest}')
    checks.check(f'L1 {label}: ir_key is deterministic', manifest.ir_key == second['manifest'].ir_key)
    if first['jsonl'].split(b'\n', 1)[1] != second['jsonl'].split(b'\n', 1)[1]:
        checks.info(f'{label}: the two analyze runs differ at the record level (the content_digest is what counts)')
    checks.check(f'L2 {label}: analyze run packed its analysed program', first['gzf'] is not None)
    if first['gzf'] is not None:
        gzf_sha256 = file_sha256(first['gzf'])
        again = side.run('gzf', first['gzf'], gzf_sha256)
        checks.check(f'L2 {label}: gzf mode gives the same content_digest as analyze mode',
                     again['manifest'].content_digest == manifest.content_digest,
                     f'{again["manifest"].content_digest} vs {manifest.content_digest}')
        checks.check(f'L2 {label}: gzf mode and analyze mode produce identical function records',
                     function_lines(again['jsonl']) == function_lines(first['jsonl']))
        checks.check(f'L2 {label}: the gzf run reports the primary symbol policy',
                     again['manifest'].producer.symbols == 'primary' and manifest.producer.symbols == 'none')
    counts = manifest.counts
    checks.check(f'L3 {label}: functions were extracted', counts.functions > 0, str(counts))
    if side.pe.primaries:
        checks.check(f'L3 {label}: pdata confirms function extents', counts.pdata_confirmed > 0, str(counts))
    else:
        checks.info(f'{label}: the image has no .pdata (built without unwind tables); extents are not pdata-confirmed')
    checks.check(f'L3 {label}: no function has an unlocated address operand', counts.mask_unlocated == 0, str(counts))
    checks.check(f'L3 {label}: no ingest limit was hit', not manifest.limits_hit, str(manifest.limits_hit))
    checks.check(f'L3 {label}: header image base equals the PE header', manifest.image_base == side.pe.image_base)
    checks.check(f'L3 {label}: probe versions are recorded', all(first['probe'].get(k) for k in
                                                                  ('ghidra', 'pyghidra', 'java', 'python')),
                 str(first['probe']))
    if manifest.warnings:
        checks.info(f'{label}: ingest warnings', ', '.join(manifest.warnings))
    rows = side.function_rows(first['directory'])
    hashers = None
    if not args.no_hashers and first['gzf'] is not None:
        hashers = hasher_check(side, first['gzf'], rows, function_lines(first['jsonl']), checks)
    public = {'artifact_sha256': side.sha256, 'ir_key': manifest.ir_key, 'content_digest': manifest.content_digest,
              'counts': json.loads(manifest.counts.model_dump_json()), 'warnings': list(manifest.warnings),
              'probe': first['probe'], 'seconds': {'extract': first['extract_seconds'], 'ingest': first['ingest_seconds']},
              'hashers': hashers}
    return public, first


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1 << 22):
            digest.update(chunk)
    return digest.hexdigest()


def hasher_check(side: Side, gzf: Path, rows: dict[int, dict], records: Sequence[dict], checks: Checks) -> dict:
    script = side.work / f'{side.label}-hashers.py'
    script.write_text(HASHER_SCRIPT, encoding='utf-8', newline='\n')
    out = side.work / f'{side.label}-hashers.json'
    settings = side.work / f'{side.label}-hasher-settings'
    settings.mkdir()
    result = run_process([os.path.abspath(side.backend.python_executable), '-B', '-X', 'utf8', str(script), str(gzf),
                          str(out), str(Path(side.backend.ghidra_dir).resolve())], cwd=side.work,
                         env=backend_module._environment(side.backend, settings), cancel=threading.Event(),
                         timeout_seconds=EXTRACT_TIMEOUT_S, separate_streams=True)
    if not checks.check(f'L5 {side.label}: Ghidra hasher child ran', result.returncode == 0 and out.is_file(),
                        result.stderr_tail):
        return {'error': 'hasher child failed'}
    return l5_report(side.label, json.loads(out.read_text(encoding='utf-8')), rows, records, checks)


def ghidriff_check(args, backend: BackendConfig, sides: dict[str, Side], results: dict, checks: Checks,
                   work: Path) -> None:
    """L4: a real Ghidriff run with retention, then gzf-mode extraction of the retained programs."""
    root = work / 'case'
    retaining = BackendConfig(backend.python_executable, backend.ghidra_dir, 1800, retain_gzf=True)
    service = ProjectService.create(Path(args.old).resolve(), Path(args.new).resolve(), 'live unified', root)
    try:
        events = []
        path, run = run_comparison(retaining, service.project, service.root, threading.Event(),
                                   lambda e: events.append((e.stage, e.message)))
        if not checks.check('L4 Ghidriff completed with retain_gzf', run.status == 'completed', run.error or str(run.status)):
            return
        record = run.settings.get('gzf')
        directory = service.root / 'runs' / run.id / 'unified' / 'gzf'
        if not checks.check('L4 two GZFs were retained and recorded', bool(record) and all(
                (directory / f'{s}.gzf').is_file() for s in ('older', 'newer')), f'{record} {events[-3:]}'):
            return
        results['ghidriff'] = {'gzf': record}
        for name, side in sides.items():
            gzf = directory / f'{name}.gzf'
            digest = file_sha256(gzf)
            checks.check(f'L4 {name}: recorded SHA-256 equals the retained file', record[name]['sha256'] == digest)
            retained = side.run('gzf', gzf, digest)
            same = retained['manifest'].content_digest == results['sides'][name]['content_digest']
            if same:
                checks.check(f'L4 {name}: Ghidriff GZF gives the content_digest of the own analysis', True)
            else:
                checks.info(f'L4 {name}: Ghidriff GZF differs from the own analysis (Ghidriff options are its own)',
                            f'{retained["manifest"].content_digest[:16]} vs {results["sides"][name]["content_digest"][:16]}')
            results['ghidriff'][name] = {'content_digest': retained['manifest'].content_digest, 'equals_own_analysis': same,
                                         'counts': json.loads(retained['manifest'].counts.model_dump_json())}
    finally:
        service.close()


def record_fixtures(directory: Path, names: tuple[str, str], sides: dict[str, Side], firsts: dict[str, dict],
                    results: dict, args) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    provenance_path = directory / 'PROVENANCE.json'
    provenance = json.loads(provenance_path.read_text(encoding='utf-8')) if provenance_path.is_file() else {}
    for name, (side_name, side) in zip(names, sides.items(), strict=True):
        first = firsts[side_name]
        (directory / f'{name}.ir.jsonl').write_bytes(first['jsonl'])
        write_json(directory / f'{name}.pe.json', pe_json(side.reader, side.pe))
        provenance[name] = {'artifact_sha256': side.sha256, 'bytes': side.dll.stat().st_size,
                            'built_with': args.built_with, 'mode': 'analyze', 'probe': first['probe'],
                            'script_sha256': extract.script_sha256(), 'content_digest': results['sides'][side_name]['content_digest'],
                            'recorded_utc': datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}
        print(f'recorded {name}: {len(first["jsonl"])} bytes of extractor output')
    write_json(provenance_path, provenance, indent=1)


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--old', required=True, type=Path)
    parser.add_argument('--new', required=True, type=Path)
    parser.add_argument('--ghidra-dir', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--tag', default='run', help='names the results file: live-unified-TAG-OS.json')
    parser.add_argument('--other-results', type=Path)
    parser.add_argument('--no-ghidriff', action='store_true')
    parser.add_argument('--no-hashers', action='store_true')
    parser.add_argument('--record', nargs=3, metavar=('FIXTURE_DIR', 'NAME_OLD', 'NAME_NEW'))
    parser.add_argument('--built-with', default='unspecified', help='free text stored in PROVENANCE.json by --record')
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    args = parse_args(argv)
    checks = Checks()
    args.out.mkdir(parents=True, exist_ok=True)
    backend = BackendConfig(args.python, str(args.ghidra_dir.resolve()), 1800)
    work = Path(tempfile.mkdtemp(prefix='ptlive-')).resolve()
    sides: dict[str, Side] = {}
    firsts: dict[str, dict] = {}
    results: dict = {'os': platform.system(), 'machine': platform.machine(), 'python': platform.python_version(),
                     'script_sha256': extract.script_sha256(), 'sides': {}}
    try:
        try:
            diagnostics = _RunDiagnostics(args.out, work, args.tag)
        except Exception:
            _diagnostic_report('initialization-error')
            diagnostics = None
        sides['older'] = Side('older', args.old.resolve(), file_sha256(args.new), backend, work)
        sides['newer'] = Side('newer', args.new.resolve(), file_sha256(args.old), backend, work)
        checks.check('L0 the self-check finds every Ghidra class the script needs',
                     runner.self_check(backend).get('ok') is True)
        for name, side in sides.items():
            results['sides'][name], firsts[name] = check_side(side, checks, args, diagnostics=diagnostics)
        if not args.no_ghidriff:
            ghidriff_check(args, backend, sides, results, checks, work)
        if args.other_results:
            other = json.loads(args.other_results.read_text(encoding='utf-8'))
            problems = compare_with_other(results, other)
            checks.check(f'L6 content_digest equals the {other.get("os", "other")} run for the same DLL bytes',
                         not problems, '; '.join(problems))
        if args.record:
            record_fixtures(Path(args.record[0]), (args.record[1], args.record[2]), sides, firsts, results, args)
        results_path = args.out / f'live-unified-{args.tag}-{platform.system().lower()}.json'
        write_json(results_path, results, indent=1)
        print(f'results: {results_path}')
    finally:
        for side in sides.values():
            side.close()
        shutil.rmtree(work, ignore_errors=True)
    if checks.failures:
        print('\n'.join(checks.failures), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
