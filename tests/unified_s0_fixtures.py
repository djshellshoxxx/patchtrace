"""Synthetic builders for the SPEC-31 S0 tests (sources, fusion, facts, pipeline). Everything here is made up in code:
no engine, tool or Microsoft binary was run, so nothing built from it is live evidence."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import random
from pathlib import Path

from patchtrace.secondary.contracts import AlternativeMatch, SecondaryMatch, SecondaryMatchSet
from patchtrace.unified.addressing import AddressMap, PeLayout
from patchtrace.unified.sources import (
    GhidriffRun,
    LoadedSecondary,
    RawGhidriff,
    SnapshotFunction,
    SnapshotMatch,
    SourceInputs,
)

BASE = 0x180000000
SIZE = 0x2000
OLD_SHA, NEW_SHA = 'a' * 64, 'b' * 64
RAW_SHA = 'c' * 64
LAYOUT = PeLayout(image_base=BASE, size_of_image=SIZE)


def addr_map() -> AddressMap:
    return AddressMap(LAYOUT, LAYOUT)


def va(rva: int) -> str:
    return f'{BASE + rva:x}'


def func(name: str, rva: int | None, *, code: str | None = None, callees=(), callers=(), diff_types=(),
         ratio: str | None = None, omitted: bool = False) -> SnapshotFunction:
    return SnapshotFunction(name=name, address=None if rva is None else va(rva), code=code, code_omitted=omitted,
                            callees=tuple(callees), callers=tuple(callers), diff_types=tuple(diff_types),
                            ratio_text=ratio)


def match(mid: str, category: str, older=(), newer=(), types=(), manual: bool = False) -> SnapshotMatch:
    return SnapshotMatch(id=mid, category=category, manual=manual, match_types=tuple(types), older=tuple(older),
                         newer=tuple(newer))


def raw_ok(table=None, sha: str = RAW_SHA) -> RawGhidriff:
    return RawGhidriff(status='ok', address_matches=table if table is not None else {}, sha256=sha)


def inputs(matches=(), raw=None, secondary=(), run_id: str = 'run-1', version: str = '1') -> SourceInputs:
    return SourceInputs(older_sha256=OLD_SHA, newer_sha256=NEW_SHA,
                        run=GhidriffRun(run_id=run_id, backend_version=version, raw=raw or raw_ok()),
                        matches=tuple(matches), secondary=tuple(secondary))


def bd(older_rva: int, newer_rva: int, algorithm: str = 'function: name hash matching', flags=(),
       sim: int = 1000, conf: int = 993, older_name: str | None = None, newer_name: str | None = None,
       base: int = BASE) -> SecondaryMatch:
    return SecondaryMatch(engine='bindiff', engine_version='8.0', older_address=base + older_rva,
                          newer_address=base + newer_rva, older_name=older_name, newer_name=newer_name,
                          similarity_milli=sim, similarity_text=f'{sim / 1000}', confidence_milli=conf,
                          confidence_text=f'{conf / 1000}', flags=tuple(flags), algorithm=algorithm)


def rz(older_rva: int | None, newer_rva: int | None, sim: int = 500, kind: str = 'PARTIAL',
       version: str = '0.9.1', base: int = BASE) -> SecondaryMatch:
    return SecondaryMatch(engine='rz-diff', engine_version=version,
                          older_address=None if older_rva is None else base + older_rva,
                          newer_address=None if newer_rva is None else base + newer_rva,
                          older_name=None, newer_name=None, similarity_milli=sim, similarity_text=f'{sim / 1000}',
                          confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes',
                          match_type=kind)


def bindiff_set(rows, *, alternatives=(), file_sha: str = 'd' * 64, older: str = OLD_SHA,
                newer: str = NEW_SHA) -> SecondaryMatchSet:
    return SecondaryMatchSet(contract='secondary/2', engine='bindiff', engine_version='8.0', older_sha256=older,
                             newer_sha256=newer, file_sha256=file_sha, image_base_subtracted='no',
                             matches=tuple(rows), alternatives=tuple(alternatives))


def rzdiff_set(rows, *, version: str = '0.9.1', file_sha: str = 'e' * 64, older: str = OLD_SHA,
               newer: str = NEW_SHA) -> SecondaryMatchSet:
    return SecondaryMatchSet(contract='secondary/2', engine='rz-diff', engine_version=version, older_sha256=older,
                             newer_sha256=newer, file_sha256=file_sha, matches=tuple(rows))


def loaded(match_set: SecondaryMatchSet, entry_id: str | None = None) -> LoadedSecondary:
    return LoadedSecondary(entry_id=entry_id or f'entry-{match_set.engine}', match_set=match_set)


def alternative(anchor_side: str, anchor_rva: int, candidate: SecondaryMatch, rank: int = 2,
                source: str = 'bindiff') -> AlternativeMatch:
    return AlternativeMatch(anchor_side=anchor_side, anchor_address=BASE + anchor_rva, candidate=candidate,
                            source=source, rank=rank)


# --- a real (synthetic) project: two PE fixtures plus an imported Ghidriff document --------------------------------

def _raw_function(name: str, rva: int, code: str | None = None, called=(), calling=()) -> dict:
    return {'name': name, 'fullname': name, 'address': va(rva), 'code': code, 'calling': list(calling),
            'called': list(called), 'sig': f'int {name}(void)'}


def patch_document(project) -> dict:
    """A synthetic PDiff document in the shape ProjectService imports: one material change (a call is added), one
    constant-only change, one cosmetic rename, one unchanged pair (address_matches only), an added and a deleted
    function. Addresses are inside the 0x2000-byte image of `patchtrace.sample.synthetic_pe`."""
    sides = {a.side: a.sha256 for a in project.artifacts}

    def modified(name, old_rva, new_rva, old_code, new_code, old_called, new_called, diff_type=('code', 'address')):
        return {'old': _raw_function(name, old_rva, old_code, old_called),
                'new': _raw_function(name, new_rva, new_code, new_called), 'diff_type': list(diff_type),
                'ratio': 0.9, 'match_types': ['SymbolsHash']}
    functions = {
        'added': [_raw_function('report_invalid_index', 0x1800, 'void report_invalid_index(void) { return; }')],
        'deleted': [_raw_function('debug_dump', 0x1400, 'void debug_dump(void) { puts("x"); }', ['puts'])],
        'modified': [
            modified('read_item', 0x1000, 0x1080, 'int read_item(int a) { return a; }',
                     'int read_item(int a) { report_invalid_index(); return a; }', [], ['report_invalid_index']),
            modified('get_version', 0x1600, 0x1700, 'int get_version(void) { return 1; }',
                     'int get_version(void) { return 2; }', [], []),
            modified('format_name', 0x1200, 0x1280,
                     'int format_name(int param_1) { int uVar1; uVar1 = param_1; return uVar1; }',
                     'int format_name(int param_9) { int iVar4; iVar4 = param_9; return iVar4; }', [], [],
                     diff_type=('address',)),
        ]}
    address_matches = {va(0x1000): [[va(0x1080), ['SymbolsHash']]], va(0x1600): [[va(0x1700), ['SymbolsHash']]],
                       va(0x1200): [[va(0x1280), ['SymbolsHash']]],
                       va(0x1300): [[va(0x1380), ['ExactBytesFunctionHasher']]]}
    return {'old_meta': {'Executable SHA256': sides['older']}, 'new_meta': {'Executable SHA256': sides['newer']},
            'functions': functions, 'matches': {'address_matches': address_matches}, 'stats': {}}


def make_project(root, *, document=None):
    """A project with a completed run whose preserved raw output is `patch_document` (or `document`)."""
    import json
    import tempfile
    from pathlib import Path

    from patchtrace.models import AnalysisRun
    from patchtrace.sample import synthetic_pe
    from patchtrace.service import ProjectService
    with tempfile.TemporaryDirectory(prefix='pt-s0-') as scratch:
        older, newer = Path(scratch) / 'older.dll', Path(scratch) / 'newer.dll'
        older.write_bytes(synthetic_pe(0))
        newer.write_bytes(synthetic_pe(1))
        service = ProjectService.create(older, newer, 'S0 synthetic', Path(root))
        try:
            raw = Path(scratch) / 'raw.json'
            raw.write_text(json.dumps(document or patch_document(service.project)), encoding='utf-8')
            service.apply_analysis(raw, AnalysisRun(status='completed', backend='synthetic', backend_version='1',
                                                    settings={'synthetic': True}))
        except Exception:
            service.close()
            raise
    return service


# --- a richer in-memory scenario (every source, a contest, one-sided rows, a correction) --------------------------

def rich_inputs(flip: bool = False) -> SourceInputs:
    """Ghidriff (3 modified, 1 unchanged, 1 added, 1 deleted), BinDiff (agreeing, conflicting and BinDiff-only
    rows), rz-diff and one analyst correction. `flip=True` describes the SAME world with older and newer swapped."""
    def sides(old, new):
        return ([new], [old]) if flip else ([old], [new])

    def pair(mid, name, o_rva, n_rva, o_code, n_code, o_calls=(), n_calls=(), diff=('code',)):
        older, newer = sides(func(name, o_rva, code=o_code, callees=o_calls, diff_types=diff),
                             func(name, n_rva, code=n_code, callees=n_calls, diff_types=diff))
        return match(mid, 'modified', older=older, newer=newer, types=['SymbolsHash'])
    manual_older, manual_newer = sides(func('manual_fn', 0x1a00), func('manual_fn', 0x1a80))
    matches = [
        pair('g1', 'read_item', 0x1000, 0x1080, 'int read_item(int a) { return a; }',
             'int read_item(int a) { report_invalid_index(); return a; }', (), ('report_invalid_index',)),
        pair('g2', 'get_version', 0x1600, 0x1700, 'int get_version(void) { return 1; }',
             'int get_version(void) { return 2; }'),
        pair('g3', 'format_name', 0x1200, 0x1280,
             'int format_name(int param_1) { int uVar1; uVar1 = param_1; return uVar1; }',
             'int format_name(int param_9) { int iVar4; iVar4 = param_9; return iVar4; }', diff=('address',)),
        match('man1', 'modified', older=manual_older, newer=manual_newer, manual=True),
    ]
    added = func('report_invalid_index', 0x1800, code='void report_invalid_index(void) { return; }')
    deleted = func('debug_dump', 0x1400, code='void debug_dump(void) { puts("x"); }', callees=('puts',))
    matches.append(match('g4', 'removed', older=[added]) if flip else match('g4', 'added', newer=[added]))
    matches.append(match('g5', 'added', newer=[deleted]) if flip else match('g5', 'removed', older=[deleted]))
    table: dict[str, list] = {}
    for o_rva, n_rva, kind in ((0x1000, 0x1080, 'SymbolsHash'), (0x1600, 0x1700, 'SymbolsHash'),
                               (0x1200, 0x1280, 'SymbolsHash'), (0x1300, 0x1380, 'ExactBytesFunctionHasher')):
        o_rva, n_rva = (n_rva, o_rva) if flip else (o_rva, n_rva)
        table.setdefault(va(o_rva), []).append([va(n_rva), [kind]])

    def bdiff(o_rva, n_rva, algorithm):
        return bd(*((n_rva, o_rva) if flip else (o_rva, n_rva)), algorithm=algorithm)

    def rzrow(o_rva, n_rva):
        return rz(*((n_rva, o_rva) if flip else (o_rva, n_rva)))
    older, newer = (NEW_SHA, OLD_SHA) if flip else (OLD_SHA, NEW_SHA)
    bindiff_rows = [bdiff(0x1000, 0x1080, 'function: hash matching'),
                    bdiff(0x1600, 0x1780, 'function: hash matching'),
                    bdiff(0x1900, 0x1980, 'function: name hash matching')]
    secondary = (loaded(bindiff_set(bindiff_rows, older=older, newer=newer)),
                 loaded(rzdiff_set([rzrow(0x1000, 0x1080), rzrow(0x1c00, 0x1c80)], older=older, newer=newer)))
    return SourceInputs(older_sha256=older, newer_sha256=newer,
                        run=GhidriffRun(run_id='run-1', backend_version='1', raw=raw_ok(table)),
                        matches=tuple(matches), secondary=secondary)


def shuffled(data: SourceInputs, seed: int) -> SourceInputs:
    """The same inputs in another order: matches, sets, rows, raw table keys and targets (G-U4 permutation)."""
    rng = random.Random(seed)
    matches = list(data.matches)
    rng.shuffle(matches)
    secondary = []
    for item in data.secondary:
        rows = list(item.match_set.matches)
        rng.shuffle(rows)
        updated = item.match_set.model_copy(update={'matches': tuple(rows)})
        secondary.append(dataclasses.replace(item, match_set=updated))
    rng.shuffle(secondary)
    table = data.run.raw.address_matches or {}
    order = list(table)
    rng.shuffle(order)
    permuted = {}
    for key in order:
        targets = list(table[key])
        rng.shuffle(targets)
        permuted[key] = targets
    raw = dataclasses.replace(data.run.raw, address_matches=permuted)
    return dataclasses.replace(data, matches=tuple(matches), secondary=tuple(secondary),
                               run=dataclasses.replace(data.run, raw=raw))


def with_raw_sha(data: SourceInputs, sha: str) -> SourceInputs:
    raw = dataclasses.replace(data.run.raw, sha256=sha)
    return dataclasses.replace(data, run=dataclasses.replace(data.run, raw=raw))


def write_worker_request(directory, data: SourceInputs, *, sources=('ghidriff', 'bindiff', 'rz-diff', 'manual'),
                         raw_status: str = 'ok', budget: int = 60, tamper=None) -> tuple[Path, SourceInputs]:
    """Write a worker request and its input files the way `pipeline` does, from loaded inputs. Returns the request
    path and `data` carrying the SHA-256 of the raw file that was written. `tamper(document, private)` may edit the
    request document or the files before the request is written."""
    from patchtrace.unified.exchange import WorkerFile, WorkerLayout, WorkerRequest
    from patchtrace.unified.sources import write_snapshot
    from patchtrace.unified.sources.secondary import write_loaded
    directory = Path(directory)
    private = directory / 'private'
    private.mkdir(parents=True)
    raw_path = directory / 'raw.json'
    raw_path.write_text(json.dumps({'matches': {'address_matches': data.run.raw.address_matches or {}}}),
                        encoding='utf-8')
    raw_sha = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    digest, size, lines = write_snapshot(private / 'matches.jsonl', data.matches)
    files = []
    for index, item in enumerate(data.secondary):
        sha, length = write_loaded(private / f'secondary-{index}.json', item)
        files.append(WorkerFile(path=str(private / f'secondary-{index}.json'), sha256=sha, size=length))
    layout = WorkerLayout(image_base=BASE, size_of_image=SIZE)
    request = WorkerRequest(
        older_sha256=data.older_sha256, newer_sha256=data.newer_sha256, older_layout=layout, newer_layout=layout,
        run_id=data.run.run_id, backend_version=data.run.backend_version, raw_sha256=raw_sha, raw_status=raw_status,
        raw_path=str(raw_path) if raw_status == 'ok' else None,
        snapshot=WorkerFile(path=str(private / 'matches.jsonl'), sha256=digest, size=size), snapshot_lines=lines,
        secondary=tuple(files), sources=tuple(sources), report_path=str(private / 'report.json'),
        progress_path=str(private / 'progress.json'), budget_seconds=budget)
    document = json.loads(request.model_dump_json())
    if tamper:
        tamper(document, private)
    (private / 'request.json').write_text(json.dumps(document), encoding='utf-8')
    return private / 'request.json', with_raw_sha(data, raw_sha)
