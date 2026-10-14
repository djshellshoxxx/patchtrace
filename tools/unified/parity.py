"""Dev-only parity harness for the SPEC-31 L1 ladder (08-evaluation s4, gate G-U3, amendment A-15).

Never shipped and never imported by `src/`: the product's BinDiff argv (SPEC-29 `build_argv`, its `FORBIDDEN_FLAGS`)
keeps `--md_index` forbidden; only this tool runs `bindiff --nologo --md_index --primary=<file>` with its own argv,
through `jobs.run_process` with a fixed absolute executable, `shell=False`, a private working directory, the audited
BinDiff child environment (`secondary.engine_env`) and bounded output. BinDiff is never bundled.

What it answers (all numbers are counts; no score is computed or averaged):

* per ladder pass (step id): how many pairs agree with each oracle (Ghidriff `matches.address_matches` and
  `functions.modified`, BinDiff `.BinDiff` function rows), how many contradict it (the oracle pairs the same older
  function with another partner) and how many the oracle simply does not mention; every contradiction is listed by
  RVA pair with both provenances (capped, with a truncation counter);
* oracle pairs the ladder did not reproduce, grouped by Ghidriff `match_types` / BinDiff algorithm, split into
  "ladder paired it differently" and "ladder left it unmatched";
* the MD-index comparison between the IR keys (`fn.md_td` = round(md * 10**12)) and a `bindiff --md_index` dump:
  exact / differs by one unit of 1e-12 / differs / missing on either side.

The report is deterministic (sorted keys, LF newlines, no timestamps), so equal inputs give an identical
`report_sha256`, which docs/qa.md records next to the live-run URL. Tests use synthetic data and a FAKE bindiff;
parity against a real BinDiff install is live-only and stays BLOCKED until `tools/bindiff_pin.json` is provisioned.
The textual layout of the real `--md_index` dump is not verified here: the parser accepts any line holding a
hexadecimal function address followed by a decimal number and counts every other line instead of guessing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

REPORT_CONTRACT = 'parity-report/1'
MAX_LISTED = 200                       # disagreements / misses listed per group (the rest is counted)
MAX_DUMP_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 512 * 1024 * 1024
_MD_LINE = re.compile(r'^\s*(?:0x)?([0-9A-Fa-f]{1,16})\s*[:,=\s]\s*(-?\d+\.\d+)\s*$')
_LADDER_SOURCES = ('pt-ladder', 'pt-bytes')
_RVA_MAX = 2**32 - 1


# ---- data ------------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class LadderPair:
    older: int
    newer: int
    step: str
    tier: str
    cls: str
    source: str

    def provenance(self) -> dict:
        return {'step': self.step, 'tier': self.tier, 'cls': self.cls, 'source': self.source}


@dataclass(frozen=True)
class OraclePair:
    older: int
    newer: int
    label: str          # Ghidriff match type / BinDiff algorithm name
    extra: str = ''     # e.g. 'modified:code,refcount' for Ghidriff `functions.modified`


@dataclass
class Oracle:
    name: str
    pairs: list[OraclePair]
    dropped: Counter


# ---- ladder pairs ---------------------------------------------------------------------------------------------------------------

def ladder_from_correspondence(corr) -> list[LadderPair]:
    """Live path: pairs straight from a `ladder.types.Correspondence` (tier-M anchors are inputs and skipped)."""
    out = []
    for p in corr.pairs:
        if p.pass_id == 'P00':
            continue
        source = 'pt-bytes' if p.family == 'F-PT-BYTES' else 'pt-ladder'
        out.append(LadderPair(corr.older_rva[p.older_fid], corr.newer_rva[p.newer_fid], p.step, p.tier, p.cls, source))
    return sorted(out, key=lambda x: (x.older, x.newer, x.step))


def ladder_from_rows(rows: Iterable) -> list[LadderPair]:
    """Result path: `UnifiedMatch` rows (models or dicts) -> one record per ladder atom of every 1:1 row."""
    out = []
    for row in rows:
        data = row if isinstance(row, dict) else row.model_dump(mode='json')
        if len(data['older']) != 1 or len(data['newer']) != 1:
            continue
        older, newer = data['older'][0]['rva'], data['newer'][0]['rva']
        for atom in data['atoms']:
            if atom['source'] in _LADDER_SOURCES and atom['older_rva'] == older and atom['newer_rva'] == newer:
                out.append(LadderPair(older, newer, atom['step'], atom['tier'], atom['cls'], atom['source']))
    return sorted(out, key=lambda x: (x.older, x.newer, x.step))


# ---- oracle readers ------------------------------------------------------------------------------------------------------------

def _hex_address(text: object) -> int | None:
    if not isinstance(text, str):
        return None
    value = text.strip().lower()
    if value.startswith('0x'):
        value = value[2:]
    if not value or any(c not in '0123456789abcdef' for c in value):
        return None
    number = int(value, 16)
    return number if number < 2**64 else None


def _rva(address: int, base: int, dropped: Counter) -> int | None:
    value = address - base
    if not 0 <= value <= _RVA_MAX:
        dropped['address-outside-image'] += 1
        return None
    return value


def read_ghidriff(raw: Mapping, older_base: int = 0, newer_base: int = 0) -> Oracle:
    """`matches.address_matches` (old address -> [[new address, [match types]], ...]) and `functions.modified`.
    Addresses are virtual addresses (Ghidra loads at the PE ImageBase), so the bases are subtracted. `EXTERNAL:<hex>`
    keys are not functions of either image: skipped and counted, exactly like the N-way reader."""
    dropped: Counter = Counter()
    pairs: list[OraclePair] = []
    table = (raw.get('matches') or {}).get('address_matches') or {}
    if not isinstance(table, Mapping):
        raise ValueError('address_matches must be an object')
    for old_text, targets in table.items():
        if str(old_text).startswith('EXTERNAL:'):
            dropped['external-key'] += 1
            continue
        old = _hex_address(old_text)
        if old is None or not isinstance(targets, list):
            dropped['unparsable-address'] += 1
            continue
        for target in targets:
            if not (isinstance(target, list) and len(target) == 2 and isinstance(target[1], list)):
                dropped['unparsable-target'] += 1
                continue
            if str(target[0]).startswith('EXTERNAL:'):
                dropped['external-key'] += 1
                continue
            new = _hex_address(target[0])
            o = _rva(old, older_base, dropped) if old is not None else None
            n = _rva(new, newer_base, dropped) if new is not None else None
            if o is None or n is None:
                continue
            label = str(target[1][0]) if target[1] else 'unknown'
            pairs.append(OraclePair(o, n, label[:64], 'all:' + ','.join(str(t) for t in target[1])[:200]))
    modified = (raw.get('functions') or {}).get('modified') or []
    for item in modified if isinstance(modified, list) else []:
        old = _hex_address((item.get('old') or {}).get('address')) if isinstance(item, dict) else None
        new = _hex_address((item.get('new') or {}).get('address')) if isinstance(item, dict) else None
        if old is None or new is None:
            dropped['modified-without-address'] += 1
            continue
        o, n = _rva(old, older_base, dropped), _rva(new, newer_base, dropped)
        if o is None or n is None:
            continue
        types = item.get('match_types') or []
        diffs = item.get('diff_type') or []
        label = str(types[0]) if types else 'unknown'
        pairs.append(OraclePair(o, n, label[:64], 'modified:' + ','.join(str(d) for d in diffs)[:200]))
    # the same pair can appear in address_matches and in modified: keep one record, preferring the richer `modified`
    unique: dict[tuple[int, int], OraclePair] = {}
    for p in pairs:
        key = (p.older, p.newer)
        if key not in unique or p.extra.startswith('modified:'):
            unique[key] = p
    return Oracle('ghidriff', [unique[k] for k in sorted(unique)], dropped)


def read_bindiff(matches: Iterable[tuple[int, int, str]], older_base: int = 0, newer_base: int = 0) -> Oracle:
    """`.BinDiff` function rows as (older address, newer address, algorithm name); rows with an address outside
    the image after subtracting the base are dropped and counted."""
    dropped: Counter = Counter()
    pairs = []
    for old, new, algorithm in matches:
        o, n = _rva(old, older_base, dropped), _rva(new, newer_base, dropped)
        if o is not None and n is not None:
            pairs.append(OraclePair(o, n, str(algorithm)[:64]))
    return Oracle('bindiff', sorted(pairs, key=lambda p: (p.older, p.newer)), dropped)


def bindiff_rows_from_file(path: Path, older_sha256: str, newer_sha256: str) -> list[tuple[int, int, str]]:
    """Hardened read of a `.BinDiff` database through the product importer (SPEC-10/29 s7.2)."""
    from patchtrace.secondary.bindiff import import_bindiff
    match_set = import_bindiff(path, older_sha256, newer_sha256)
    return [(m.older_address, m.newer_address, m.algorithm) for m in match_set.matches]


# ---- MD index ------------------------------------------------------------------------------------------------------------------

def parse_md_dump(text: str) -> tuple[dict[int, str], int]:
    """(address -> decimal text, number of lines that could not be parsed). Later lines win for a repeated address."""
    values: dict[int, str] = {}
    unparsed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _MD_LINE.match(line)
        if match is None:
            unparsed += 1
            continue
        values[int(match.group(1), 16)] = match.group(2)
    return values, unparsed


def md_key_of(text: str) -> int | None:
    """round(value * 10**12) of a decimal text without binary floating point (the IR stores this integer)."""
    try:
        return int((Decimal(text) * 10**12).to_integral_value(rounding='ROUND_HALF_EVEN'))
    except (InvalidOperation, ValueError):
        return None


def compare_md(ir_keys: Mapping[int, int | None], dump: Mapping[int, str], *, image_base: int = 0) -> dict:
    """Histogram of IR md keys (by RVA) against a dump (by address minus `image_base`)."""
    dropped: Counter = Counter()
    dumped: dict[int, int] = {}
    for address, text in dump.items():
        rva = _rva(address, image_base, dropped)
        key = md_key_of(text)
        if rva is not None and key is not None:
            dumped[rva] = key
    exact = near = far = missing_dump = missing_ir = 0
    samples = []
    for rva in sorted(set(ir_keys) | set(dumped)):
        ir, ref = ir_keys.get(rva), dumped.get(rva)
        if ir is None and ref is None:
            continue
        if ref is None:
            missing_dump += 1
        elif ir is None:
            missing_ir += 1
        elif ir == ref:
            exact += 1
        elif abs(ir - ref) <= 1:
            near += 1
        else:
            far += 1
            if len(samples) < MAX_LISTED:
                samples.append({'rva': rva, 'ir_key': ir, 'dump_key': ref})
    compared = exact + near + far
    return {'compared': compared, 'exact': exact, 'differs_1e-12': near, 'differs': far,
            'missing_in_dump': missing_dump, 'missing_in_ir': missing_ir,
            'exact_per_mille': (1000 * exact // compared) if compared else None,
            'dropped': dict(sorted(dropped.items())), 'differing_samples': samples}


def read_ir_md(path: Path) -> dict[int, int | None]:
    """{rva: md_td} from a `program-ir/1` sidecar (frozen DDL, 02 s3), opened read-only and immutable."""
    db = sqlite3.connect(f'{Path(path).resolve().as_uri()}?mode=ro&immutable=1', uri=True)
    try:
        db.execute('PRAGMA query_only=1')
        db.execute('PRAGMA trusted_schema=OFF')
        return {rva: td for rva, td in db.execute('SELECT rva, md_td FROM fn ORDER BY rva')}
    finally:
        db.close()


# ---- comparison -----------------------------------------------------------------------------------------------------------------

def _index(oracle: Oracle):
    by_pair = {(p.older, p.newer): p for p in oracle.pairs}
    by_old: dict[int, list[OraclePair]] = {}
    for p in oracle.pairs:
        by_old.setdefault(p.older, []).append(p)
    return by_pair, by_old


def compare_oracle(ladder: Sequence[LadderPair], oracle: Oracle) -> dict:
    by_pair, by_old = _index(oracle)
    ladder_by_old: dict[int, list[LadderPair]] = {}
    ladder_pairs = set()
    for lp in ladder:
        ladder_by_old.setdefault(lp.older, []).append(lp)
        ladder_pairs.add((lp.older, lp.newer))
    steps: dict[str, dict] = {}
    for lp in ladder:
        row = steps.setdefault(lp.step, {'pairs': 0, 'agree': 0, 'disagree': 0, 'absent': 0, 'listed': []})
        row['pairs'] += 1
        if (lp.older, lp.newer) in by_pair:
            row['agree'] += 1
        elif lp.older in by_old:
            row['disagree'] += 1
            if len(row['listed']) < MAX_LISTED:
                row['listed'].append({'older': lp.older, 'newer': lp.newer, 'ladder': lp.provenance(),
                                      'oracle': [{'newer': o.newer, 'label': o.label, 'extra': o.extra}
                                                 for o in by_old[lp.older]]})
        else:
            row['absent'] += 1
    for row in steps.values():
        row['disagreements_truncated'] = max(0, row['disagree'] - len(row['listed']))
        row['disagreements'] = row.pop('listed')
    not_reproduced: dict[str, dict] = {}
    for p in oracle.pairs:
        if (p.older, p.newer) in ladder_pairs:
            continue
        group = not_reproduced.setdefault(p.label, {'count': 0, 'paired_differently': 0, 'unmatched': 0, 'listed': []})
        group['count'] += 1
        other = ladder_by_old.get(p.older)
        group['paired_differently' if other else 'unmatched'] += 1
        if len(group['listed']) < MAX_LISTED:
            group['listed'].append({'older': p.older, 'newer': p.newer, 'extra': p.extra,
                                    'ladder_newer': sorted({o.newer for o in other or ()})})
    for group in not_reproduced.values():
        group['listed_truncated'] = max(0, group['count'] - len(group['listed']))
        group['samples'] = group.pop('listed')
    return {'pairs': len(oracle.pairs), 'dropped': dict(sorted(oracle.dropped.items())),
            'steps': {k: steps[k] for k in sorted(steps)},
            'not_reproduced': {k: not_reproduced[k] for k in sorted(not_reproduced)},
            'not_reproduced_total': sum(g['count'] for g in not_reproduced.values())}


def build_report(ladder: Sequence[LadderPair], oracles: Sequence[Oracle] = (), *, md: dict | None = None,
                 meta: Mapping[str, str] | None = None) -> dict:
    report = {
        'contract': REPORT_CONTRACT,
        'ladder': {'pairs': len(ladder),
                   'by_step': dict(sorted(Counter(lp.step for lp in ladder).items())),
                   'by_tier': dict(sorted(Counter(lp.tier for lp in ladder).items()))},
        'oracles': {o.name: compare_oracle(ladder, o) for o in sorted(oracles, key=lambda o: o.name)},
        'md_index': md,
        'meta': dict(sorted((meta or {}).items())),
    }
    report['report_sha256'] = report_digest(report)
    return report


def canonical(report: Mapping) -> str:
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + '\n'


def report_digest(report: Mapping) -> str:
    body = {k: v for k, v in report.items() if k != 'report_sha256'}
    return hashlib.sha256(canonical(body).encode('utf-8')).hexdigest()


# ---- the BinDiff MD dump (dev-only argv, A-15) ---------------------------------------------------------------------------------

def md_dump_argv(executable: Path | str, binexport: Path | str) -> list[str]:
    """The ONLY place that builds a BinDiff argv with `--md_index` (A-15); product code never does."""
    return [str(executable), '--nologo', '--md_index', f'--primary={binexport}']


def run_md_dump(executable: Path, binexport: Path, *, cancel: threading.Event | None = None, timeout: float = 900.0,
                runner=None) -> dict:
    """Run `bindiff --md_index` on a COPY of the BinExport file in a private working directory and return
    {'stdout': text, 'exit': code, 'input_sha256': ...}. `runner` is injectable for tests (default: run_process)."""
    from patchtrace.jobs import run_process
    from patchtrace.secondary.bindiff_probe import build_env, make_private_dirs
    runner = runner or run_process
    exe = Path(executable)
    if not exe.is_absolute():
        raise ValueError('configure an absolute BinDiff executable path')
    workdir = Path(tempfile.mkdtemp(prefix='pt-md-'))
    try:
        make_private_dirs(workdir)
        (workdir / 'in').mkdir(exist_ok=True)
        copy = workdir / 'in' / 'primary.BinExport'
        shutil.copyfile(binexport, copy)
        digest = hashlib.sha256(copy.read_bytes()).hexdigest()
        result = runner(md_dump_argv(exe, copy), cwd=workdir, env=build_env(exe, workdir), cancel=cancel or threading.Event(),
                        timeout_seconds=timeout, log_limit=MAX_DUMP_BYTES, separate_streams=True,
                        stderr_limit=256 * 1024)
        return {'stdout': result.log_tail, 'exit': result.returncode, 'reason': getattr(result, 'reason', None),
                'input_sha256': digest}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---- CLI --------------------------------------------------------------------------------------------------------------------------

def _read_json(path: Path) -> dict:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError('JSON input is larger than 512 MiB')
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as handle:
        return json.load(handle)


def _read_rows(path: Path) -> list:
    if path.is_dir():
        from patchtrace.unified.store import read_manifest, read_rows
        manifest, _digest = read_manifest(path)
        return list(read_rows(path, manifest))
    opener = gzip.open if path.suffix == '.gz' else open
    rows = []
    with opener(path, 'rt', encoding='utf-8') as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _parse_int(text: str) -> int:
    return int(text, 0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    sub = parser.add_subparsers(dest='command', required=True)
    rep = sub.add_parser('report', help='compare ladder pairs with oracles and write parity-report.json')
    rep.add_argument('--rows', type=Path, required=True, help='unified result directory or rows .jsonl[.gz]')
    rep.add_argument('--ghidriff-raw', type=Path)
    rep.add_argument('--bindiff', type=Path, help='a .BinDiff database')
    rep.add_argument('--older-sha256')
    rep.add_argument('--newer-sha256')
    rep.add_argument('--older-image-base', type=_parse_int, default=0)
    rep.add_argument('--newer-image-base', type=_parse_int, default=0)
    rep.add_argument('--bindiff-basis', choices=('va', 'rva'), default='rva')
    rep.add_argument('--ir-older', type=Path, help='program-ir/1 ir.sqlite3 of the older side (MD comparison)')
    rep.add_argument('--md-dump', type=Path, help='text dump of `bindiff --md_index` for the older BinExport')
    rep.add_argument('--out', type=Path, required=True)
    dump = sub.add_parser('md-dump', help='run bindiff --md_index on a BinExport copy (dev only, live)')
    dump.add_argument('--bindiff-exe', type=Path, required=True)
    dump.add_argument('--binexport', type=Path, required=True)
    dump.add_argument('--out', type=Path, required=True)
    dump.add_argument('--timeout', type=float, default=900.0)
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == 'md-dump':
        result = run_md_dump(args.bindiff_exe, args.binexport, timeout=args.timeout)
        args.out.write_text(result['stdout'], encoding='utf-8', newline='\n')
        print(json.dumps({'exit': result['exit'], 'input_sha256': result['input_sha256'], 'bytes': len(result['stdout'])}))
        return 0 if result['exit'] == 0 else 1

    ladder = ladder_from_rows(_read_rows(args.rows))
    oracles = []
    if args.ghidriff_raw:
        oracles.append(read_ghidriff(_read_json(args.ghidriff_raw), args.older_image_base, args.newer_image_base))
    if args.bindiff:
        if not (args.older_sha256 and args.newer_sha256):
            parser.error('--bindiff needs --older-sha256 and --newer-sha256')
        base_o = args.older_image_base if args.bindiff_basis == 'va' else 0
        base_n = args.newer_image_base if args.bindiff_basis == 'va' else 0
        oracles.append(read_bindiff(bindiff_rows_from_file(args.bindiff, args.older_sha256, args.newer_sha256),
                                    base_o, base_n))
    md = None
    if args.ir_older and args.md_dump:
        dump_values, unparsed = parse_md_dump(args.md_dump.read_text(encoding='utf-8'))
        md = compare_md(read_ir_md(args.ir_older), dump_values,
                        image_base=args.older_image_base if args.bindiff_basis == 'va' else 0)
        md['dump_lines_unparsed'] = unparsed
    report = build_report(ladder, oracles, md=md, meta={'tool': 'tools/unified/parity.py'})
    args.out.write_text(canonical(report), encoding='utf-8', newline='\n')
    print(report['report_sha256'])
    return 0


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
    sys.exit(main())
