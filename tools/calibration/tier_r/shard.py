"""Deterministic sharding of Tier R work for GitHub Actions (SPEC-32 s13).

    python -m tools.calibration.tier_r.shard plan      --seed S --shards N [--subset smoke|suites|cards|mutations|noise|full]
    python -m tools.calibration.tier_r.shard run-shard --plan-json F --shard I --out DIR
    python -m tools.calibration.tier_r.shard merge     --in DIR --out DIR

Heavy runs (Ghidra, rizin, compiler farms) belong on runners, not in agent loops. `plan` lists cases (catalogue cards,
authored suites, mutation seed x operator, A/A and noise configs), orders them by SHA-256(seed:id) and deals them
round-robin, so a plan is a pure function of (seed, subset, repository files). `run-shard` runs one shard's cases through
`python -m tools.calibration.tier_r <cmd>` (SPEC-32 s12; each command is expected to print one JSON summary on stdout)
with a per-case timeout and writes `shard-<i>.json`: label metadata, feature tables and aggregate metrics only, never an
image, binary or function table. `merge` folds shard files into one `tier-r-report/1` document (+ provenance file and a
Markdown rendering) and fails loudly on missing, duplicate, foreign or inconsistent shards.

Only our own synthetic suites and permissively licensed pinned sources are accepted. Anything Microsoft-derived (Tier W
paths, Windows component names, Winbindex/msdl) is refused at plan time, before a command and before a write.
Exit codes: 0 ok, 1 case failures reported, 2 usage/contract error, 3 BLOCKED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from patchtrace.calibration.scope import TIER_R_CLAIM

from ..common import canonical_json, digest, r12
from .contracts import COSMETIC_OPERATORS, PERMISSIVE_SPDX, SEMANTIC_OPERATORS, ContractError, load_report

REPO_ROOT = Path(__file__).resolve().parents[3]
PLAN_CONTRACT = 'tier-r-plan/1'
SHARD_CONTRACT = 'tier-r-shard/1'
MERGE_CONTRACT = 'tier-r-merge/1'
SUBSETS = ('smoke', 'suites', 'cards', 'mutations', 'noise', 'full')
ENGINES = ('rz-diff', 'bindiff', 'ghidriff')
MAX_SHARDS = 256
DEFAULT_TIMEOUT = 900
MAX_SHARD_BYTES = 8 * 1024 * 1024
OK, FINDINGS, USAGE, BLOCKED = 0, 1, 2, 3
SMOKE_SUITE = '_template/tiny'
# Result keys that could carry code or per-function tables never leave a shard.
DROP_KEYS = frozenset({'functions', 'image', 'images', 'binary', 'binaries', 'bytes', 'content', 'base64', 'blob',
                       'pe', 'pdb'})
MS_PATTERN = re.compile(r'microsoft|tier[-_]w|(^|[^a-z0-9])tw\.|ntoskrnl|ntkrnl|winbindex|msdl\.|system32|winsxs'
                        r'|\.msu\b|\.cab\b', re.IGNORECASE)
ENV_KEEP = ('PATH', 'HOME', 'LC_ALL', 'TZ', 'SYSTEMROOT', 'TEMP', 'TMP', 'RZ_DIFF', 'GHIDRA_INSTALL_DIR', 'JAVA_HOME',
            'SOURCE_DATE_EPOCH')
STATUS_ORDER = {'ok': 0, 'skipped': 0, 'findings': 1, 'blocked': 2, 'timeout': 3, 'failed': 4}


class ShardError(Exception):
    """Contract-level failure (exit 2): bad plan, refused input, missing/duplicate/inconsistent shards."""


# ---- Microsoft refusal ---------------------------------------------------------------------------------------------

def _family_names() -> frozenset[str]:
    try:
        from ..tier_w.catalogue import FAMILIES
    except Exception:  # noqa: BLE001 - the list is a convenience on top of the pattern
        return frozenset()
    return frozenset(FAMILIES)


def refuse_microsoft(*texts: str) -> None:
    """Raise ShardError when any text names Microsoft-derived or Tier W material."""
    families = _family_names()
    for text in texts:
        if MS_PATTERN.search(text):
            raise ShardError(f'refused: {text!r} looks Microsoft-derived or Tier W (local-only, decision O1)')
        for part in re.split(r'[\\/\s=:]+', text.lower()):
            if part in families:
                raise ShardError(f'refused: {text!r} names the Windows component {part} (Tier W is local-only)')


# ---- case enumeration ----------------------------------------------------------------------------------------------

def _load_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def _cards(root: Path) -> list[str]:
    """Ids of buildable case cards: recipe exists for the project and the licence is permissive."""
    try:
        recipes = {r['project'] for r in _load_json(root / 'tools/calibration/tier_r/catalogue/recipes.json')['recipes']}
    except (OSError, ValueError, KeyError, TypeError):
        recipes = set()
    files = sorted((root / 'tools/calibration/tier_r/catalogue').glob('*.json')) + sorted(
        (root / 'corpus/catalog').glob('*.json'))
    found = set()
    for path in files:
        if path.name == 'recipes.json':
            continue
        try:
            data = _load_json(path)
        except (OSError, ValueError):
            continue
        for card in data if isinstance(data, list) else ():
            if (isinstance(card, dict) and card.get('contract') == 'case-card/1' and card.get('project') in recipes
                    and card.get('license_spdx') in PERMISSIVE_SPDX and isinstance(card.get('id'), str)):
                found.add(card['id'])
    return sorted(found)


def _suites(root: Path) -> list[str]:
    return sorted(p.parent.relative_to(root / 'corpus/ours').as_posix()
                  for p in (root / 'corpus/ours').glob('*/*/suite.json'))


def mutation_seeds(seed: int, count: int) -> list[int]:
    return [seed * 1000 + k for k in range(count)]


def enumerate_cases(root: Path, *, subset: str, seed: int, seeds_per_op: int = 1) -> list[str]:
    """Case ids (sorted, unique). Id grammar: card:ID | suite:G/N | mutate:G/N:OP:SEED | aa:G/N | noise:G/N."""
    if subset not in SUBSETS:
        raise ShardError(f'unknown subset {subset!r}; choose from {", ".join(SUBSETS)}')
    suites, cards = _suites(root), _cards(root)
    ops = (*SEMANTIC_OPERATORS, *COSMETIC_OPERATORS)
    cases: set[str] = set()
    if subset == 'smoke':
        if SMOKE_SUITE in suites:
            cases |= {f'suite:{SMOKE_SUITE}', f'aa:{SMOKE_SUITE}', f'noise:{SMOKE_SUITE}',
                      f'mutate:{SMOKE_SUITE}:cmp-flip:{mutation_seeds(seed, 1)[0]}'}
        cases |= {f'card:{c}' for c in cards if c.startswith('zlib-')}
    if subset in ('suites', 'full'):
        cases |= {f'suite:{s}' for s in suites} | {f'aa:{s}' for s in suites}
    if subset in ('cards', 'full'):
        cases |= {f'card:{c}' for c in cards}
    if subset in ('mutations', 'full'):
        cases |= {f'mutate:{s}:{op}:{n}' for s in suites for op in ops for n in mutation_seeds(seed, seeds_per_op)}
    if subset in ('noise', 'full'):
        cases |= {f'noise:{s}' for s in suites}
    for case in cases:
        refuse_microsoft(case)
    return sorted(cases)


_CASE = re.compile(r'^(card|suite|aa|noise):([A-Za-z0-9._/-]{1,128})$|^(mutate):([A-Za-z0-9._/-]{1,128}):([a-z0-9-]{1,32}):(\d{1,12})$')


def case_steps(case_id: str) -> list[list[str]]:
    """Subcommand argv (after `python -m tools.calibration.tier_r`) for one case id."""
    refuse_microsoft(case_id)
    m = _CASE.match(case_id)
    if not m or '..' in case_id.replace(':', '/').split('/'):
        raise ShardError(f'malformed case id {case_id!r}')
    if m.group(3) == 'mutate':
        if m.group(5) not in (*SEMANTIC_OPERATORS, *COSMETIC_OPERATORS):
            raise ShardError(f'unknown mutation operator in {case_id!r}')
        return [['mutate', '--suite', f'corpus/ours/{m.group(4)}', '--operator', m.group(5), '--seed', m.group(6)]]
    kind, name = m.group(1), m.group(2)
    if kind == 'card':
        return [['fetch', name], ['build-card', name]]
    if kind == 'suite':
        return [['build-suite', f'corpus/ours/{name}']]
    return [[kind, '--suite', f'corpus/ours/{name}']]


# ---- plan ----------------------------------------------------------------------------------------------------------

def _rank(seed: int, case_id: str) -> str:
    return hashlib.sha256(f'{seed}:{case_id}'.encode()).hexdigest()


def split(cases: Sequence[str], shards: int, seed: int) -> list[list[str]]:
    """Deal `cases` into at most `shards` shards: order by SHA-256(seed:id), round-robin, each shard sorted."""
    if not 1 <= shards <= MAX_SHARDS:
        raise ShardError(f'shards must be 1..{MAX_SHARDS}')
    if len(set(cases)) != len(cases):
        raise ShardError('duplicate case id in work list')
    if not cases:
        raise ShardError('empty work list (no cases for this subset)')
    n = min(shards, len(cases))
    ordered = sorted(cases, key=lambda c: (_rank(seed, c), c))
    return [sorted(ordered[i::n]) for i in range(n)]


def parse_engines(value: str) -> list[str]:
    engines = sorted({e.strip() for e in value.split(',') if e.strip()})
    bad = [e for e in engines if e not in ENGINES]
    if bad or not engines:
        raise ShardError(f'engines must be a comma list of {", ".join(ENGINES)}; got {value!r}')
    return engines


def make_plan(root: Path, *, seed: int, shards: int, engines: str = 'rz-diff', subset: str = 'smoke',
              seeds_per_op: int = 1) -> dict:
    cases = enumerate_cases(root, subset=subset, seed=seed, seeds_per_op=seeds_per_op)
    parts = split(cases, shards, seed)
    plan = {'contract': PLAN_CONTRACT, 'seed': seed, 'subset': subset, 'engines': parse_engines(engines),
            'of': len(parts), 'cases_total': len(cases), 'shards': [{'shard': i, 'cases': c} for i, c in enumerate(parts)]}
    plan['plan_sha256'] = digest(plan, 'plan_sha256')
    return plan


def matrix(plan: dict) -> dict:
    """GitHub Actions matrix: {"include":[{"shard":i,"of":N,"cases":[...]}]} (+ plan digest, seed, engines)."""
    return {'include': [{'shard': s['shard'], 'of': plan['of'], 'cases': s['cases'], 'seed': plan['seed'],
                         'plan': plan['plan_sha256'], 'engines': ','.join(plan['engines'])} for s in plan['shards']]}


# ---- run-shard -----------------------------------------------------------------------------------------------------

# A runner returns (returncode, stdout, reason) or (returncode, stdout, reason, stderr); stderr is optional.
Runner = Callable[[list[str], int, dict[str, str]], tuple]
STDERR_LINES = 20
STDERR_CHARS = 4000
REASON_CHARS = 240


def default_runner(argv: list[str], timeout: int, env: dict[str, str]) -> tuple[int | None, str, str | None, str]:
    """(returncode, stdout, reason, stderr). `shell=False`, bounded timeout; returncode None on timeout."""
    try:
        done = subprocess.run(argv, cwd=REPO_ROOT, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return None, '', f'timeout after {timeout}s', (exc.stderr or b'')[-STDERR_CHARS * 4:].decode('utf-8', 'replace')
    except OSError as exc:
        return 127, '', f'cannot start: {exc.strerror or exc}', ''
    return (done.returncode, done.stdout[-4_000_000:].decode('utf-8', 'replace'), None,
            done.stderr[-STDERR_CHARS * 4:].decode('utf-8', 'replace'))


def _call(runner: Runner, argv: list[str], timeout: int, env: dict[str, str]) -> tuple[int | None, str, str | None, str]:
    result = runner(argv, timeout, env)
    rc, out, reason = result[:3]
    return rc, out, reason, (result[3] if len(result) > 3 else '')


def stderr_tail(text: str, lines: int = STDERR_LINES, chars: int = STDERR_CHARS) -> str:
    """The last `lines` non-empty stderr lines, at most `chars` characters (the tail is kept)."""
    kept = [ln.rstrip() for ln in (text or '').splitlines() if ln.strip()][-lines:]
    return '\n'.join(kept)[-chars:]


def failure_reason(rc: int | None, reason: str | None, summary: dict | None, stderr: str) -> str:
    """One-line, bounded reason for a failed or BLOCKED step: runner reason, the command's own error, or stderr."""
    if reason:
        text = reason
    else:
        text = ''
        for key in ('error', 'reason'):
            if summary and isinstance(summary.get(key), str) and summary[key].strip():
                text = summary[key]
                break
        if not text and summary and isinstance(summary.get('blocked'), dict) and summary['blocked']:
            text = '; '.join(f'{k}: {v}' for k, v in sorted(summary['blocked'].items()))
        if not text and summary and summary.get('errors'):
            text = '; '.join(str(e) for e in summary['errors'][:3])
        if not text:
            tail = stderr_tail(stderr, 1)
            text = tail or 'no diagnostic output'
        text = f'exit {rc}: {text}'
    return ' '.join(text.split())[:REASON_CHARS]


def _env(scratch: Path) -> dict[str, str]:
    env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    env.update({'PATCHTRACE_CALIB_ROOT': str(scratch), 'LC_ALL': 'C', 'TZ': 'UTC',
                'PYTHONPATH': str(REPO_ROOT / 'src'), 'PYTHONHASHSEED': '0'})
    return env


def _summary(stdout: str) -> dict | None:
    """The command's JSON summary: the whole output, else the last one-line object, else the last block that starts
    with `{` in column 0 (the CLI pretty-prints) and runs to the end."""
    text = stdout.strip()
    candidates = [text]
    lines = text.splitlines()
    candidates += [ln for ln in reversed(lines) if ln.lstrip().startswith('{')][:1]
    candidates += ['\n'.join(lines[i:]) for i in range(len(lines) - 1, -1, -1) if lines[i].startswith('{')][:1]
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _scratch_json(scratch: Path, value) -> dict | None:
    """A JSON file named by a command summary, read only when it lies inside this shard's scratch store."""
    try:
        path = Path(value).resolve()
        path.relative_to(scratch.resolve())
        if path.suffix != '.json' or path.stat().st_size > MAX_SHARD_BYTES:
            return None
        doc = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return None
    return doc if isinstance(doc, dict) else None


def _scratch_labels(scratch: Path) -> list[dict]:
    """Label metadata (no function tables) of every pair built in this shard's scratch store."""
    out = []
    for path in sorted((scratch / 'known-answer' / 'labels').glob('*.json')):
        doc = _scratch_json(scratch, path)
        if doc and doc.get('contract') == 'known-answer-labels/1':
            out.append(_label_meta(doc))
    return out


def sanitize(value, depth: int = 0):
    """Aggregate-only view of a result: scalars, short strings, bounded nesting; code/table keys dropped."""
    if depth > 8:
        raise ShardError('result nesting too deep')
    if isinstance(value, dict):
        return {str(k): sanitize(v, depth + 1) for k, v in sorted(value.items()) if str(k).lower() not in DROP_KEYS}
    if isinstance(value, list):
        if len(value) > 5000:
            raise ShardError('result list too long for an aggregate-only shard file')
        return [sanitize(v, depth + 1) for v in value]
    if isinstance(value, str):
        if len(value) > 2000:
            raise ShardError('result string too long for an aggregate-only shard file')
        return value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and value == value and abs(value) != float('inf'):
        return value
    raise ShardError('non-JSON-safe value in result')


def _label_meta(doc: dict) -> dict:
    keys = ('pair_id', 'stratum', 'method', 'project', 'lineage', 'family', 'summary', 'digest_sha256')
    return {k: doc[k] for k in keys if k in doc}


def _absorb(summary: dict, labels: list, features: list, reports: list) -> None:
    """Pull labels metadata, feature tables and tier-r-report documents out of one case summary."""
    if summary.get('contract') == 'known-answer-labels/1':
        labels.append(_label_meta(summary))
    if summary.get('contract') == 'tier-r-report/1':
        reports.append(summary)
    for key, sink in (('labels', labels), ('features', features), ('reports', reports)):
        for item in summary.get(key) or ():
            if isinstance(item, dict):
                sink.append(_label_meta(item) if sink is labels and item.get('contract') else item)
    if isinstance(summary.get('report'), dict):
        reports.append(summary['report'])


def _classify(rc: int | None, reason: str | None, summary: dict | None = None) -> str:
    if rc is None:
        return 'timeout'
    status = {0: 'ok', 1: 'findings', 3: 'blocked'}.get(rc, 'failed')
    if status == 'ok' and summary and summary.get('status') == 'skipped':
        return 'skipped'
    return status


def _report_problem(case_id: str, status: str, detail: str | None, stderr: str, log) -> None:
    """Print one reason line and a bounded stderr tail to the job log (never into the shard JSON)."""
    label = 'BLOCKED' if status == 'blocked' else status.upper()
    log(f'[{label}] {case_id}: {detail}')
    tail = stderr_tail(stderr)
    if tail:
        log('  stderr (last lines):\n' + '\n'.join('    ' + ln for ln in tail.splitlines()))


def run_shard(plan: dict, shard: int, *, timeout: int = DEFAULT_TIMEOUT, runner: Runner | None = None,
              python: str | None = None, scratch: Path | None = None, engines: Sequence[str] | None = None,
              verify_plan: bool = True, log: Callable[[str], None] | None = None) -> dict:
    runner = runner or default_runner       # looked up at call time so tests and callers can substitute it
    log = log or (lambda text: print(text, file=sys.stderr, flush=True))
    entry = next((s for s in plan['shards'] if s['shard'] == shard), None)
    if entry is None:
        raise ShardError(f'plan has no shard {shard}')
    if verify_plan and digest(plan, 'plan_sha256') != plan.get('plan_sha256'):
        raise ShardError('plan digest mismatch')
    py = python or sys.executable
    engines = list(engines or plan['engines'])
    with tempfile.TemporaryDirectory(prefix=f'tier-r-shard{shard}-') as tmp:
        scope = Path(scratch or tmp)
        env = _env(scope)
        labels: list = []
        features: list = []
        reports: list = []
        results = []
        for case_id in entry['cases']:
            status, detail, summary = 'ok', None, None
            for step in case_steps(case_id):
                rc, out, reason, err = _call(runner, [py, '-m', 'tools.calibration.tier_r', *step], timeout, env)
                parsed = _summary(out)
                status = _classify(rc, reason, parsed)
                detail = None
                if parsed is not None:
                    summary = sanitize(parsed)
                    refuse_microsoft(canonical_json(summary).decode())
                    _absorb(summary, labels, features, reports)
                if status == 'skipped':
                    detail = ' '.join(str(parsed.get('reason') or 'skipped').split())[:REASON_CHARS]
                    log(f'[SKIPPED] {case_id}: {detail}')
                elif status in ('timeout', 'failed', 'blocked'):
                    detail = failure_reason(rc, reason, parsed, err)
                    _report_problem(case_id, status, detail, err, log)
                elif rc:
                    detail = f'exit {rc}'
                if status in ('timeout', 'failed', 'blocked'):
                    break
            results.append({'id': case_id, 'status': status, 'reason': detail,
                            'digest': hashlib.sha256(canonical_json(summary)).hexdigest() if summary else None})
        for meta in _scratch_labels(scope):
            if meta not in labels:
                labels.append(meta)
        if not (os.environ.get('PATCHTRACE_TIER_R_NO_EVAL')):
            for engine in engines:
                rc, out, reason, err = _call(runner, [py, '-m', 'tools.calibration.tier_r', 'evaluate', '--engines',
                                                      engine, '--symbols', 'hidden'], timeout, env)
                parsed = _summary(out)
                if parsed is not None:
                    report_doc = _scratch_json(scope, parsed.get('report')) if isinstance(parsed.get('report'), str) else None
                    parsed = sanitize(parsed)
                    if report_doc is not None:
                        parsed['report'] = sanitize(report_doc)
                    refuse_microsoft(canonical_json(parsed).decode())
                    _absorb(parsed, labels, features, reports)
                status = _classify(rc, reason, parsed)
                detail = reason or (f'exit {rc}' if rc else None)
                if status in ('timeout', 'failed', 'blocked'):
                    detail = failure_reason(rc, reason, parsed, err)
                    _report_problem(f'evaluate:{engine}', status, detail, err, log)
                results.append({'id': f'evaluate:{engine}', 'status': status, 'reason': detail, 'digest': None})
    doc = {'contract': SHARD_CONTRACT, 'shard': shard, 'of': plan['of'], 'seed': plan['seed'],
           'plan_sha256': plan['plan_sha256'], 'subset': plan['subset'], 'engines': engines,
           'cases': results, 'labels': sorted(labels, key=canonical_json), 'features': sorted(features, key=canonical_json),
           'reports': reports}
    refuse_microsoft(canonical_json(doc).decode())
    doc['shard_sha256'] = digest(doc, 'shard_sha256')
    return doc


def write_shard(doc: dict, out: Path) -> Path:
    out = Path(out)
    if 'tier-w' in out.resolve().parts:
        raise ShardError('refused: output inside a tier-w directory')
    out.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(doc, sort_keys=True, indent=1, allow_nan=False) + '\n').encode()
    if len(data) > MAX_SHARD_BYTES:
        raise ShardError(f'shard file would be {len(data)} bytes (cap {MAX_SHARD_BYTES}); it must be aggregate-only')
    path = out / f'shard-{doc["shard"]}.json'
    path.write_bytes(data)
    return path


# ---- merge ---------------------------------------------------------------------------------------------------------

COUNTS = ('pairs', 'truth_same', 'identity_tp', 'identity_fp', 'identity_fn', 'changed_truth', 'changed_tp',
          'changed_fp', 'changed_fn', 'matched_negatives', 'cosmetic_matched', 'cosmetic_flagged',
          'ignored_predictions', 'ambiguous_records')


def _ratio(num: int, den: int) -> float | None:
    return r12(num / den) if den else None


def combine_metrics(items: Iterable[dict]) -> dict:
    """Sum counts, then recompute ratios; fp_rate is rebuilt from per-shard flagged = round(rate x negatives)."""
    items = list(items)
    total = {k: sum(int(m[k]) for m in items) for k in COUNTS}
    flagged = sum(round((m['fp_rate'] or 0.0) * m['matched_negatives']) for m in items)
    total.update(
        identity_precision=_ratio(total['identity_tp'], total['identity_tp'] + total['identity_fp']),
        identity_recall=_ratio(total['identity_tp'], total['identity_tp'] + total['identity_fn']),
        changed_precision=_ratio(total['changed_tp'], total['changed_tp'] + total['changed_fp']),
        changed_recall=_ratio(total['changed_tp'], total['changed_tp'] + total['changed_fn']),
        fp_rate=_ratio(flagged, total['matched_negatives']))
    return total


def _engine_status(rows: list[dict]) -> dict:
    states = {r['status'] for r in rows}
    versions = {r['version'] for r in rows if r.get('version')}
    if len(versions) > 1:
        raise ShardError(f'engine {rows[0]["engine"]} ran with different versions: {sorted(versions)}')
    status = (next(iter(states)) if len(states) == 1 else 'partial')
    if sum(r['failures'] for r in rows) and status == 'ok':
        status = 'partial'
    reason = '; '.join(sorted({r['reason'] for r in rows if r.get('reason')}))[:500] or None
    return {'engine': rows[0]['engine'], 'status': status, 'version': next(iter(versions), None), 'reason': reason,
            'runs': sum(r['runs'] for r in rows), 'failures': sum(r['failures'] for r in rows)}


def load_shards(directory: Path, *, plan: dict | None = None) -> list[dict]:
    """Read shard-*.json; fail loudly on missing, duplicate, foreign or tampered shard files."""
    docs = []
    for path in sorted(Path(directory).glob('shard-*.json')):
        try:
            doc = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise ShardError(f'{path.name}: unreadable ({exc})') from None
        if not isinstance(doc, dict) or doc.get('contract') != SHARD_CONTRACT:
            raise ShardError(f'{path.name}: not a {SHARD_CONTRACT} document')
        if digest(doc, 'shard_sha256') != doc.get('shard_sha256'):
            raise ShardError(f'{path.name}: shard digest mismatch')
        if path.name != f'shard-{doc["shard"]}.json':
            raise ShardError(f'{path.name}: file name does not match shard index {doc["shard"]}')
        docs.append(doc)
    if not docs:
        raise ShardError(f'no shard-*.json files in {directory}')
    seen: dict[int, int] = {}
    for doc in docs:
        seen[doc['shard']] = seen.get(doc['shard'], 0) + 1
    dup = sorted(i for i, n in seen.items() if n > 1)
    if dup:
        raise ShardError(f'duplicate shards: {dup}')
    heads = {(d['of'], d['seed'], d['plan_sha256'], d['subset']) for d in docs}
    if len(heads) != 1:
        raise ShardError('shards come from different plans (of/seed/plan/subset differ)')
    of = docs[0]['of']
    missing = sorted(set(range(of)) - set(seen))
    extra = sorted(set(seen) - set(range(of)))
    if missing or extra:
        raise ShardError(f'shard set incomplete or foreign: missing={missing} unexpected={extra} (of {of})')
    if plan is not None:
        if plan['plan_sha256'] != docs[0]['plan_sha256']:
            raise ShardError('shards do not belong to the given plan')
        for doc in docs:
            want = next(s['cases'] for s in plan['shards'] if s['shard'] == doc['shard'])
            got = sorted(c['id'] for c in doc['cases'] if not c['id'].startswith('evaluate:'))
            if got != want:
                raise ShardError(f'shard {doc["shard"]} did not run exactly its planned cases')
    return sorted(docs, key=lambda d: d['shard'])


def merge(docs: list[dict]) -> tuple[dict, dict]:
    """(tier-r-report/1 aggregate, tier-r-merge/1 provenance). Both carry deterministic digests."""
    reports = [r for d in docs for r in d['reports']]
    inputs: dict[str, dict] = {}
    pairs: dict[tuple[str, str], dict] = {}
    engine_rows: dict[str, list] = {}
    strata: dict[str, dict[str, list]] = {}
    wrong: list[dict] = []
    truncated = 0
    symbols = {r.get('symbols', 'hidden') for r in reports}
    if len(symbols) > 1:
        raise ShardError('shards mix symbols hidden and visible; merge them separately')
    for report in reports:
        try:
            load_report(json.dumps(report).encode())
        except ContractError as exc:
            raise ShardError(f'shard contains an invalid tier-r-report/1: {exc}') from None
        for ref in report['inputs']:
            prior = inputs.setdefault(ref['pair_id'], ref)
            if prior != ref:
                raise ShardError(f'pair {ref["pair_id"]} has conflicting label digests across shards')
        for row in report['pairs']:
            key = (row['pair_id'], row['engine'])
            if key in pairs:
                raise ShardError(f'pair {key[0]} / {key[1]} evaluated in more than one shard')
            pairs[key] = row
        for row in report['engines']:
            engine_rows.setdefault(row['engine'], []).append(row)
        for stratum, per_engine in report['strata'].items():
            for engine, metrics in per_engine.items():
                strata.setdefault(stratum, {}).setdefault(engine, []).append(metrics)
        wrong += report['wrong_matches']
        truncated += report['wrong_matches_truncated']
    requested = sorted({e for d in docs for e in d['engines']})
    for engine in requested:
        engine_rows.setdefault(engine, [{'engine': engine, 'status': 'blocked', 'version': None, 'runs': 0,
                                         'failures': 0, 'reason': 'no evaluation result from any shard'}])
    wrong.sort(key=lambda w: (w['pair_id'], w['engine'], w['old_rva'] is None, w['old_rva'] or 0,
                              w['new_rva'] or 0, w['kind']))
    kept = wrong[:5000]
    failing = sorted(c['id'] for d in docs for c in d['cases'] if c['status'] not in ('ok', 'findings', 'skipped'))
    notes = [f'merged {len(docs)} shard(s), seed {docs[0]["seed"]}, subset {docs[0]["subset"]}, '
             f'plan {docs[0]["plan_sha256"][:12]}']
    if failing:
        notes.append(f'{len(failing)} case(s) failed, timed out or were blocked; see the merge provenance file')
    report = {'contract': 'tier-r-report/1', 'symbols': next(iter(symbols), 'hidden'),
              'inputs': sorted(inputs.values(), key=lambda r: r['pair_id']),
              'engines': [_engine_status(engine_rows[e]) for e in sorted(engine_rows)],
              'strata': {s: {e: combine_metrics(m) for e, m in sorted(per.items())} for s, per in sorted(strata.items())},
              'pairs': [pairs[k] for k in sorted(pairs)], 'wrong_matches': kept,
              'wrong_matches_truncated': truncated + len(wrong) - len(kept), 'notes': notes}
    report['report_sha256'] = digest(report, 'report_sha256')
    try:
        load_report(json.dumps(report).encode())
    except ContractError as exc:
        raise ShardError(f'merged aggregate violates tier-r-report/1: {exc}') from None
    prov = {'contract': MERGE_CONTRACT, 'plan_sha256': docs[0]['plan_sha256'], 'seed': docs[0]['seed'],
            'subset': docs[0]['subset'], 'shards': [{'shard': d['shard'], 'shard_sha256': d['shard_sha256'],
                                                      'cases': len(d['cases'])} for d in docs],
            'cases': sorted(({'id': c['id'], 'status': c['status'], 'reason': c['reason']}
                             for d in docs for c in d['cases']), key=lambda c: c['id']),
            'failing_cases': failing, 'labels': sorted((x for d in docs for x in d['labels']), key=canonical_json),
            'features': sorted((x for d in docs for x in d['features']), key=canonical_json),
            'report_sha256': report['report_sha256']}
    prov['merge_sha256'] = digest(prov, 'merge_sha256')
    return report, prov


def _fmt(value) -> str:
    return '-' if value is None else (f'{value:.4f}' if isinstance(value, float) else str(value))


def render_markdown(report: dict, prov: dict) -> str:
    lines = ['# Tier R aggregate report', '', f'> {TIER_R_CLAIM}', '',
             f'- report_sha256: `{report["report_sha256"]}`', f'- symbols: {report["symbols"]}',
             f'- plan: `{prov["plan_sha256"]}`, seed {prov["seed"]}, subset {prov["subset"]}, {len(prov["shards"])} shard(s)',
             f'- failing cases: {len(prov["failing_cases"])}', '', '## Engines', '',
             '| engine | status | version | runs | failures | reason |', '|---|---|---|---|---|---|']
    lines += [f'| {e["engine"]} | {e["status"]} | {_fmt(e["version"])} | {e["runs"]} | {e["failures"]} | '
              f'{(e["reason"] or "-").replace("|", "/")} |' for e in report['engines']]
    lines += ['', '## Strata', '', '| stratum | engine | pairs | id precision | id recall | changed P | changed R | fp rate |',
              '|---|---|---|---|---|---|---|---|']
    for stratum, per in report['strata'].items():
        for engine, m in per.items():
            lines.append(f'| {stratum} | {engine} | {m["pairs"]} | {_fmt(m["identity_precision"])} | '
                         f'{_fmt(m["identity_recall"])} | {_fmt(m["changed_precision"])} | '
                         f'{_fmt(m["changed_recall"])} | {_fmt(m["fp_rate"])} |')
    if prov['failing_cases']:
        lines += ['', '## Failing cases', ''] + [f'- `{c}`' for c in prov['failing_cases']]
    lines += ['', 'Aggregate metrics only. No images, binaries or function tables are included.', '']
    return '\n'.join(lines)


def write_merge(report: dict, prov: dict, out: Path) -> list[Path]:
    out = Path(out)
    if 'tier-w' in out.resolve().parts:
        raise ShardError('refused: output inside a tier-w directory')
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, data in (('tier-r-aggregate.json', report), ('tier-r-merge.json', prov)):
        path = out / name
        path.write_bytes((json.dumps(data, sort_keys=True, indent=1, allow_nan=False) + '\n').encode())
        paths.append(path)
    md = out / 'tier-r-report.md'
    md.write_text(render_markdown(report, prov), encoding='utf-8')
    return paths + [md]


# ---- CLI -----------------------------------------------------------------------------------------------------------

def _github_output(values: dict[str, str]) -> None:
    target = os.environ.get('GITHUB_OUTPUT')
    if target:
        with open(target, 'a', encoding='utf-8') as handle:
            for k, v in values.items():
                handle.write(f'{k}={v}\n')


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog='tier_r.shard', description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('plan', help='emit the GitHub Actions matrix JSON')
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--shards', type=int, default=4)
    p.add_argument('--engines', default='rz-diff')
    p.add_argument('--subset', default='smoke', choices=SUBSETS)
    p.add_argument('--seeds-per-operator', type=int, default=1)
    p.add_argument('--root', type=Path, default=REPO_ROOT)
    p.add_argument('--plan-out', type=Path, help='also write the full plan document here')
    r = sub.add_parser('run-shard', help='run one shard and write shard-<i>.json')
    r.add_argument('--plan', type=Path, help='plan document from `plan --plan-out`')
    r.add_argument('--shard', type=int, required=True)
    r.add_argument('--of', type=int)
    r.add_argument('--seed', type=int)
    r.add_argument('--plan-sha256')
    r.add_argument('--cases', help='JSON list of case ids (the matrix entry)')
    r.add_argument('--engines', default='rz-diff')
    r.add_argument('--subset', default='smoke')
    r.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='seconds per case')
    r.add_argument('--out', type=Path, required=True)
    m = sub.add_parser('merge', help='fold shard files into one tier-r-report/1')
    m.add_argument('--in', dest='src', type=Path, required=True)
    m.add_argument('--plan', type=Path)
    m.add_argument('--out', type=Path, required=True)
    return ap


def _plan_from_args(args) -> dict:
    if args.plan:
        return json.loads(args.plan.read_text(encoding='utf-8'))
    if args.cases is None or args.of is None or args.seed is None or not args.plan_sha256:
        raise ShardError('run-shard needs --plan, or --cases with --of --seed --plan-sha256')
    cases = json.loads(args.cases)
    if not isinstance(cases, list) or not all(isinstance(c, str) for c in cases):
        raise ShardError('--cases must be a JSON list of strings')
    shards = [{'shard': i, 'cases': cases if i == args.shard else []} for i in range(args.of)]
    plan = {'contract': PLAN_CONTRACT, 'seed': args.seed, 'subset': args.subset, 'engines': parse_engines(args.engines),
            'of': args.of, 'cases_total': len(cases), 'shards': shards, 'plan_sha256': args.plan_sha256}
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == 'plan':
            plan = make_plan(args.root, seed=args.seed, shards=args.shards, engines=args.engines, subset=args.subset,
                             seeds_per_op=args.seeds_per_operator)
            body = json.dumps(matrix(plan), sort_keys=True, separators=(',', ':'))
            if args.plan_out:
                args.plan_out.write_text(json.dumps(plan, sort_keys=True, indent=1) + '\n', encoding='utf-8')
            _github_output({'matrix': body, 'plan_sha256': plan['plan_sha256'], 'shards': str(plan['of'])})
            print(body)
            return OK
        if args.cmd == 'run-shard':
            plan = _plan_from_args(args)
            doc = run_shard(plan, args.shard, timeout=args.timeout, verify_plan=args.plan is not None)
            path = write_shard(doc, args.out)
            bad = [c['id'] for c in doc['cases'] if c['status'] in ('failed', 'timeout')]
            blocked = [c['id'] for c in doc['cases'] if c['status'] == 'blocked']
            print(json.dumps({'shard': doc['shard'], 'file': path.name, 'cases': len(doc['cases']),
                              'failed': bad, 'blocked': blocked, 'shard_sha256': doc['shard_sha256']}, sort_keys=True))
            return FINDINGS if bad else (BLOCKED if blocked else OK)
        plan = json.loads(args.plan.read_text(encoding='utf-8')) if args.plan else None
        report, prov = merge(load_shards(args.src, plan=plan))
        write_merge(report, prov, args.out)
        print(json.dumps({'report_sha256': report['report_sha256'], 'merge_sha256': prov['merge_sha256'],
                          'shards': len(prov['shards']), 'failing_cases': len(prov['failing_cases'])}, sort_keys=True))
        return FINDINGS if prov['failing_cases'] else OK
    except (ShardError, ValueError, OSError) as exc:
        print(f'tier_r.shard: {exc}', file=sys.stderr)
        return USAGE


if __name__ == '__main__':
    raise SystemExit(main())
