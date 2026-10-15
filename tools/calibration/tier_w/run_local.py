"""One-command Tier W run for the OWNER's machine (SPEC-33; runbook docs/runbooks/tier-w-local-run.md).

    PATCHTRACE_CALIB_ROOT=D:\\ptcal PYTHONPATH=src python -m tools.calibration.tier_w.run_local \\
        --corpus-id tier-w-2026q4 --python <venv python> --ghidra-dir <Ghidra> --consent-hosts winbindex.m417z.com,msdl.microsoft.com

Chains the SPEC-33 s11 subcommands (`python -m tools.calibration.tier_w <stage>`): catalogue, resolve, pairs, fetch,
symbols, labels, run, evaluate, status, then the repository guard. Decision O1 (local-only) is enforced here:
- refuses to run on CI (CI / GITHUB_ACTIONS set) and when PATCHTRACE_CALIB_ROOT is unset, inside the work tree or under
  a dotted/too-long path;
- network stages (catalogue, resolve, fetch) run only when `--consent-hosts` names exactly the allowed hosts;
- full stage output goes to log files under `<root>/tier-w/run-local/`; the terminal receives AGGREGATE numbers only
  (counts, precision/recall, statuses), never file names, pair ids, hashes, paths, function names or lineages;
- nothing is uploaded, copied into the repository or written outside the root; the guard stage proves the work tree
  is still free of Tier-W data.
Exit codes follow tier_w: 0 ok, 1 partial, 2 configuration/consent, 3 BLOCKED, 5 cancelled.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from .. import corpus
from .paths import (
    BLOCKED,
    CANCELLED,
    CONFIG,
    OK,
    PARTIAL,
    REPO_ROOT,
    Layout,
    TierWError,
    check_corpus_id,
    check_root,
    tool_safe_path,
    write_json,
)

ALLOWED_HOSTS = frozenset({'winbindex.m417z.com', 'msdl.microsoft.com'})
# stage -> (needs network consent, passes backend options)
STAGES: dict[str, tuple[bool, bool]] = {
    'catalogue': (True, False), 'resolve': (True, False), 'pairs': (False, False), 'fetch': (True, False),
    'symbols': (False, False), 'labels': (False, False), 'run': (False, True), 'evaluate': (False, False),
    'status': (False, False)}
STAGE_ORDER = tuple(STAGES)
CI_VARS = ('CI', 'GITHUB_ACTIONS', 'TF_BUILD', 'JENKINS_URL', 'GITLAB_CI')
# Output filtering: only these string values may reach the terminal, only numeric/bool leaves otherwise.
SAFE_STRINGS = frozenset({'ok', 'partial', 'blocked', 'failed', 'skipped', 'cancelled', 'symbols-hidden',
                          'symbols-visible', 'n/a', 'insufficient-labels', 'circular', 'rz-diff', 'ghidriff',
                          'bindiff', 'W'})
UNSAFE_KEY_TOKENS = frozenset({'path', 'file', 'name', 'sha', 'sha256', 'hash', 'kb', 'pair', 'lineage', 'id', 'ids',
                               'tag', 'tags', 'host', 'url', 'reason', 'message', 'error', 'family', 'binary',
                               'symbol', 'function', 'stratum', 'source'})
Runner = Callable[[list[str], dict[str, str], float], tuple[int, str]]


def aggregate_only(value, key: str = ''):
    """Numbers, bools, None and a few enum strings survive; anything that could name Microsoft data is dropped."""
    if any(token in UNSAFE_KEY_TOKENS for token in re.split(r'[^a-z0-9]+', key.lower())):
        return _DROP
    if isinstance(value, dict):
        out = {}
        for k in sorted(value):
            kept = aggregate_only(value[k], str(k))
            if kept is not _DROP and kept != {}:
                out[str(k)] = kept
        return out
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value if value in SAFE_STRINGS else _DROP
    if isinstance(value, list):
        nums = [v for v in value if isinstance(v, (int, float)) and not isinstance(v, bool)]
        return nums if len(nums) == len(value) and len(value) <= 12 else _DROP
    return _DROP


class _Drop:
    def __repr__(self) -> str:
        return '<dropped>'


_DROP = _Drop()


def last_json(text: str) -> dict | None:
    for line in reversed(text.strip().splitlines()):
        if line.lstrip().startswith('{'):
            try:
                value = json.loads(line)
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def preflight(environ, *, worktree: Path = REPO_ROOT, consent: str = '') -> tuple[Path, list[str]]:
    """Validated root plus warnings. Raises TierWError (code -> exit) on any O1 violation."""
    hit = [v for v in CI_VARS if environ.get(v)]
    if hit:
        raise TierWError('PT-TIERW-CONFIG', f'refusing to run in CI ({hit[0]} is set): Tier W data is local-only '
                                            '(decision O1). Run this on the owner machine')
    if not environ.get(corpus.ROOT_ENV):
        raise TierWError('PT-TIERW-CONFIG', f'set {corpus.ROOT_ENV} to a short directory outside the repository, '
                                            'for example D:\\ptcal or /srv/ptcal')
    root = check_root(Path(environ[corpus.ROOT_ENV]), worktree)
    problems = tool_safe_path(root)
    if problems:
        raise TierWError('PT-TIERW-CONFIG', problems[0])
    hosts = {h.strip() for h in consent.split(',') if h.strip()}
    if hosts - ALLOWED_HOSTS:
        raise TierWError('PT-TIERW-CONFIG', 'consent names a host outside the allow-list; allowed hosts are '
                                            + ', '.join(sorted(ALLOWED_HOSTS)))
    return root, ([] if hosts else ['no --consent-hosts: network stages (catalogue, resolve, fetch) will be skipped'])


def cli_available() -> bool:
    return any(importlib.util.find_spec(name) is not None
               for name in ('tools.calibration.tier_w.__main__', 'tools.calibration.tier_w.cli'))


def stage_argv(stage: str, args, python: str) -> list[str]:
    argv = [python, '-m', 'tools.calibration.tier_w', stage, '--corpus-id', args.corpus_id]
    needs_net, backend = STAGES[stage]
    if needs_net:
        argv += ['--consent-hosts', args.consent_hosts]
    if backend:
        if args.python:
            argv += ['--python', args.python]
        if args.ghidra_dir:
            argv += ['--ghidra-dir', args.ghidra_dir]
        argv += ['--timeout', str(args.timeout)]
    return argv


def default_runner(argv: list[str], env: dict[str, str], timeout: float) -> tuple[int, str]:
    try:
        done = subprocess.run(argv, cwd=REPO_ROOT, env=env, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, ''
    except OSError:
        return 127, ''
    return done.returncode, (done.stdout + b'\n' + done.stderr).decode('utf-8', 'replace')


def _child_env(root: Path) -> dict[str, str]:
    keep = ('PATH', 'HOME', 'USERPROFILE', 'SYSTEMROOT', 'TEMP', 'TMP', 'JAVA_HOME', 'GHIDRA_INSTALL_DIR', 'LC_ALL',
            'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE')
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update({corpus.ROOT_ENV: str(root), 'PYTHONPATH': str(REPO_ROOT / 'src') + os.pathsep + str(REPO_ROOT)})
    return env


def run_pipeline(args, environ, runner: Runner = default_runner, out=print) -> int:
    try:
        corpus_id = check_corpus_id(args.corpus_id)
        root, warnings = preflight(environ, consent=args.consent_hosts)
        selected = [s.strip() for s in args.only.split(',')] if args.only else list(STAGE_ORDER)
        unknown = [s for s in selected if s not in STAGES]
        if unknown:
            raise TierWError('PT-TIERW-INPUT', f'unknown stage(s) {unknown}; stages are {", ".join(STAGE_ORDER)}')
    except TierWError as exc:
        out(json.dumps({'tier_w_run_local': 'refused', 'code': exc.code, 'message': exc.message}, sort_keys=True))
        return CONFIG
    if not args.dry_run and not cli_available():
        out(json.dumps({'tier_w_run_local': 'blocked', 'message': 'python -m tools.calibration.tier_w is not '
                        'available in this checkout (SPEC-33 s11 CLI not landed); update the repository'},
                       sort_keys=True))
        return BLOCKED
    layout = Layout(root)
    logs = layout.base / 'run-local' / corpus_id
    python = args.interpreter or sys.executable
    env = _child_env(root)
    results: dict[str, dict] = {}
    worst = OK
    plan = [(s, stage_argv(s, args, python)) for s in selected]
    for note in warnings:
        out(f'note: {note}')
    if args.dry_run:
        out(json.dumps({'tier_w_run_local': 'dry-run', 'stages': [s for s, _ in plan]}, sort_keys=True))
        return OK
    logs.mkdir(parents=True, exist_ok=True)
    for stage, argv in plan:
        if STAGES[stage][0] and not args.consent_hosts:
            results[stage] = {'status': 'skipped'}
            continue
        code, text = runner(argv, env, args.stage_timeout)
        (logs / f'{stage}.log').write_text(text, encoding='utf-8')
        summary = last_json(text)
        view = aggregate_only(summary) if summary else {}
        results[stage] = {'status': {OK: 'ok', PARTIAL: 'partial', BLOCKED: 'blocked', CANCELLED: 'cancelled'}
                          .get(code, 'failed'), 'exit': code, **({'aggregate': view} if view else {})}
        worst = max(worst, PARTIAL if code == PARTIAL else 0)
        if code not in (OK, PARTIAL):
            worst = code if code in (CONFIG, BLOCKED, CANCELLED) else CONFIG
            break
    else:
        code, text = runner([python, '-m', 'tools.calibration.corpus', 'guard'], env, args.stage_timeout)
        results['guard'] = {'status': 'ok' if code == OK else 'failed', 'exit': code}
        if code != OK:
            worst = max(worst, PARTIAL)
    final = {'tier_w_run_local': 'done' if worst in (OK, PARTIAL) else 'stopped', 'exit': worst, 'stages': results}
    try:
        write_json(layout.base / 'reports' / f'{corpus_id}.run-local.json', {'tier': 'W', **final})
    except TierWError:
        pass
    out(json.dumps(final, sort_keys=True, indent=1))
    out('Aggregate-only output. Full logs and all Tier W data stay under the corpus root; nothing was uploaded.')
    return worst


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog='tier_w.run_local', description='One-command local Tier W run (owner machine).')
    ap.add_argument('--corpus-id', required=True, help='tier-w-<name>')
    ap.add_argument('--consent-hosts', default='', help='comma list; exactly winbindex.m417z.com,msdl.microsoft.com')
    ap.add_argument('--python', default='', help='Python with pyghidra/ghidriff for the run stage')
    ap.add_argument('--ghidra-dir', default='')
    ap.add_argument('--timeout', type=int, default=3600, help='per-pair Ghidra timeout passed to the run stage')
    ap.add_argument('--stage-timeout', type=float, default=24 * 3600)
    ap.add_argument('--only', default='', help='comma list of stages (default: all, in order)')
    ap.add_argument('--interpreter', default='', help='interpreter for the subcommands (default: this one)')
    ap.add_argument('--dry-run', action='store_true', help='validate environment and list stages, run nothing')
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    return run_pipeline(build_parser().parse_args(argv), os.environ)


if __name__ == '__main__':
    raise SystemExit(main())
