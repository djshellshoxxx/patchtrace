"""Headless smoke of the frozen desktop executable (windows-acceptance spec section 2).

usage: frozen_smoke.py PATH_TO_PatchTrace.exe

Checks (each prints PASS/FAIL; any FAIL gives exit 1):
  A1  every command answers --help with exit 0 and `usage:` on stdout
  A2  unknown command exits 2 without a traceback
  A3  missing project exits 2 with a message, no traceback, no Qt
  A4  --self-test exits 0 and removes its patchtrace-self-test-* temp directory (frozen only)
  A5  `rank <sample> --json --dry-run`: exit 0 or 4, stdout is exactly one JSON document, stderr has no traceback
  A10 path cases through the CLI (spaces, Unicode, OneDrive-style, long): same ranking as the ASCII baseline,
      or an actionable exit-2/3 message; never a traceback. Trailing dot/space and reserved names (CON, NUL)
      are NOT exercised: Windows cannot create such directories through ordinary APIs.
  A6s Three-build series through the CLI with IMPORTED synthetic Ghidriff results (no Ghidra runs): two hops,
      one three-node chain, `series chains --json` parses. The native `--run` variant (real Ghidra) is not done.
  B1  `secondary binexport-check` on a host-generated minimal BinExport2: exit 0, one JSON document, pinned
      protobuf with upb in the worker (SPEC-10b §9.3). The program under test spawns its own worker child
      (frozen: the exe itself) through run_process and the Job Object memory cap, so this is the production route.
  B2  a JSON lookalike and a structurally invalid export exit 2 with their reason slugs and no traceback.

Project and series fixtures are written by the host interpreter (the source tree, `pip install -e`); only the
program under test is launched as a subprocess. `run_checks` is also used by tests/test_acceptance_smoke.py
with `python -m patchtrace` as the launcher, which verifies the logic everywhere but proves nothing about the
frozen package: only the Windows CI step does.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

COMMANDS = ('rank', 'flags', 'correlate', 'cache', 'acquire', 'series', 'secondary')
BASELINE_KEYS = ('rank', 'pairing_id', 'score', 'raw', 'function')  # match_id is random per project


def run(launcher: Sequence[str], *args: str, env: dict | None = None, timeout: int = 180):
    return subprocess.run([*launcher, *map(str, args)], capture_output=True, text=True, encoding='utf-8',
                          errors='replace', timeout=timeout, env=env)


def _json_doc(stdout: str):
    """Parse stdout as exactly one JSON document followed by a newline; None if it is anything else."""
    if not stdout.endswith('\n') or stdout.count('\n') != 1:
        return None
    try:
        return json.loads(stdout)
    except ValueError:
        return None


def _entries(doc) -> list[tuple]:
    return [tuple(e[k] for k in BASELINE_KEYS) for e in doc['result']['entries']]


def _sample_project(root: Path) -> Path:
    from patchtrace.service import ProjectService
    service = ProjectService.sample(root)
    path = service.root
    service.close()
    return path


def _import_pair(path: Path, modified, deleted=()) -> None:
    """Import a synthetic Ghidriff result into a pair project (the same route the GUI import takes)."""
    from patchtrace.service import ProjectService

    def func(name, address, code):
        return {'name': name, 'fullname': name, 'address': f'{address:x}', 'code': code, 'calling': [],
                'called': [], 'sig': f'int {name}(void)'}

    with ProjectService.open(path) as service:
        sides = {a.side: a.sha256 for a in service.project.artifacts}
        raw = {'old_meta': {'SHA256': sides['older']}, 'new_meta': {'SHA256': sides['newer']},
               'functions': {'added': [], 'deleted': [func(*d) for d in deleted], 'modified': [
                   {'old': func(*o), 'new': func(*n), 'diff': '', 'diff_type': ['code'], 'ratio': r,
                    'match_types': ['SymbolsHash']} for o, n, r in modified]}}
        file = path.parent / f'{path.name}.raw.json'
        file.write_text(json.dumps(raw), encoding='utf-8')
        service.import_diff(file)
        file.unlink()


def path_cases(base: Path) -> list[tuple[str, Path]]:
    """Parent directories for A10. The long case is sized under the 260-character MAX_PATH by the project
    file names it must still hold, so it is expected to work; failure to create it is reported, not hidden."""
    long_dir = base / 'long'
    while len(str(long_dir)) < 200:
        long_dir = long_dir / ('segment' + 'x' * 20)
    return [('ascii', base / 'plain'), ('spaces', base / 'with space' / 'my project'),
            ('unicode-cyrillic', base / 'Проект' / 'дело'), ('unicode-cjk', base / '研究'),
            ('onedrive-style', base / 'OneDrive - Contoso Ltd' / 'PatchTrace'), ('long-200', long_dir)]


def run_checks(launcher: Sequence[str], *, frozen: bool, emit: Callable[[str], None] = print) -> list[str]:
    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = '') -> None:
        emit(f'{"PASS" if ok else "FAIL"} {label}')
        if not ok:
            failures.append(f'{label}: {detail[-400:]}')

    for command in COMMANDS:
        r = run(launcher, command, '--help')
        check(f'A1 {command} --help', r.returncode == 0 and 'usage:' in r.stdout, f'rc={r.returncode} {r.stderr}')
    r = run(launcher, 'bogus-command')
    check('A2 unknown command exits 2, no traceback', r.returncode == 2 and 'Traceback' not in r.stderr,
          f'rc={r.returncode} {r.stderr}')
    with tempfile.TemporaryDirectory(prefix='pt-smoke-') as scratch_name:
        scratch = Path(scratch_name)
        missing = scratch / 'does' / 'not' / 'exist'
        r = run(launcher, 'rank', missing)
        check('A3 missing project exits 2 with message, no traceback',
              r.returncode == 2 and bool(r.stderr.strip()) and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stderr}')
        if frozen:
            temp = scratch / 'tmp'
            temp.mkdir()
            env = dict(os.environ, QT_QPA_PLATFORM='offscreen', TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
            r = run(launcher, '--self-test', env=env, timeout=240)
            check('A4 --self-test exits 0', r.returncode == 0, f'rc={r.returncode} {r.stdout} {r.stderr}')
            left = [p.name for p in temp.glob('patchtrace-self-test-*')]
            check('A4 self-test temp directory removed', not left, str(left))

        baseline_dir = _sample_project(scratch / 'baseline' / 'case')
        r = run(launcher, 'rank', baseline_dir, '--json', '--dry-run')
        doc = _json_doc(r.stdout)
        check('A5 rank --json: exit 0/4, one JSON document, no traceback',
              r.returncode in (0, 4) and doc is not None and doc.get('contract') == 'enrichment-cli/1'
              and 'Traceback' not in r.stderr, f'rc={r.returncode} {r.stdout[-200:]} {r.stderr}')
        baseline = _entries(doc) if doc is not None and r.returncode == 0 else None
        check('A5 baseline ranking is non-empty', bool(baseline), str(baseline))

        for label, parent in path_cases(scratch / 'paths'):
            try:
                created = _sample_project(parent / 'case')
            except OSError as exc:  # host could not create the directory: report, do not claim a CLI result
                check(f'A10 {label}: fixture creation', False, f'host cannot create project: {exc!r}')
                continue
            r = run(launcher, 'rank', created, '--json', '--dry-run')
            doc = _json_doc(r.stdout)
            same = r.returncode == 0 and doc is not None and baseline is not None and _entries(doc) == baseline
            actionable = r.returncode in (2, 3) and bool(r.stderr.strip())
            check(f'A10 {label}: same ranking as ASCII baseline (or actionable error)',
                  (same or actionable) and 'Traceback' not in r.stderr, f'rc={r.returncode} {r.stderr}')
            if label != 'long-200':  # the long case may legally fail on a runner without long-path support
                check(f'A10 {label}: ranking equals baseline', same, f'rc={r.returncode} {r.stderr}')

        # A6s: three builds through the CLI; pair results imported, not computed by Ghidra.
        from patchtrace.sample import synthetic_pe
        builds = []
        for i in range(3):
            build = scratch / 'builds' / f'b{i}.dll'
            build.parent.mkdir(exist_ok=True)
            build.write_bytes(synthetic_pe(i))
            builds.append(build)
        root = scratch / 'series' / 'Ünï series'
        args = ['series', 'create', '--builds', *builds, '--root', root, '--labels', 'a', 'b', 'c', '--json']
        r = run(launcher, *args)
        doc = _json_doc(r.stdout)
        check('A6s series create (3 builds): exit 0, two hop projects', r.returncode == 0 and doc is not None
              and len(doc['result']['pair_projects']) == 2 and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stdout[-300:]} {r.stderr}')
        if r.returncode == 0 and doc is not None:
            plan = [root / p['path'] for p in doc['result']['pair_projects']]
            _import_pair(plan[0], [(('f', 0x1000, 'v0'), ('f', 0x1010, 'v1'), 0.75)])
            _import_pair(plan[1], [(('f', 0x1010, 'v1'), ('f', 0x1020, 'v2'), 0.5)])
            r = run(launcher, *args)
            check('A6s series create after import: exit 0', r.returncode == 0, f'rc={r.returncode} {r.stderr}')
            r = run(launcher, 'series', 'chains', root / 'series.json', '--json')
            doc = _json_doc(r.stdout)
            chains = doc['result']['chains'] if doc is not None else []
            check('A6s series chains --json: one chain over three builds, two edges',
                  r.returncode == 0 and len(chains) == 1 and len(chains[0]['nodes']) == 3
                  and len(chains[0]['edges']) == 2 and 'Traceback' not in r.stderr,
                  f'rc={r.returncode} {r.stdout[-300:]} {r.stderr}')
        # Immutable copied artifacts must be writable again before the temporary tree is removed (Windows).
        for p in scratch.rglob('*'):
            try:
                if p.is_file():
                    p.chmod(0o600)
            except OSError:
                pass
        shutil.rmtree(scratch, ignore_errors=True)
    binexport_checks(launcher, frozen=frozen, check=check)
    return failures


def _binexport_bytes(sha: str) -> bytes:
    """Minimal valid BinExport2 built by the HOST runtime (the program under test only reads it)."""
    from patchtrace.secondary.binexport_proto import load_binexport2_class
    m = load_binexport2_class()()
    m.meta_information.executable_id = sha
    m.meta_information.executable_name = 'smoke.dll'
    m.meta_information.architecture_name = 'x86-64'
    m.meta_information.timestamp = 1_760_000_000
    m.call_graph.vertex.add(address=0x180001000)
    return m.SerializeToString()


def binexport_checks(launcher: Sequence[str], *, frozen: bool, check: Callable[..., None]) -> None:
    sha = 'ab' * 32
    # From source, the child must import this tree (an editable install elsewhere could shadow it).
    env = None if frozen else dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    with tempfile.TemporaryDirectory(prefix='pt-smoke-bx-') as scratch_name:
        scratch = Path(scratch_name)
        good = scratch / 'smoke.BinExport'
        good.write_bytes(_binexport_bytes(sha))
        r = run(launcher, 'secondary', 'binexport-check', good, '--artifact-sha256', sha, '--role', 'older',
                '--json', env=env)
        doc = _json_doc(r.stdout)
        result = (doc or {}).get('result') or {}
        check('B1 binexport-check: exit 0, one JSON document, upb worker',
              r.returncode == 0 and result.get('id_binding') == 'sha256' and result.get('functions') == 1
              and result.get('protobuf_version') == '7.36.2' and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stdout[-300:]} {r.stderr}')
        lookalike = scratch / 'renamed.BinExport'
        lookalike.write_text('{"not": "a BinExport"}', encoding='utf-8')
        bad = scratch / 'truncated.BinExport'
        bad.write_bytes(_binexport_bytes(sha)[:-1])
        for label, path, slug in (('lookalike', lookalike, 'lookalike_json'), ('truncated', bad, 'wire_truncated')):
            r = run(launcher, 'secondary', 'binexport-check', path, '--artifact-sha256', sha, '--role', 'older',
                    env=env)
            check(f'B2 binexport-check {label}: exit 2 [{slug}], no traceback',
                  r.returncode == 2 and f'[{slug}]' in r.stderr and 'Traceback' not in r.stderr,
                  f'rc={r.returncode} {r.stderr}')


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    exe = str(Path(sys.argv[1]).resolve())
    failures = run_checks([exe], frozen=True)
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
