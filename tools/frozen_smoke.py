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
  C1-C4 `intelligence import` and `explain` on the sample project and the SYNTHETIC CSAF fixture: one JSON document,
      the report contract and applicability, an escaped LF-only Markdown export, and exit 2 for a document that
      lacks the CVE. No network: `fetch` is covered by tests with a fake opener, never by this smoke.
  U1  SPEC-31 S1: the Ghidra extractor script is in the frozen package exactly once and byte-identical to the source
      tree's copy, and the BinDiff v8 notice ships (frozen only; the script runs in the user's external Python, so
      it must travel as a data file, 03 s3).
  U2  once S0b's `src/patchtrace/unified/cli.py` exists in the tree: `unified --help` exits 0 with `usage:` and
      `unified _worker --self-check` exits 0 (reads the packaged script through importlib.resources in the frozen
      process). Until then it prints SKIP, which is neither a pass nor a failure.

Project and series fixtures are written by the host interpreter (the source tree, `pip install -e`); only the
program under test is launched as a subprocess. `run_checks` is also used by tests/test_acceptance_smoke.py
with `python -m patchtrace` as the launcher, which verifies the logic everywhere but proves nothing about the
frozen package: only the Windows CI step does.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

COMMANDS = ('rank', 'flags', 'correlate', 'cache', 'acquire', 'series', 'secondary', 'intelligence', 'unified', 'intel-tools')
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
            line = next((x for x in r.stdout.splitlines() if x.startswith('optional-deps:')), '')
            check('A4 self-test reports every optional dependency present', bool(line) and 'missing=none' in line,
                  line or r.stdout[-300:])
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
    intelligence_checks(launcher, frozen=frozen, check=check)
    unified_checks(launcher, frozen=frozen, check=check, emit=emit)
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


def intelligence_checks(launcher: Sequence[str], *, frozen: bool, check: Callable[..., None]) -> None:
    root = Path(__file__).resolve().parents[1]
    advisory = root / 'tests' / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'
    cve = 'CVE-2099-10001'
    # From source, the child must import this tree (an editable install elsewhere could shadow it).
    env = None if frozen else dict(os.environ, PYTHONPATH=str(root / 'src'))
    scratch = Path(tempfile.mkdtemp(prefix='pt-smoke-intel-'))
    try:
        project = _sample_project(scratch / 'case')
        r = run(launcher, 'intelligence', 'import', project, advisory, '--cve', cve, '--json', env=env)
        doc = _json_doc(r.stdout)
        check('C1 intelligence import: exit 0, one JSON document', r.returncode == 0 and doc is not None
              and doc.get('command') == 'intelligence import' and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stdout[-300:]} {r.stderr}')
        exported = scratch / 'report.md'
        r = run(launcher, 'intelligence', 'explain', project, '--cve', cve, '--export', exported, '--json', env=env)
        doc = _json_doc(r.stdout)
        report = ((doc or {}).get('result') or {}).get('report') or {}
        sides = report.get('applicability') or {}
        check('C2 intelligence explain --json: report intelligence/1, older affected, newer fixed',
              r.returncode == 0 and report.get('contract') == 'intelligence/1' and report.get('cve') == cve
              and (sides.get('older') or {}).get('resolution') == 'affected'
              and (sides.get('newer') or {}).get('resolution') == 'fixed' and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stdout[-300:]} {r.stderr}')
        data = exported.read_bytes() if exported.is_file() else b''
        check('C3 explain --export .md: escaped, LF only, no raw HTML',
              data.startswith(b'# Advisory report for `CVE-2099-10001`\n') and b'\r' not in data and b'<' not in data,
              f'{len(data)} bytes {data[:120]!r}')
        r = run(launcher, 'intelligence', 'import', project, advisory, '--cve', 'CVE-2099-99999', env=env)
        check('C4 intelligence import without the CVE: exit 2, no traceback',
              r.returncode == 2 and 'does not list' in r.stderr and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stderr}')
    finally:
        for p in scratch.rglob('*'):  # copied artifacts are read-only; Windows cannot remove them otherwise
            try:
                if p.is_file():
                    p.chmod(0o600)
            except OSError:
                pass
        shutil.rmtree(scratch, ignore_errors=True)
EXTRACTOR_SCRIPT = 'patchtrace/unified/extract/ghidra_script.py'
BINDIFF_NOTICE = 'licenses/upstream/bindiff-v8-aecc14d/LICENSE'


def unified_checks(launcher: Sequence[str], *, frozen: bool, check: Callable[..., None],
                   emit: Callable[[str], None] = print, source_root: Path | None = None) -> None:
    """U1: file-level checks of the frozen onedir (the launcher's directory); U2: the unified CLI, when it exists."""
    if not frozen:
        return
    package = Path(launcher[0]).resolve().parent
    found = sorted(p for p in package.rglob('ghidra_script.py') if p.as_posix().endswith('/' + EXTRACTOR_SCRIPT))
    check('U1 extractor script is in the package exactly once', len(found) == 1, str([str(p) for p in found]))
    if len(found) == 1:
        expected = Path(__file__).resolve().parents[1] / 'src' / EXTRACTOR_SCRIPT
        same = hashlib.sha256(found[0].read_bytes()).hexdigest() == hashlib.sha256(expected.read_bytes()).hexdigest()
        check('U1 packaged extractor script equals the source tree copy', same, str(found[0]))
    check('U1 BinDiff v8 notice ships with the package', (package / BINDIFF_NOTICE).is_file(), BINDIFF_NOTICE)
    root = source_root if source_root is not None else Path(__file__).resolve().parents[1]
    if not (root / 'src' / 'patchtrace' / 'unified' / 'cli.py').is_file():
        emit('SKIP U2 unified --help / unified _worker --self-check (src/patchtrace/unified/cli.py does not exist yet)')
        return
    r = run(launcher, 'unified', '--help')
    check('U2 unified --help', r.returncode == 0 and 'usage:' in r.stdout, f'rc={r.returncode} {r.stderr}')
    r = run(launcher, 'unified', '_worker', '--self-check', timeout=240)
    check('U2 unified _worker --self-check', r.returncode == 0 and 'Traceback' not in r.stderr,
          f'rc={r.returncode} {r.stdout[-200:]} {r.stderr}')


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
