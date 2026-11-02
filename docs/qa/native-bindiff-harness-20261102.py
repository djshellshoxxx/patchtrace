"""Reviewed authored-pair QA only. Default checks setup; --run requires coordinator release."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import patchtrace
from patchtrace.jobs import run_process
from patchtrace.secondary import binexport_run
from patchtrace.secondary.bindiff_inputs import bind_pair
from patchtrace.secondary.binexport_run import accept_binexport
from patchtrace.secondary.cli_bindiff import c3_acceptor
from patchtrace.secondary.contracts import SecondaryError
from patchtrace.secondary.registry import BinDiffAdapter
from patchtrace.secondary.scheduler import ProjectRef, run_engines

REPO = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name('ExportBinExport20261102.java')
PINS = Path(__file__).with_name('native-bindiff-tool-pins-20261102.json')
MAX_EXPORT = 16 * 1024 * 1024  # This tiny smoke's bound; production C3 limits are unchanged.


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_hash(path: Path, expected: str) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or sha(path) != expected:
        raise ValueError(f'pinned regular-file digest differs: {path}')
    return expected


def properties(path: Path) -> dict[str, str]:
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def setup(tool_root: Path, source_head: str) -> dict:
    pin = json.loads(PINS.read_text())
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if head != source_head:
        raise ValueError('repository head differs from the reviewed source')
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=REPO):
        raise ValueError('tracked checkout changes require a new source review')
    subprocess.run(['git', 'diff', '--exit-code', pin['base_source'], head, '--', 'src', 'tools'],
                   cwd=REPO, check=True, capture_output=True)
    if Path(patchtrace.__file__).resolve() != REPO / 'src/patchtrace/__init__.py':
        raise ValueError('production imports are not bound to this checkout')
    if Path(sys.prefix).resolve() != tool_root / 'venv' or Path(sys.executable).is_symlink():
        raise ValueError('use the copied native venv bound to this checkout')
    if importlib.metadata.version('ziglang') != '0.17.0':
        raise ValueError('compiler package version differs')
    compiler = Path(importlib.metadata.distribution('ziglang').locate_file('ziglang/zig'))
    require_hash(compiler, pin['compiler_sha256'])
    require_hash(SCRIPT, pin['script_sha256'])
    for name, expected in pin['source_sha256'].items():
        require_hash(REPO / 'tests/fixtures' / name, expected)
    for relative, expected in pin['tool_files_sha256'].items():
        require_hash(tool_root / relative, expected)
    ghidra = tool_root / pin['ghidra_relative']
    if (properties(ghidra / 'Ghidra/application.properties').get('application.version') != '11.0.3'
            or properties(ghidra / 'Ghidra/Extensions/BinExport/extension.properties').get('version') != '11.0.3'):
        raise ValueError('Ghidra/exporter versions do not agree with 11.0.3')
    return {'source_head': head, 'base_source': pin['base_source'], 'python': sys.executable,
            'production_import': patchtrace.__file__, 'compiler': str(compiler),
            'compiler_sha256': pin['compiler_sha256'], 'tool_files_sha256': pin['tool_files_sha256'],
            'script_sha256': pin['script_sha256'], 'pins_sha256': sha(PINS), 'driver_sha256': sha(Path(__file__)),
            'binexport_signed': False, 'bindiff_independent_trust_verified': False,
            'ghidra': str(ghidra), 'java': str(tool_root / pin['java_relative']),
            'bindiff': str(tool_root / pin['bindiff_relative'])}


def child_env(home: Path, java: Path) -> dict[str, str]:
    """No inherited credentials, proxies, Java injection options or user configs."""
    result = {'PATH': os.pathsep.join((str(java.parent), os.defpath)), 'JAVA_HOME': str(java.parents[1]),
              'HOME': str(home), 'USERPROFILE': str(home), 'APPDATA': str(home), 'LOCALAPPDATA': str(home),
              'TMPDIR': str(home / 'tmp'), 'TMP': str(home / 'tmp'), 'TEMP': str(home / 'tmp'),
              'XDG_CACHE_HOME': str(home / 'cache'), 'XDG_CONFIG_HOME': str(home / 'config'),
              'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'ZIG_GLOBAL_CACHE_DIR': str(home / 'zig-global'),
              'ZIG_LOCAL_CACHE_DIR': str(home / 'zig-local')}
    if os.name == 'nt':
        for key in ('SystemRoot', 'WINDIR'):
            if key in os.environ:
                result[key] = os.environ[key]
    return result


def headless_argv(java: Path, ghidra: Path, home: Path, projects: Path, role: str) -> list[str]:
    # Exact upstream launch.sh entry, with explicit Java and private state instead of auto-selection.
    return [str(java), '-Xmx2G', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2',
            '-XX:ActiveProcessorCount=2', '-Djava.system.class.loader=ghidra.GhidraClassLoader',
            '-Djava.awt.headless=true', '-Dfile.encoding=UTF8', f'-Duser.home={home}',
            f'-Dapplication.cachedir={home / "cache"}', f'-Djava.io.tmpdir={home / "tmp"}',
            '-cp', str(ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar'), 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless', str(projects), role, '-max-cpu', '1']


def export_guard(folder: Path) -> str | None:
    entries = list(folder.iterdir())
    if len(entries) > 2:
        return 'output-limit'
    total = 0
    for path in entries:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return 'output-unexpected'
        total += info.st_size
    return 'output-limit' if total > MAX_EXPORT else None


class Session:
    def __init__(self, root: Path, record: dict):
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root, self.record = root, record
        self.cancel = threading.Event()
        self.record.update(status='running', target_execution=False, processes=[], exports=[], controls=[])
        self.save()

    def save(self):
        path = self.root / 'receipt.json'
        pending = self.root / 'receipt.new'
        pending.write_text(json.dumps(self.record, indent=2, default=str) + '\n')
        pending.replace(path)  # Both receipt names belong to this exclusively created session.

    def run(self, argv, **kwargs):
        row = {'argv': list(map(str, argv)), 'cwd': str(kwargs['cwd']),
               'env_keys': sorted(kwargs['env']), 'timeout_seconds': kwargs['timeout_seconds']}
        self.record['processes'].append(row)
        self.save()
        started = time.monotonic()
        prefix = self.root / f'process-{len(self.record["processes"]):02d}'
        request = None
        if '_binexport-worker' in argv and '--request' in argv:
            request = Path(argv[argv.index('--request') + 1])
            if request.stat().st_size > 1024 * 1024:
                raise ValueError('worker request exceeds smoke evidence bound')
            shutil.copyfile(request, prefix.with_suffix('.request.json'))
        try:
            result = run_process(argv, **kwargs)
            row.update(returncode=result.returncode, reason=result.reason,
                       stdout_total=result.stdout_total, stderr_total=result.stderr_total)
            if request is not None:
                worker_result = request.with_name('out.json')
                if worker_result.is_file() and worker_result.stat().st_size <= 1024 * 1024:
                    shutil.copyfile(worker_result, prefix.with_suffix('.result.json'))
            for name, raw in (('stdout', result.log_bytes), ('stderr', result.stderr_bytes)):
                if raw is not None:
                    path = prefix.with_suffix('.' + name)
                    path.write_bytes(raw)
                    row[name] = {'path': str(path), 'sha256': sha(path), 'retained_bytes': len(raw)}
            return result
        except Exception as exc:
            row['error'] = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            row['elapsed_seconds'] = round(time.monotonic() - started, 3)
            self.save()


@contextmanager
def record_c3(session: Session):
    """Log the existing worker runner's actual argv/results, without changing any C3 decision or bound."""
    original = binexport_run.run_process
    if original is not run_process:
        raise ValueError('C3 process runner was already substituted')
    binexport_run.run_process = session.run
    try:
        yield
    finally:
        binexport_run.run_process = original


def require_clean(result, stage: str):
    if result.returncode != 0 or result.reason:
        raise RuntimeError(f'{stage} failed: exit={result.returncode}, reason={result.reason}')


def exercise(session: Session):
    root, record = session.root, session.record
    java, ghidra = Path(record['java']), Path(record['ghidra'])
    for folder in ('home', 'home/tmp', 'home/cache', 'home/config', 'projects', 'inputs', 'scripts', 'accepted'):
        (root / folder).mkdir(mode=0o700, parents=True, exist_ok=True)
    script = root / 'scripts' / SCRIPT.name
    shutil.copyfile(SCRIPT, script)
    require_hash(script, record['script_sha256'])
    env = child_env(root / 'home', java)
    artifacts, exports, accepted, hashes = [], [], [], []
    for role, name in (('older', 'old.c'), ('newer', 'new.c')):
        source = root / 'inputs' / name
        shutil.copyfile(REPO / 'tests/fixtures' / name, source)
        require_hash(source, json.loads(PINS.read_text())['source_sha256'][name])
        artifact = root / 'inputs' / f'{role}.dll'
        command = [sys.executable, '-m', 'ziglang', 'cc', '-target', 'x86_64-windows-gnu', '-shared',
                   '-nostdlib', '-Wl,--no-entry', '-fno-sanitize=all', '-O0', '-o', str(artifact), str(source)]
        require_clean(session.run(command, cwd=root, env=env, cancel=session.cancel, timeout_seconds=120,
                                  log_limit=256 * 1024, separate_streams=True, stderr_limit=256 * 1024,
                                  max_output_bytes=8 * 1024 * 1024), 'compilation')
        if not 0 < artifact.stat().st_size <= 1024 * 1024:
            raise RuntimeError('authored PE exceeds smoke size bound')
        artifact_sha = sha(artifact)
        artifacts.append(artifact)
        hashes.append(artifact_sha)
        folder = root / role
        folder.mkdir(mode=0o700)
        common = headless_argv(java, ghidra, root / 'home', root / 'projects', role)
        require_clean(session.run([*common, '-import', str(artifact), '-analysisTimeoutPerFile', '180'],
                                  cwd=root, env=env, cancel=session.cancel, timeout_seconds=300,
                                  log_limit=512 * 1024, separate_streams=True, stderr_limit=512 * 1024,
                                  memory_limit_bytes=8 * 1024**3, max_output_bytes=8 * 1024 * 1024), 'analysis')
        command = [*common, '-process', artifact.name, '-noanalysis', '-scriptPath', str(script.parent),
                   '-preScript', script.name, str(folder), artifact_sha]
        result = session.run(command, cwd=root, env=env, cancel=session.cancel, timeout_seconds=180,
                             log_limit=512 * 1024, separate_streams=True, stderr_limit=512 * 1024,
                             memory_limit_bytes=8 * 1024**3, max_output_bytes=8 * 1024 * 1024,
                             check_output=lambda folder=folder: export_guard(folder))
        require_clean(result, 'export')
        if f'PATCHTRACE_BINEXPORT_OK {artifact_sha}' not in result.log_tail:
            raise RuntimeError('exporter did not confirm completion')
        export = folder / 'output.BinExport'
        item = accept_binexport(export, artifact_sha256=artifact_sha, role=role, private_dir=root / 'accepted',
                                cancel=session.cancel, accept_unbound=False)
        record['exports'].append({'role': role, 'artifact': str(artifact), 'artifact_sha256': artifact_sha,
                                  'source_sha256': sha(source), 'export': str(export), 'sha256': sha(export),
                                  'snapshot': str(item.snapshot_path), 'summary': item.summary.model_dump(mode='json'),
                                  'subtract_imagebase': False, 'remap_mnemonics': False, 'prepend_namespace': False})
        exports.append(export)
        accepted.append(item)
        session.save()
    try:
        bind_pair(accepted[1], accepted[0], hashes[0], hashes[1])
    except SecondaryError as exc:
        if exc.code != 'PT-SECONDARY-ORIENTATION':
            raise
        record['controls'].append({'swapped_pair': 'refused-before-BinDiff', 'code': exc.code})
    else:
        raise RuntimeError('swapped pair was accepted')
    try:
        accept_binexport(exports[0], artifact_sha256='0' * 64, role='older', private_dir=root / 'accepted',
                         cancel=session.cancel, accept_unbound=False)
    except SecondaryError as exc:
        if exc.code != 'PT-SECONDARY-PAIR' or exc.reason != 'executable_id_mismatch':
            raise
        record['controls'].append({'wrong_hash': 'refused-before-BinDiff', 'code': exc.code, 'reason': exc.reason})
    else:
        raise RuntimeError('wrong artifact hash was accepted')
    raw = root / 'raw'
    adapter = BinDiffAdapter(record['bindiff'], older=exports[0], newer=exports[1], raw_dir=raw,
                            acceptor=c3_acceptor(root / 'scheduler-accepted'), probe_runner=session.run)
    (outcome,) = run_engines(ProjectRef(*artifacts, *hashes), ['bindiff'], cancel=session.cancel, env={},
                            registry={'bindiff': adapter}, runner=session.run,
                            per_engine_timeout={'bindiff': 180.0})
    record['engine_run'] = outcome.run.model_dump(mode='json')
    record['match_set'] = outcome.match_set.model_dump(mode='json') if outcome.match_set else None
    session.save()
    if outcome.run.status != 'ok' or outcome.match_set is None:
        raise RuntimeError(f'production BinDiff path failed: {outcome.error or outcome.run.status}')
    result = outcome.match_set
    if (result.older_sha256, result.newer_sha256) != tuple(hashes) or not result.matches:
        raise RuntimeError('result lacks nonempty correctly owned matches')
    if result.engine_version != '8 (@568181968, Sep 25 2023)' or any(not m.algorithm for m in result.matches):
        raise RuntimeError('result version or algorithm provenance differs')
    kept = list(raw.glob('bindiff-*.BinDiff'))
    if len(kept) != 1 or sha(kept[0]) != outcome.run.output_sha256:
        raise RuntimeError('raw BinDiff preservation differs from recorded output hash')
    if any(sha(path) != digest for path, digest in zip(artifacts, hashes, strict=True)):
        raise RuntimeError('authored artifact bytes changed')
    record.update(status='passed', raw_bindiff=str(kept[0]), raw_bindiff_sha256=sha(kept[0]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool-root', type=Path, required=True)
    parser.add_argument('--source-head', required=True)
    parser.add_argument('--run-dir', type=Path)
    parser.add_argument('--run', action='store_true', help='Only after reviewed source and coordinator release')
    args = parser.parse_args(argv)
    record = setup(args.tool_root.resolve(), args.source_head)
    record['scope'] = 'Authored Linux real-plugin smoke only; no target execution, signed oracle or corpus claim'
    if not args.run:
        print(json.dumps({**record, 'status': 'setup-checked', 'native_executed': False}, indent=2))
        return 0
    if args.run_dir is None:
        parser.error('--run-dir is required for execution')
    session = Session(args.run_dir.resolve(), record)
    try:
        with record_c3(session):
            exercise(session)
    except (Exception, KeyboardInterrupt) as exc:
        record.update(status='failed', error=f'{type(exc).__name__}: {exc}')
    finally:
        session.save()
    print(json.dumps({'status': record['status'], 'receipt': str(session.root / 'receipt.json')}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
