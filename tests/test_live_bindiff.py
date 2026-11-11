"""Live BinDiff acceptance (SPEC-29 §9.4, §10). REAL BinDiff only; mocked tests live elsewhere.

Never skipped: without `PATCHTRACE_BINDIFF` this records `blocked` in build/live-status/bindiff.json and
prints `LIVE ACCEPTANCE BLOCKED`. With `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` (set by the live job only after a
verified provisioning) an unavailable or unsupported tool FAILS.

Input pair, in order of preference:
- `PATCHTRACE_LIVE_BINEXPORT_DIR` with older.BinExport, newer.BinExport and pair.json
  {"older_sha256", "newer_sha256"}: real exports, accepted through C3's `accept_binexport` (`blocked` without C3);
- `PATCHTRACE_LIVE_SYNTHETIC_PAIR=1`: the SYNTHETIC pair of tests/bindiff_live_pair.py. When C3 is in the
  build the files go through C3's `accept_binexport` inside `BinDiffAdapter`, exactly as `secondary run
  --engine bindiff` does (production path); otherwise their ids are used as known by construction. Results on
  it are real-tool behaviour on synthetic input, never real-driver evidence; the status JSON says which input
  and which acceptance route ran.
Checks: probe (+ pinned version text when PATCHTRACE_BINDIFF_EXPECTED_VERSION is set), reversed pair refused
before spawn, end-to-end through `run_engines` + `BinDiffAdapter`, and on the synthetic route also cancel as
soon as the output file appears and a sub-second timeout (the partial-file hazard of SPEC-29 §4.4), plus the
`unshare -rn` no-network run on Linux.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from bindiff_live_pair import write_pair
from live_status import live_status_dir

from patchtrace.jobs import run_process
from patchtrace.secondary import bindiff_probe, bindiff_run
from patchtrace.secondary.bindiff_inputs import AcceptedBinExportLike, bind_pair
from patchtrace.secondary.cli_bindiff import c3_acceptor
from patchtrace.secondary.contracts import SecondaryError
from patchtrace.secondary.registry import BinDiffAdapter
from patchtrace.secondary.scheduler import ProjectRef, run_engines

pytestmark = pytest.mark.live_bindiff
LARGE_FUNCTIONS = 50_000  # real v8: output appears after about 2 s and the write phase lasts about 1 s (measured)


@dataclass(frozen=True)
class Inputs:
    older: AcceptedBinExportLike
    newer: AcceptedBinExportLike
    older_sha256: str
    newer_sha256: str
    older_artifact: Path
    newer_artifact: Path
    label: str
    acceptance: str
    synthetic: bool
    paths: tuple[Path, Path] | None = None   # with `acceptor`: the adapter accepts these itself (CLI wiring)
    acceptor: Callable | None = None


def _check(status: str, reason: str, **details) -> dict:
    return {'status': status, 'reason': reason, **details}


def _accept_both(acceptor: Callable, older: Path, newer: Path, older_sha: str, newer_sha: str):
    cancel = threading.Event()
    return (acceptor(older, artifact_sha256=older_sha, role='older', accept_unbound=False, cancel=cancel,
                     other_sha256=newer_sha),
            acceptor(newer, artifact_sha256=newer_sha, role='newer', accept_unbound=False, cancel=cancel,
                     other_sha256=older_sha))


def _inputs(tmp_path: Path) -> tuple[Inputs | None, str]:
    """Raises SecondaryError when C3 rejects an input (recorded by the caller as a failed check)."""
    acceptor = c3_acceptor(tmp_path / 'accepted')
    pair_dir = os.environ.get('PATCHTRACE_LIVE_BINEXPORT_DIR')
    if pair_dir:
        if acceptor is None:
            return None, 'real .BinExport pair given but C3 BinExport acceptance is not in this build'
        root = Path(pair_dir)
        hashes = json.loads((root / 'pair.json').read_text(encoding='utf-8'))
        older_sha, newer_sha = hashes['older_sha256'], hashes['newer_sha256']
        paths = (root / 'older.BinExport', root / 'newer.BinExport')
        older, newer = _accept_both(acceptor, *paths, older_sha, newer_sha)
        return Inputs(older, newer, older_sha, newer_sha, root / 'older.artifact', root / 'newer.artifact',
                      f'real exports from {root.name}', 'C3 accept_binexport', False, paths, acceptor), ''
    if os.environ.get('PATCHTRACE_LIVE_SYNTHETIC_PAIR') == '1':
        pair = write_pair(tmp_path / 'pair')
        label = (f'SYNTHETIC tests/bindiff_live_pair.py ({pair.functions}/{pair.functions + 1} functions; '
                 'not real-driver evidence)')
        if acceptor is None:
            return Inputs(pair.older, pair.newer, pair.older_sha256, pair.newer_sha256, pair.older_artifact,
                          pair.newer_artifact, label, 'ids known by construction (C3 not in this build)',
                          True), ''
        paths = (pair.older.snapshot_path, pair.newer.snapshot_path)
        older, newer = _accept_both(acceptor, *paths, pair.older_sha256, pair.newer_sha256)
        return Inputs(older, newer, pair.older_sha256, pair.newer_sha256, pair.older_artifact, pair.newer_artifact,
                      label, 'C3 accept_binexport inside BinDiffAdapter (production path)', True, paths,
                      acceptor), ''
    return None, ('no .BinExport pair: set PATCHTRACE_LIVE_BINEXPORT_DIR (real exports) or '
                  'PATCHTRACE_LIVE_SYNTHETIC_PAIR=1 (synthetic pair)')


def _reversed_refused(inputs: Inputs) -> dict:
    try:
        bind_pair(inputs.newer, inputs.older, inputs.older_sha256, inputs.newer_sha256)
    except SecondaryError as exc:
        if exc.code == 'PT-SECONDARY-ORIENTATION':
            return _check('passed', 'reversed .BinExport pair refused before any spawn')
        return _check('failed', f'reversed pair gave {exc.code}')
    return _check('failed', 'reversed .BinExport pair was not rejected')


def _end_to_end(exe: str, inputs: Inputs, tmp_path: Path, expected_version: str | None) -> dict:
    raw_dir = tmp_path / 'raw'
    older, newer = inputs.paths if inputs.paths else (inputs.older, inputs.newer)
    adapter = BinDiffAdapter(exe, older=older, newer=newer, raw_dir=raw_dir, acceptor=inputs.acceptor)
    project = ProjectRef(inputs.older_artifact, inputs.newer_artifact, inputs.older_sha256, inputs.newer_sha256)
    (out,) = run_engines(project, ['bindiff'], cancel=threading.Event(), env={}, registry={'bindiff': adapter},
                         per_engine_timeout={'bindiff': 1800.0})
    if out.run.status != 'ok':
        error = out.error
        return _check('failed', f'{out.run.status}: {error.code} ({error.kind}): {error.message}' if error
                      else out.run.status, provenance=out.run.provenance)
    match_set = out.match_set
    kept = sorted(raw_dir.glob('bindiff-*.BinDiff'))
    details = {'matches': len(match_set.matches), 'engine_version': match_set.engine_version,
               'output_sha256': out.run.output_sha256, 'duration_ms': out.run.duration_ms,
               'bindiff_summary': out.run.provenance.get('bindiff_summary'),
               'algorithms': sorted({m.algorithm for m in match_set.matches})[:6]}
    problems = []
    if not match_set.matches:
        problems.append('zero matches')
    if (match_set.older_sha256, match_set.newer_sha256) != (inputs.older_sha256, inputs.newer_sha256):
        problems.append('match set is not bound to the project artifact hashes')
    if any(not m.algorithm for m in match_set.matches):
        problems.append('a match has no algorithm name')
    if len(kept) != 1 or hashlib.sha256(kept[0].read_bytes()).hexdigest() != out.run.output_sha256:
        problems.append('raw .BinDiff not preserved exactly once with the run output hash')
    if 'version_warning' in out.run.provenance:
        problems.append('metadata.version disagrees with the probed major version')
    if expected_version and match_set.engine_version != expected_version:
        problems.append(f'metadata.version {match_set.engine_version!r} is not the pinned {expected_version!r}')
    if kept:
        status_dir = live_status_dir()
        status_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(kept[0], status_dir / 'bindiff-live.BinDiff')
        (status_dir / 'bindiff-live-stdout.txt').write_text(adapter._raw.stdout if adapter._raw else '',
                                                             encoding='utf-8')
    return _check('failed' if problems else 'passed', '; '.join(problems) or 'end-to-end run imported and validated',
                  **details)


def _stopped_run(cap, pair, tmp_path: Path, name: str, *, timeout: float, cancel_on_output: bool) -> dict:
    """Run `execute` on the large pair and stop it (cancel at the first output byte, or a short timeout)."""
    parent, raw_dir = tmp_path / f'wd-{name}', tmp_path / f'raw-{name}'
    parent.mkdir()
    cancel, seen = threading.Event(), []

    def watch():
        deadline = time.monotonic() + 600
        while not cancel.is_set() and time.monotonic() < deadline:
            for out in parent.glob('patchtrace-bindiff-*/out'):
                try:
                    if (out / bindiff_run.EXPECTED_NAME).exists():
                        seen.append({p.name: p.stat().st_size for p in out.iterdir()})
                        cancel.set()
                        return
                except OSError:
                    pass
            time.sleep(0.005)

    watcher = threading.Thread(target=watch, daemon=True) if cancel_on_output else None
    if watcher:
        watcher.start()
    try:
        raw = bindiff_run.execute(cap, pair, raw_dir, cancel=cancel, timeout_seconds=timeout, parent_dir=parent)
    except SecondaryError as exc:
        return _check('failed', f'{exc.code} ({exc.kind}): {exc.message}')
    finally:
        cancel.set()
        if watcher:
            watcher.join(5)
    expected = 'cancelled' if cancel_on_output else 'timeout'
    leftovers = sorted(p.name for p in parent.iterdir())
    preserved = sorted(p.name for p in raw_dir.glob('*')) if raw_dir.exists() else []
    details = {'out_at_stop': seen[0] if seen else None, 'workdir_left': leftovers, 'preserved': preserved}
    if raw.reason is None:
        return _check('blocked', f'inconclusive: BinDiff finished before the {expected} could be applied', **details)
    if raw.reason != expected or raw.kept_path is not None or preserved or leftovers:
        return _check('failed', f'stop was {raw.reason!r}; partial output must be discarded unread', **details)
    return _check('passed', f'{expected} discarded the partial output unread and removed the workdir', **details)


def _no_network(cap, pair, inputs: Inputs, tmp_path: Path, matches: int | None) -> dict:
    if os.name == 'nt':
        return _check('blocked', 'Linux-only check (unshare -rn); Windows network behaviour is live-only (manual)')
    unshare = shutil.which('unshare', path='/usr/bin:/bin')
    if not unshare:
        return _check('blocked', 'unshare is not installed')
    tmp_path.mkdir(parents=True, exist_ok=True)
    probe = run_process([unshare, '-rn', '/bin/true'], cwd=tmp_path, env={'PATH': '/usr/bin:/bin'},
                        cancel=threading.Event(), timeout_seconds=30)
    if probe.reason or probe.returncode != 0:
        return _check('blocked', f'user+network namespaces unavailable here (unshare -rn exit {probe.returncode})')

    def runner(argv, **kwargs):
        return run_process([unshare, '-rn', '--', *argv], **kwargs)

    try:
        raw = bindiff_run.execute(cap, pair, tmp_path / 'raw-nonet', cancel=threading.Event(), timeout_seconds=600,
                                  runner=runner, parent_dir=tmp_path)
        match_set = bindiff_run.import_output(raw.kept_path, raw.output_sha256, pair, inputs.older_sha256,
                                              inputs.newer_sha256, raw.summary)
    except SecondaryError as exc:
        return _check('failed', f'run in an empty network namespace failed: {exc.code} ({exc.kind}): {exc.message}')
    if matches is not None and len(match_set.matches) != matches:
        return _check('failed', f'{len(match_set.matches)} matches without network vs {matches} with')
    return _check('passed', 'identical result inside unshare -rn (no network namespace access)',
                  matches=len(match_set.matches))


def _overall(checks: dict) -> str:
    statuses = [c['status'] for c in checks.values()]
    return 'failed' if 'failed' in statuses else 'passed' if set(statuses) == {'passed'} else 'blocked'


def test_live_bindiff_status(record_live_status, tmp_path):
    exe = os.environ.get('PATCHTRACE_BINDIFF', '').strip()
    required = os.environ.get('PATCHTRACE_REQUIRE_LIVE_BINDIFF') == '1'
    if not exe:
        reason = 'PATCHTRACE_BINDIFF is not set: no BinDiff installed or provisioned on this machine'
        record_live_status('bindiff', 'failed' if required else 'blocked', reason)
        if required:
            pytest.fail(reason)
        return
    report = bindiff_probe.probe_report(exe, use_cache=False)
    if not report.capability.supported:
        reason = f'probe: {report.kind}: {report.capability.reason}'
        record_live_status('bindiff', 'failed' if required else 'blocked', reason)
        if required:
            pytest.fail(reason)
        return
    cap = report.capability
    exe_sha = hashlib.sha256(Path(cap.path).read_bytes()).hexdigest()
    checks = {'probe': _check('passed', 'supported', version=cap.version, untested_version=report.untested_version,
                              executable_sha256=exe_sha)}
    expected_version = os.environ.get('PATCHTRACE_BINDIFF_EXPECTED_VERSION') or None
    if expected_version:
        checks['pinned_version'] = _check('passed' if cap.version == expected_version else 'failed',
                                          f'probe version {cap.version!r}, pin {expected_version!r}')
    try:
        inputs, why = _inputs(tmp_path)
    except SecondaryError as exc:  # C3 refused an input BinDiff would be given: an integration failure
        inputs, why = None, f'C3 accept_binexport refused the input: {exc.code} ({exc.kind}): {exc.message}'
        checks['acceptance'] = _check('failed', why)
    extra: dict = {}
    if inputs is None:
        checks['end_to_end'] = _check('blocked', why)
    else:
        extra = {'input': inputs.label, 'acceptance': inputs.acceptance}
        checks['reversed_refused'] = _reversed_refused(inputs)
        checks['end_to_end'] = _end_to_end(exe, inputs, tmp_path / 'e2e', expected_version)
        pair = bind_pair(inputs.older, inputs.newer, inputs.older_sha256, inputs.newer_sha256)
        if inputs.synthetic:
            large = write_pair(tmp_path / 'large', LARGE_FUNCTIONS)
            big_older, big_newer = large.older, large.newer
            if inputs.acceptor is not None:
                big_older, big_newer = _accept_both(inputs.acceptor, large.older.snapshot_path,
                                                    large.newer.snapshot_path, large.older_sha256,
                                                    large.newer_sha256)
            big = bind_pair(big_older, big_newer, large.older_sha256, large.newer_sha256)
            checks['cancel_at_first_output'] = _stopped_run(cap, big, tmp_path, 'cancel', timeout=600,
                                                            cancel_on_output=True)
            checks['timeout_mid_run'] = _stopped_run(cap, big, tmp_path, 'timeout', timeout=0.5,
                                                     cancel_on_output=False)
        else:
            reason = 'needs the large synthetic pair (PATCHTRACE_LIVE_SYNTHETIC_PAIR=1); covered by fakes otherwise'
            checks['cancel_at_first_output'] = _check('blocked', reason)
            checks['timeout_mid_run'] = _check('blocked', reason)
        checks['no_network'] = _no_network(cap, pair, inputs, tmp_path / 'nonet',
                                           checks['end_to_end'].get('matches'))
    overall = _overall(checks)
    blocked = [f'{name}: {c["reason"]}' for name, c in checks.items() if c['status'] == 'blocked']
    failed = [f'{name}: {c["reason"]}' for name, c in checks.items() if c['status'] == 'failed']
    reason = '; '.join(failed or blocked) or 'all live checks passed'
    record_live_status('bindiff', overall, reason, checks=checks, **extra)
    assert overall != 'failed', checks
