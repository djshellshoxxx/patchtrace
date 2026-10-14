"""Pure orchestration for the evidence panel (C6 spec §4, §6; track G BinDiff setup §16). No Qt.

Thread rule: the GUI thread (owner of the project service and its SQLite connection) builds the
immutable :class:`EvidenceRequest` / :class:`RunRequest` / :class:`ValidationRequest`; worker threads
only run :func:`load_evidence` / :func:`execute_run` / :func:`probe_bindiff` /
:func:`validate_binexports` on them. Persisting an engine result (:func:`persist_outcome`) is called on
the GUI thread only.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ..enrichment.storage import EnrichmentStore, Entry, Guard
from ..models import FunctionMatch
from . import bindiff_probe, cli_bindiff, load_secondary, scheduler
from .bindiff_inputs import MAX_BINEXPORT_BYTES, BoundInput, bind_pair
from .contracts import Capability, SecondaryError, SecondaryMatchSet
from .engine_env import engine_env
from .evidence_view import (
    CALIBRATION_FALLBACK,
    LOG_LINES,
    SECONDARY_ENGINES,
    STALE_PAIR,
    STALE_REVISION,
    STALE_RUN,
    Cancelled,
    EngineOutcomeView,
    EvidenceViewModel,
    build_view_model,
    failed_model,
    sanitize_text,
)
from .registry import REGISTRY, BinDiffAdapter, EngineAdapter, build_registry
from .runs import EngineOutcome
from .store import cache_snapshot, publish_engine_set, publish_run, select_current

TIMEOUT_RANGE = (60, 86_400)
DEFAULT_TIMEOUT = 1800
PARALLEL_RANGE = (1, scheduler.MAX_PARALLEL)
STDERR_VIEW = 2 * 1024 * 1024

__all__ = ['EngineOutcomeView', 'EvidenceRequest', 'RunRequest', 'load_evidence', 'detect_stale',
           'select_sets', 'outcome_view', 'capability_view', 'probe_engines', 'execute_run', 'persist_outcome',
           'build_request', 'Cancelled', 'BinDiffSetup', 'BinDiffProbeView', 'ValidationRequest',
           'BinExportValidation', 'SetupProblem', 'probe_bindiff', 'validate_binexports', 'describe_problem',
           'setup_capability', 'bindiff_adapter']


@dataclass(frozen=True)
class EvidenceRequest:
    project_id: str
    run_id: str | None
    revision: int
    older_sha256: str
    newer_sha256: str
    matches: tuple[FunctionMatch, ...]        # snapshot; read-only in the worker
    sets: tuple[tuple[Entry, SecondaryMatchSet], ...]
    outcomes: tuple[EngineOutcomeView, ...] = ()
    calibration_level: str = CALIBRATION_FALLBACK
    generation: int = 0
    ghidriff_version: str | None = None


@dataclass(frozen=True)
class RunRequest:
    project_id: str
    revision: int
    generation: int
    engines: tuple[str, ...]
    max_parallel: int
    timeout_s: int
    older_path: Path
    newer_path: Path
    older_sha256: str
    newer_sha256: str
    run_id: str | None = None
    capabilities: Mapping[str, Capability] = field(default_factory=dict)
    cache: Mapping[str, SecondaryMatchSet] = field(default_factory=dict)  # snapshot built on the GUI thread
    # Track G (§16.6, additive): the GUI BinDiff setup and the CLI's raw folder `<project>/runs/<run>/raw/secondary`.
    bindiff: BinDiffSetup | None = None
    bindiff_raw_dir: Path | None = None

    def __post_init__(self):
        if not self.engines:
            raise ValueError('select at least one engine')
        if not PARALLEL_RANGE[0] <= self.max_parallel <= PARALLEL_RANGE[1]:
            raise ValueError(f'parallel engines must be between {PARALLEL_RANGE[0]} and {PARALLEL_RANGE[1]}')
        if not TIMEOUT_RANGE[0] <= self.timeout_s <= TIMEOUT_RANGE[1]:
            raise ValueError('timeout must be between 60 and 86400 seconds')
        if self.bindiff is not None and self.bindiff_raw_dir is None:
            raise ValueError('a BinDiff setup needs the project raw folder')


def select_sets(rows: Sequence[tuple[Entry, SecondaryMatchSet]]
                ) -> tuple[tuple[tuple[Entry, SecondaryMatchSet], ...], tuple[str, ...]]:
    """Newest non-stale set per engine (SPEC-28 C5); duplicates never reach reconcile/assess."""
    chosen, notes = select_current(list(rows))
    engines = sorted({note.split(':', 1)[0] for note in notes})
    warnings = tuple(f'Multiple stored sets for {engine}; showing the newest.' for engine in engines)
    return tuple(chosen), warnings


def load_evidence(request: EvidenceRequest, cancel: Callable[[], bool] = lambda: False) -> EvidenceViewModel:
    """Worker-side: pure over the immutable request. Raises Cancelled; any other failure is an E5 model."""
    common = dict(project_id=request.project_id, run_id=request.run_id, revision=request.revision,
                  older_sha256=request.older_sha256, newer_sha256=request.newer_sha256,
                  calibration_level=request.calibration_level, generation=request.generation)
    try:
        chosen, warnings = select_sets(request.sets)
        stale = None
        for entry, match_set in chosen:
            if (match_set.older_sha256, match_set.newer_sha256) != (request.older_sha256, request.newer_sha256):
                stale = STALE_PAIR
                break
            if request.run_id is not None and entry.guard.run_id != request.run_id:
                stale = stale or STALE_RUN
        return build_view_model(matches=request.matches, sets=tuple(s for _, s in chosen),
                                outcomes=request.outcomes, warnings=warnings, stale_reason=stale,
                                ghidriff_version=request.ghidriff_version, cancel=cancel, **common)
    except Cancelled:
        raise
    except ValueError as exc:
        return failed_model(f'PT-EVIDENCE-ASSEMBLY: {exc}', **common)
    except Exception as exc:  # noqa: BLE001 - a bug degrades to E5 with the class name only
        return failed_model(f'PT-EVIDENCE-ASSEMBLY: unexpected {type(exc).__name__}', **common)


def detect_stale(vm: EvidenceViewModel | EvidenceRequest, current_revision: int, current_run_id: str | None,
                 current_pair: tuple[str, str]) -> str | None:
    """First matching reason (spec §4.3), evaluated on the GUI thread without re-running anything."""
    run_id = vm.ghidriff_run_id if isinstance(vm, EvidenceViewModel) else vm.run_id
    if (vm.older_sha256, vm.newer_sha256) != tuple(current_pair):
        return STALE_PAIR
    if run_id != current_run_id:
        return STALE_RUN
    if vm.revision != current_revision:
        return STALE_REVISION
    return None


def build_request(service, *, generation: int = 0, outcomes: Sequence[EngineOutcomeView] = (),
                  calibration_level: str = CALIBRATION_FALLBACK) -> EvidenceRequest | None:
    """GUI-thread only: snapshot the project and read stored sets through its own connection."""
    project = service.project if service else None
    if project is None:
        return None
    sides = {a.side: a.sha256 for a in project.artifacts}
    run = latest_run(project)
    rows = tuple(load_secondary(EnrichmentStore(service.store)))
    return EvidenceRequest(project.id, run.id if run else None, project.revision, sides.get('older', ''),
                           sides.get('newer', ''), tuple(project.matches), rows, tuple(outcomes),
                           calibration_level, generation, run.backend_version if run else None)


def latest_run(project):
    return next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)


# ---- engine runs (SPEC-28 scheduler) ----------------------------------------------------------


def _tail_lines(text: str, lines: int = LOG_LINES) -> str:
    clipped = text[-STDERR_VIEW:]
    clean = '\n'.join(sanitize_text(line, 2000) for line in clipped.splitlines()[-lines:])
    return clean


def outcome_view(outcome: EngineOutcome) -> EngineOutcomeView:
    """Adapter from the SPEC-28 `EngineOutcome`; the only place that knows its shape."""
    run = outcome.run
    message = str(outcome.error.message) if outcome.error is not None else ''
    engine = run.engine if run.engine in SECONDARY_ENGINES else 'rz-diff'
    return EngineOutcomeView(engine, run.status, run.engine_version, run.error_code,
                             sanitize_text(message.splitlines()[0] if message else '', 200),
                             _tail_lines(run.stderr_tail), run.duration_ms, run.run_id, run.started_utc,
                             outcome.match_set, run)


def capability_view(cap: Capability) -> EngineOutcomeView | None:
    """An unsupported probe result as a panel outcome (E7 reasons); supported engines yield None."""
    if cap.supported or cap.engine not in SECONDARY_ENGINES:
        return None
    reason = (cap.reason or 'engine unsupported').removeprefix('PT-SECONDARY-UNSUPPORTED: ')
    return EngineOutcomeView(cap.engine, 'unsupported', cap.version, 'PT-SECONDARY-UNSUPPORTED',
                             sanitize_text(reason, 200))


def probe_engines(cancel: threading.Event, *, registry: Mapping[str, EngineAdapter] = REGISTRY,
                  env: Mapping[str, str] | None = None) -> dict[str, Capability]:
    """Capability probes only; nothing is run on the binaries. A probe that raises is unsupported."""
    env = engine_env(os.environ, 'rz-diff') if env is None else env
    found: dict[str, Capability] = {}
    for engine in SECONDARY_ENGINES:
        adapter = registry.get(engine)
        try:
            found[engine] = adapter.probe(env, cancel) if adapter else Capability(
                engine=engine, supported=False, version=None, path='', supports_json=False, reason='not registered')
        except Exception as exc:  # noqa: BLE001
            found[engine] = Capability(engine=engine, supported=False, version=None, path='',
                                       supports_json=False, reason=f'probe failed: {type(exc).__name__}')
    return found


def execute_run(request: RunRequest, cancel: threading.Event, *,
                on_event: Callable[[scheduler.EngineEvent], None] | None = None,
                on_outcome: Callable[[EngineOutcome], None] | None = None,
                registry: Mapping[str, EngineAdapter] | None = None, env: Mapping[str, str] | None = None,
                runner: Callable | None = None,
                acceptor_factory: Callable[[Path], Callable | None] | None = None) -> tuple[EngineOutcome, ...]:
    """Worker-side: run through the SPEC-28 scheduler; never touches a store or a widget.

    Without an explicit registry the default `REGISTRY` is used (C6 behaviour), unless the request carries a
    GUI BinDiff setup for a run that includes BinDiff: then the BinDiff adapter is the CLI construction
    (`bindiff_adapter`), built here per run because an adapter holds the bound pair of one invocation."""
    if registry is None:
        registry = REGISTRY
        if request.bindiff is not None and 'bindiff' in request.engines:
            registry = build_registry(bindiff=bindiff_adapter(request.bindiff, request.bindiff_raw_dir,
                                                              acceptor_factory=acceptor_factory))
    ref = scheduler.ProjectRef(request.older_path, request.newer_path, request.older_sha256, request.newer_sha256)
    snapshot = dict(request.cache)

    class Snapshot:
        def find(self, key):
            return snapshot.get(key)

    extra = {'runner': runner} if runner is not None else {}
    return scheduler.run_engines(
        ref, list(request.engines), max_parallel=request.max_parallel,
        per_engine_timeout=dict.fromkeys(request.engines, float(request.timeout_s)), cancel=cancel,
        cache=Snapshot(), env=engine_env(os.environ, 'rz-diff') if env is None else env, on_event=on_event,
        on_outcome=on_outcome, registry=registry, **extra)


def run_cache(service, older_sha256: str, newer_sha256: str) -> dict[str, SecondaryMatchSet]:
    """GUI-thread cache snapshot for RunRequest.cache."""
    return cache_snapshot(EnrichmentStore(service.store), older_sha256, newer_sha256)


def persist_outcome(service, request: RunRequest, view: EngineOutcomeView) -> str | None:
    """GUI-thread only. Store the engine set and run record when the project still matches the request.

    Returns None on success or a stale reason (result discarded, nothing written).
    """
    project = service.project if service else None
    if project is None or project.id != request.project_id:
        return 'the project changed while the engine ran'
    run = latest_run(project)
    sides = {a.side: a.sha256 for a in project.artifacts}
    if (sides.get('older'), sides.get('newer')) != (request.older_sha256, request.newer_sha256):
        return STALE_PAIR
    if run is None or run.id != request.run_id:
        return STALE_RUN
    if view.run is None:
        return None
    store = EnrichmentStore(service.store)
    match_set = view.match_set
    digest = match_set.file_sha256 if match_set else view.run.cache_key
    guard = Guard(project.id, run.id, run.raw_sha256, digest)
    if match_set is not None and view.status == 'ok':
        publish_engine_set(store, guard, guard, project.revision, match_set)
    publish_run(store, guard, guard, project.revision, view.run)
    return None


# ---- track G: BinDiff + BinExport GUI setup (multi-engine-evidence-panel.md §16) ------------------------
#
# Pure helpers behind the Engines-tab BinDiff section. Probing and validation reuse the CLI code paths
# unchanged (`bindiff_probe.probe_report`, `cli_bindiff.c3_acceptor` + `bindiff_inputs.bind_pair`, and
# `cli_bindiff.adapter_from_args` for the run), so the GUI never forks BinDiff/BinExport logic. Every text
# below is plain (no markup), names no paths and never echoes worker stderr.

# `tools/bindiff_pin.json` version_text without its 'BinDiff ' prefix (`Capability.version` format); a test keeps
# the two equal. The pin file lives outside the package, so the frozen app cannot read it at runtime.
PINNED_BINDIFF_VERSION = '8 (@568181968, Sep 25 2023)'
PROBE_TEXT: dict[str, str] = {
    'empty': ('No BinDiff executable chosen. BinDiff is never looked up on PATH: choose the bindiff executable '
              '(bindiff.exe on Windows) of an installed BinDiff 8 and press Probe BinDiff.'),
    'found-one': ('Found an installed BinDiff at the path above; it has not been run. Press Probe BinDiff to '
                  'check it.'),
    'found-many': ('Found {n} installed BinDiff executables; pick one from the list or use Browse, then press '
                   'Probe BinDiff.'),
    'unchecked': ('Not checked yet. Probe BinDiff runs only bindiff --version and --help; it never reads the '
                  'project files.'),
    'probing': 'Checking BinDiff (bindiff --version and --help only)...',
    'usable': 'Usable: BinDiff {version}. Version check: {pin}.',
    'unusable': 'Not usable: {reason}',
}
PIN_NOTES: dict[str, str] = {
    'pinned': 'the BinDiff 8 build PatchTrace was tested with',
    'tested': ('a BinDiff {major} build other than the one PatchTrace was tested with; accepted because every '
               'required option is present'),
    'untested-newer': ('newer than the tested BinDiff 8; accepted because every required option is present, and '
                       'results are recorded as from an untested version'),
}
VALIDATION_TEXT: dict[str, str] = {
    'idle': ('Choose the .BinExport of the older file (BinDiff primary) and of the newer file (BinDiff '
             'secondary), then press Validate .BinExport files.'),
    'no-project': 'Open a project to validate .BinExport files.',
    'missing': 'Choose both .BinExport files first: one for the older file and one for the newer file.',
    'step': 'Validating the {side} .BinExport in an isolated checker (step {n} of 2)...',
    'pair': "Checking that the two .BinExport files form this project's pair...",
    'ok': "Both .BinExport files are valid BinExport2 and belong to this project's files.",
    'ok-asserted': ('Both .BinExport files are valid BinExport2; at least one is tied to this project only by '
                    'your confirmation.'),
    'rejected': 'Not accepted: {message}',
    'cancelled': 'Validation cancelled; nothing was kept.',
    'stopped': 'The check stopped unexpectedly ({name}); nothing was kept.',
}
BINDING_TEXT: dict[str, str] = {
    'sha256': 'SHA-256, matches the {side} file',
    'md5': 'MD5 only, accepted on your confirmation (not checked)',
    'empty': 'none, accepted on your confirmation (not checked)',
    'other': 'not a SHA-256, accepted on your confirmation (not checked)',
}
SETUP_REASON: dict[str, str] = {
    'inputs': 'BinDiff {version} is usable; choose and validate both .BinExport files in BinDiff setup.',
    'rejected': 'BinDiff {version} is usable, but the .BinExport files were not accepted: {message}',
}
RUN_PREVIEW_BINDIFF = 'BinDiff compares the two validated .BinExport files (older = primary, newer = secondary).'
UNSUPPORTED_PREFIX = 'PT-SECONDARY-UNSUPPORTED: '
_SIDES = ('older', 'newer')
_SIDE_IN_MESSAGE = re.compile(r'\bThe (older|newer) \.BinExport\b')
_LOOKALIKE = {'sqlite': 'a SQLite database (perhaps a .BinDiff result)', 'json': 'JSON', 'zip': 'a ZIP archive',
              'pe': 'a Windows executable', 'elf': 'an ELF executable', 'pdf': 'a PDF'}
_UNBOUND = {'md5': 'records only an MD5 hash of its source file, not a SHA-256',
            'empty': 'records no hash of its source file',
            'other': 'records an id that is not a SHA-256 of its source file',
            None: 'does not record a SHA-256 of its source file'}
_UNAVAILABLE = frozenset({'protobuf_missing', 'protobuf_not_upb', 'protobuf_too_old', 'descriptor_mismatch',
                          'worker_unavailable'})
_LIMITS = frozenset({'memory_cap', 'record_too_large'})


@dataclass(frozen=True)
class BinDiffSetup:
    """What the GUI hands to a run: the user's explicit executable path (never PATH) and the two inputs."""
    executable: str
    older_binexport: Path
    newer_binexport: Path
    accept_unbound: bool = False


@dataclass(frozen=True)
class BinDiffProbeView:
    executable: str                 # the field text that was probed
    capability: Capability
    kind: str | None                # SPEC-29 §6 kind when unusable
    pin: Literal['pinned', 'tested', 'untested-newer', 'unsupported']
    message: str                    # plain status line
    technical: str                  # plain details on demand

    @property
    def supported(self) -> bool:
        return self.capability.supported


@dataclass(frozen=True)
class SetupProblem:
    code: str | None                # PT-SECONDARY-*
    kind: str | None                # SPEC-29 §6 kind
    reason: str | None              # SPEC-10b §7 slug
    side: str | None                # 'older' | 'newer' | None (the pair)
    message: str                    # plain words for the status line
    technical: str                  # code, kind, slug, side and the fixed-template message
    unbound: bool = False           # the explicit unbound confirmation could resolve it


@dataclass(frozen=True)
class BinExportSideView:
    role: str
    functions: int | None
    architecture: str               # sanitized file string
    id_binding: str                 # sha256 | md5 | empty | other
    file_sha256: str                # of the validated snapshot
    address_basis: str
    warnings: tuple[str, ...]

    @property
    def line(self) -> str:
        count = 'an unknown number of functions' if self.functions is None else (
            f'{self.functions:,} function' + ('' if self.functions == 1 else 's'))
        binding = BINDING_TEXT.get(self.id_binding, BINDING_TEXT['other']).format(side=self.role)
        return f'{self.role.capitalize()}: {count}, architecture {self.architecture}, executable id {binding}.'


@dataclass(frozen=True)
class ValidationRequest:
    older_path: Path
    newer_path: Path
    older_sha256: str
    newer_sha256: str
    accept_unbound: bool = False

    @property
    def key(self) -> tuple[str, str, bool, str, str]:
        """Identity a validation answers: paths as given, override, and the project's artifact pair."""
        return (str(self.older_path), str(self.newer_path), bool(self.accept_unbound), self.older_sha256,
                self.newer_sha256)


@dataclass(frozen=True)
class BinExportValidation:
    status: Literal['ok', 'failed', 'cancelled']
    key: tuple
    older: BinExportSideView | None = None
    newer: BinExportSideView | None = None
    binding: str = ''               # EngineRun.provenance['binexport_binding'] a run with these inputs records
    problem: SetupProblem | None = None
    stopped: str = ''               # exception class name of an unexpected failure

    @property
    def message(self) -> str:
        if self.status == 'cancelled':
            return VALIDATION_TEXT['cancelled']
        if self.status == 'failed':
            if self.problem is None:
                return VALIDATION_TEXT['stopped'].format(name=self.stopped or 'unknown')
            return VALIDATION_TEXT['rejected'].format(message=self.problem.message)
        head = VALIDATION_TEXT['ok' if self.binding in ('', 'sha256') else 'ok-asserted']
        return '\n'.join([head, *(side.line for side in (self.older, self.newer) if side is not None)])

    @property
    def technical(self) -> str:
        if self.problem is not None:
            return self.problem.technical
        if self.status != 'ok':
            return f'Status: {self.status}' + (f'\nException: {self.stopped}' if self.stopped else '')
        lines = [f'Binding recorded with a run: {self.binding}']
        for side in (self.older, self.newer):
            if side is not None:
                lines.append(f'{side.role}: snapshot SHA-256 {side.file_sha256}, id binding {side.id_binding}, '
                             f'address basis {side.address_basis}, checker notes '
                             f'{", ".join(side.warnings) or "none"}')
        return '\n'.join(lines)


def pin_status(capability: Capability, untested_version: bool) -> str:
    if not capability.supported:
        return 'unsupported'
    if (capability.version or '') == PINNED_BINDIFF_VERSION:
        return 'pinned'
    return 'untested-newer' if untested_version else 'tested'


def probe_view(executable: str, report: bindiff_probe.ProbeReport) -> BinDiffProbeView:
    cap = report.capability
    pin = pin_status(cap, report.untested_version)
    if cap.supported:
        version = sanitize_text(cap.version or '?', 120)
        note = PIN_NOTES[pin].format(major=report.major if report.major is not None else '?')
        message = PROBE_TEXT['usable'].format(version=version, pin=note)
    else:
        reason = (cap.reason or 'BinDiff is not usable.').removeprefix(UNSUPPORTED_PREFIX)
        message = PROBE_TEXT['unusable'].format(reason=sanitize_text(reason, 300))
    technical = '\n'.join([
        f'Probe result: {"usable" if cap.supported else "not usable"}', f'Kind: {report.kind or "-"}',
        f'Version: {sanitize_text(cap.version or "-", 120)}',
        f'Major: {report.major if report.major is not None else "-"}', f'Pin status: {pin}',
        f'Untested newer major: {"yes" if report.untested_version else "no"}',
        f'Executable name: {sanitize_text(Path(cap.path).name if cap.path else "-", 80)}'])
    return BinDiffProbeView(executable, cap, report.kind, pin, message, technical)


def probe_bindiff(executable: str, cancel: threading.Event, *, runner: Callable | None = None) -> BinDiffProbeView:
    """Worker-side SPEC-29 §2 probe of the path the user typed (only `--version` and `--nologo --help`)."""
    text = (executable or '').strip()
    kwargs = {'runner': runner} if runner is not None else {}
    return probe_view(text, bindiff_probe.probe_report(text or None, cancel=cancel, **kwargs))


def _plain_problem(code: str, kind: str | None, reason: str, side: str | None) -> str:
    who = f'The {side} .BinExport' if side else 'A .BinExport file'
    lower = who[0].lower() + who[1:]
    if kind == 'binexport-orientation' or reason == 'orientation_swapped' or code == 'PT-SECONDARY-ORIENTATION':
        return ('The two .BinExport files are swapped: the file chosen as older was exported from the newer file '
                '(or the reverse). Swap them and validate again.')
    if kind == 'binexport-same-file' or reason == 'same_file_twice':
        return ('The same .BinExport was chosen for both sides. Choose one export of the older file and one of '
                'the newer file.')
    if kind == 'identical-pair' or reason == 'identical_pair':
        return "This project's older and newer files are identical, so there is nothing to compare."
    if kind == 'binexport-arch-mismatch':
        return ('The two .BinExport files describe different processor architectures, so they cannot be a patch '
                'pair.')
    if kind == 'binexport-wrong-artifact' or reason == 'executable_id_mismatch':
        target = f"this project's {side} file" if side else 'the project file it was chosen for'
        return f'{who} was exported from a different file than {target} (its SHA-256 executable id does not match).'
    if kind == 'binexport-unbound' or (reason.startswith('executable_id_') and reason != 'executable_id_mismatch'):
        detail = _UNBOUND.get(reason.removeprefix('executable_id_') or None, _UNBOUND[None])
        return (f'{who} {detail}, so PatchTrace cannot check that it belongs to this project. Re-export it with an '
                'exporter that records SHA-256 (Ghidra does), or tick the confirmation below if you exported it '
                'from exactly this file yourself.')
    if reason == 'address_basis_mixed':
        return ('One file uses virtual addresses and the other subtracted the image base. Export both with the '
                'same "Subtract Imagebase" choice.')
    if kind == 'binexport-too-large' or reason == 'too_large':
        return f'{who} is larger than the {MAX_BINEXPORT_BYTES >> 20} MiB limit.'
    if reason in _LIMITS or reason.startswith('count_cap:'):
        return f'{who} exceeds a size or record-count limit of the checker.'
    if reason == 'unreadable':
        return f'{who} could not be opened for reading.'
    if reason == 'not_regular_file':
        return f'{who} is not a regular file.'
    if reason == 'empty_file':
        return f'{who} is empty.'
    if reason == 'file_changed_during_read':
        return f'{who} changed while it was being read. Try again once it is no longer being written.'
    if reason.startswith('lookalike_'):
        thing = _LOOKALIKE.get(reason.removeprefix('lookalike_'), 'another kind of file')
        subject = f'The {side} file' if side else 'The file'
        return f'{subject} looks like {thing}, not a .BinExport file.'
    if kind == 'binexport-unsupported' or reason in _UNAVAILABLE or code == 'PT-SECONDARY-UNSUPPORTED':
        return 'BinExport validation is not available in this build (the BinExport2 reader is missing).'
    if reason == 'worker_timeout':
        return f'Checking {lower} took longer than its time limit and was stopped; the file was not accepted.'
    if reason == 'worker_oom':
        return f'Checking {lower} needed more memory than allowed; the file was not accepted.'
    if kind == 'workdir-error':
        return 'PatchTrace could not prepare a private working folder for the check. Check the free disk space.'
    if code == 'PT-SECONDARY-CANCEL' or reason == 'cancelled':
        return VALIDATION_TEXT['cancelled']
    if code == 'PT-SECONDARY-RUN':
        return f'The isolated checker stopped unexpectedly while reading {lower}; the file was not accepted.'
    if code == 'PT-SECONDARY-LIMIT':
        return f'{who} exceeds a size or record-count limit of the checker.'
    if code == 'PT-SECONDARY-PAIR':
        return f"{who} does not belong to this project's pair of files."
    if kind == 'binexport-invalid' or code == 'PT-SECONDARY-INPUT':
        return f'{who} is not a valid BinExport2 file (its structure failed a check).'
    return f'{who} was not accepted.'


def describe_problem(exc: SecondaryError, side: str | None = None) -> SetupProblem:
    """SPEC-29 kinds and SPEC-10b slugs -> short plain words; the machine fields stay in `technical`.

    Never uses `SecondaryError.diagnostics` (sanitised worker stderr): the GUI shows no worker output."""
    code = str(getattr(exc, 'code', '') or '')
    kind = getattr(exc, 'kind', None)
    reason = getattr(exc, 'reason', None)
    raw = str(getattr(exc, 'message', '') or '')
    if side not in _SIDES:
        found = _SIDE_IN_MESSAGE.search(raw)
        side = found.group(1) if found else None
    message = _plain_problem(code, kind, reason or '', side)
    unbound = kind == 'binexport-unbound' or bool(
        reason and reason.startswith('executable_id_') and reason != 'executable_id_mismatch')
    technical = '\n'.join([f'Code: {code or "-"}', f'Kind: {kind or "-"}', f'Reason: {reason or "-"}',
                           f'Side: {side or "pair"}', f'Message: {sanitize_text(raw.replace(chr(10), " "), 300)}'])
    return SetupProblem(code or None, kind, reason, side, message, technical, unbound)


def _sha256_file(path: Path, cancel: threading.Event) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1 << 20):
            if cancel.is_set():
                raise SecondaryError('PT-SECONDARY-CANCEL', 'cancelled', reason='cancelled')
            digest.update(chunk)
    return digest.hexdigest()


def _same_file(older: Path, newer: Path, cancel: threading.Event) -> bool:
    """The same export chosen twice (same file, or identical bytes); a best-effort early message only."""
    try:
        if os.path.samefile(older, newer):
            return True
        first, second = os.stat(older), os.stat(newer)
        if first.st_size != second.st_size or first.st_size > MAX_BINEXPORT_BYTES:
            return False
        return _sha256_file(older, cancel) == _sha256_file(newer, cancel)
    except OSError:
        return False  # unreadable files are reported by the acceptor with their own reason


def _side_view(accepted, bound: BoundInput) -> BinExportSideView:
    summary = accepted.summary
    addresses = getattr(summary, 'function_addresses', None)
    warnings = tuple(sanitize_text(w, 80) for w in (getattr(summary, 'warnings', None) or ()))[:16]
    return BinExportSideView(bound.role, len(addresses) if addresses is not None else None,
                             sanitize_text(getattr(summary, 'architecture_name', None) or 'unknown', 60),
                             bound.id_kind, bound.file_sha256,
                             sanitize_text(getattr(summary, 'address_basis', None) or 'unknown', 16), warnings)


def _release_snapshots(folder: Path) -> None:
    """C3 snapshots are read-only (0o400); make them removable so cleanup also works on Windows."""
    for path in folder.rglob('*'):
        try:
            path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            pass


def validate_binexports(request: ValidationRequest, cancel: threading.Event, *,
                        acceptor_factory: Callable[[Path], Callable | None] | None = None,
                        progress: Callable[[str], None] | None = None) -> BinExportValidation:
    """Worker-side: accept older then newer exactly like `secondary run --engine bindiff` (CLI `c3_acceptor`,
    so C3 `accept_binexport` in its capped worker), then `bind_pair`. Snapshots live in a private temporary
    folder that is removed afterwards. Never raises for a rejected file; reports `failed`/`cancelled`."""
    key = request.key
    if cancel.is_set():
        return BinExportValidation('cancelled', key)

    def step(name: str) -> None:
        if progress is not None:
            progress(name)
    side: str | None = None
    try:
        older_path, newer_path = Path(request.older_path), Path(request.newer_path)
        if _same_file(older_path, newer_path, cancel):
            raise SecondaryError('PT-SECONDARY-PAIR', 'The same .BinExport file was supplied for both sides.',
                                 kind='binexport-same-file')
        with tempfile.TemporaryDirectory(prefix='patchtrace-bxcheck-', ignore_cleanup_errors=True) as tmp:
            try:
                acceptor = (acceptor_factory or cli_bindiff.c3_acceptor)(Path(tmp))
                if acceptor is None:
                    raise SecondaryError('PT-SECONDARY-UNSUPPORTED', 'BinExport validation is unavailable in this '
                                         'build.', kind='binexport-unsupported')
                common = dict(accept_unbound=request.accept_unbound, cancel=cancel)
                side = 'older'
                step('older')
                older = acceptor(older_path, artifact_sha256=request.older_sha256, role='older',
                                 other_sha256=request.newer_sha256, **common)
                side = 'newer'
                step('newer')
                newer = acceptor(newer_path, artifact_sha256=request.newer_sha256, role='newer',
                                 other_sha256=request.older_sha256, **common)
                side = None
                step('pair')
                pair = bind_pair(older, newer, request.older_sha256, request.newer_sha256,
                                 accept_unbound=request.accept_unbound)
                return BinExportValidation('ok', key, _side_view(older, pair.older), _side_view(newer, pair.newer),
                                           pair.provenance()['binexport_binding'])
            finally:
                _release_snapshots(Path(tmp))
    except SecondaryError as exc:
        status = 'cancelled' if exc.code == 'PT-SECONDARY-CANCEL' or cancel.is_set() else 'failed'
        return BinExportValidation(status, key, problem=describe_problem(exc, side))
    except Exception as exc:  # noqa: BLE001 - class name only; messages may carry paths
        if cancel.is_set():
            return BinExportValidation('cancelled', key)
        return BinExportValidation('failed', key, stopped=type(exc).__name__)


def setup_capability(probe: BinDiffProbeView | None, validation: BinExportValidation | None,
                     key: tuple | None) -> Capability | None:
    """The BinDiff capability the Engines tab shows. None = not configured (keep the default probe result)."""
    if probe is None:
        return None
    cap = probe.capability
    if not cap.supported:
        return cap
    current = validation is not None and validation.key == key
    if current and validation.status == 'ok':
        return cap
    version = sanitize_text(cap.version or '?', 120)
    if current and validation.status == 'failed':
        message = validation.problem.message if validation.problem else validation.message
        reason = SETUP_REASON['rejected'].format(version=version, message=message)
    else:
        reason = SETUP_REASON['inputs'].format(version=version)
    return cap.model_copy(update={'supported': False, 'reason': UNSUPPORTED_PREFIX + reason})


def bindiff_adapter(setup: BinDiffSetup, raw_dir: Path, *,
                    acceptor_factory: Callable[[Path], Callable | None] | None = None) -> BinDiffAdapter:
    """Exactly the `secondary run --engine bindiff` construction (`cli_bindiff.adapter_from_args`) from the GUI
    fields. The environment is empty on purpose: only the field counts (no `PATCHTRACE_BINDIFF`, never PATH)."""
    args = argparse.Namespace(bindiff=setup.executable, older_binexport=Path(setup.older_binexport),
                              newer_binexport=Path(setup.newer_binexport),
                              accept_unbound_binexport=bool(setup.accept_unbound))
    adapter = cli_bindiff.adapter_from_args(args, Path(raw_dir), environ={}, acceptor_factory=acceptor_factory)
    if adapter is None:  # only when nothing is configured; a BinDiffSetup always names the executable
        raise ValueError('a BinDiff setup needs an executable')
    return adapter
