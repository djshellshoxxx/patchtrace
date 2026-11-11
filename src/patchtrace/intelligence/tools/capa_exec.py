"""Qt-free local operations of the Capabilities panel (CAP-6b): probe a chosen capa, preview a run, run one side.

Nothing here starts on its own, searches PATH or reaches the network. A probe starts the chosen program with its
version options only; a run is `run_job` on a private copy of each file (the target file itself is never executed).
Results are published by the GUI thread (`publish`), because the project connection belongs to it."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...gui.text import sanitize_text
from .capa import DEFAULT_TIMEOUT, MEMORY_DEFAULT, CapaConfig, probe
from .capa_view import rules_label
from .common import DEFAULT_LIMITS, ToolManifest
from .runner import ArtifactRef, JobResult, RunRequest, Setup, run_job

BACKENDS = ('vivisect', 'ghidra')
TIMEOUT_RANGE = (10, 86_400)
PATH_LIMIT = 256   # settings text limit: a longer path is refused, never cut into a different usable path
SIDES = ('older', 'newer')
NO_NETWORK = 'no network is used'


@dataclass(frozen=True, slots=True)
class RunSpec:
    """Everything a worker needs; immutable, no widget, no connection."""
    project_dir: str
    exe: str
    backend: str
    timeout: int
    artifacts: tuple[ArtifactRef, ArtifactRef]   # older, newer

    def request(self, artifact: ArtifactRef) -> RunRequest:
        return RunRequest((artifact,), Setup(capa=self.config()), engines=('capa',), max_parallel=1,
                          timeout=self.timeout)

    def config(self) -> CapaConfig:
        return CapaConfig(Path(self.exe), backend=self.backend, timeout=self.timeout)  # type: ignore[arg-type]


def path_error(text: str) -> str | None:
    """Why `text` cannot be the capa path, or None. PATH is never searched, so only an absolute path is allowed."""
    if not text.strip():
        return 'Enter or browse to the absolute path of an installed capa.'
    if len(text) > PATH_LIMIT:
        return f'The path is longer than {PATH_LIMIT} characters; choose a shorter location.'
    if not Path(text).is_absolute():
        return 'The path must be absolute; PATH is never searched.'
    return None


def probe_tool(exe: str, backend: str, timeout: int, cancel) -> ToolManifest:
    """Worker: start the program with its version and help options only."""
    from ...jobs import run_process
    return probe(CapaConfig(Path(exe), backend=backend, timeout=timeout),  # type: ignore[arg-type]
                 cancel=cancel, runner=run_process)


def usable(manifest: ToolManifest | None, exe: str, backend: str) -> str | None:
    """Why the probed program cannot be run with these options, or None."""
    if manifest is None:
        return 'Probe the program first.'
    if not manifest.supported:
        return manifest.reason or 'The probe found this capa unusable.'
    if Path(manifest.cli_path) != Path(exe):
        return 'The path changed after the probe; probe again.'
    if manifest.backend and manifest.backend != backend:
        return 'The backend changed after the probe; probe again.'
    return None


def preview_text(spec: RunSpec, manifest: ToolManifest) -> str:
    older, newer = spec.artifacts
    limits = DEFAULT_LIMITS['capa']
    lines = [
        f'Older file: {Path(older.path).name}, sha256 {older.sha256}',
        f'Newer file: {Path(newer.path).name}, sha256 {newer.sha256}',
        f'Program: {spec.exe}, sha256 {manifest.executable_sha256}, version {manifest.version}',
        f'Rules: {rules_label(manifest)} ({manifest.rules_identity()})',
        f'Backend: {spec.backend}',
        'Command: capa is started on a private copy of each file with JSON output; the file is analysed, never run '
        'as a program. Disassembly may use instruction emulation inside capa; nothing native is executed.',
        f'Time limit per file: {spec.timeout} s (default {DEFAULT_TIMEOUT} s)',
        f'Memory cap: {MEMORY_DEFAULT // 1024 ** 3} GiB; output cap: {limits.stdout_bytes // 1024 ** 2} MiB',
        'One file at a time, in a private scratch folder that is removed afterwards.',
        f'Network: {NO_NETWORK}.']
    return sanitize_text('\n'.join(lines), 4_000, multiline=True)


def run_sides(spec: RunSpec, manifest: ToolManifest, cancel, report) -> list[JobResult]:
    """Worker: the older file, then the newer one. `report(side, n, 2)` precedes each side. A failure is that side's
    run row (`run_job` never raises)."""
    from ...jobs import run_process
    results: list[JobResult] = []
    for number, (side, artifact) in enumerate(zip(SIDES, spec.artifacts, strict=True), 1):
        report(side, number, 2)
        results.append(run_job('capa', artifact, manifest, spec.request(artifact), cancel, run_process,
                               Path(spec.project_dir)))
        if cancel.is_set():
            break
    return results


def publish(service, project, results: list[JobResult]) -> list[JobResult]:
    """GUI thread: store each run and its evidence. Returns the results that did not produce evidence."""
    from ...enrichment.storage import EnrichmentStore
    from .store import ToolStore
    tools = ToolStore(EnrichmentStore(service.store), service.root, project.id, project.revision)
    for result in results:
        tools.publish_run(result.run)
        if result.evidence is not None and not result.run.cache_hit:
            tools.publish_evidence(result.evidence)
    return [r for r in results if r.run.status not in ('ok', 'none-found')]
