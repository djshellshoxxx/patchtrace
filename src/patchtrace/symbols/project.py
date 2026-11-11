"""Backend-facing glue for `local` symbol mode (SPEC-53 GHR-3): CodeView names from the project's artifacts,
staging into the run's scratch directory, and the run-settings record. Qt-free; no network."""
from __future__ import annotations

import threading
from pathlib import Path

from .modes import SymbolError
from .staging import StagingResult, Want, stage_symbols, want_from_codeview


def wants_for_project(project, root: Path, cancel: threading.Event) -> list[Want]:
    """The PDB each side's PE asks for (verified artifact copies; a side without CodeView asks for nothing)."""
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..pe_overview import inspect_pe
    wants = []
    for artifact in project.artifacts:
        try:
            with VerifiedArtifactReader.open_artifact(artifact, root, cancel.is_set) as reader:
                overview = inspect_pe(reader, cancel=cancel.is_set)
        except ArtifactBytesError:
            continue
        want = want_from_codeview(artifact.side, overview.codeview) if overview.status != 'cancelled' else None
        if want is not None:
            wants.append(want)
    if cancel.is_set():
        raise SymbolError('PT-CANCEL', 'analysis cancelled while reading PDB identities')
    return wants


def stage_for_project(project, root: Path, dirs: tuple[str, ...], dest: Path,
                      cancel: threading.Event) -> StagingResult:
    return stage_symbols(wants_for_project(project, root, cancel), dirs, dest, cancel=cancel.is_set)


def run_settings(mode: str, result: StagingResult | None, launcher_version: str) -> dict:
    """Additive run `settings` keys (SPEC-53 section 7.3): names and hashes only, never paths."""
    staged = result.staged if result else ()
    return {'symbol_mode': mode,
            'symbol_servers': ['ghidra-configured'] if mode == 'online' else [],
            'symbol_input_digest': result.digest if result else 'none',
            'launcher_version': launcher_version if mode == 'local' else 'none',
            'staged_symbols': [{'name': s.pdb_name, 'guid_age': s.guid_age, 'sha256': s.sha256} for s in staged],
            'skipped_symbols': [{'name': s.pdb_name, 'side': s.side, 'reason': s.reason}
                                for s in (result.skipped if result else ())]}
