"""BinDiff, only from files the user supplied: a finished `<pair_id>.BinDiff` (read by the production hardened importer)
or a `<pair_id>.older.BinExport` + `<pair_id>.newer.BinExport` pair driven through the supervised runner (C3
`accept_binexport`, `bind_pair`, `run_bindiff`; fixed argv, allow-listed environment, no PATH lookup). The executable is
an explicit path (`executable` or `PATCHTRACE_BINDIFF`). Without a BinDiff, a `.BinDiff` or a `.BinExport` pair the
engine is `blocked` with its reason, never a zero. The export-driven path has been run only against fakes here (no BinDiff
installation in CI); the first real run is a live check."""
from __future__ import annotations

import os
import tempfile
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.bindiff_inputs import bind_pair
from patchtrace.secondary.bindiff_probe import probe
from patchtrace.secondary.bindiff_run import DEFAULT_TIMEOUT, run_bindiff
from patchtrace.secondary.binexport_run import accept_binexport
from patchtrace.secondary.contracts import SecondaryError

from .common import EngineOutput, blocked, failed, from_match_set

ENV_VAR = 'PATCHTRACE_BINDIFF'


class BindiffImportProvider:
    """`<imports>/<pair_id>.BinDiff` placed by the user, read by the production hardened importer."""
    engine = 'bindiff'

    def __init__(self, imports: Path | None):
        self.imports = None if imports is None else Path(imports)

    def __call__(self, labels, symbols):
        path = None if self.imports is None else self.imports / f'{labels.pair_id}.BinDiff'
        if path is None or not path.is_file():
            return blocked(self.engine, 'no BinDiff installation was driven and no imported '
                           f'{labels.pair_id}.BinDiff exists in the imports folder')
        osha, nsha = (s.sha256 if symbols == 'hidden' else s.debug_sha256 for s in (labels.older, labels.newer))
        try:
            match_set = import_bindiff(path, osha, nsha)
        except SecondaryError as exc:
            return failed(self.engine, exc.message)
        return from_match_set(self.engine, match_set, labels.older.image_base)


class BindiffProvider:
    """An imported `.BinDiff` wins; otherwise a supplied `.BinExport` pair is diffed by a BinDiff the user pointed to."""
    engine = 'bindiff'

    def __init__(self, imports: Path | None, *, executable: str | None = None,
                 environ: Mapping[str, str] | None = None, timeout_seconds: int = DEFAULT_TIMEOUT,
                 probe_fn: Callable = probe, accept_fn: Callable = accept_binexport, run_fn: Callable = run_bindiff):
        self.imports = None if imports is None else Path(imports)
        self.executable = executable or (os.environ if environ is None else environ).get(ENV_VAR)
        self.timeout_seconds = timeout_seconds
        self.probe_fn, self.accept_fn, self.run_fn = probe_fn, accept_fn, run_fn
        self._imported = BindiffImportProvider(imports)

    def _exports(self, labels) -> tuple[Path, Path] | None:
        if self.imports is None:
            return None
        pair = (self.imports / f'{labels.pair_id}.older.BinExport', self.imports / f'{labels.pair_id}.newer.BinExport')
        return pair if all(p.is_file() for p in pair) else None

    def __call__(self, labels, symbols) -> EngineOutput:
        if self.imports is not None and (self.imports / f'{labels.pair_id}.BinDiff').is_file():
            return self._imported(labels, symbols)
        exports = self._exports(labels)
        if exports is None:
            return blocked(self.engine, f'no imported {labels.pair_id}.BinDiff and no {labels.pair_id}.older.BinExport'
                           f' + .newer.BinExport pair exists in the imports folder')
        if not self.executable:
            return blocked(self.engine, f'a BinExport pair exists but no BinDiff executable was given (pass a path or '
                           f'set {ENV_VAR}; it is never searched for)')
        cancel = threading.Event()
        capability = self.probe_fn(self.executable, cancel=cancel)
        if not capability.supported:
            return blocked(self.engine, capability.reason or 'BinDiff is not usable on this machine')
        osha, nsha = (s.sha256 if symbols == 'hidden' else s.debug_sha256 for s in (labels.older, labels.newer))
        try:
            with tempfile.TemporaryDirectory(prefix='ptbd') as scratch:
                work = Path(scratch)
                (work / 'in').mkdir()
                older = self.accept_fn(exports[0], artifact_sha256=osha, role='older', private_dir=work / 'in',
                                       cancel=cancel)
                newer = self.accept_fn(exports[1], artifact_sha256=nsha, role='newer', private_dir=work / 'in',
                                       cancel=cancel)
                outcome = self.run_fn(capability, bind_pair(older, newer, osha, nsha), work / 'raw', osha, nsha,
                                      cancel=cancel, timeout_seconds=self.timeout_seconds)
        except SecondaryError as exc:
            return failed(self.engine, exc.message)
        return from_match_set(self.engine, outcome.match_set, labels.older.image_base)
