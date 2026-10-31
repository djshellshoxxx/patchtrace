"""Run the whole unified pipeline on corpus pairs with a REAL Ghidra and write `unified-outcomes/1` (dev only; live workflow).

usage: python -m tools.unified.live_pairs --labels DIR --store DIR --ghidra-dir DIR --out FILE [--run NAME]
           [--pairs all|ID,ID] [--roles P0,P1,mutation] [--prefix TEXT] [--limit N] [--swap]

Per label document (SPEC-32 `known-answer-labels/1` under `<calib root>/known-answer/labels/`): a project over the two
engine images (`<store>/images/<sha256>/<file>`, never executed), a real Ghidriff run that retains both programs, the
extractor in `gzf` mode on each, the sidecars placed below the run, then `unified run` with decompilation, and the stored
rows reduced to `unified-outcomes/1`. `--swap` also runs the older/newer swapped orientation of each pair (G-U4).
A pair that cannot run is listed on stderr and left out of the document, so the gate reports `insufficient-data`
for it instead of a pass. Exit codes: 0 ok, 1 a pair failed, 2 usage or contract error.
"""
from __future__ import annotations

import argparse
import platform
import shutil
import sys
import tempfile
import threading
from collections.abc import Sequence
from pathlib import Path

from patchtrace import backend as backend_module
from patchtrace.backend import BackendConfig
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline, store
from patchtrace.unified.ir.place import place_ir
from tools.calibration.tier_r import contracts as C
from tools.live_unified_check import EXTRACT_TIMEOUT_S, Side, file_sha256
from tools.unified import outcomes
from tools.unified.corpus import manifest as corpus_manifest

OK, PAIR_FAILED, USAGE = 0, 1, 2


def image_path(store_dir: Path, side: C.ImageSide) -> Path:
    path = Path(store_dir) / 'images' / side.sha256 / side.file_name
    if not path.is_file():
        raise FileNotFoundError(f'image {side.sha256[:12]} {side.file_name} is not in the store')
    return path


def load_labels(directory: Path) -> list[C.KnownAnswerLabels]:
    return [C.load_labels(p.read_bytes()) for p in sorted(Path(directory).glob('*.json'))]


def select(docs: Sequence[C.KnownAnswerLabels], pairs: str, roles: str, prefix: str = '') -> list[C.KnownAnswerLabels]:
    wanted = None if pairs == 'all' else set(pairs.split(','))
    kinds = None if roles == 'all' else set(roles.split(','))
    chosen = []
    for doc in docs:
        role, _ = corpus_manifest.role_of(doc)
        if role is not None and (wanted is None or doc.pair_id in wanted) and (kinds is None or role in kinds) \
                and doc.pair_id.startswith(prefix):
            chosen.append(doc)
    return chosen


def outcome_of(service: ProjectService, doc: C.KnownAnswerLabels, orientation: outcomes.Orientation) -> outcomes.PairOutcome:
    """The rows of the current stored unified result of the project, reduced; nothing is recomputed."""
    loaded = pipeline.load_current(service, pipeline.make_plan(service))
    facts = {f.row_id: f for f in store.read_facts(loaded.directory, loaded.manifest)}
    modified = frozenset(m.id for m in service.project.matches if m.category == 'modified')
    return outcomes.collect(store.read_rows(loaded.directory, loaded.manifest), doc, orientation=orientation,
                            facts=facts, flagged={'ghidriff': modified})


def analyse_pair(doc: C.KnownAnswerLabels, store_dir: Path, backend: BackendConfig, work: Path,
                 orientation: outcomes.Orientation) -> outcomes.PairOutcome:
    old, new = image_path(store_dir, doc.older), image_path(store_dir, doc.newer)
    if orientation == 'swapped':
        old, new = new, old
    retaining = BackendConfig(backend.python_executable, backend.ghidra_dir, backend.timeout_seconds, retain_gzf=True)
    service = ProjectService.create(old, new, doc.pair_id, work / f'{doc.pair_id}-{orientation}')
    sides: dict[str, Side] = {}
    try:
        raw_path, run = backend_module.run_comparison(retaining, service.project, service.root,
                                                      threading.Event(), lambda _e: None)
        if run.status != 'completed':
            # A/A identical-byte controls are NOT successful native evaluations: preserve the
            # distinct status without producing a fabricated zero-change result.
            reason = f'Ghidriff run {run.status}: {run.error}'
            if run.status == 'failed':
                # The backend has already redacted and written this log into its private
                # quarantine. Surface a bounded tail in the CI job log before work cleanup;
                # the old live workflow otherwise lost the real native failure evidence.
                log = Path(raw_path) / 'analysis.log'
                if log.is_file() and not log.is_symlink():
                    tail = backend_module.redact_log(
                        log.read_text(encoding='utf-8', errors='replace')[-4096:], 2048)
                    if tail:
                        reason += f' [analysis.log tail: {tail}]'
            raise RuntimeError(reason)
        # run_comparison writes the raw result but deliberately does NOT mutate
        # ProjectService. Unified planning requires a persisted completed native run.
        service.apply_analysis(raw_path, run)
        gzf = service.root / 'runs' / run.id / 'unified' / 'gzf'
        for label, dll, other in (('older', old, new), ('newer', new, old)):
            sides[label] = Side(label, dll, file_sha256(other), backend, work)
            program = gzf / f'{label}.gzf'
            built = sides[label].run('gzf', program, file_sha256(program))
            place_ir(service.root, run.id, built['directory'])
        pipeline.run_unified(service, pipeline.UnifiedOptions(backend=backend, timeout_s=EXTRACT_TIMEOUT_S))
        return outcome_of(service, doc, orientation)
    finally:
        for side in sides.values():
            side.close()
        service.close()


def run_all(docs: Sequence[C.KnownAnswerLabels], store_dir: Path, backend: BackendConfig, *, swap: bool,
            work: Path) -> tuple[list[outcomes.PairOutcome], list[str]]:
    done, failed = [], []
    for doc in docs:
        for orientation in ('forward', 'swapped') if swap else ('forward',):
            try:
                done.append(analyse_pair(doc, store_dir, backend, work, orientation))
            except Exception as exc:        # a pair that cannot run is reported, never skipped silently
                failed.append(f'{doc.pair_id} ({orientation}): {type(exc).__name__}: {exc}')
    return done, failed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m tools.unified.live_pairs', description=__doc__.split('\n\n')[0])
    parser.add_argument('--labels', required=True, type=Path)
    parser.add_argument('--store', required=True, type=Path)
    parser.add_argument('--ghidra-dir', required=True, type=Path)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--run', default='live')
    parser.add_argument('--pairs', default='all')
    parser.add_argument('--roles', default='all')
    parser.add_argument('--prefix', default='', help='keep pair ids that start with this text (a mutant class: mut-<class>-)')
    parser.add_argument('--limit', type=int, default=0, help='at most N pairs per role (0 = all)')
    parser.add_argument('--swap', action='store_true')
    args = parser.parse_args(argv)
    try:
        docs = select(load_labels(args.labels), args.pairs, args.roles, args.prefix)
        if args.limit:
            seen: dict[str, int] = {}
            kept = []
            for doc in docs:
                role = corpus_manifest.role_of(doc)[0]
                seen[role] = seen.get(role, 0) + 1
                if seen[role] <= args.limit:
                    kept.append(doc)
            docs = kept
        if not docs:
            raise C.ContractError('no label document selected')
    except (C.ContractError, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return USAGE
    backend = BackendConfig(args.python, str(args.ghidra_dir.resolve()), 1800)
    work = Path(tempfile.mkdtemp(prefix='ptpairs-')).resolve()
    try:
        done, failed = run_all(docs, args.store, backend, swap=args.swap, work=work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(outcomes.dump(outcomes.build(args.run, f'{platform.system()}-{platform.release()}', done)))
    print(f'{len(done)} outcomes written to {args.out}')
    if failed:
        print('\n'.join(failed), file=sys.stderr)
    return PAIR_FAILED if failed else OK


if __name__ == '__main__':
    raise SystemExit(main())
