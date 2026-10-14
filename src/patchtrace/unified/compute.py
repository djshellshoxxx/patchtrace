"""SPEC-31 compute step (01 s5 `compute`): sources -> fusion -> S0 facts -> result files, plus the identity that
tells the owner the `result_id` BEFORE the run. Pure given its inputs and free of the project database: the worker
child calls it, and so does the in-process mode (`--in-process`, tests; B-20).

Layer: above `facts`, below `pipeline` and `worker` (01 s3). S0 mode has no ProgramIR; the same inputs in any order
give byte-identical parts (G-U4).
"""
from __future__ import annotations

import dataclasses
import json
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from . import keys, store
from .addressing import AddressMap, PeLayout
from .contracts import ResultKeyInputs, SourceRef, UnifiedMatch, UnifiedResultManifest
from .exchange import (
    ALL_SOURCES,
    StageEvent,
    WorkerReport,
    fail,
    inside,
    read_request,
    write_atomic,
)
from .facts import verdict
from .facts.channels import FactsContext
from .fusion import arbiter
from .limits import DEFAULT_LIMITS, Budget, UnifiedError, UnifiedLimits
from .registry import REGISTRY, Registry
from .sources import DEGRADING, GhidriffRun, RawGhidriff, SourceInputs, read_snapshot
from .sources.ghidriff import GhidriffAdapter, load_raw
from .sources.manual import ManualAdapter, manual_digest_of
from .sources.secondary import SecondaryAdapter, bindiff_flags, read_loaded, source_ref_of

DEGRADING_SUFFIXES = ('-address-basis-not-comparable', '-pair-mismatch')


@dataclass(frozen=True)
class Identity:
    source_refs: tuple[SourceRef, ...]
    manual_digest: str
    config_digest: str
    result_id: str
    key_inputs: ResultKeyInputs


def compute_config_digest(registry: Registry = REGISTRY, limits: UnifiedLimits = DEFAULT_LIMITS) -> str:
    return keys.config_digest(
        pass_table_digest=registry.pass_table_digest(), registry_digest=registry.digest(),
        channel_versions=dict(registry.channel_versions), proof_versions=dict(registry.proof_versions),
        limits_digest=keys.limits_digest(limits))


def plan_identity(inputs: SourceInputs, addr: AddressMap, sources: Iterable[str], registry: Registry = REGISTRY,
                  limits: UnifiedLimits = DEFAULT_LIMITS) -> Identity:
    """The inputs that make a result (02 s5) without computing it: the owner calls this before the run (cache
    lookup) and again with the worker's observed raw status to check the answer."""
    selected = frozenset(sources)
    refs: list[SourceRef] = []
    if 'ghidriff' in selected:
        refs.append(GhidriffAdapter(registry).source_ref(inputs))
    # Every stored set of a selected engine is an input, one for another pair included: it is refused with a
    # degrading limitation, which changes the result, so it must change the id (same id, same content).
    refs.extend(source_ref_of(s) for s in inputs.secondary if s.match_set.engine in selected)
    manual_refs = ManualAdapter().source_refs(inputs, addr) if 'manual' in selected else ()
    refs.extend(manual_refs)
    manual = manual_digest_of(inputs, addr) if manual_refs else keys.manual_digest([])
    config = compute_config_digest(registry, limits)
    raw_sha = inputs.run.raw.sha256
    if raw_sha is None:
        raise fail('PT-UNIFIED-INPUT', 'no-raw-hash')
    ordered = tuple(sorted(refs, key=lambda r: (r.source, r.entry_id, r.file_sha256 or '', r.version)))
    key_inputs = ResultKeyInputs(older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256,
                                 ghidriff_raw_sha256=raw_sha, ir_older_digest=None, ir_newer_digest=None,
                                 sources=ordered, manual_digest=manual, config_digest=config)
    return Identity(ordered, manual, config, keys.result_key(key_inputs), key_inputs)


def is_degrading(limitation: str) -> bool:
    """A limitation that makes the result `partial` (a missing or unusable input), as opposed to a plain note."""
    slug = limitation.split(':', 1)[0]
    return slug in DEGRADING or slug.endswith(DEGRADING_SUFFIXES)


def compute_result(inputs: SourceInputs, addr: AddressMap, *, result_dir: Path, sources: Iterable[str] = ALL_SOURCES,
                   registry: Registry = REGISTRY, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
                   emit: Callable[[StageEvent], None] | None = None,
                   created_utc: str | None = None) -> UnifiedResultManifest:
    """Sources -> fusion -> S0 facts -> parts and manifest in `result_dir`."""
    budget = budget or Budget()
    say = emit or (lambda _event: None)
    selected = frozenset(sources)
    ident = plan_identity(inputs, addr, selected, registry, limits)
    say(StageEvent('sources', 0, 3))
    scoped = dataclasses.replace(inputs, secondary=tuple(s for s in inputs.secondary
                                                          if s.match_set.engine in selected))
    outputs = []
    if 'ghidriff' in selected:
        outputs.append(GhidriffAdapter(registry).atoms(inputs, addr, budget))
    if scoped.secondary:
        outputs.append(SecondaryAdapter(registry).atoms(scoped, addr, budget))
    if 'manual' in selected:
        outputs.append(ManualAdapter().atoms(inputs, addr, budget))
    atoms = [a for o in outputs for a in o.atoms]
    groups = [g for o in outputs for g in o.groups]
    nodes = arbiter.merge_nodes(o.nodes for o in outputs)
    say(StageEvent('fusion', 1, 3))
    decided = arbiter.decide(atoms, groups, nodes, registry=registry, budget=budget, limits=limits)
    say(StageEvent('facts', 2, 3))
    context = FactsContext.build(older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256, addr=addr,
                                 matches=inputs.matches, rows=decided, bindiff_flags=bindiff_flags(scoped, addr),
                                 limits=limits)
    rows: list[UnifiedMatch] = []
    facts = []
    for d in decided:
        budget.tick()
        if d.pair is not None and d.decision in ('matched', 'tentative', 'candidate', 'contested'):
            row_id = keys.row_id(inputs.older_sha256, inputs.newer_sha256, d.older, d.newer)
            judged = verdict.judge(row_id, d.decision, context.collect(d), limits)
            facts.append(judged.facts)
            rows.append(arbiter.to_match(d, nodes, inputs.older_sha256, inputs.newer_sha256,
                                         materiality=judged.facts.verdict, change_classes=judged.classes,
                                         extra_hints=judged.hints))
        else:
            rows.append(arbiter.to_match(d, nodes, inputs.older_sha256, inputs.newer_sha256))
    say(StageEvent('write', 3, 3))
    limitations = sorted({'ir-not-extracted', *(x for o in outputs for x in o.limitations)})
    status = 'partial' if any(is_degrading(x) for x in limitations) else 'complete'
    return store.write_result(
        Path(result_dir), older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256,
        ghidriff_run_id=inputs.run.run_id, ghidriff_raw_sha256=inputs.run.raw.sha256 or '0' * 64, ir_older=None,
        ir_newer=None, sources=ident.source_refs, manual_digest=ident.manual_digest, config_digest=ident.config_digest,
        status=status, limitations=limitations, rows=rows, facts=facts, created_utc=created_utc, limits=limits)


def run_request(request_path: Path, result_dir: Path, *, cancel: threading.Event | None = None,
                emit: Callable[[StageEvent], None] | None = None, limits: UnifiedLimits = DEFAULT_LIMITS,
                registry: Registry = REGISTRY) -> WorkerReport:
    """Load the request's inputs (every file re-hashed), compute into `result_dir` and describe the outcome."""
    started = time.monotonic()
    request_path = Path(request_path).resolve()
    req = read_request(request_path)
    private = request_path.parent
    snapshot = read_snapshot(inside(req.snapshot.path, private), expected_sha256=req.snapshot.sha256,
                             expected_lines=req.snapshot_lines, limits=limits)
    secondary = tuple(read_loaded(inside(f.path, private), expected_sha256=f.sha256, expected_size=f.size)
                      for f in req.secondary)
    if req.raw_status == 'ok':
        raw = load_raw(Path(req.raw_path) if req.raw_path else None, req.raw_sha256, limits)
    else:
        raw = RawGhidriff(status=req.raw_status, sha256=req.raw_sha256)
    inputs = SourceInputs(older_sha256=req.older_sha256, newer_sha256=req.newer_sha256,
                          run=GhidriffRun(run_id=req.run_id, backend_version=req.backend_version, raw=raw),
                          matches=snapshot, secondary=secondary)
    addr = AddressMap(PeLayout(**req.older_layout.model_dump()), PeLayout(**req.newer_layout.model_dump()))
    marks: dict[str, int] = {}

    def forward(event: StageEvent) -> None:
        marks[event.stage] = int((time.monotonic() - started) * 1000)
        if req.progress_path:
            try:
                write_atomic(inside(req.progress_path, private),
                             json.dumps({'stage': event.stage, 'done': event.done, 'total': event.total}).encode())
            except (OSError, UnifiedError):
                pass
        if emit:
            emit(event)
    manifest = compute_result(inputs, addr, result_dir=Path(result_dir), sources=req.sources, registry=registry,
                              limits=limits, budget=Budget.after(req.budget_seconds, cancel), emit=forward)
    return WorkerReport(ok=True, status=manifest.status, result_id=manifest.result_id, raw_status=raw.status,
                        rows=manifest.counts.total(),
                        facts=next(p.records for p in manifest.parts if p.name == 'facts.jsonl.gz'),
                        limitations=manifest.limitations, stage_ms=marks)
