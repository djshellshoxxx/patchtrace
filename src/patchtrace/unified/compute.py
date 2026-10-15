"""SPEC-31 compute step (01 s5 `compute`): sources -> (ladder) -> fusion -> facts -> result files, plus the identity that
tells the owner the `result_id` BEFORE the run. Pure given its inputs and free of the project database: the worker
child calls it, and so does the in-process mode (`--in-process`, tests; B-20).

Layer: above `facts`, below `pipeline` and `worker` (01 s3). Without ProgramIR this is S0 mode: external engines and
the analyst's corrections only, the S0 channels of the stored code. With `IrInputs` (two verified sidecars) the ladder
(P00-P19, the residual passes P16-P19 unless backup B-07 switches them off) adds its atoms as sources `pt-ladder` and
`pt-bytes`, and the facts use the IR channels C0-C5 with the structural proofs. The same inputs in any order give
byte-identical parts (G-U4).
"""
from __future__ import annotations

import dataclasses
import json
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ..enrichment.identity import domain_id
from . import keys, store
from .addressing import AddressMap, PeLayout
from .contracts import ChangeFacts, IrRef, ResultKeyInputs, SourceRef, UnifiedMatch, UnifiedResultManifest
from .exchange import (
    ALL_SOURCES,
    StageEvent,
    WorkerIr,
    WorkerRefacts,
    WorkerReport,
    fail,
    inside,
    read_refacts,
    read_request,
    write_atomic,
)
from .facts import verdict
from .facts.channels import FactsContext
from .facts.irchannels import IrSides
from .facts.refacts import select_for_decompile
from .fusion import arbiter
from .ir.ladder_port import ReaderMnemonics, ReaderSide
from .ir.reader import IrReader
from .ladder.engine import run_ladder
from .ladder.residual import pass_table, table_digest
from .limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError, UnifiedLimits
from .registry import REGISTRY, Registry
from .sources import DEGRADING, AdapterOutput, GhidriffRun, RawGhidriff, SourceInputs, read_snapshot
from .sources.ghidriff import GhidriffAdapter, load_raw
from .sources.ladder import anchor_pairs, ladder_output
from .sources.manual import ManualAdapter, manual_digest_of
from .sources.secondary import SecondaryAdapter, bindiff_flags, read_loaded, source_ref_of

TIMEOUT = 'timeout'    # limitation: the deadline passed after the ladder began; unfinished rows stay `unknown` (U7-06)
DEGRADING_SUFFIXES = ('-address-basis-not-comparable', '-pair-mismatch')
Sections = tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Identity:
    source_refs: tuple[SourceRef, ...]
    manual_digest: str
    config_digest: str
    result_id: str
    key_inputs: ResultKeyInputs


@dataclass(frozen=True)
class IrInputs:
    """The two ProgramIR sidecars of a run, opened and verified by the caller, and the PE sections (start rva, end
    rva) that DATA-MAP/1 needs for its region shift. The caller owns the readers and closes them."""
    older: IrReader
    newer: IrReader
    older_sections: Sections = ()
    newer_sections: Sections = ()

    def digests(self) -> tuple[str, str]:
        return self.older.manifest.content_digest, self.newer.manifest.content_digest

    def refs(self) -> tuple[IrRef, IrRef]:
        def ref(reader: IrReader) -> IrRef:
            manifest = reader.manifest
            return IrRef(ir_key=manifest.ir_key, content_digest=manifest.content_digest,
                         producer_mode=manifest.producer.mode, functions=manifest.counts.functions)
        return ref(self.older), ref(self.newer)


@dataclass(frozen=True)
class Computed:
    """A staged result: its manifest and the pairs worth an on-demand decompile (S3b, 05 s2.8; none without IR)."""
    manifest: UnifiedResultManifest
    refacts: tuple[tuple[int, int], ...] = ()


def pass_tables_digest(registry: Registry = REGISTRY, *, residual: bool = True) -> str:
    """The `pass_table_digest` input of `keys.config_digest`: the executable ladder table (with the residual passes
    unless backup B-07 skips them, `residual.table_digest`) together with the registry's pass rows, which decide the
    family and evidence class of every atom the ladder makes."""
    return domain_id('unified-pass-tables', 1, {'registry': registry.pass_table_digest(),
                                                'ladder': table_digest(pass_table(residual=residual))})


def compute_config_digest(registry: Registry = REGISTRY, limits: UnifiedLimits = DEFAULT_LIMITS, *,
                          residual: bool = True) -> str:
    return keys.config_digest(
        pass_table_digest=pass_tables_digest(registry, residual=residual), registry_digest=registry.digest(),
        channel_versions=dict(registry.channel_versions), proof_versions=dict(registry.proof_versions),
        limits_digest=keys.limits_digest(limits))


def plan_identity(inputs: SourceInputs, addr: AddressMap, sources: Iterable[str], registry: Registry = REGISTRY,
                  limits: UnifiedLimits = DEFAULT_LIMITS, *, ir: tuple[str, str] | None = None,
                  residual: bool = True) -> Identity:
    """The inputs that make a result (02 s5) without computing it: the owner calls this before the run (cache
    lookup) and again with the worker's observed raw status to check the answer. `ir` = the content digests of the
    two ProgramIR sidecars the run will use, or None for S0 mode."""
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
    config = compute_config_digest(registry, limits, residual=residual)
    raw_sha = inputs.run.raw.sha256
    if raw_sha is None:
        raise fail('PT-UNIFIED-INPUT', 'no-raw-hash')
    ordered = tuple(sorted(refs, key=lambda r: (r.source, r.entry_id, r.file_sha256 or '', r.version)))
    key_inputs = ResultKeyInputs(older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256,
                                 ghidriff_raw_sha256=raw_sha, ir_older_digest=None if ir is None else ir[0],
                                 ir_newer_digest=None if ir is None else ir[1], sources=ordered,
                                 manual_digest=manual, config_digest=config)
    return Identity(ordered, manual, config, keys.result_key(key_inputs), key_inputs)


def is_degrading(limitation: str) -> bool:
    """A limitation that makes the result `partial` (a missing or unusable input), as opposed to a plain note."""
    slug = limitation.split(':', 1)[0]
    return slug in DEGRADING or slug == TIMEOUT or slug.endswith(DEGRADING_SUFFIXES)


def _ladder(ir: IrInputs, manual: AdapterOutput, limits: UnifiedLimits, budget: Budget, residual: bool) -> AdapterOutput:
    """Run the ladder over the two sidecars: the analyst's 1:1 corrections are the P00 anchors, the residual passes
    read their mnemonics from the sidecars on demand."""
    anchors, outside = anchor_pairs(manual.atoms, ir.older, ir.newer)
    passes = pass_table(residual=residual, older=ReaderMnemonics(ir.older), newer=ReaderMnemonics(ir.newer))
    correspondence = run_ladder(ReaderSide(ir.older, limits), ReaderSide(ir.newer, limits), anchors=anchors,
                                limits=limits, budget=budget, passes=passes)
    return ladder_output(correspondence, ir.older, ir.newer, anchors_skipped=outside)


def _announce(emit: Callable[[StageEvent], None] | None, ir: bool) -> Callable[[str], None]:
    steps = ('sources', *(('ladder',) if ir else ()), 'fusion', 'facts', 'write')

    def say(step: str) -> None:
        if emit is not None:
            emit(StageEvent(step, steps.index(step), len(steps) - 1))
    return say


def compute_stage(inputs: SourceInputs, addr: AddressMap, *, result_dir: Path, sources: Iterable[str] = ALL_SOURCES,
                  registry: Registry = REGISTRY, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
                  emit: Callable[[StageEvent], None] | None = None, created_utc: str | None = None,
                  ir: IrInputs | None = None, residual: bool = True) -> Computed:
    """Sources -> ladder (with `ir`) -> fusion -> facts -> parts and manifest in `result_dir`."""
    budget = budget or Budget()
    say = _announce(emit, ir is not None)
    selected = frozenset(sources)
    ident = plan_identity(inputs, addr, selected, registry, limits, residual=residual)  # refs and digests of the manifest
    say('sources')
    scoped = dataclasses.replace(inputs, secondary=tuple(s for s in inputs.secondary
                                                          if s.match_set.engine in selected))
    outputs = []
    if 'ghidriff' in selected:
        outputs.append(GhidriffAdapter(registry).atoms(inputs, addr, budget))
    if scoped.secondary:
        outputs.append(SecondaryAdapter(registry).atoms(scoped, addr, budget))
    manual = ManualAdapter().atoms(inputs, addr, budget) if 'manual' in selected else AdapterOutput()
    if 'manual' in selected:
        outputs.append(manual)
    if ir is not None:
        say('ladder')
        outputs.append(_ladder(ir, manual, limits, budget, residual))
    atoms = [a for o in outputs for a in o.atoms]
    groups = [g for o in outputs for g in o.groups]
    nodes = arbiter.merge_nodes(o.nodes for o in outputs)
    say('fusion')
    if budget.cancel is not None and budget.cancel.is_set():
        budget.check()                              # a cancel always aborts; only a spent deadline keeps the partial
    # U7-06: a deadline the ladder already spent must not discard its partial result, so fusion and the fact context
    # (bounded work over the ladder's output) run under a cancel-only budget and the row loop below stops by itself.
    late = ir is not None and budget.expired()
    shared = Budget(None, budget.cancel, check_every=budget.check_every, clock=budget.clock) if late else budget
    decided = arbiter.decide(atoms, groups, nodes, registry=registry, budget=shared, limits=limits)
    say('facts')
    sides = None if ir is None else IrSides(ir.older, ir.newer, ir.older_sections, ir.newer_sections,
                                            identical=inputs.older_sha256 == inputs.newer_sha256)
    context = FactsContext.build(older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256, addr=addr,
                                 matches=inputs.matches, rows=decided, bindiff_flags=bindiff_flags(scoped, addr),
                                 limits=limits, ir_sides=sides, budget=shared)
    rows: list[UnifiedMatch] = []
    facts = []
    judged_pairs = []
    truncated = False
    for d in decided:
        if not truncated:
            try:
                budget.tick()
            except BudgetExhausted as exc:
                if exc.code == 'PT-UNIFIED-CANCEL':
                    raise
                truncated = True                    # the rest keep their decision and an `unknown` materiality
        if not truncated and d.pair is not None and d.decision in ('matched', 'tentative', 'candidate', 'contested'):
            row_id = keys.row_id(inputs.older_sha256, inputs.newer_sha256, d.older, d.newer)
            judged = verdict.judge(row_id, d.decision, context.collect(d), limits)
            facts.append(judged.facts)
            judged_pairs.append((d.pair, judged))
            rows.append(arbiter.to_match(d, nodes, inputs.older_sha256, inputs.newer_sha256,
                                         materiality=judged.facts.verdict, change_classes=judged.classes,
                                         extra_hints=judged.hints, flags=judged.flags))
        else:
            rows.append(arbiter.to_match(d, nodes, inputs.older_sha256, inputs.newer_sha256))
    say('write')
    limitations = sorted({*(['ir-not-extracted'] if ir is None else []), *(x for o in outputs for x in o.limitations)})
    if truncated or 'ladder-partial:deadline' in limitations:
        limitations = sorted({*limitations, TIMEOUT})
    status = 'partial' if any(is_degrading(x) for x in limitations) else 'complete'
    refs = (None, None) if ir is None else ir.refs()
    manifest = store.write_result(
        Path(result_dir), older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256,
        ghidriff_run_id=inputs.run.run_id, ghidriff_raw_sha256=inputs.run.raw.sha256 or '0' * 64, ir_older=refs[0],
        ir_newer=refs[1], sources=ident.source_refs, manual_digest=ident.manual_digest,
        config_digest=ident.config_digest, status=status, limitations=limitations, rows=rows, facts=facts,
        created_utc=created_utc, limits=limits)
    refacts = tuple(select_for_decompile(judged_pairs, limits.l41_decompile_pairs)) if ir is not None else ()
    return Computed(manifest, refacts)


def compute_result(inputs: SourceInputs, addr: AddressMap, *, result_dir: Path, sources: Iterable[str] = ALL_SOURCES,
                   registry: Registry = REGISTRY, limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
                   emit: Callable[[StageEvent], None] | None = None, created_utc: str | None = None,
                   ir: IrInputs | None = None, residual: bool = True) -> UnifiedResultManifest:
    """`compute_stage` for callers that only want the manifest."""
    return compute_stage(inputs, addr, result_dir=result_dir, sources=sources, registry=registry, limits=limits,
                         budget=budget, emit=emit, created_utc=created_utc, ir=ir, residual=residual).manifest


def refacts_stage(inputs: SourceInputs, addr: AddressMap, *, result_dir: Path, ir: IrInputs, refacts: WorkerRefacts,
                  sources: Iterable[str] = ALL_SOURCES, registry: Registry = REGISTRY,
                  limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
                  emit: Callable[[StageEvent], None] | None = None, residual: bool = True) -> UnifiedResultManifest:
    """S3b second phase (05 s2.8, 01 s5 `refacts`): the staged result of `compute_stage` is read back, the decided rows
    are rebuilt from its rows (no second ladder, no second fusion), the chosen pairs are judged again with the C text of
    their two sides as the second channel (`FactsContext.build(decompiled=)`), and the parts and the manifest are
    written again. A pair without a text on both sides is left as it is. The result id does not change: the text is
    deterministic given the retained programs and is not an input of the key (a text only ever adds a second channel)."""
    budget = budget or Budget()
    result_dir = Path(result_dir)
    if emit is not None:
        emit(StageEvent('refacts', 0, 1))
    manifest, _sha = store.read_manifest(result_dir)
    selected = frozenset(sources)
    if manifest.result_id != plan_identity(inputs, addr, selected, registry, limits, ir=ir.digests(),
                                           residual=residual).result_id:
        raise UnifiedError('PT-UNIFIED-STORE', 'The staged result is not the one this request describes',
                           reason='staged-mismatch')
    texts = {side: refacts.texts(side) for side in ('older', 'newer')}
    usable = [pair for pair in refacts.pairs if pair[0] in texts['older'] and pair[1] in texts['newer']]
    if not usable:
        return manifest
    rows = list(store.read_rows(result_dir, manifest, limits))
    facts = list(store.read_facts(result_dir, manifest, limits))
    decided = [arbiter.decided_from_match(row) for row in rows]
    nodes = {key: info for row in rows for key, info in arbiter.node_info(row).items()}
    scoped = dataclasses.replace(inputs, secondary=tuple(s for s in inputs.secondary
                                                          if s.match_set.engine in selected))
    sides = IrSides(ir.older, ir.newer, ir.older_sections, ir.newer_sections,
                    identical=inputs.older_sha256 == inputs.newer_sha256)
    context = FactsContext.build(older_sha256=inputs.older_sha256, newer_sha256=inputs.newer_sha256, addr=addr,
                                 matches=inputs.matches, rows=decided, bindiff_flags=bindiff_flags(scoped, addr),
                                 limits=limits, ir_sides=sides, budget=budget, decompiled=texts)
    index = {d.pair: i for i, d in enumerate(decided) if d.pair is not None}
    again: dict[str, ChangeFacts] = {}
    for pair in usable:
        budget.tick()
        position = index.get(pair)
        if position is None:
            continue
        d = decided[position]
        judged = verdict.judge(rows[position].row_id, d.decision, context.collect(d), limits)
        again[rows[position].row_id] = judged.facts
        rows[position] = arbiter.to_match(d, nodes, inputs.older_sha256, inputs.newer_sha256,
                                          materiality=judged.facts.verdict, change_classes=judged.classes,
                                          extra_hints=judged.hints, flags=judged.flags)
    if emit is not None:
        emit(StageEvent('refacts', 1, 1))
    return store.write_result(
        result_dir, older_sha256=manifest.older_sha256, newer_sha256=manifest.newer_sha256,
        ghidriff_run_id=manifest.ghidriff_run_id, ghidriff_raw_sha256=manifest.ghidriff_raw_sha256,
        ir_older=manifest.ir_older, ir_newer=manifest.ir_newer, sources=manifest.sources,
        manual_digest=manifest.manual_digest, config_digest=manifest.config_digest, status=manifest.status,
        limitations=manifest.limitations, rows=rows, facts=[again.get(f.row_id, f) for f in facts],
        created_utc=manifest.created_utc, limits=limits)


def _check_ir_side(side: str, reader: IrReader, spec: WorkerIr, artifact_sha256: str, other_sha256: str,
                   layout) -> None:
    manifest = reader.manifest
    if manifest.ir_key != spec.ir_key or manifest.content_digest != spec.content_digest:
        raise UnifiedError('PT-UNIFIED-STALE', 'The ProgramIR changed after the request was made', reason='ir-changed')
    if manifest.artifact_sha256 != artifact_sha256:
        if manifest.artifact_sha256 == other_sha256 and artifact_sha256 != other_sha256:
            raise fail('PT-UNIFIED-ORIENTATION', 'ir-reversed')
        raise fail('PT-UNIFIED-PAIR', f'ir-{side}-artifact')
    if (manifest.image_base, manifest.size_of_image) != (layout.image_base, layout.size_of_image):
        raise fail('PT-UNIFIED-PAIR', f'ir-{side}-layout')


def open_ir(req) -> IrInputs | None:
    """The request's sidecars, opened with full verification and checked against the pair; the caller closes the
    readers (`close_ir`). A sidecar of another artifact, in the wrong orientation or changed since the request is a
    typed error, never a silent S0 run."""
    if req.ir_older is None:
        return None
    opened: list[IrReader] = []
    try:
        for side, spec, sha, other, layout in (
                ('older', req.ir_older, req.older_sha256, req.newer_sha256, req.older_layout),
                ('newer', req.ir_newer, req.newer_sha256, req.older_sha256, req.newer_layout)):
            directory = Path(spec.directory)
            if not directory.is_absolute():
                raise fail('PT-UNIFIED-INPUT', 'ir-path')
            reader = IrReader.open(directory)
            opened.append(reader)
            _check_ir_side(side, reader, spec, sha, other, layout)
    except BaseException:
        for reader in opened:
            reader.close()
        raise
    return IrInputs(opened[0], opened[1], req.ir_older.sections, req.ir_newer.sections)


def close_ir(ir: IrInputs | None) -> None:
    if ir is not None:
        ir.older.close()
        ir.newer.close()


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
    ir = open_ir(req)
    budget = Budget.after(req.budget_seconds, cancel)
    try:
        if req.refacts is None:
            computed = compute_stage(inputs, addr, result_dir=Path(result_dir), sources=req.sources,
                                     registry=registry, limits=limits, budget=budget, emit=forward, ir=ir,
                                     residual=req.residual)
        else:
            file = read_refacts(inside(req.refacts.path, private), expected_sha256=req.refacts.sha256)
            computed = Computed(refacts_stage(inputs, addr, result_dir=Path(result_dir), ir=ir, refacts=file,
                                              sources=req.sources, registry=registry, limits=limits, budget=budget,
                                              emit=forward, residual=req.residual))
    finally:
        close_ir(ir)
    manifest = computed.manifest
    return WorkerReport(ok=True, status=manifest.status, result_id=manifest.result_id, raw_status=raw.status,
                        rows=manifest.counts.total(),
                        facts=next(p.records for p in manifest.parts if p.name == 'facts.jsonl.gz'),
                        limitations=manifest.limitations, stage_ms=marks, refacts=computed.refacts)
