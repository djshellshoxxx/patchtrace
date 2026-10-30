"""R7 research-only bounded dependence slicing over synthetic high-P-code-shaped operation facts.

Neither an extractor nor a source of security verdicts. Caller-supplied control edges,
SSA names, and artifact provenance are *not* verified against Ghidra or ProgramIR.
No target binaries are loaded/executed and no persistent product schema is changed.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Iterable, Literal

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_OPCODE = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
MAX_INPUT_OPS = 4096


class SliceCancelled(Exception):
    """Cancellation requested; no partial result is promoted."""


def _token(value: str, what: str) -> None:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise ValueError(f"invalid {what}")


@dataclass(frozen=True, slots=True)
class Scope:
    """Caller-asserted provenance; syntactic validation is not byte verification."""

    artifact_sha256: str
    function_rva: int
    ir_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.artifact_sha256) is not str or not _SHA.fullmatch(self.artifact_sha256):
            raise ValueError("invalid artifact_sha256")
        if self.ir_digest is not None and (type(self.ir_digest) is not str
                                           or not _SHA.fullmatch(self.ir_digest)):
            raise ValueError("invalid ir_digest")
        if type(self.function_rva) is not int or not 0 <= self.function_rva <= 0xFFFFFFFF:
            raise ValueError("invalid function_rva")


@dataclass(frozen=True, slots=True)
class Op:
    """Ephemeral high-P-code-shaped fact, **not** a new ProgramIR representation."""

    uid: str
    rva: int
    opcode: str
    inputs: tuple[str, ...] = ()
    output: str | None = None
    controls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _token(self.uid, "uid")
        if type(self.rva) is not int or not 0 <= self.rva <= 0xFFFFFFFF:
            raise ValueError("invalid rva")
        if type(self.opcode) is not str or not _OPCODE.fullmatch(self.opcode):
            raise ValueError("invalid opcode")
        for value, label in ((self.inputs, "inputs"), (self.controls, "controls")):
            if type(value) is not tuple or len(value) > 32:
                raise ValueError(f"invalid {label}")
            for item in value:
                _token(item, label)
        if self.output is not None:
            _token(self.output, "output")
            if self.output.startswith(("param:", "const:")):
                raise ValueError("output cannot define external/constant value")


@dataclass(frozen=True, slots=True)
class SliceReport:
    scope: Scope
    seed: str
    direction: Literal["backward", "forward"]
    sites: tuple[tuple[str, int, str], ...]  # uid, original instruction RVA, p-code opcode
    boundaries: tuple[str, ...]             # caller-designated parameter/live-in values
    unknowns: tuple[str, ...]               # unmodelled effects, missing edges, caps
    frontier: tuple[str, ...]               # unvisited operation uids at traversal boundary
    truncated: bool

    @property
    def status(self) -> str:
        # Success is *only* relative to the supplied graph; never semantic equivalence.
        return "incomplete" if self.unknowns or self.truncated else "bounded-within-supplied-graph"


def slice_ops(
    ops: Iterable[Op],
    seed: str,
    scope: Scope,
    *,
    direction: Literal["backward", "forward"] = "backward",
    max_nodes: int = 64,
    max_depth: int = 16,
    cancelled: Callable[[], bool] | None = None,
) -> SliceReport:
    """Bounded syntactic dependency walk; no implicit alias/call/control completeness claims.

    Backward: unique SSA definitions and explicitly supplied control dependencies.
    Forward: SSA uses and explicitly supplied control-dependent operations.
    Unknown memory/call effects are recorded, not inferred. Caller must establish
    authenticity of each graph edge and provenance before using a result as evidence.
    """
    _token(seed, "seed")
    if not isinstance(scope, Scope):
        raise ValueError("invalid scope")
    if direction not in ("backward", "forward"):
        raise ValueError("invalid direction")
    if type(max_nodes) is not int or not 1 <= max_nodes <= MAX_INPUT_OPS:
        raise ValueError("invalid max_nodes")
    if type(max_depth) is not int or not 0 <= max_depth <= 64:
        raise ValueError("invalid max_depth")
    if cancelled is not None and cancelled():
        raise SliceCancelled()
    items = list(ops)
    if len(items) > MAX_INPUT_OPS:
        raise ValueError("too many operations")
    by_id: dict[str, Op] = {}
    definitions: dict[str, list[str]] = defaultdict(list)
    uses: dict[str, list[str]] = defaultdict(list)
    control_dependents: dict[str, list[str]] = defaultdict(list)
    for item in items:
        if not isinstance(item, Op):
            raise ValueError("invalid operation")
        if item.uid in by_id:
            raise ValueError("duplicate operation uid")
        by_id[item.uid] = item
        if item.output is not None:
            definitions[item.output].append(item.uid)
        for variable in item.inputs:
            uses[variable].append(item.uid)
        for control in item.controls:
            control_dependents[control].append(item.uid)
    if seed not in by_id:
        raise ValueError("seed not found")
    queue = deque([(seed, 0)])
    seen: set[str] = set()
    frontier: set[str] = set()
    unknowns: set[str] = set()
    boundaries: set[str] = set()
    truncated = False
    while queue:
        if cancelled is not None and cancelled():
            raise SliceCancelled()
        uid, depth = queue.popleft()
        if uid in seen:
            continue
        if len(seen) == max_nodes:
            truncated = True
            unknowns.add("node-cap")
            frontier.add(uid)
            frontier.update(ref for ref, _ in queue if ref not in seen)
            break
        seen.add(uid)
        item = by_id[uid]
        if item.opcode in ("LOAD", "STORE"):
            unknowns.add(f"memory-alias:{uid}")
        if item.opcode in ("CALL", "CALLIND", "CALLOTHER"):
            unknowns.add(f"call-effects:{uid}")
        if item.opcode in ("CALLIND", "BRANCHIND"):
            unknowns.add(f"indirect-target:{uid}")
        neighbors: set[str] = set()
        if direction == "backward":
            for control in item.controls:
                if control in by_id:
                    neighbors.add(control)
                else:
                    unknowns.add(f"missing-control:{control}")
            for variable in item.inputs:
                if variable.startswith(("const:", "param:")):
                    if variable.startswith("param:"):
                        boundaries.add(variable)
                    continue
                candidates = definitions.get(variable, ())
                if len(candidates) == 1:
                    neighbors.add(candidates[0])
                elif len(candidates) > 1:
                    unknowns.add(f"multiple-defs:{variable}")
                else:
                    unknowns.add(f"missing-def:{variable}")
        else:
            if item.output is not None:
                neighbors.update(uses.get(item.output, ()))
            neighbors.update(control_dependents.get(uid, ()))
            boundaries.update(x for x in item.inputs if x.startswith("param:"))
        neighbors.difference_update(seen)
        if depth >= max_depth and neighbors:
            truncated = True
            unknowns.add(f"depth-cap:{uid}")
            frontier.update(neighbors)
        else:
            queue.extend((ref, depth + 1) for ref in sorted(neighbors))
    selected = sorted((by_id[uid] for uid in seen), key=lambda x: (x.rva, x.uid))
    return SliceReport(scope, seed, direction, tuple((n.uid, n.rva, n.opcode) for n in selected),
                       tuple(sorted(boundaries)), tuple(sorted(unknowns)), tuple(sorted(frontier)), truncated)
