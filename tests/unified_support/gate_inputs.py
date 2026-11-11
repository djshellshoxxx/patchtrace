"""Scripted engines and generated evaluator inputs, not extraction or binary-matching evidence.

The reused label_doc helper supplies SYNTHETIC sentinel hashes and fictional tool banners.
They are test constants, not claimed observed SHAs or versions. No PE is claimed to implement a registry
class by this module. Use pairs.py for authored image transformations; see fixture-gaps.md for that boundary.
UNVERIFIED: all new tests and timing budgets remain unexecuted.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from unified_s6_helpers import label_doc, mutation_doc
from unified_support.statistics import paired_difference

from tools.calibration.tier_r.contracts import KnownAnswerLabels
from tools.unified import outcomes
from tools.unified.corpus import manifest as cm
from tools.unified.mutations import classes


@dataclass(frozen=True)
class ScriptedEngine:
    """Deliberate endpoint and verdict faults to prove an evaluator detects its intended failure."""

    null_verdict: str = "unchanged"
    mutant_verdict: str = "material"
    wrong_every: int = 0

    def rows(self, n: int = 20, *, edited: bool = False) -> tuple[outcomes.OutcomeRow, ...]:
        out = []
        for i in range(n):
            older = 0x1000 + 16 * i
            wrong = bool(self.wrong_every and i % self.wrong_every == 0)
            newer = older + 8 if wrong else older
            out.append(outcomes.OutcomeRow(
                older=(older,), newer=(newer,), decision="matched",
                materiality=self.mutant_verdict if edited else self.null_verdict,
                truth="wrong" if wrong else "right", edited="edited" if edited else "not-edited",
                basis=(outcomes.Basis(component="K1", tier="A", cls="E-BODY",
                                      source="pt-ladder", step="P04-bytes-exact"),)))
        return tuple(out)


GOOD = ScriptedEngine()
FALSE_CHANGES = ScriptedEngine(null_verdict="material")
HIDES_CHANGES = ScriptedEngine(mutant_verdict="cosmetic")
WRONG_MATCHES = ScriptedEngine(wrong_every=2)


def pair(doc: KnownAnswerLabels, rows: Iterable[outcomes.OutcomeRow], *,
         orientation: str = "forward", legacy_tools: Sequence[str] = ()) -> outcomes.PairOutcome:
    return outcomes.collect_rows(rows, doc, orientation=orientation, legacy_tools=legacy_tools)


def run(pairs: Iterable[outcomes.PairOutcome], name: str = "scripted-a",
        platform: str = "synthetic") -> outcomes.OutcomeSet:
    return outcomes.build(name, platform, pairs)


def releases(n: int = 30) -> list[KnownAnswerLabels]:
    # These are simulated groups for evaluator tests, not independently sampled real project lineages.
    return [label_doc(f"synthetic-rel-{i}", "release", project=f"synthetic-p{i}") for i in range(n)]


def precision_inputs(n: int = 30, engine: ScriptedEngine = GOOD
                     ) -> tuple[cm.CorpusManifest, outcomes.OutcomeSet]:
    docs = releases(n)
    return cm.build(docs, {}), run(pair(d, engine.rows()) for d in docs)


def mutants(per_class: int = 20) -> list[KnownAnswerLabels]:
    return [mutation_doc(f"scripted-{c.id}-{i}", c.id, f"fixture_{c.id.replace('-', '_')}_{i}")
            for c in classes.CLASSES for i in range(per_class)]


def planted_rows(doc: KnownAnswerLabels, engine: ScriptedEngine = GOOD) -> tuple[outcomes.OutcomeRow, ...]:
    planted = outcomes.planted_of(doc)
    assert planted is not None
    cls = classes.BY_ID[doc.case["unified_class"]]
    verdict = "review" if cls.verdicts == ("review",) and engine == GOOD else engine.mutant_verdict
    return (outcomes.OutcomeRow(older=(planted.older_rva,), newer=(planted.newer_rva,), decision="matched",
                               materiality=verdict, truth="right", edited="edited"),)


def paired_recall(good: Sequence[int], bad: Sequence[int]) -> dict:
    if len(good) != len(bad):
        raise ValueError("paired observations must have the same lineages")
    groups = {f"simulated-L{i}": (float(a), 1.0, float(b), 1.0)
              for i, (a, b) in enumerate(zip(good, bad, strict=True))}
    return paired_difference(groups, seed="synthetic-paired-recall")
