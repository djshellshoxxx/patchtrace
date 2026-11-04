# R2 — Unified binary matching research and validation

Research date: 2026-10-30 UTC. Baseline: [`a04f5a299a8d4afef023261e52e08d14678cf1e7`](https://github.com/djshellshoxxx/patchtrace/commit/a04f5a299a8d4afef023261e52e08d14678cf1e7).
Branch: `codex/r2-unified-matching-research-20261030`.
Delivery: [draft PR #131](https://github.com/djshellshoxxx/patchtrace/pull/131).

## Outcome and evidence boundary

This is an executed research-and-development investigation: primary-source review,
source inventory, ablations, synthetic scaling, native experiments, regression-first
repairs and independent review. It improves deterministic evidence handling,
preserves previously lost unmatched functions, and removes a measured quadratic
CFG query cost. **Representative real-world accuracy and full R2 acceptance remain
open.** Exact tests, CI outcomes, failures and limitations are in report 05.

Ghidriff stays primary; unified results stay derived; original comparisons, L1/L2
separation, ordinal confidence and analyst decisions are preserved. No target
binary was executed, no locked test was used for tuning, and no neural model,
new solver dependency or production threshold was introduced.

## Reports

| Report | Questions answered |
|---|---|
| [00 — Repository reconciliation](00-reconciliation.md) | Exact baseline, branches, PRs, ownership and actual CI evidence. |
| [01 — Implementation inventory](01-implementation-inventory.md) | Nine component profiles answer all twelve engine questions; P00–P19 and missing integrations mapped to source. |
| [02 — Algorithms and upstream implementations](02-algorithms-and-upstream.md) | Exact, structural, residual and learned methods; complexity, licenses, evidence correlation and primary references. |
| [03 — Graphs, residual matching and performance](03-graph-residual-performance.md) | Twenty-three ablations, candidate caps, bounded assignment, MD collision, 1k–100k scale and before/after optimization. |
| [04 — Fusion, identity and false matches](04-fusion-identity-false-matches.md) | Seventeen root-cause categories, arbitration, provenance, analyst explanations, relation semantics and gaps. |
| [05 — Baseline and validation](05-baseline-and-validation.md) | Measurement populations, native versus synthetic results, red/green tests, integrated review and CI limits. |
| [06 — Limitations and R3 handoff](06-limitations-and-r3-handoff.md) | Acceptance checklist, prioritized next experiments/owners, evaluation protocol and semantic-change requirements. |
| [07 — Native rz-diff investigation](07-native-rizin-findings.md) | Twenty-two attempts plus five diagnostics; conditional side reversal, pinned source proof and safe repair constraints. |
| [08 — Native cJSON development probe](08-native-cjson-development.md) | Real-source R1 pair, two reviewed positive functions, native extraction/fusion and export/unblinded-review limits. |

The [results directory](results/) contains bounded JSON evidence: hashes, timings,
candidate/decision counts, pass statistics, native output, manifests, rows, facts
and explicit failures. Reports and research scripts include reproduction commands.
Tool distributions, DLLs, GZFs and private Tier W data are not committed.

## Findings that change practical decisions

1. **Residual matching already exists.** P16–P19 implement reference vectors,
   block votes, layout gaps and rejection-aware assignment. P02 is unit-tested
   but production supplies no export map; exported Ghidra labels reach P03.
   Diaphora Mode A imports separately but has no operational unified adapter.
2. **Agreement must retain its actual evidence.** The atom cap could discard the
   second class that justified B+B acceptance. R2 retains its witness and strongest
   opposition, rejects impossible caps, stabilizes native-atom ordering, and
   attributes manual groups explicitly to the analyst.
3. **Unmatched is an observation.** IR-only functions now survive as SHA/RVA-bound
   one-sided W/E-UNKNOWN rows. Native replay restores two helpers in each
   split/merge example without asserting addition/removal or N:M recognition.
4. **Structural equality is not identity proof.** Nonisomorphic CFGs share a
   production MD key. The resulting B evidence is distinct from final automatic
   acceptance. No reviewed paper establishes a model/solver winner for this corpus.
5. **Scale depends on candidate shape.** At 100k functions per side, exact-key
   matching takes 3.430 s / 250.6 MiB; selective residual matching takes 31.064 s /
   1,116.1 MiB. P16 resolves those twins; this is not a 100k LAP result. Common-only
   buckets can abstain and lose all candidate coverage.
6. **A measured hot path was quadratic.** Dominator intervals reduce the 10k-chain
   back-edge query from 1.552340 s to 0.027999 s, about 55× in that microbenchmark.
   Independent semantic checks and an operation-count regression protect output.
7. **Native execution and accuracy differ.** Ghidriff completed a constructed
   constant edit but emitted no modified function; IR facts retained the delta.
   Rizin produced twenty parser failures and reversed two parsed address-shift
   proposals under a specific singleton condition. These remain failures/unknowns.
8. **Inspect the gate report.** Main's advisory unified run had 27 failed jobs,
   zero measured matched rows and NOT READY gates despite overall success.
   Current-head CI is tracked separately; no default-on or probability claim follows.

## Implementation and ownership

Five production modules change: `unified/compute.py`, `fusion/arbiter.py`,
`ir/cfg.py`, `read_text.py` and `sources/ladder.py`. Cache policy adds `matching/2`
while preserving `ude/1` and IR keys. Default acceptance, pass order and thresholds
are unchanged. Research runners and their safety regressions remain separate.

R1 corpus/calibration work is separately owned. Development artifacts were read
only, with private copies for native analysis; existing branches and checkouts
were preserved. Before merging, reconcile current refs and inspect exact-head
Linux, Windows, native and review gates. This draft is not a release claim.
