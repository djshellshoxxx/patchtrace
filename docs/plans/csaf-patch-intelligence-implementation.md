# Post–multi-engine PatchTrace intelligence implementation plan

Status: future milestones only. Do not start before SPEC-10/11/27 runner + reconciliation and reliability acceptance are completed. Includes SPEC-28 CSAF, SPEC-29 three optional CLI adapters and SPEC-30 deterministic patch intent engine. Documentation only.

## End-state ASCII workflow

```text
      OLD PE x64                 NEW PE x64
          |                          |
          +--------+-----------------+
                   |
       Preliminary PE inspection
                   |
       Parallel DIFF engines (opt in)
       Ghidriff | BinDiff | rz-diff
                   |
       Pair identity + arbitration
                   |
       [match confidence / contested]
                   |
          +--------+----------------------------+
          |                                     |
   Microsoft CSAF JSON                    Tool evidence
  Security advisory + VEX             capa | FLOSS | DiE
          |                                 |      |
  CVE + CWE + product status         capabilities strings
  + threat/remediation text             + build quality
          |                                     |
          +----------------+--------------------+
                           |
                   Patch Intent Engine
             versioned CWE rules + evidence
             lineage + source/sink/guard joins
                           |
                Ranked function hypotheses
                counterevidence and unknowns
                           |
             Ghidra CFG/p-code / runtime trace
               (optional higher proof level)
                           |
                 Analyst review and reports
```

## Dependencies and delivery order
- [ ] Gate 0: reconcile/merge active GitHub PRs and branch ownership; verify current main contains tested BinDiff importer, rz-diff runner and evidence report. Never overwrite in-flight feature branches.
- [ ] Gate 1: complete BinDiff actual CLI execution, BinExport input support, optional parallel scheduling, rz-diff stdout isolation, matching identity normalization and calibrated/ordinal evidence UI; Windows real fixture.
- [ ] SPEC-28a: complete CSAF fixture corpus and versioned source schema; pin official source/index discovery, fetching, OASIS validation, product/VEX status contract; separate offline and consented network acceptance.
- [ ] SPEC-28b: complete deterministic curated CWE language/rule pack, negation tests, product applicability and cross-revision conflict tests; explicit unknown output.
- [ ] SPEC-29a: implement kapa/capa adapter with tested Ghidra backend and pinned rule pack, normalize rule scope and address references.
- [ ] SPEC-29b: implement FLOSS adapter with exact JSON schema, recovered string provenance and deduplicated change records.
- [ ] SPEC-29c: implement optional DiE console adapter for compiler/packer distortion alerts. Gate on measured usefulness, not marketing.
- [ ] SPEC-30a: typed evidence graph, immutable lineage-group references, canonical address conversion and failed/abstained status.
- [ ] SPEC-30b: deterministic hypothesis rule evaluator and matched-function candidate ranking, unresolved/unmatched queue, source and counterevidence explanations.
- [ ] SPEC-30c: pure CLI/report integration; add Qt CVE intelligence pane with verbose contextual tooltips; preserve stand-alone UI and Ghidra host plugin contract.
- [ ] SPEC-30d: independent labeled holdout corpus, per-tool ablations, noise regression and per-CWE calibration study; no confidence probability before passing criteria.
- [ ] Release: Linux/Windows static validation, Windows end-to-end PE test, CSAF offline import and consented fetch, cancellation, stress, QA, modular module index, docs and reproducible build. No automatic release without passing gates.

## Engineering and coordination rules
Spec before code, test-first red/green/refactor, stable typed public contracts and generated valid/invalid JSON fixtures, versioned idempotent migration with full project backup, read-only source artifacts, one writer to SQLite, pure core separate from UI and transport, limited process concurrency, clear owner per module, cache keyed by all relevant digests, reversible feature flags. Multiple workers own exclusive files, share schema freeze before parallel work, an integrator reviews cross-module changes. Every PR is merged or explicitly closed; record unresolved checks and never silently label incomplete work finished. Security tests cover malformed advisories and hostile binaries, output-escaping, subprocess bounds, airgapped mode and avoidance of target execution.

## Decision record
Choose capa because it returns behavior/capability evidence tied to code locations and already supports Ghidra. Choose FLOSS because recovered stack/decoded strings can uncover previously invisible patch context with source provenance. Choose DiE console strictly to flag compiler/packer differences that inflate false leads; exclude it from default profile if empirical evidence shows little value. Do not include extra diff engines, fuzzy hash scores, YARA rules that restate existing clues, or generic header inspection as independent proof. PE library and signature checking remain prerequisites of basic file inspection, not part of these three research agents.

## Research provenance
Microsoft CSAF directory https://msrc.microsoft.com/csaf ; CSAF 2.0 https://docs.oasis-open.org/csaf/csaf/v2.0/cs01/csaf-v2.0-cs01.html ; capa https://github.com/mandiant/capa ; FLOSS https://github.com/mandiant/flare-floss ; DiE https://github.com/horsicq/Detect-It-Easy .
