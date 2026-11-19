# Phase 2 reference reconciliation receipt

Current comparison: **`068513a72e8a1412ce3960d3024c462d68d51376`**, tree
`2183dcf3b9cfee268c3ebb163ad9f3e9e928e10f`.
Original reference: **`4522030ff3ff76d720a5efc33953aaa5e5837398`**.

[Full disposition](../plans/phase2-reference-contract-disposition-20261118.md)
and [machine-readable mapping](../plans/phase2-reference-contract-disposition-20261118.json)
cover all nine proposed record families and current enrichment/pilot consumers.
No production source or existing test changed in this checkpoint.

## Sealed evidence

[Archive](phase2-reference-contract-disposition-20261118.zip): **118 members**,
**694,145 bytes**, SHA-256
`fd6a538c735fb6a40552075fd7725e8d0d0c602f9d1107b57eb1b07ca456f252`.

The manifest binds every member except itself by relative path, size and SHA-256.
The archive includes 73 exact current Git snapshots, all five unchanged historical
reference files, 62 exact symbol/caller proofs, structural schema inventories,
four independent invocation receipts and the original navigation observations.
Both source manifests were independently checked against Git objects before
sealing; all archive member hashes were read back and verified.

Eight prior batch-seven files preserve the earlier missing-`jsonschema` collection
incident and later reference-only pass, with their original comparison attribution.
Those outcomes are not relabeled as current-source results.

## Actual outcomes

| Invocation | Outcome | What it establishes |
| --- | --- | --- |
| `current-contracts` | 697 passed, 0 failed/skipped; 8.29 s | Eleven inspected current enrichment, storage, UI and pilot contract/adapter/fusion files; source-only Python import/schema children and authored offscreen Qt |
| `reference-original` | 23 passed, 0 failed/skipped; 0.12 s | Unchanged original schema/examples/provenance test; already-installed runtime dependency; no installation |
| `wire-boundary` | 10 passed, 0 failed/skipped; 0.21 s | Current models and public snapshot parser refuse the incompatible reference wire objects |
| `navigation-boundary-red` | **3 failed, 4 passed**, 0 skipped; 1.67 s | Actual stored/reopened desktop navigation accepts a stale excerpt, wrong side or wrong run; existing validator refusals and valid navigation are positive controls |

The counts describe separate, overlapping purposes and are not additive feature
coverage. Reference schema success does not validate arithmetic, source
authenticity, identity derivation or runtime compatibility.

The navigation probe is immutable at SHA-256
`61b5d7c21778e12ba71bc6d32a0779f7d1d457656955bf2bfdab64c8c5953688`.
Its row is intentionally authored through real pipeline/store publication, not
claimed to be emitted by an ordinary detector. Four JSON observations retain
the stored locator, actual reveal call, selected text and empty diagnostics.

An optional external-file Ruff invocation initially ran outside the project and
used default import classification, producing two `I001` diagnostics. The
[supplemental lint receipt](phase2-reference-contract-disposition-20261118-lint.json)
retains a replay of that exact configuration and the subsequent explicit pinned
project configuration: **all checks pass without any probe edit**. This appendix
does not rewrite the already sealed archive. No product-source Ruff regression
is inferred from the outside-project invocation.

## Limits and next slice

The current hardening backlog already names the UI validator wiring as open.
Root approved a separate spec/test-first hook in the signal-navigation path,
using `views.validate_location` before revealing code and a bounded diagnosis.
That fix is not in this checkpoint. The observation-only replay plugin permits
independent reruns into a fresh directory while preserving the original probe
and observations.

No live provider, target, native engine, compiler, package, frozen application,
Windows acceptance, calibration run or manual desktop acceptance occurred.
Reference-only capabilities and broader semantic branch residues remain open.
No remote mutation, merge, release or whole-branch closure occurred.
