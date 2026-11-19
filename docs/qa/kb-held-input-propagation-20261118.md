# Internal KB held-input propagation qualification

Baseline: `9ad2ec5cdbde85155fdca3cdd88804fd8b2e1a53`. Final production:
`d9a939911f39f3641bd5eed97a2ce067d618856b`, tree
`2277f61c82eb8115344c1edaa287b9d60d1733ed`.

The existing KB import route now accepts the original operation-owned reader
pair internally. Only `kbcorrelation/service.py`, `wiring.py` and `store.py`
change production. The [contract](../specs/kb-held-inputs.md) preserves ordinary
calls, full source/scope/revision admission, complete hashes and committed
project ownership. This is not a package entry point. Independent root review
and selective integration are requested; native/package acceptance is open.

## Reproducible evidence

[Sealed archive](kb-held-input-propagation-20261118.zip): **147 members**,
**884,214 bytes**, SHA-256
`3371fd77e415259e04ebbd22674280d31fa9443784b70e627dbdd2cbab73de8f`.
All archive members were read back against their manifest. The packet verifies
81 exact Git snapshots, 150 unchanged complete function spans, three complete
production caller searches and nine preserved original independent files.
The five reviewed core files/spec still equal `97408609` byte for byte.

The new source handoff excludes design pick `76e71040`, which root already
retained separately. Apply these commits in order only after independent review:

| Commit | Purpose |
| --- | --- |
| `da968d605da2cd8d979b45fdfa838078a8f7cec2` | Internal-only contract and genuine missing-capability regressions |
| `3fee8026ce9d176c80deb574eb5f78a6eeb5e7d6` | Three-file capability propagation |
| `73b7de55cb4ff3556f68fac616d47244626bc887` | Saved/global admission and same-live-operation resume controls; module index |
| `77be0e3409e5e18087399dc61296ac1a83cf8662` | Short-read bounded-prefix contract and regressions before correction |
| `d9a939911f39f3641bd5eed97a2ce067d618856b` | Accumulate the existing finite prefix across successful short reads |

Every commit retains `[no release]`. Exact parents, trees, full patches and
source bytes are in `history.json`, `commits/` and `git/` inside the archive.

## Actual results and retained failures

| Source / invocation | Result | Interpretation |
| --- | --- | --- |
| `da968d60`, original spec red | 32 failed / 1 passed | Existing APIs do not accept the new keywords; ordinary positional import passed. No setup/collection errors. |
| `3fee8026`, first focused | 33 passed | Initial propagation before short-read review. |
| `73b7de55`, added admission/resume controls | 39 passed | Historical focused result; not relabeled as final qualification. |
| Root unchanged probe at `73b7de55` | 3 failed / 2 passed | Legitimate 1/17/127-byte reads raise `PT-KBC-INPUT` because only the first block enters the PE prefix; full/4096 reads pass. |
| `77be0e34`, prefix spec red | 6 failed / 6 passed | New prefix controls fail before correction; ordinary injection and normal-read neighbors pass. |
| `d9a93991`, focused source | 50 passed | The 39 existing cases plus 11 finite-prefix controls. |
| `d9a93991`, unchanged independent probe | 5 passed in 0.34 s | Original file hash unchanged; fresh observations and 49 exact imported-module proofs. |
| `d9a93991`, 15-file affected gate | 300 passed in 8.51 s; zero skips/errors/failures | Full selected KB/core gate with 99 imported modules matching the exact Git source. |
| `d9a93991`, required full Ruff and diff check | Passed | `ruff check src tests tools`; baseline-to-source whitespace check. |

These invocations overlap and are not additive coverage. Every original log,
XML, command and independent observation is retained unchanged. The root probe
SHA-256 is `672e1a2e13e990c1e1249d319f714ef8e91425d44fcafe63dd6fe32a3d9feee6`.

The affected gate includes the two new test files plus existing service, store,
recovery, CLI, acquisition CLI, all three saved-scope suites, inventory source
admission, investigation service, neutral readers, held ingestion and creation
checkpoints. It uses absolute source paths, offscreen Qt and normal system temp.
Inherited network denial was active. The original probe records no network or
process events; the affected suite records 18 authored Python subprocess events
from its existing CLI/import/crash tests and only local `socket.gethostname`
audit events. No socket/connect events, target, native engine or package process
are credited. The runner is an execution safeguard, not a product sandbox.

## Preserved behavior

The same live pair and checkpoint reach the real inspector, pre-intent and
pre-create full hashes, both project factories and core create. Ordinary
positional-only injections retain their original call shape. No TypeError retry
or source pathname fallback is introduced. Held loop replies must be `bytes`
and fit the finite requested chunk; malformed replies fail before digest/size
progress. The provider owns positive held-byte accounting and KB checks use
zero. Core project-owned verification retains its original positive accounting.

Inspection now accumulates at most the existing 4096 bytes across short reads.
The full digest and size remain identical to ordinary inspection. Tests include
the last admissible signature position and refusal of signatures at 4096/4160;
this correction adds no late-header support or increased header budget.

Actual project/SQLite tests deny selected-source pathname opens, check four
borrowed reads per side and exact accounting, retain the original descriptors,
delete source paths, then reopen the project copies. Typed stops retain their
original exception object at preapproval, attachment-hash, core-copy,
save-verification and pre-COMMIT boundaries. Arming a stop after committed save
does not insert a new failure before the existing created journal. Same-live
intent resume is accepted; expired or wrong-path bindings refuse.

Finite saved selection, an explicitly empty selection, full-global supersession,
malformed coverage, expected pair/revision and ordered source snapshot are
exercised through the real route. Existing admission, association and recovery
functions retain byte-identical spans where outside the approved propagation.
No schema, durable journal shape, CLI/GUI flow, core or worker code changed.

## Gates still open

This capability remains internal until separately reviewed durable protection
prevents reader-less generic recovery from reopening stored package paths.
The existing post-create injected fault still leaves a valid project and an
intent with unset project identity; that limitation is explicitly tested and
retained. Expected project identity, held-origin provenance/reconciliation,
lost-lease recovery and postcommit project-copy checkpoint coverage remain
separate work. Portable descriptor controls do not establish native Windows
sharing, worker/FDI behavior, package intake or frozen journey acceptance.
The whole PW02 feature and final platform/security/release gates remain open.
