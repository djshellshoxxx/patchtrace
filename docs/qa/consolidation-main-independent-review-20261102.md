# Independent review of frozen combined merge

## Decision and identity

**APPROVE the conflict resolution in `7dc6ab09aadf088faa0b34a0e8a5ca64963539e9`**, tree `fcf68b5cd75b11d9cd6718ca6def12e917c678f7`. No source correctness blocker found in this merge delta. This does not certify unrelated historical candidate functionality, later portability fixes, native Windows acceptance, or final current-candidate hosted gates.

Reviewed only immutable Git objects and a separate archive extracted at `/tmp/patchtrace-combined-review-7dc6ab09`. The author's changing worktree was not used as test input. No production edits or remote writes by this reviewer.

| Parent | Local commit | Published identity represented |
|---|---|---|
| Candidate | `419324610bfecaa843f4ed4a0130f57383f62a65` | PR #159 `56374f867594dd923383c91ea71970cb7d24d173`, tree `816864d631ec19ac8c0e8a273b18fda42ac01599` |
| Main snapshot | `0f57eaa18ec1cd7971526c9ea8828aa8909cf14a` | Main `ce8c65bf41541cf6adb52289d2a530ce2817a53a`, tree `0f90e002704d93e8343568acf0bde443dcc4b2eb` |

The main snapshot has equal contents, not equal commit ancestry, to published main. Remote integration must retain the real published parent mapping.

## Parent-content preservation

A complete tree-entry comparison against Git's actual merge-base, `25c9795bd9cd58bfad855f30594ee3a0c7584cec`, found:

- All 444 paths changed only by the candidate retain the candidate's exact mode/object entry.
- All six paths changed only by main retain main's exact mode/object entry.
- Paths equal in both parents remain equal, except the three explicitly new consolidation QA receipt files.
- Seventeen paths changed in both parents; sixteen required explicit resolution and `kbcorrelation/wiring.py` retained the candidate's compatible create-only GUI factory addition.

Thus the merge introduces no unexplained overwrite or deletion outside the reviewed shared changes. In `docs/modules.md`, the only candidate-to-merge change strengthens the backup completion description to require observed staging-name removal. Other parent-specific module entries remain intact.

## Scope and provenance review

`context.saved_search_scope`, `ReverseIndex.within_scope`, and the service's saved-scope behavior remain intact. Context construction first validates the saved coverage, obtains a bounded index, and checks that requested/inspected scope membership can still be reproduced. A recorded empty cached corpus stays empty. No missing scope is replaced by a whole-corpus guess.

The merged `index.py` preserves current main's single-snapshot ambiguity rule, comparison across all active native/synthetic snapshots in an ambiguous release month, disputed-edge identities, and month isolation. Its addition relative to main is the candidate's bounded index view. `context.py` retains current main's JSON-locatable CVRF/CSAF fallback while running it inside the saved scope.

The persisted bundle contract remains version 1; the existing optional card-facts field retains its empty default for legacy bundles. Key policy remains version 3. Existing field/source validators, raw source identities, conservative applicability wording, and the prohibition on promoting documentary context to function-level fix claims are preserved. The XML fallback regression now provides its actual constructed coverage; it does not weaken production missing-scope rejection.

Independent controls combined the two parent behaviors directly:

- Adding an unselected same-month empty synthetic snapshot did not change a native advisory bundle or dispute its selected edge, under either provided-files or frozen cached-corpus scope.
- Explicitly including that snapshot still disputed the native applicability and withheld context interpretation.
- Adding an unselected CSAF document did not make an otherwise unlocatable XML card eligible under either saved scope type.
- Explicitly expanding scope allowed the locatable CSAF fallback and retained both source dependencies.

PR #158's unique `test_mixed_native_and_synthetic_revisions_dispute_withdrawn_remediation` is preserved verbatim. Its function text was independently compared against the connector-fetched exact remote file at `e1b79e048d3963d747bc9f07448b039a250180ed`, blob `0d02a22fecb618c2f27413d573d70343663886c5`. The distinct #153 valid-synthetic-row-without-remediation regression also remains present.

## Backup safeguards

Both `src/patchtrace/verified_backup.py` and `tests/test_verified_backup_publication_admission.py` are byte-identical to the current-main parent, respectively blobs `058559c9b9f703915e04eee44c5135a9eb6e566d` and `df997477bcf2e56fbd92edbccbc472aa2f370b00`. Their specification and review receipts retain the stage-ownership, removal/observed-absence, failed-publication evidence, and no-first-prune rules. The separate two-observation byte-stability repair is intentionally not part of this frozen merge.

## Tracker recovery and documentation

Independent recovery reproduced the author's transformation from the exact main blob `72552207db2bc02d111e2766296e7358b1c1cc16`:

- Original SHA-256: `49012016598c230cf7f762adb9bf6ea61a5f59503b2a15e006b204c93b229e1b`; 24 NUL bytes.
- Base64 re-encoding begins with the exact recorded truncation-warning wrapper.
- Removing that wrapper and decoding gives 553 lines with one invalid UTF-8 line, line 257.
- Replacing that damaged line/span with intact pre-#153 main tracker lines 251–593 reproduces reconstructed-main SHA-256 `bdbd40058249fd857549d12fdc0a8c0e64a3775809fddff2dbb9ffcfca7c0bbb`.
- The merged tracker hash is `f3a13a5f4c15b4d087d1004f42255dea1279c06894a14de660a31ba5812bf15f`.
- Multiset comparison found zero missing nonblank lines, including multiplicity, from either the intact candidate tracker or reconstructed main tracker. The same check found zero missing nonblank lines from either parent's complete `docs/qa.md`.

This establishes preservation of available text, not recovery of unknowable new text that may have existed only in the already-truncated span. The consolidation note and recovery JSON explicitly disclose that limitation; the original binary remains addressable in preserved Git history.

**Nonblocking receipt wording correction:** `63d11d3` is called the "common base" in the recovery metadata. It is the intact pre-#153 main used for reconstruction and the local main snapshot's parent. Git's actual merge-base of these local merge parents is `25c9795`. Describe the reconstruction input by its role to avoid implying that it is the graph merge-base. This terminology does not change the verified tree or recovery results.

## Independent verification

On the extracted frozen commit:

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_kbc_*.py tests/test_verified_backup_publication_admission.py
1131 passed in 25.57s

python3 -m ruff check src tests tools
All checks passed!
```

The additional scope/fallback interaction controls described above passed. These are offline source/import/context checks, not live provider, target execution, native analysis, or release qualification. Historical QA counts remain scoped to their original source and are not additive.
