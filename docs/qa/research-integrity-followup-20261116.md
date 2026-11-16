# Research integrity recovery — 2026-11-16

Base: PR #298 head `2d330075fbe00209fbe096ee29b60dcfd0e347b4`.
Selective recovery preserves current protections instead of merging historical
integration branches wholesale.

## Tier R provenance and receipt preservation (#164)

Recovered the missing analysis-cache provenance key, ambiguous unchanged-control
handling, and immutable build receipts. Equal debug-image bytes no longer make
different recipes/source contexts share a SideData result. The key includes the
newer source-directory normalization context. Ambiguous declared controls remain
unchecked rather than contributing verified agreement.

Every complete build record is retained by its content digest before atomically
updating the legacy build.json view using a separate staged inode. Existing
receipts require bounded exact-byte verification; collisions, symlinks and
unsupported publication fail closed. Sync/link/view failures preserve earlier
records. This local-store writer does not claim hostile-parent race protection.

Historical regression recovery reproduced **16 failures and 5 passes** before
implementation. Final integrated selection: **155 passed, 8 skipped**:

```
tests/test_tier_r_build_receipts_r1.py
tests/test_tier_r_label_promotion_r1.py
tests/test_tier_r_session_provenance_r1.py
tests/test_tier_r_factory.py
tests/test_tier_r_catalogue.py
tests/test_tier_r_msvc.py
tests/test_unified_rb01_harness.py
```

Five factory and two RB-01 cases require unavailable LLVM/MinGW tools; one MSVC
case requires Windows. The fake-compiler build integration verifies that equal
bytes with different recipe provenance retain both receipts. Independent review
ran the three new regression files: **29 passed**, with no blocking finding.

## Native API research IO controls (#222)

Recovered the distinct-byte/context C controls and added reusable exact-mode
validation for matrix, IO, wrong-bytes and wrong-IO runs. Validation requires the
specific row inventories, error/read counts and process exits; missing or extra
rows, malformed bytes, unexpected stderr and crashes cannot qualify. Invalid
mode/variant selection fails before mutation/execution. Each attempt reserves
exclusive evidence names and preserves failed-run raw bytes and provenance.

Integrated `test_rzdiff_io_evidence.py` and `test_rzdiff_native_evidence.py`:
**136 passed** after the worker-count portability repair, including the compiled repository-authored C coverage helper.
That helper uses list doubles; it is not linked-native Rizin qualification.
Independent source review found no blocking issue. No product singleton refusal,
runtime approval, cache policy or quarantine changes were made.

Fresh pinned Linux API execution exposed an incorrect fixed two-worker read-count
assumption. Pinned source analysis established the per-worker singleton preread.
The repaired validator requires native and independent host counts to agree,
derives exact read counts from that observation, and retains all other exact
negative-control invariants. All six fresh stock/corrected/negative modes matched
expectations. [Raw receipts and provenance](native-api-20261116/README.md) retain
the earlier loader and fixed-count failures separately. This qualifies authored
Linux API controls only; it does not qualify CLI JSON or product acceptance.

Whole-tree Ruff and whitespace checks passed. Hosted and live native qualification
remain separate. These test counts do not imply Windows, CLI JSON, real-binary
matching, original-pair timeout repair or release acceptance.

## Additional branch disposition

#154 and #157 were closed as semantically superseded through already-integrated
#215 and #217 after implementation/spec/regression review. Their exact original
heads are not ancestors of main; archival QA/evidence and branches are retained.
Together with the prior ten ancestry-verified closures, twelve redundant PRs are
closed. #150 retains a distinct research stack and stays open. #164 and #222 are
not approved for wholesale merging by these selective recoveries.
