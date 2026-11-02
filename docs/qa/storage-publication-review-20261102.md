# Independent backup-publication review — 2026-11-02

No blocking findings in the revised candidate. The pending-scan fail-open blocker found during this review is resolved.

- Reviewer: `/root/msrc_recover`; author: `/root/rd_recover`.
- Base: `9c468bc75077484c1780305d7cc927b30fd0bc8b`.
- Reviewed head: `58c1c12e6fb76e9ae8453724166b76f70d8aa8f6`.
- Tree: `36d8cbdf04f14bcc632726e9fce83a7cb24f3e27`.
- Clean isolated checkout: `/workspace/scratch/142cb233d750/wt-storage-adoption-review`.

The exact original #151 review allegation and retained SQLite probe were inspected. The first candidate, `536aebc`, retained failed publications correctly but used `Path.glob` to enumerate pending stages. That API swallowed directory-read errors, allowing valid but incomplete failed finals to be adopted. Three independent real-SQLite controls reproduced this with PermissionError, FileNotFoundError and OSError; the actual second-thread publication control already passed. The blocker receipt and red log are retained separately.

The revised code uses explicit error-propagating directory scans. Final enumeration precedes pending-stage enumeration; opening, iteration or entry-metadata errors refuse all candidates. A pending stage excludes its final even with cached verification. Post-link failure retains stage/final bytes, while only the owned stage may be removed after final byte validation. The implementation never deletes or renames a final path, preserves foreign/replaced artifacts, and allows an earlier completed backup. The real retention/history and close/reopen regressions exercise preservation of rows absent from a failed copy.

Independent verification:

- Revised focused selection plus four independent controls: **67 passed in 5.12 s**.
- Expanded six independent controls: **6 passed in 0.48 s**, including both entry-metadata failure paths and a second thread observing the linked-but-unvalidated final before successful completion. The four earlier controls overlap this six-test run; counts are not additive.
- Changed-file Ruff and base-to-head whitespace checks passed.

The initial 536aebc author selection passed 60 tests while the additional review controls exposed the blocker. An intermediate edit mistake in the expanded reviewer-only test file caused two setup failures; its test function grouping was corrected before the final six-test result. No production source was changed by the reviewer.

The JSON sibling hashes every changed file and the final independent control source. Logs and controls live in `reviews-msrc/`. No remote mutation, native/heavy/full-suite job, native Windows acceptance or power-loss guarantee is claimed. Legacy unmarked backups retain the existing policy; arbitrary same-user namespace mutation is outside this bounded claim. This is independent evidence, not a GitHub APPROVE event.
