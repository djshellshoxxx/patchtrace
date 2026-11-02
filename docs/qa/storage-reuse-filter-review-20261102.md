# Independent storage reuse filter review — 2026-11-02

No blocking finding at `94caeb1e3ac723163f47f952ba395346a197cd02`, parent `7d9dce5c228235cecb7a08f3b55895addeb05b86`. Candidate worktree was clean and its source remained unchanged. Changed-file SHA-256 values and exact commands are recorded in the JSON sibling.

The six-line filter rejects only already-ineligible cached verdicts. Eligible candidates still pass through `_cached` and its complete fresh fingerprint, and `trusted_backup` still checks the facts actually returned. Cache entries and facts are immutable snapshots read under the existing lock. A stale refusal cannot authorize deletion; preparatory `find_verified_backup` remains able to hash changed candidates and establish a new verdict. No cap, deletion behavior, or metadata-only trust path was introduced.

Independent execution: **52 related tests passed in 4.24s**, including byte-tampering, publication collision, history-pruning, retention, and Windows stat-API controls. The exact final four new tests were copied byte-for-byte to a detached parent worktree: **four expected failures in 0.41s**, each at the unwanted-byte-read assertion. Source import paths were verified in both worktrees. Whole-repository Ruff and whitespace checks passed.

Seven reviewer-only controls passed in 0.53s. Four replace and really verify the SQLite candidate between the prefilter and final check (failed database, foreign project, changed snapshot, missing history table); `_cached` returns the new known verdict, and all are refused. A fifth removes the cache entry during that interval. A sixth checks that a newer ineligible candidate does not hide an older eligible backup and that only the eligible bytes are hashed. The public-save control verifies that a foreign cached backup plus an unverifiable replacement keeps every prior history row, commits the new save, preserves prior backup bytes, and leaves no temporary file.

One nonblocking pre-existing documentation nit: the verified-backup row in `docs/modules.md` still describes publication as “rename”. The newer normative spec and implementation correctly require exclusive, non-replacing hard-link publication.

Evidence is in `storage-filter-review/`; the JSON sibling binds its files by SHA-256. This review makes no full-suite, throughput, native Windows, or power-loss acceptance claim. No remote writes were made; the separate CG-3 candidate remains frozen.
