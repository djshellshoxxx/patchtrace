# Independent Windows secondary fixture review — 2026-11-02

No blocking findings in source `3731a8cfae1e5bed7f2311400586db831a606395`, tree `2300c46ad0062f397b588ba1b4721826f39d2436`, from `eccfb8d587f94e927f857fad248531a002ecc36c`. QA-only `f33ab9e7d43b8ae4d4e1609e2f1f2a64961122f7` retains identical tests. Worktree clean; adjacent JSON binds hashes.

The two test changes correct text stdout newline translation and the former root-relative Windows executable path. Explicit binary LF/CRLF cases retain exact raw-digest assertions. Actual absolute paths with spaces, with and without `.exe`, reach the real probe through an injected runner. Version0.9.1 remains quarantined, with matching and old-cache reuse forbidden. Production code and pins are unchanged.

Independent validation: **52 passed in 1.19 s**, changed-test Ruff and diff checks passed. A separate PureWindowsPath control verified refusal before probe for the original path and exactly one probe followed by orientation quarantine for a drive-absolute path. Both newline digests match the saved Windows failure traceback; no native executable was run by that control.

Actual Windows CI remains required. No full/native/performance job, repository edit or remote action was performed.
