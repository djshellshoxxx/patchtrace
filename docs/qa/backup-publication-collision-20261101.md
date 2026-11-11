# Backup collision review — November 1, 2026

The fresh PR151 review found that `part.replace(target)` could overwrite a prior verified backup on a repeated timestamp; subsequent publication verification failure would then leave earlier evidence lost. Actual SQLite regressions on the original candidate reproduced two failures: overwritten earlier backup and reused/deleted preexisting `.part`. Original logs are retained.

Source `3ff98f7748f30db3223348389fb2661c7aec92d3` uses an exclusively created unique sibling stage and an atomic hard link that cannot replace an occupied destination. It cleans only its owned stage inode, preserves earlier final/pending evidence and retains post-publication byte verification. A racing destination or unavailable hardlinks fails closed; there is no replacing fallback. The normative spec states this limitation.

Coordinator39 backup/prune/sidecar/retention tests passed3.17s; independent39 passed2.86s. Independent real SQLite controls additionally preserve original backup bytes/trust on collision, keep a replaced temporary inode/name untouched, and show actual ProjectService saves under unsupported/EPERM link failures keep all history while committing current snapshots. Injected failures are not native Windows filesystem acceptance. Full Ruff/diff checks pass. Receipt:`backup-publication-independent-review-20261101.json`; first red and green logs retained compressed.

The final published head still requires exact-head cross-OS/full/Qt/quality/package acceptance. Prior successful checks apply to the earlier source only. No arbitrary same-user writer lock or universal durability claim.
