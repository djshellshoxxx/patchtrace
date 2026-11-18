# Local KEV context in pilot and KB CLI — 2026-11-16

Parent: `f5cfcfa699d04385e222faab9dbef4cf48378f23` (PR #297).
Completes the remaining saved K4 context-wiring item through existing adapters.

- The pilot collector reads the verified local `KevStore` snapshot into
  `CatalogKev`; loaded dates/identities reach CVE contexts and the existing
  `PilotInputs.kev_snapshot_id`. Missing, damaged or unreadable catalogs stay
  unknown. Recovery notes are preserved; nothing is fetched or executed.
- `pilot why/review` compare the current local snapshot with stored input
  identities. An older matching result can be reused under the existing store
  policy; otherwise changed snapshots are reported stale.
- `kb search --kev-dir DIR` passes the existing exploitation lookup to its
  service. Edges and cards receive CVE-level status; JSON retains listing date,
  snapshot identity and source provenance. Direct service calls without a lookup
  retain their previous behavior. Advisory lookup, coverage and persistence
  remain separate from the KEV annotation.

The two end-to-end regressions failed before implementation: search rejected
`--kev-dir`, and pilot retained unknown context with an unchanged identity.
Final controls exercise listing, nonmembership, replacement/removal, historical
matching-result reuse, corrupted bytes, denied reads, source provenance and
unchanged function/edge order. Catalogue reads leave local files byte-identical.

Combined affected integration selection: **1,224 passed in 36.99 seconds** over
21 test files (R7, project/input paths, KB workflows, pilot, KEV, contracts,
backup integrity and help). Whole-tree Ruff and whitespace checks passed.
These are synthetic/offline and offscreen results, not native accuracy or
Windows package acceptance. Earlier developmental failures were repaired and
the complete affected selection rerun; they are not counted as passing runs.

The supplementary broader batched run has also exposed the already documented
runner restriction: `test_network_consent_guard.py::test_a_local_unix_socket_is_not_network`
cannot create AF_UNIX sockets (`PermissionError: Operation not permitted`).
No sandbox permission or consent assertion was weakened. Another grouped run
was killed with signal 9; the evidence UI subset passed independently (54
tests), and the remaining group passed on a verbose rerun (878 tests).
Another later group was also killed, so full-suite acceptance is
therefore still open even where smaller selections pass.

Required current-head hosted full QA, Windows package/smoke and release checks
remain mandatory. Original timeout-pair/native accuracy and manual acceptance
gates remain open. No release-ready or all-features-complete claim.
