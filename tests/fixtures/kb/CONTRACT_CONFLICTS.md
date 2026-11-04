# KB fixture contract conflicts and verification gaps

These are historical fixture-authoring constraints discovered on the original
source branch, followed by current reconciliation notes. They do not override
the current source contracts or describe limits of the integration session.

1. The broad KB/CVE specs name proposed `patch-search/1` records and fields such as `SourceSnapshot`, `KbCveEdge`, `PairCandidate`, `BinaryRef`, and `SearchCoverage`. The current `src/patchtrace/kbcorrelation/contracts.py` defines the shipped-in-tree `kbcorrelation/1` vocabulary instead, including `SourceDoc`, `KbCveEdge`, `PairProposal`, and coverage states `complete_in_scope`, `partial_in_scope`, `stale_cache`, `unknown_scope`, and `not_searched`. The fixture files therefore assert only their own synthetic wrapper format and do not assert that either contract implementation is present in new runtime code.

2. Current tracked fixtures use the explicitly synthetic `cvrf-json/0` / `cvrf-xml/0` placeholder dialects. The live MSRC CVRF v3 document body shape remains UNVERIFIED in the research notes. The new CVRF-shaped examples do not claim to be authentic provider samples.

3. Prompt 4 asks for reducer property tests, but a module named `src/patchtrace/kbcorrelation/reducer.py` was not present at the inspected branch path. Existing tests already exercise `tests/kbc_helpers.py`, `tests/kbc_k1_support.py`, `src/patchtrace/kbcorrelation/sources/cvrf.py`, and `sources/importer.py`. Adding tests against a nonexistent reducer API would invent a contract, so this branch records the reducer invariants in a fixture corpus test-plan file rather than importing a guessed API.

4. The fixture task asks for 9 named crash-injection points across source commit, artifact verification, project creation, sidecar attach, triage and migration. Current inspected tree did not expose the proposed companion-store path/API; its exact owner and injection seams are UNVERIFIED. The accompanying harness treats these names as a protocol specification only and does not imply the store exists.

5. Update-package container labels (MSU, CAB, PSFX, forward/reverse delta) describe synthetic scenarios only. No payload is included, and no claim is made that each container or reconstruction path is supported by current code.

6. For all generated fixture digests, byte counts, live URLs, licences and provider schema compatibility, values are UNVERIFIED unless directly calculated from authored bytes or checked against an authoritative source. The original fixture-authoring task did not permit execution or network verification.

## Current-contract reconciliation (2026-10-30)

The placeholder CVRF fixtures remain distinct from the live MSRC dialect now
implemented in the application. No production parser is changed to accommodate
these invented shapes. Missing socket-denial fixtures are explicitly registered.
The unknown-type CVRF test derives a type-99 case from a valid known-issue record;
its original lookup referenced a scenario that existed only in the CSAF file.
SYN-CSAF-005 intentionally has no vulnerabilities. A separate `confusable_kb.json` case
decodes to Cyrillic U+0417, with a guard assertion against accidental double
escaping. The original incorrectly escaped corpus entry is preserved unchanged. The BOM case is rejected and the CRLF case imported by the real parser.
See README.md for the remaining structural-only coverage limitations.
