# Rules

**Planned:** the Rules dock is reserved at Ctrl+Shift+R. No panel implementation appears in the inspected branch. A separate CLI workflow exists for proposing, reviewing, testing, and exporting individual rule versions.

The YRX plan starts from one changed-function pair and verified evidence. It separates a candidate, an analyst decision, an accepted stored version, test results, and a local export. Accepting a candidate stores a version; it does not publish or export a file automatically.

Review why each byte window, string, import, or capability was selected. Address-dependent bytes need appropriate masking. Derived rules share the origin of their source evidence and must not become independent votes for the same relationship.

The documented test grid distinguishes Match, No match, and Not scanned. An unreadable file, timeout, missing engine, or absent scan must remain Not scanned. A match on a local test set does not establish general selectivity beyond that set.

The existing guide records a live evidence-wiring limitation for rules propose. If that seam is unavailable, do not expect changing the label or retrying repeatedly to create a valid candidate.

Sources: [YRX plan](../specs/program-e/YRX-integration-plan.md) and [CLI guide](../guide/16-cli-reference.md). **UNVERIFIED:** live candidate generation, graphical controls, real-series tests, export behavior, and native Windows acceptance were not run here.
