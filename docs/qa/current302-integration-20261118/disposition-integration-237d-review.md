# Integration 237d independent disposition and ZIP review

Exact source: `237d216f0784d429bfc5c61103100346576e0831`, tree `e5b934d1438d9298a1695645e48b9e46c02ee0af`.

Merge `22aa4e8f58f69b7d8c90c15b263c732c8c6bdeac` has the actual parents `6cc6b6b77564e12eaec2917877d94525a69c7102` and `121ffb0bcdd6af4f24e5035389d4709dffddf263`. The following commit adds copied-target predecessor compatibility in lineage, its spec and its regression controls.

**No ZIP or overlap-preservation blocker found in this bounded review.**

- All 40 paths changed only on current #304 remain byte-identical, including native publication work, .tsp support and separate source/QA evidence.
- The L1 test file remains exactly current #304, retaining the valid-.tsp fixture and missing-metadata BLOCKED control.
- Resolver, service, ZIP verifier and their listed incoming controls are byte-identical to the reviewed new #302 versions.
- The Windows acceptance specification retains both the incoming separator-normalization rule and current #304 native-publication appendix.
- All nine fresh ancestor-designated PR tips, including moved #302, are now ancestors of this local integration commit. The four selective-port PRs retain their narrower semantic conditions.

Six authored ZIP cases were evaluated against incoming #302 and this exact integration (12 evaluations). Benign backslash names are accepted under POSIX and simulated Windows reader separators; NUL truncation and case aliases remain rejected. The earlier retained cross-head control shows the false rejection in old #304. These are bounded Linux controls, not native Windows qualification.

The separate lineage reviewer owns independent behavior review of partial order, ambiguity, enumeration bounds and the copied-target compatibility follow-up. This report does not replace that review or the hosted gates.

No closure or remote merge is approved by local ancestry. Closures remain conditional on a qualified #304 merge, verification on main and a fresh exact-head check. No PR, branch, source file or target acquisition was changed by this review.

Machine-readable checks and exact paths: [integration-237d-review.json](integration-237d-review.json). Historical refresh and all eleven incoming commits: [receipt.json](receipt.json), [new302-overlap-map.json](new302-overlap-map.json).
