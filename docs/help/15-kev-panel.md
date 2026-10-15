# KEV context

**Planned:** the KEV dock is reserved at Ctrl+Shift+X, tabbed with KB. Its panel implementation is absent from the inspected branch. The kev CLI is documented separately and can work with stored catalog snapshots.

KEV is context about a CVE listed in CISA's Known Exploited Vulnerabilities catalog. It is not a property assigned to a particular function in your binary. Catalog membership does not establish product applicability, patch coverage, or the identity of the changed code.

Use a recorded snapshot and read its date, source, and freshness. A catalog that is absent, stale, or unreadable cannot support a current negative answer. Even a current non-listing states only what that snapshot contains.

The CLI guide describes local import, status, lookup, and diff operations, plus a fetch operation requiring exact-host consent. Fetching the catalog is separate from looking up a CVE locally; opening stored results should not cause automatic refresh.

KEV does not change attention ranking or engine matching values. Keep it in a separate context lane when writing your conclusion. Do not translate membership into a numeric function score.

Sources: [KEV plan](../specs/program-e/KEV-integration-plan.md), [CLI guide](../guide/16-cli-reference.md), and [evidence guide](../guide/12-evidence-and-engines.md). **UNVERIFIED:** current upstream catalog contents, graphical integration, report attachment, and native Windows behavior were not checked here.
