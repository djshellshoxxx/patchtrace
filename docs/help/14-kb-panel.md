# KB and patch search

**Planned:** the KB dock is reserved at Ctrl+Shift+K. The inspected branch has partial KB correlation infrastructure but no KB panel implementation. The existing guide also identifies no registered kb or patch command providing the complete planned workflow.

A KB number identifies an update context. The planned workflow connects updates, advisory CVEs, products, and candidate binary pairs while retaining the source for each relationship. Sharing a monthly document or update context is not sufficient to establish a confirmed KB-to-CVE relationship.

Check product, architecture, servicing branch, and older/newer orientation before selecting a pair. A numerically larger file version or a later-looking timestamp is not a complete predecessor decision. Cumulative and superseding updates can complicate the relationship.

Current file-name acquisition through the Microsoft symbol-server workflow is separate from KB-first patch search. Finding two downloadable versions does not establish that they bracket a specific CVE fix. Keep unresolved applicability explicit in your notes.

Network acquisition must show an operation-specific request and exact hosts before approval. Imported advisory text remains untrusted data and does not prove what a function does. Do not interpret unavailable packages or unresolved deltas as an unchanged binary.

Sources: [KB plan](../specs/program-e/KB-integration-plan.md), [privacy guide](../guide/17-privacy-and-network.md), and [open questions](../guide/99-open-doc-questions.md). **UNVERIFIED:** end-to-end KB search, source joins, predecessor resolution, and acquisition acceptance were not run here.
